use std::{
    collections::VecDeque,
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Condvar, Mutex, OnceLock,
    },
    time::Duration,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CLEANUP_WORKERS: usize = 2;
const CLEANUP_QUEUE_CAPACITY: usize = 32;
const CLEANUP_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(2);
const FORCE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const FAILURE_HISTORY_CAPACITY: usize = 128;

pub(crate) type CleanupPhase<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub(crate) trait CleanupPayload: Send + 'static {
    fn normal_cleanup(&mut self) -> CleanupPhase<'_>;
    fn force_cleanup(&mut self) -> CleanupPhase<'_>;
}

type Completion = Box<dyn FnOnce(CleanupJobOutcome) + Send + 'static>;
type RuntimeFactory =
    Arc<dyn Fn(usize) -> Result<tokio::runtime::Runtime, String> + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CleanupJobMeta {
    pub kind: &'static str,
    pub generation: Option<u64>,
    pub route_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CleanupFailureSummary {
    pub job_kind: String,
    pub generation: Option<u64>,
    pub route_id_summary: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CleanupSupervisorSnapshot {
    pub worker_count: usize,
    pub force_only_worker_count: usize,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub admission_capacity: usize,
    pub available_admission_slots: usize,
    pub accepting_new_peers: bool,
    pub active_jobs: usize,
    pub submitted_jobs: u64,
    pub completed_jobs: u64,
    pub normal_jobs: u64,
    pub forced_jobs: u64,
    pub force_failed_jobs: u64,
    pub failed_jobs: u64,
    pub timed_out_jobs: u64,
    pub panicked_jobs: u64,
    pub executor_unavailable_jobs: u64,
    pub saturated_jobs: u64,
    pub last_failure: Option<CleanupFailureSummary>,
    pub recent_failures: Vec<CleanupFailureSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupForceTrigger {
    Failure,
    TimedOut,
    Panicked,
    ExecutorUnavailable,
}

#[derive(Debug, Clone)]
pub(crate) enum CleanupJobOutcome {
    Completed,
    Forced {
        trigger: CleanupForceTrigger,
        force_failed: bool,
    },
}

impl CleanupJobOutcome {
    pub(crate) fn error_message(&self) -> Option<String> {
        match self {
            Self::Completed => None,
            Self::Forced {
                trigger,
                force_failed,
            } => {
                let trigger = match trigger {
                    CleanupForceTrigger::Failure => "cleanup job failed",
                    CleanupForceTrigger::TimedOut => "cleanup job timed out",
                    CleanupForceTrigger::Panicked => "cleanup job panicked",
                    CleanupForceTrigger::ExecutorUnavailable => {
                        "cleanup executor became unavailable"
                    }
                };
                let force = if *force_failed {
                    "forced teardown failed"
                } else {
                    "forced teardown completed"
                };
                Some(format!("{trigger}; {force}"))
            }
        }
    }
}

pub(crate) struct CleanupPermit {
    supervisor: Arc<CleanupSupervisor>,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct RejectedCleanup<P> {
    pub permit: CleanupPermit,
    pub payload: P,
    pub reason: String,
}

struct CleanupJob {
    meta: CleanupJobMeta,
    timeout: Duration,
    payload: Option<Box<dyn CleanupPayload>>,
    permit: Option<CleanupPermit>,
    completion: Option<Completion>,
}

impl CleanupJob {
    fn finish(&mut self, outcome: CleanupJobOutcome) {
        self.payload.take();
        self.permit.take();
        if let Some(completion) = self.completion.take() {
            completion(outcome);
        }
    }
}

#[derive(Default)]
struct CleanupMetrics {
    normal_workers: AtomicUsize,
    force_only_workers: AtomicUsize,
    active_jobs: AtomicUsize,
    submitted_jobs: AtomicU64,
    completed_jobs: AtomicU64,
    normal_jobs: AtomicU64,
    forced_jobs: AtomicU64,
    force_failed_jobs: AtomicU64,
    failed_jobs: AtomicU64,
    timed_out_jobs: AtomicU64,
    panicked_jobs: AtomicU64,
    executor_unavailable_jobs: AtomicU64,
    saturated_jobs: AtomicU64,
    recent_failures: Mutex<VecDeque<CleanupFailureSummary>>,
}

pub(crate) struct CleanupSupervisor {
    queue: Mutex<VecDeque<CleanupJob>>,
    has_work: Condvar,
    startup: Condvar,
    queue_capacity: usize,
    admission: Arc<Semaphore>,
    accepting: AtomicBool,
    stopping: AtomicBool,
    worker_handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
    metrics: CleanupMetrics,
    #[cfg(test)]
    worker_exit_after_jobs: AtomicUsize,
}

impl CleanupSupervisor {
    fn new(queue_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::with_capacity(queue_capacity)),
            has_work: Condvar::new(),
            startup: Condvar::new(),
            queue_capacity,
            admission: Arc::new(Semaphore::new(queue_capacity)),
            accepting: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            worker_handles: Mutex::new(Vec::new()),
            metrics: CleanupMetrics::default(),
            #[cfg(test)]
            worker_exit_after_jobs: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn start_for_test(
        worker_count: usize,
        queue_capacity: usize,
    ) -> Result<Arc<Self>, String> {
        Self::start_with(worker_count, queue_capacity)
    }

    fn start_with(worker_count: usize, queue_capacity: usize) -> Result<Arc<Self>, String> {
        let supervisor = Self::new(queue_capacity);
        supervisor.launch_workers(worker_count, default_runtime_factory())?;
        Ok(supervisor)
    }

    fn launch_workers(
        self: &Arc<Self>,
        worker_count: usize,
        runtime_factory: RuntimeFactory,
    ) -> Result<(), String> {
        if worker_count == 0 {
            return Err("cleanup executor unavailable: no workers configured".into());
        }
        let (ready_tx, ready_rx) = mpsc::sync_channel(worker_count);
        let mut spawned = 0_usize;
        for index in 0..worker_count {
            let worker = Arc::clone(self);
            let runtime_factory = Arc::clone(&runtime_factory);
            let ready_tx = ready_tx.clone();
            if let Ok(handle) = std::thread::Builder::new()
                .name(format!("mrd-webrtc-cleanup-{index}"))
                .spawn(move || {
                    let runtime = catch_unwind(AssertUnwindSafe(|| runtime_factory(index)))
                        .unwrap_or_else(|_| Err("cleanup runtime factory panicked".into()));
                    let Ok(runtime) = runtime else {
                        let _ = ready_tx.send(false);
                        return;
                    };
                    worker.metrics.normal_workers.fetch_add(1, Ordering::AcqRel);
                    let _ = ready_tx.send(true);
                    worker.wait_for_startup();
                    if worker.stopping.load(Ordering::Acquire) {
                        worker.metrics.normal_workers.fetch_sub(1, Ordering::AcqRel);
                        return;
                    }
                    worker.run_worker(runtime);
                })
            {
                spawned += 1;
                self.worker_handles
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(handle);
            }
        }
        drop(ready_tx);
        let mut ready = 0_usize;
        for _ in 0..spawned {
            match ready_rx.recv_timeout(WORKER_READY_TIMEOUT) {
                Ok(true) => ready += 1,
                Ok(false) => {}
                Err(_) => break,
            }
        }
        if ready == 0 {
            self.stopping.store(true, Ordering::Release);
            self.startup.notify_all();
            self.has_work.notify_all();
            return Err("cleanup executor unavailable: every runtime failed to initialize".into());
        }
        self.accepting.store(true, Ordering::Release);
        self.startup.notify_all();
        Ok(())
    }

    fn wait_for_startup(&self) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while !self.accepting.load(Ordering::Acquire) && !self.stopping.load(Ordering::Acquire) {
            queue = self
                .startup
                .wait(queue)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }

    async fn reserve(self: &Arc<Self>) -> Result<CleanupPermit, String> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err("cleanup capacity unavailable".into());
        }
        let permit = tokio::time::timeout(
            CLEANUP_ADMISSION_TIMEOUT,
            Arc::clone(&self.admission).acquire_owned(),
        )
        .await
        .map_err(|_| "cleanup capacity admission timed out".to_string())?
        .map_err(|_| "cleanup capacity unavailable".to_string())?;
        if !self.accepting.load(Ordering::Acquire) {
            drop(permit);
            return Err("cleanup executor unavailable".into());
        }
        Ok(CleanupPermit {
            supervisor: Arc::clone(self),
            _permit: permit,
        })
    }

    #[cfg(test)]
    fn try_reserve(self: &Arc<Self>) -> Result<CleanupPermit, String> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err("cleanup capacity unavailable".into());
        }
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| "cleanup capacity exhausted".to_string())?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err("cleanup executor unavailable".into());
        }
        Ok(CleanupPermit {
            supervisor: Arc::clone(self),
            _permit: permit,
        })
    }

    fn run_worker(&self, runtime: tokio::runtime::Runtime) {
        let mut force_only = false;
        loop {
            let mut job = {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                while queue.is_empty() {
                    if self.stopping.load(Ordering::Acquire) {
                        if force_only {
                            self.metrics
                                .force_only_workers
                                .fetch_sub(1, Ordering::AcqRel);
                        } else {
                            self.metrics.normal_workers.fetch_sub(1, Ordering::AcqRel);
                        }
                        return;
                    }
                    queue = self
                        .has_work
                        .wait(queue)
                        .unwrap_or_else(|poison| poison.into_inner());
                }
                queue.pop_front().expect("non-empty cleanup queue")
            };
            self.metrics.active_jobs.fetch_add(1, Ordering::AcqRel);
            let outcome = if force_only {
                execute_force_only(&runtime, &mut job, CleanupForceTrigger::ExecutorUnavailable)
            } else {
                execute_job(&runtime, &mut job)
            };
            self.metrics.active_jobs.fetch_sub(1, Ordering::AcqRel);
            let meta = job.meta;
            let completion = catch_unwind(AssertUnwindSafe(|| job.finish(outcome.clone())));
            self.record_completion(
                &meta,
                if completion.is_err() {
                    &CleanupJobOutcome::Forced {
                        trigger: CleanupForceTrigger::Panicked,
                        force_failed: false,
                    }
                } else {
                    &outcome
                },
            );
            if !force_only && self.should_exit_worker_for_test() {
                let previous = self.metrics.normal_workers.fetch_sub(1, Ordering::AcqRel);
                if previous == 1 {
                    self.accepting.store(false, Ordering::Release);
                    self.metrics
                        .force_only_workers
                        .fetch_add(1, Ordering::AcqRel);
                    force_only = true;
                } else {
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    fn should_exit_worker_for_test(&self) -> bool {
        self.worker_exit_after_jobs
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok_and(|previous| previous == 1)
    }

    #[cfg(not(test))]
    fn should_exit_worker_for_test(&self) -> bool {
        false
    }

    fn record_completion(&self, meta: &CleanupJobMeta, outcome: &CleanupJobOutcome) {
        self.metrics.completed_jobs.fetch_add(1, Ordering::AcqRel);
        let failure = match outcome {
            CleanupJobOutcome::Completed => {
                self.metrics.normal_jobs.fetch_add(1, Ordering::AcqRel);
                return;
            }
            CleanupJobOutcome::Forced {
                trigger,
                force_failed,
            } => {
                self.metrics.forced_jobs.fetch_add(1, Ordering::AcqRel);
                if *force_failed {
                    self.metrics
                        .force_failed_jobs
                        .fetch_add(1, Ordering::AcqRel);
                }
                match trigger {
                    CleanupForceTrigger::Failure => "normal cleanup failed; force phase ran",
                    CleanupForceTrigger::TimedOut => {
                        self.metrics.timed_out_jobs.fetch_add(1, Ordering::AcqRel);
                        "normal cleanup timed out; force phase ran"
                    }
                    CleanupForceTrigger::Panicked => {
                        self.metrics.panicked_jobs.fetch_add(1, Ordering::AcqRel);
                        "normal cleanup panicked; force phase ran"
                    }
                    CleanupForceTrigger::ExecutorUnavailable => {
                        self.metrics
                            .executor_unavailable_jobs
                            .fetch_add(1, Ordering::AcqRel);
                        "normal executor unavailable; force phase ran"
                    }
                }
            }
        };
        self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
        let mut failures = self
            .metrics
            .recent_failures
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if failures.len() == FAILURE_HISTORY_CAPACITY {
            failures.pop_front();
        }
        failures.push_back(CleanupFailureSummary {
            job_kind: meta.kind.into(),
            generation: meta.generation,
            route_id_summary: meta
                .route_id
                .map(|route| format!("route-{:08x}", route as u32)),
            reason: if matches!(
                outcome,
                CleanupJobOutcome::Forced {
                    force_failed: true,
                    ..
                }
            ) {
                format!("{failure}; force phase failed")
            } else {
                failure.into()
            },
        });
    }

    pub(crate) fn snapshot(&self) -> CleanupSupervisorSnapshot {
        let queue_depth = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len();
        let recent_failures = self
            .metrics
            .recent_failures
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        CleanupSupervisorSnapshot {
            worker_count: self.metrics.normal_workers.load(Ordering::Acquire),
            force_only_worker_count: self.metrics.force_only_workers.load(Ordering::Acquire),
            queue_capacity: self.queue_capacity,
            queue_depth,
            admission_capacity: self.queue_capacity,
            available_admission_slots: self.admission.available_permits(),
            accepting_new_peers: self.accepting.load(Ordering::Acquire),
            active_jobs: self.metrics.active_jobs.load(Ordering::Acquire),
            submitted_jobs: self.metrics.submitted_jobs.load(Ordering::Acquire),
            completed_jobs: self.metrics.completed_jobs.load(Ordering::Acquire),
            normal_jobs: self.metrics.normal_jobs.load(Ordering::Acquire),
            forced_jobs: self.metrics.forced_jobs.load(Ordering::Acquire),
            force_failed_jobs: self.metrics.force_failed_jobs.load(Ordering::Acquire),
            failed_jobs: self.metrics.failed_jobs.load(Ordering::Acquire),
            timed_out_jobs: self.metrics.timed_out_jobs.load(Ordering::Acquire),
            panicked_jobs: self.metrics.panicked_jobs.load(Ordering::Acquire),
            executor_unavailable_jobs: self
                .metrics
                .executor_unavailable_jobs
                .load(Ordering::Acquire),
            saturated_jobs: self.metrics.saturated_jobs.load(Ordering::Acquire),
            last_failure: recent_failures.last().cloned(),
            recent_failures,
        }
    }

    #[cfg(test)]
    fn inject_worker_exit_after_jobs(&self, jobs: usize) {
        self.worker_exit_after_jobs.store(jobs, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn shutdown_for_test(&self) {
        self.stopping.store(true, Ordering::Release);
        self.accepting.store(false, Ordering::Release);
        self.startup.notify_all();
        self.has_work.notify_all();
        let handles = std::mem::take(
            &mut *self
                .worker_handles
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        );
        for handle in handles {
            let _ = handle.join();
        }
    }
}

enum PhaseResult {
    Completed,
    Failed,
    TimedOut,
    Panicked,
}

fn run_normal_phase(
    runtime: &tokio::runtime::Runtime,
    timeout: Duration,
    payload: &mut dyn CleanupPayload,
) -> PhaseResult {
    catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            match tokio::time::timeout(timeout, payload.normal_cleanup()).await {
                Ok(Ok(())) => PhaseResult::Completed,
                Ok(Err(_)) => PhaseResult::Failed,
                Err(_) => PhaseResult::TimedOut,
            }
        })
    }))
    .unwrap_or(PhaseResult::Panicked)
}

fn run_force_phase(
    runtime: &tokio::runtime::Runtime,
    payload: &mut dyn CleanupPayload,
) -> PhaseResult {
    catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            match tokio::time::timeout(FORCE_CLEANUP_TIMEOUT, payload.force_cleanup()).await {
                Ok(Ok(())) => PhaseResult::Completed,
                Ok(Err(_)) => PhaseResult::Failed,
                Err(_) => PhaseResult::TimedOut,
            }
        })
    }))
    .unwrap_or(PhaseResult::Panicked)
}

fn execute_job(runtime: &tokio::runtime::Runtime, job: &mut CleanupJob) -> CleanupJobOutcome {
    let Some(payload) = job.payload.as_mut() else {
        return CleanupJobOutcome::Forced {
            trigger: CleanupForceTrigger::Failure,
            force_failed: true,
        };
    };
    let trigger = match run_normal_phase(runtime, job.timeout, payload.as_mut()) {
        PhaseResult::Completed => return CleanupJobOutcome::Completed,
        PhaseResult::Failed => CleanupForceTrigger::Failure,
        PhaseResult::TimedOut => CleanupForceTrigger::TimedOut,
        PhaseResult::Panicked => CleanupForceTrigger::Panicked,
    };
    execute_force(runtime, payload.as_mut(), trigger)
}

fn execute_force_only(
    runtime: &tokio::runtime::Runtime,
    job: &mut CleanupJob,
    trigger: CleanupForceTrigger,
) -> CleanupJobOutcome {
    let Some(payload) = job.payload.as_mut() else {
        return CleanupJobOutcome::Forced {
            trigger,
            force_failed: true,
        };
    };
    execute_force(runtime, payload.as_mut(), trigger)
}

fn execute_force(
    runtime: &tokio::runtime::Runtime,
    payload: &mut dyn CleanupPayload,
    trigger: CleanupForceTrigger,
) -> CleanupJobOutcome {
    CleanupJobOutcome::Forced {
        trigger,
        force_failed: !matches!(run_force_phase(runtime, payload), PhaseResult::Completed),
    }
}

fn default_runtime_factory() -> RuntimeFactory {
    Arc::new(|_| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "cleanup runtime initialization failed".into())
    })
}

fn global_supervisor() -> Result<&'static Arc<CleanupSupervisor>, String> {
    static SUPERVISOR: OnceLock<Result<Arc<CleanupSupervisor>, String>> = OnceLock::new();
    match SUPERVISOR
        .get_or_init(|| CleanupSupervisor::start_with(CLEANUP_WORKERS, CLEANUP_QUEUE_CAPACITY))
    {
        Ok(supervisor) => Ok(supervisor),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) async fn reserve_cleanup_slot() -> Result<CleanupPermit, String> {
    global_supervisor()?.reserve().await
}

#[cfg(test)]
pub(crate) async fn reserve_cleanup_slot_from(
    supervisor: &Arc<CleanupSupervisor>,
) -> Result<CleanupPermit, String> {
    supervisor.reserve().await
}

pub(crate) fn submit_cleanup<P, A, C>(
    permit: CleanupPermit,
    meta: CleanupJobMeta,
    timeout: Duration,
    payload: P,
    accepted: A,
    completion: C,
) -> Result<(), RejectedCleanup<P>>
where
    P: CleanupPayload,
    A: FnOnce() + Send + 'static,
    C: FnOnce(CleanupJobOutcome) + Send + 'static,
{
    let supervisor = Arc::clone(&permit.supervisor);
    if supervisor.metrics.normal_workers.load(Ordering::Acquire) == 0
        && supervisor
            .metrics
            .force_only_workers
            .load(Ordering::Acquire)
            == 0
    {
        return Err(RejectedCleanup {
            permit,
            payload,
            reason: "cleanup executor unavailable".into(),
        });
    }
    let mut queue = supervisor
        .queue
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if queue.len() >= supervisor.queue_capacity {
        supervisor
            .metrics
            .saturated_jobs
            .fetch_add(1, Ordering::AcqRel);
        drop(queue);
        return Err(RejectedCleanup {
            permit,
            payload,
            reason: "reserved cleanup invariant violated".into(),
        });
    }
    supervisor
        .metrics
        .submitted_jobs
        .fetch_add(1, Ordering::AcqRel);
    queue.push_back(CleanupJob {
        meta,
        timeout,
        payload: Some(Box::new(payload)),
        permit: Some(permit),
        completion: Some(Box::new(completion)),
    });
    // The queue owns the physical payload before logical state becomes Closing. Workers cannot
    // observe it until notification below, so accepted is the atomic publication boundary.
    accepted();
    supervisor.has_work.notify_one();
    Ok(())
}

pub fn cleanup_supervisor_snapshot() -> CleanupSupervisorSnapshot {
    match global_supervisor() {
        Ok(supervisor) => supervisor.snapshot(),
        Err(_) => CleanupSupervisorSnapshot {
            worker_count: 0,
            force_only_worker_count: 0,
            queue_capacity: CLEANUP_QUEUE_CAPACITY,
            queue_depth: 0,
            admission_capacity: CLEANUP_QUEUE_CAPACITY,
            available_admission_slots: 0,
            accepting_new_peers: false,
            active_jobs: 0,
            submitted_jobs: 0,
            completed_jobs: 0,
            normal_jobs: 0,
            forced_jobs: 0,
            force_failed_jobs: 0,
            failed_jobs: 1,
            timed_out_jobs: 0,
            panicked_jobs: 0,
            executor_unavailable_jobs: 1,
            saturated_jobs: 0,
            last_failure: Some(executor_start_failure()),
            recent_failures: vec![executor_start_failure()],
        },
    }
}

fn executor_start_failure() -> CleanupFailureSummary {
    CleanupFailureSummary {
        job_kind: "executor-start".into(),
        generation: None,
        route_id_summary: None,
        reason: "cleanup executor unavailable".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const TEST_COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);

    enum NormalBehavior {
        Complete,
        Fail,
        Panic,
        Wait(Arc<Semaphore>),
    }

    struct TestPayload {
        behavior: NormalBehavior,
        forced: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for TestPayload {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl CleanupPayload for TestPayload {
        fn normal_cleanup(&mut self) -> CleanupPhase<'_> {
            Box::pin(async move {
                match &self.behavior {
                    NormalBehavior::Complete => Ok(()),
                    NormalBehavior::Fail => Err("secret raw failure".into()),
                    NormalBehavior::Panic => panic!("injected cleanup panic"),
                    NormalBehavior::Wait(gate) => {
                        let _ = gate.acquire().await;
                        Ok(())
                    }
                }
            })
        }

        fn force_cleanup(&mut self) -> CleanupPhase<'_> {
            Box::pin(async move {
                self.forced.store(true, Ordering::Release);
                Ok(())
            })
        }
    }

    fn submit_test(
        supervisor: &Arc<CleanupSupervisor>,
        behavior: NormalBehavior,
        timeout: Duration,
        kind: &'static str,
    ) -> (
        mpsc::Receiver<CleanupJobOutcome>,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        let permit = supervisor.try_reserve().expect("lifetime cleanup slot");
        let forced = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let payload = TestPayload {
            behavior,
            forced: Arc::clone(&forced),
            dropped: Arc::clone(&dropped),
        };
        let (outcome_tx, outcome_rx) = mpsc::channel();
        submit_cleanup(
            permit,
            CleanupJobMeta {
                kind,
                generation: Some(7),
                route_id: Some(0x1234_5678_9abc_def0),
            },
            timeout,
            payload,
            || {},
            move |outcome| outcome_tx.send(outcome).expect("outcome receiver"),
        )
        .map_err(|rejected| rejected.reason)
        .expect("reserved cleanup admission");
        (outcome_rx, forced, dropped)
    }

    #[test]
    fn timed_out_and_panicked_jobs_force_cleanup_before_completion() {
        let supervisor = CleanupSupervisor::start_with(2, 4).expect("supervisor");
        let (timeout_rx, timeout_forced, timeout_dropped) = submit_test(
            &supervisor,
            NormalBehavior::Wait(Arc::new(Semaphore::new(0))),
            Duration::from_millis(20),
            "timeout-test",
        );
        assert!(matches!(
            timeout_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Forced {
                trigger: CleanupForceTrigger::TimedOut,
                force_failed: false
            }
        ));
        assert!(timeout_forced.load(Ordering::Acquire));
        assert!(timeout_dropped.load(Ordering::Acquire));
        let (panic_rx, panic_forced, _) = submit_test(
            &supervisor,
            NormalBehavior::Panic,
            Duration::from_secs(1),
            "panic-test",
        );
        assert!(matches!(
            panic_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Forced {
                trigger: CleanupForceTrigger::Panicked,
                force_failed: false
            }
        ));
        assert!(panic_forced.load(Ordering::Acquire));
        supervisor.shutdown_for_test();
    }

    #[test]
    fn admission_waits_for_runtime_readiness_and_is_lifetime_bounded() {
        let supervisor = CleanupSupervisor::new(2);
        assert!(supervisor.try_reserve().is_err());
        supervisor
            .launch_workers(1, default_runtime_factory())
            .expect("worker runtime handshake");
        let first = supervisor.try_reserve().expect("first lifetime slot");
        let second = supervisor.try_reserve().expect("second lifetime slot");
        assert!(supervisor.try_reserve().is_err());
        drop(first);
        assert!(supervisor.try_reserve().is_ok());
        drop(second);
        supervisor.shutdown_for_test();
    }

    #[test]
    fn blocked_runtime_readiness_never_accepts_admission_or_jobs() {
        let supervisor = CleanupSupervisor::new(1);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let factory: RuntimeFactory = Arc::new(move |_| {
            entered_tx.send(()).expect("ready barrier observer");
            release_rx
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .recv()
                .expect("ready barrier release");
            default_runtime_factory()(0)
        });
        let starting = Arc::clone(&supervisor);
        let launch = std::thread::spawn(move || starting.launch_workers(1, factory));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("runtime factory entered");
        assert!(supervisor.try_reserve().is_err());
        assert_eq!(supervisor.snapshot().queue_depth, 0);
        release_tx.send(()).unwrap();
        launch.join().unwrap().expect("worker becomes ready");
        assert!(supervisor.try_reserve().is_ok());
        supervisor.shutdown_for_test();
    }

    #[test]
    fn all_runtime_initialization_failures_leave_no_admission_or_queue() {
        let supervisor = CleanupSupervisor::new(2);
        let error = supervisor
            .launch_workers(2, Arc::new(|_| Err("injected runtime init failure".into())))
            .expect_err("all failed workers make the supervisor unavailable");
        assert!(error.contains("unavailable"));
        assert!(supervisor.try_reserve().is_err());
        assert_eq!(supervisor.snapshot().queue_depth, 0);
        supervisor.shutdown_for_test();
    }

    #[test]
    fn last_worker_failure_force_drains_admitted_queue_and_rejects_new_peers() {
        let supervisor = CleanupSupervisor::start_with(1, 3).expect("supervisor");
        supervisor.inject_worker_exit_after_jobs(1);
        let gate = Arc::new(Semaphore::new(0));
        let (first_rx, _, _) = submit_test(
            &supervisor,
            NormalBehavior::Wait(Arc::clone(&gate)),
            Duration::from_secs(1),
            "normal-before-worker-exit",
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while supervisor.snapshot().active_jobs == 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        let (second_rx, second_forced, _) = submit_test(
            &supervisor,
            NormalBehavior::Complete,
            Duration::from_secs(1),
            "force-after-worker-exit",
        );
        let (third_rx, third_forced, _) = submit_test(
            &supervisor,
            NormalBehavior::Complete,
            Duration::from_secs(1),
            "force-after-worker-exit",
        );
        gate.add_permits(1);
        assert!(matches!(
            first_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Completed
        ));
        for receiver in [second_rx, third_rx] {
            assert!(matches!(
                receiver.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
                CleanupJobOutcome::Forced {
                    trigger: CleanupForceTrigger::ExecutorUnavailable,
                    force_failed: false
                }
            ));
        }
        assert!(second_forced.load(Ordering::Acquire));
        assert!(third_forced.load(Ordering::Acquire));
        assert!(supervisor.try_reserve().is_err());
        assert_eq!(supervisor.snapshot().queue_depth, 0);
        supervisor.shutdown_for_test();
    }

    #[test]
    fn snapshot_never_copies_raw_errors_or_full_route_identity() {
        let supervisor = CleanupSupervisor::start_with(1, 1).expect("supervisor");
        let (outcome_rx, _, _) = submit_test(
            &supervisor,
            NormalBehavior::Fail,
            Duration::from_secs(1),
            "redaction-test",
        );
        let _ = outcome_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while supervisor.snapshot().recent_failures.is_empty()
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }
        let failure = supervisor.snapshot().last_failure.unwrap();
        assert_eq!(failure.route_id_summary.as_deref(), Some("route-9abcdef0"));
        assert!(!failure.reason.contains("secret raw failure"));
        assert!(!failure.reason.contains("12345678"));
        supervisor.shutdown_for_test();
    }
}
