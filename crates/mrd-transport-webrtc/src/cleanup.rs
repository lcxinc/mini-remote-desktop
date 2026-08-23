use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        mpsc, Arc, Condvar, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use tokio::{
    sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

const CLEANUP_WORKERS: usize = 2;
const CLEANUP_QUEUE_CAPACITY: usize = 32;
const CLEANUP_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(2);
const FAILURE_HISTORY_CAPACITY: usize = 128;

pub(crate) type CleanupPhase<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub(crate) trait CleanupPayload: Send + 'static {
    fn normal_cleanup(&mut self) -> CleanupPhase<'_>;
    fn force_cleanup(&mut self) -> CleanupPhase<'_>;

    fn force_retry_safe(&self) -> bool {
        true
    }

    fn preserve_on_error(&self) -> bool {
        false
    }
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
    pub ownership_registry_depth: usize,
    pub admission_capacity: usize,
    pub available_admission_slots: usize,
    pub accepting_new_peers: bool,
    pub active_jobs: usize,
    pub active_deadline_reporters: usize,
    pub submitted_jobs: u64,
    pub completed_jobs: u64,
    pub normal_jobs: u64,
    pub forced_jobs: u64,
    pub force_failed_jobs: u64,
    pub quarantined_jobs: u64,
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
    Panicked,
}

#[derive(Debug, Clone)]
pub(crate) enum CleanupJobOutcome {
    Completed,
    Failed,
    Forced {
        trigger: CleanupForceTrigger,
        force_failed: bool,
    },
    Quarantined {
        trigger: CleanupForceTrigger,
    },
}

impl CleanupJobOutcome {
    pub(crate) fn error_message(&self) -> Option<String> {
        match self {
            Self::Completed => None,
            Self::Failed => Some("cleanup job failed; physical teardown completed".into()),
            Self::Forced {
                trigger,
                force_failed,
            } => {
                let trigger = match trigger {
                    CleanupForceTrigger::Failure => "cleanup job failed",
                    CleanupForceTrigger::Panicked => "cleanup job panicked",
                };
                let force = if *force_failed {
                    "forced teardown failed"
                } else {
                    "forced teardown completed"
                };
                Some(format!("{trigger}; {force}"))
            }
            Self::Quarantined { trigger } => {
                let reason = match trigger {
                    CleanupForceTrigger::Failure => "physical teardown failed",
                    CleanupForceTrigger::Panicked => "physical teardown panicked",
                };
                Some(format!("{reason}; ownership quarantined"))
            }
        }
    }

    pub(crate) fn is_quarantined(&self) -> bool {
        matches!(self, Self::Quarantined { .. })
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

struct CleanupOwnership {
    payload: Box<dyn CleanupPayload>,
    _permit: CleanupPermit,
}

const JOB_QUEUED: u8 = 0;
const JOB_RUNNING: u8 = 1;
const JOB_FINISHED: u8 = 2;
const JOB_QUARANTINED: u8 = 3;

struct CleanupJob {
    id: u64,
    meta: CleanupJobMeta,
    deadline: Instant,
    stage: AtomicU8,
    deadline_reported: AtomicBool,
    terminal: Notify,
    ownership: AsyncMutex<Option<CleanupOwnership>>,
    completion: Mutex<Option<Completion>>,
}

#[derive(Default)]
struct CleanupMetrics {
    normal_workers: AtomicUsize,
    force_only_workers: AtomicUsize,
    active_jobs: AtomicUsize,
    active_deadline_reporters: AtomicUsize,
    submitted_jobs: AtomicU64,
    completed_jobs: AtomicU64,
    normal_jobs: AtomicU64,
    forced_jobs: AtomicU64,
    force_failed_jobs: AtomicU64,
    quarantined_jobs: AtomicU64,
    failed_jobs: AtomicU64,
    timed_out_jobs: AtomicU64,
    panicked_jobs: AtomicU64,
    executor_unavailable_jobs: AtomicU64,
    saturated_jobs: AtomicU64,
    recent_failures: Mutex<VecDeque<CleanupFailureSummary>>,
}

pub(crate) struct CleanupSupervisor {
    queue: Mutex<VecDeque<Arc<CleanupJob>>>,
    registry: Mutex<HashMap<u64, Arc<CleanupJob>>>,
    has_work: Notify,
    startup: Condvar,
    startup_lock: Mutex<()>,
    queue_capacity: usize,
    admission: Arc<Semaphore>,
    accepting: AtomicBool,
    stopping: AtomicBool,
    next_job_id: AtomicU64,
    worker_handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
    metrics: CleanupMetrics,
    #[cfg(test)]
    worker_exit_after_jobs: AtomicUsize,
}

impl CleanupSupervisor {
    fn new(queue_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::with_capacity(queue_capacity)),
            registry: Mutex::new(HashMap::with_capacity(queue_capacity)),
            has_work: Notify::new(),
            startup: Condvar::new(),
            startup_lock: Mutex::new(()),
            queue_capacity,
            admission: Arc::new(Semaphore::new(queue_capacity)),
            accepting: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            next_job_id: AtomicU64::new(1),
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
            let _startup = self
                .startup_lock
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            self.stopping.store(true, Ordering::Release);
            self.startup.notify_all();
            self.has_work.notify_waiters();
            return Err("cleanup executor unavailable: every runtime failed to initialize".into());
        }
        let _startup = self
            .startup_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.accepting.store(true, Ordering::Release);
        self.startup.notify_all();
        Ok(())
    }

    fn wait_for_startup(&self) {
        let mut startup = self
            .startup_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while !self.accepting.load(Ordering::Acquire) && !self.stopping.load(Ordering::Acquire) {
            startup = self
                .startup
                .wait(startup)
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

    fn run_worker(self: &Arc<Self>, runtime: tokio::runtime::Runtime) {
        loop {
            let worker = Arc::clone(self);
            let result = catch_unwind(AssertUnwindSafe(|| {
                runtime.block_on(async move { worker.worker_loop().await })
            }));
            match result {
                Ok(WorkerExit::Stop | WorkerExit::Injected) => return,
                Err(_) => {
                    self.accepting.store(false, Ordering::Release);
                    self.record_executor_failure();
                    continue;
                }
            }
        }
    }

    async fn worker_loop(self: Arc<Self>) -> WorkerExit {
        let mut tasks = JoinSet::new();
        loop {
            // Register before inspecting the queue/stop flags. `notify_waiters` does not
            // retain a permit, so registering afterwards could lose shutdown between
            // the state check and `select!` and strand the worker thread in `join()`.
            let notified = self.has_work.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            while let Some(job) = self.pop_queued_job() {
                if job
                    .stage
                    .compare_exchange(JOB_QUEUED, JOB_RUNNING, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                self.metrics.active_jobs.fetch_add(1, Ordering::AcqRel);
                let deadline_supervisor = Arc::clone(&self);
                let deadline_job = Arc::clone(&job);
                self.metrics
                    .active_deadline_reporters
                    .fetch_add(1, Ordering::AcqRel);
                let reporter_guard = DeadlineReporterGuard {
                    supervisor: Arc::clone(&deadline_supervisor),
                };
                tokio::spawn(run_deadline_reporter(
                    deadline_supervisor,
                    deadline_job,
                    reporter_guard,
                ));
                let task_supervisor = Arc::clone(&self);
                tasks.spawn(async move {
                    run_supervised_job(task_supervisor, job).await;
                });
            }

            if self.stopping.load(Ordering::Acquire) && tasks.is_empty() && self.queue_is_empty() {
                self.metrics.normal_workers.fetch_sub(1, Ordering::AcqRel);
                return WorkerExit::Stop;
            }

            tokio::select! {
                _ = &mut notified => {}
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = joined;
                    if tasks.is_empty() && self.should_exit_worker_for_test() {
                        let exited = self
                            .metrics
                            .normal_workers
                            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |workers| {
                                if workers > 1 {
                                    Some(workers - 1)
                                } else {
                                    None
                                }
                            })
                            .is_ok();
                        if exited {
                            return WorkerExit::Injected;
                        }
                        self.accepting.store(false, Ordering::Release);
                    }
                }
            }
        }
    }

    fn pop_queued_job(&self) -> Option<Arc<CleanupJob>> {
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pop_front()
    }

    fn queue_is_empty(&self) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_empty()
    }

    fn record_deadline_if_running(&self, job: &CleanupJob) {
        if !matches!(job.stage.load(Ordering::Acquire), JOB_QUEUED | JOB_RUNNING)
            || job.deadline_reported.swap(true, Ordering::AcqRel)
        {
            return;
        }
        self.metrics.timed_out_jobs.fetch_add(1, Ordering::AcqRel);
        self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
        self.push_failure(
            &job.meta,
            "physical cleanup still in progress after deadline",
        );
    }

    fn finish_job(&self, job: &Arc<CleanupJob>, outcome: CleanupJobOutcome) {
        if job
            .stage
            .compare_exchange(
                JOB_RUNNING,
                JOB_FINISHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        job.terminal.notify_waiters();
        self.metrics.active_jobs.fetch_sub(1, Ordering::AcqRel);
        self.registry
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&job.id);
        let ownership = job
            .ownership
            .try_lock()
            .expect("completed cleanup task released ownership lock")
            .take();
        drop(ownership);
        self.record_completion(&job.meta, &outcome);
        if let Some(completion) = job
            .completion
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            let _ = catch_unwind(AssertUnwindSafe(|| completion(outcome)));
        }
    }

    fn quarantine_job(&self, job: &Arc<CleanupJob>, trigger: CleanupForceTrigger) {
        if job
            .stage
            .compare_exchange(
                JOB_RUNNING,
                JOB_QUARANTINED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        job.terminal.notify_waiters();
        self.metrics.active_jobs.fetch_sub(1, Ordering::AcqRel);
        self.metrics.quarantined_jobs.fetch_add(1, Ordering::AcqRel);
        self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
        if trigger == CleanupForceTrigger::Panicked {
            self.metrics.panicked_jobs.fetch_add(1, Ordering::AcqRel);
        }
        self.push_failure(
            &job.meta,
            match trigger {
                CleanupForceTrigger::Failure => "physical cleanup failed; ownership quarantined",
                CleanupForceTrigger::Panicked => "physical cleanup panicked; ownership quarantined",
            },
        );
        let outcome = CleanupJobOutcome::Quarantined { trigger };
        if let Some(completion) = job
            .completion
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            let _ = catch_unwind(AssertUnwindSafe(|| completion(outcome)));
        }
    }

    fn record_completion(&self, meta: &CleanupJobMeta, outcome: &CleanupJobOutcome) {
        self.metrics.completed_jobs.fetch_add(1, Ordering::AcqRel);
        match outcome {
            CleanupJobOutcome::Completed => {
                self.metrics.normal_jobs.fetch_add(1, Ordering::AcqRel);
            }
            CleanupJobOutcome::Failed => {
                self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
                self.push_failure(meta, "physical cleanup reported a terminal failure");
            }
            CleanupJobOutcome::Forced {
                trigger,
                force_failed,
            } => {
                self.metrics.forced_jobs.fetch_add(1, Ordering::AcqRel);
                self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
                if *force_failed {
                    self.metrics
                        .force_failed_jobs
                        .fetch_add(1, Ordering::AcqRel);
                }
                self.push_failure(
                    meta,
                    match trigger {
                        CleanupForceTrigger::Failure if *force_failed => {
                            "normal and forced cleanup failed"
                        }
                        CleanupForceTrigger::Failure => {
                            "normal cleanup failed; forced teardown completed"
                        }
                        CleanupForceTrigger::Panicked => {
                            "normal cleanup panicked; forced teardown completed"
                        }
                    },
                );
            }
            CleanupJobOutcome::Quarantined { .. } => {}
        }
    }

    fn record_executor_failure(&self) {
        self.metrics
            .executor_unavailable_jobs
            .fetch_add(1, Ordering::AcqRel);
        self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
        self.push_failure(
            &CleanupJobMeta {
                kind: "executor-runtime",
                generation: None,
                route_id: None,
            },
            "cleanup executor event loop restarted after panic",
        );
    }

    fn push_failure(&self, meta: &CleanupJobMeta, reason: &'static str) {
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
            reason: reason.into(),
        });
    }

    pub(crate) fn snapshot(&self) -> CleanupSupervisorSnapshot {
        let queue_depth = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len();
        let ownership_registry_depth = self
            .registry
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
            ownership_registry_depth,
            admission_capacity: self.queue_capacity,
            available_admission_slots: self.admission.available_permits(),
            accepting_new_peers: self.accepting.load(Ordering::Acquire),
            active_jobs: self.metrics.active_jobs.load(Ordering::Acquire),
            active_deadline_reporters: self
                .metrics
                .active_deadline_reporters
                .load(Ordering::Acquire),
            submitted_jobs: self.metrics.submitted_jobs.load(Ordering::Acquire),
            completed_jobs: self.metrics.completed_jobs.load(Ordering::Acquire),
            normal_jobs: self.metrics.normal_jobs.load(Ordering::Acquire),
            forced_jobs: self.metrics.forced_jobs.load(Ordering::Acquire),
            force_failed_jobs: self.metrics.force_failed_jobs.load(Ordering::Acquire),
            quarantined_jobs: self.metrics.quarantined_jobs.load(Ordering::Acquire),
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

    #[cfg(test)]
    pub(crate) fn release_quarantined_for_test(&self) {
        let quarantined = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let ids = registry
                .iter()
                .filter_map(|(id, job)| {
                    (job.stage.load(Ordering::Acquire) == JOB_QUARANTINED).then_some(*id)
                })
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| registry.remove(&id))
                .collect::<Vec<_>>()
        };
        for job in quarantined {
            let ownership = job
                .ownership
                .try_lock()
                .expect("quarantined task released ownership lock")
                .take();
            drop(ownership);
        }
    }

    #[cfg(test)]
    pub(crate) fn shutdown_for_test(&self) {
        assert_eq!(
            self.registry
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .len(),
            0,
            "test cleanup supervisor cannot stop with owned or quarantined jobs"
        );
        {
            let _startup = self
                .startup_lock
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            self.stopping.store(true, Ordering::Release);
            self.accepting.store(false, Ordering::Release);
            self.startup.notify_all();
        }
        self.has_work.notify_waiters();
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

enum WorkerExit {
    Stop,
    Injected,
}

struct DeadlineReporterGuard {
    supervisor: Arc<CleanupSupervisor>,
}

impl Drop for DeadlineReporterGuard {
    fn drop(&mut self) {
        self.supervisor
            .metrics
            .active_deadline_reporters
            .fetch_sub(1, Ordering::AcqRel);
    }
}

async fn run_deadline_reporter(
    supervisor: Arc<CleanupSupervisor>,
    job: Arc<CleanupJob>,
    _guard: DeadlineReporterGuard,
) {
    let terminal = job.terminal.notified();
    tokio::pin!(terminal);
    terminal.as_mut().enable();
    if matches!(
        job.stage.load(Ordering::Acquire),
        JOB_FINISHED | JOB_QUARANTINED
    ) {
        return;
    }
    tokio::select! {
        _ = &mut terminal => {}
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(job.deadline)) => {
            supervisor.record_deadline_if_running(&job);
        }
    }
}

struct JobRunGuard {
    supervisor: Arc<CleanupSupervisor>,
    job: Arc<CleanupJob>,
    armed: bool,
}

impl JobRunGuard {
    fn new(supervisor: Arc<CleanupSupervisor>, job: Arc<CleanupJob>) -> Self {
        Self {
            supervisor,
            job,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for JobRunGuard {
    fn drop(&mut self) {
        if self.armed {
            self.supervisor
                .quarantine_job(&self.job, CleanupForceTrigger::Panicked);
        }
    }
}

async fn run_supervised_job(supervisor: Arc<CleanupSupervisor>, job: Arc<CleanupJob>) {
    let mut run_guard = JobRunGuard::new(Arc::clone(&supervisor), Arc::clone(&job));
    let decision = {
        let mut ownership = job.ownership.lock().await;
        let ownership = ownership
            .as_mut()
            .expect("running cleanup job retains physical ownership");
        match ownership.payload.normal_cleanup().await {
            Ok(()) => RunDecision::Finish(CleanupJobOutcome::Completed),
            Err(_) if ownership.payload.force_retry_safe() => {
                match ownership.payload.force_cleanup().await {
                    Ok(()) => RunDecision::Finish(CleanupJobOutcome::Forced {
                        trigger: CleanupForceTrigger::Failure,
                        force_failed: false,
                    }),
                    Err(_) if ownership.payload.preserve_on_error() => {
                        RunDecision::Quarantine(CleanupForceTrigger::Failure)
                    }
                    Err(_) => RunDecision::Finish(CleanupJobOutcome::Forced {
                        trigger: CleanupForceTrigger::Failure,
                        force_failed: true,
                    }),
                }
            }
            Err(_) if ownership.payload.preserve_on_error() => {
                RunDecision::Quarantine(CleanupForceTrigger::Failure)
            }
            Err(_) => RunDecision::Finish(CleanupJobOutcome::Failed),
        }
    };
    run_guard.disarm();
    match decision {
        RunDecision::Finish(outcome) => supervisor.finish_job(&job, outcome),
        RunDecision::Quarantine(trigger) => supervisor.quarantine_job(&job, trigger),
    }
}

enum RunDecision {
    Finish(CleanupJobOutcome),
    Quarantine(CleanupForceTrigger),
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
    if supervisor.metrics.normal_workers.load(Ordering::Acquire) == 0 {
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
    let id = supervisor.next_job_id.fetch_add(1, Ordering::Relaxed);
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let job = Arc::new(CleanupJob {
        id,
        meta,
        deadline,
        stage: AtomicU8::new(JOB_QUEUED),
        deadline_reported: AtomicBool::new(false),
        terminal: Notify::new(),
        ownership: AsyncMutex::new(Some(CleanupOwnership {
            payload: Box::new(payload),
            _permit: permit,
        })),
        completion: Mutex::new(Some(Box::new(completion))),
    });
    supervisor
        .registry
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(id, Arc::clone(&job));
    queue.push_back(job);
    supervisor
        .metrics
        .submitted_jobs
        .fetch_add(1, Ordering::AcqRel);
    accepted();
    drop(queue);
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
            ownership_registry_depth: 0,
            admission_capacity: CLEANUP_QUEUE_CAPACITY,
            available_admission_slots: 0,
            accepting_new_peers: false,
            active_jobs: 0,
            active_deadline_reporters: 0,
            submitted_jobs: 0,
            completed_jobs: 0,
            normal_jobs: 0,
            forced_jobs: 0,
            force_failed_jobs: 0,
            quarantined_jobs: 0,
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
    fn deadline_never_cancels_running_ownership_and_panic_quarantines_it() {
        let supervisor = CleanupSupervisor::start_with(2, 4).expect("supervisor");
        let gate = Arc::new(Semaphore::new(0));
        let (timeout_rx, timeout_forced, timeout_dropped) = submit_test(
            &supervisor,
            NormalBehavior::Wait(Arc::clone(&gate)),
            Duration::from_millis(20),
            "timeout-test",
        );
        assert!(matches!(
            timeout_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.timed_out_jobs, 1);
        assert_eq!(snapshot.ownership_registry_depth, 1);
        assert_eq!(snapshot.available_admission_slots, 3);
        assert!(!timeout_forced.load(Ordering::Acquire));
        assert!(!timeout_dropped.load(Ordering::Acquire));
        gate.add_permits(1);
        assert!(matches!(
            timeout_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Completed
        ));
        assert!(timeout_dropped.load(Ordering::Acquire));

        let (panic_rx, _, panic_dropped) = submit_test(
            &supervisor,
            NormalBehavior::Panic,
            Duration::from_secs(1),
            "panic-test",
        );
        assert!(matches!(
            panic_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Quarantined {
                trigger: CleanupForceTrigger::Panicked
            }
        ));
        assert!(!panic_dropped.load(Ordering::Acquire));
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.quarantined_jobs, 1);
        assert_eq!(snapshot.ownership_registry_depth, 1);
        let (after_panic_rx, _, _) = submit_test(
            &supervisor,
            NormalBehavior::Complete,
            Duration::from_secs(1),
            "after-panic",
        );
        assert!(matches!(
            after_panic_rx
                .recv_timeout(TEST_COMPLETION_TIMEOUT)
                .unwrap(),
            CleanupJobOutcome::Completed
        ));
        supervisor.release_quarantined_for_test();
        assert!(panic_dropped.load(Ordering::Acquire));
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
    fn last_worker_failure_drains_admitted_jobs_without_aborting_them() {
        let supervisor = CleanupSupervisor::start_with(1, 3).expect("supervisor");
        supervisor.inject_worker_exit_after_jobs(1);
        let gate = Arc::new(Semaphore::new(0));
        let (first_rx, _, _) = submit_test(
            &supervisor,
            NormalBehavior::Wait(Arc::clone(&gate)),
            Duration::from_secs(1),
            "normal-before-worker-exit",
        );
        let (second_rx, second_forced, _) = submit_test(
            &supervisor,
            NormalBehavior::Complete,
            Duration::from_secs(1),
            "after-worker-exit",
        );
        let (third_rx, third_forced, _) = submit_test(
            &supervisor,
            NormalBehavior::Complete,
            Duration::from_secs(1),
            "after-worker-exit",
        );
        for receiver in [second_rx, third_rx] {
            assert!(matches!(
                receiver.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
                CleanupJobOutcome::Completed
            ));
        }
        gate.add_permits(1);
        assert!(matches!(
            first_rx.recv_timeout(TEST_COMPLETION_TIMEOUT).unwrap(),
            CleanupJobOutcome::Completed
        ));
        assert!(!second_forced.load(Ordering::Acquire));
        assert!(!third_forced.load(Ordering::Acquire));
        let deadline = Instant::now() + TEST_COMPLETION_TIMEOUT;
        while supervisor.snapshot().accepting_new_peers && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(supervisor.try_reserve().is_err());
        assert_eq!(supervisor.snapshot().queue_depth, 0);
        supervisor.shutdown_for_test();
    }

    #[test]
    fn completed_short_jobs_cancel_deadline_reporters_without_accumulation() {
        const CAPACITY: usize = 4;
        let supervisor = CleanupSupervisor::start_with(1, CAPACITY).expect("supervisor");
        let mut maximum_reporters = 0;
        for _ in 0..4 {
            let receivers = (0..CAPACITY)
                .map(|_| {
                    let (receiver, _, _) = submit_test(
                        &supervisor,
                        NormalBehavior::Complete,
                        Duration::from_secs(10),
                        "short-job",
                    );
                    receiver
                })
                .collect::<Vec<_>>();
            for receiver in receivers {
                let outcome = receiver
                    .recv_timeout(TEST_COMPLETION_TIMEOUT)
                    .unwrap_or_else(|error| {
                        panic!(
                            "short cleanup completion stalled: {error:?}; snapshot={:?}",
                            supervisor.snapshot()
                        )
                    });
                assert!(matches!(outcome, CleanupJobOutcome::Completed));
            }
            maximum_reporters =
                maximum_reporters.max(supervisor.snapshot().active_deadline_reporters);
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        while supervisor.snapshot().active_deadline_reporters != 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let active_after_completion = supervisor.snapshot().active_deadline_reporters;
        supervisor.shutdown_for_test();

        assert!(
            maximum_reporters <= CAPACITY,
            "deadline reporters must remain bounded by lifetime cleanup slots"
        );
        assert_eq!(
            active_after_completion, 0,
            "terminal jobs must cancel their deadline reporters immediately"
        );
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
        let failure = supervisor.snapshot().last_failure.unwrap();
        assert_eq!(failure.route_id_summary.as_deref(), Some("route-9abcdef0"));
        assert!(!failure.reason.contains("secret raw failure"));
        assert!(!failure.reason.contains("12345678"));
        supervisor.shutdown_for_test();
    }
}
