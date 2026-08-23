use std::{
    collections::VecDeque,
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    time::Duration,
};

const CLEANUP_WORKERS: usize = 2;
#[cfg(not(test))]
const CLEANUP_QUEUE_CAPACITY: usize = 32;
#[cfg(test)]
const CLEANUP_QUEUE_CAPACITY: usize = 16;

type CleanupFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
type Completion = Box<dyn FnOnce(CleanupJobOutcome) + Send + 'static>;

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
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub active_jobs: usize,
    pub submitted_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub timed_out_jobs: u64,
    pub panicked_jobs: u64,
    pub saturated_jobs: u64,
    pub last_failure: Option<CleanupFailureSummary>,
    pub recent_failures: Vec<CleanupFailureSummary>,
}

#[derive(Debug, Clone)]
pub(crate) enum CleanupJobOutcome {
    Completed,
    Failed(String),
    TimedOut,
    Panicked,
    Saturated,
    ExecutorUnavailable,
}

impl CleanupJobOutcome {
    pub(crate) fn error_message(&self) -> Option<String> {
        match self {
            Self::Completed => None,
            Self::Failed(reason) => Some(reason.clone()),
            Self::TimedOut => Some("cleanup job timed out".into()),
            Self::Panicked => Some("cleanup job panicked".into()),
            Self::Saturated => Some("cleanup supervisor queue saturated".into()),
            Self::ExecutorUnavailable => Some("cleanup supervisor unavailable".into()),
        }
    }
}

struct CleanupJob {
    meta: CleanupJobMeta,
    timeout: Duration,
    future: Option<CleanupFuture>,
    completion: Option<Completion>,
}

impl CleanupJob {
    fn finish(&mut self, outcome: CleanupJobOutcome) {
        self.future.take();
        if let Some(completion) = self.completion.take() {
            completion(outcome);
        }
    }
}

impl Drop for CleanupJob {
    fn drop(&mut self) {
        if self.completion.is_some() {
            self.finish(CleanupJobOutcome::ExecutorUnavailable);
        }
    }
}

#[derive(Default)]
struct CleanupMetrics {
    worker_count: AtomicUsize,
    active_jobs: AtomicUsize,
    submitted_jobs: AtomicU64,
    completed_jobs: AtomicU64,
    failed_jobs: AtomicU64,
    timed_out_jobs: AtomicU64,
    panicked_jobs: AtomicU64,
    saturated_jobs: AtomicU64,
    recent_failures: Mutex<VecDeque<CleanupFailureSummary>>,
}

struct CleanupSupervisor {
    queue: Mutex<VecDeque<CleanupJob>>,
    has_work: Condvar,
    queue_capacity: usize,
    stopping: std::sync::atomic::AtomicBool,
    worker_handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
    metrics: CleanupMetrics,
}

impl CleanupSupervisor {
    fn start() -> Arc<Self> {
        Self::start_with(CLEANUP_WORKERS, CLEANUP_QUEUE_CAPACITY)
    }

    fn start_with(worker_count: usize, queue_capacity: usize) -> Arc<Self> {
        let supervisor = Arc::new(Self {
            queue: Mutex::new(VecDeque::with_capacity(queue_capacity)),
            has_work: Condvar::new(),
            queue_capacity,
            stopping: std::sync::atomic::AtomicBool::new(false),
            worker_handles: Mutex::new(Vec::new()),
            metrics: CleanupMetrics::default(),
        });
        for index in 0..worker_count {
            let worker = Arc::clone(&supervisor);
            if let Ok(handle) = std::thread::Builder::new()
                .name(format!("mrd-webrtc-cleanup-{index}"))
                .spawn(move || worker.run_worker())
            {
                supervisor
                    .metrics
                    .worker_count
                    .fetch_add(1, Ordering::AcqRel);
                supervisor
                    .worker_handles
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(handle);
            }
        }
        supervisor
    }

    fn submit(&self, mut job: CleanupJob) {
        self.metrics.submitted_jobs.fetch_add(1, Ordering::AcqRel);
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if queue.len() >= self.queue_capacity {
            drop(queue);
            // A synchronous Drop path cannot safely block a caller runtime waiting for workers
            // that may themselves depend on that runtime. Saturation is explicit fail-closed
            // backpressure: release all job ownership, complete the waiter with Err, and count it.
            self.metrics.saturated_jobs.fetch_add(1, Ordering::AcqRel);
            let meta = job.meta;
            job.finish(CleanupJobOutcome::Saturated);
            self.record_completion(&meta, &CleanupJobOutcome::Saturated);
            return;
        }
        if self.metrics.worker_count.load(Ordering::Acquire) == 0 {
            drop(queue);
            let meta = job.meta;
            job.finish(CleanupJobOutcome::ExecutorUnavailable);
            self.record_completion(&meta, &CleanupJobOutcome::ExecutorUnavailable);
            return;
        }
        queue.push_back(job);
        self.has_work.notify_one();
    }

    fn run_worker(&self) {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                self.metrics.worker_count.fetch_sub(1, Ordering::AcqRel);
                return;
            }
        };
        loop {
            let mut job = {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                while queue.is_empty() {
                    if self.stopping.load(Ordering::Acquire) {
                        self.metrics.worker_count.fetch_sub(1, Ordering::AcqRel);
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
            let outcome = catch_unwind(AssertUnwindSafe(|| execute_job(&runtime, &mut job)))
                .unwrap_or(CleanupJobOutcome::Panicked);
            self.metrics.active_jobs.fetch_sub(1, Ordering::AcqRel);
            let meta = job.meta;
            let completion = catch_unwind(AssertUnwindSafe(|| job.finish(outcome.clone())));
            if completion.is_err() {
                self.record_completion(&meta, &CleanupJobOutcome::Panicked);
            } else {
                self.record_completion(&meta, &outcome);
            }
        }
    }

    fn record_completion(&self, meta: &CleanupJobMeta, outcome: &CleanupJobOutcome) {
        self.metrics.completed_jobs.fetch_add(1, Ordering::AcqRel);
        let failure = match outcome {
            CleanupJobOutcome::Completed => return,
            // Job-provided errors may contain remote library diagnostics. Keep the detailed
            // value route-local for its shutdown waiter; process-wide health metadata is
            // deliberately structural and never copies that payload.
            CleanupJobOutcome::Failed(_) => "cleanup job reported failure".into(),
            CleanupJobOutcome::TimedOut => {
                self.metrics.timed_out_jobs.fetch_add(1, Ordering::AcqRel);
                "cleanup deadline exceeded".into()
            }
            CleanupJobOutcome::Panicked => {
                self.metrics.panicked_jobs.fetch_add(1, Ordering::AcqRel);
                "cleanup job panicked".into()
            }
            CleanupJobOutcome::Saturated => "cleanup supervisor queue saturated".into(),
            CleanupJobOutcome::ExecutorUnavailable => "cleanup executor unavailable".into(),
        };
        self.metrics.failed_jobs.fetch_add(1, Ordering::AcqRel);
        let mut failures = self
            .metrics
            .recent_failures
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if failures.len() == 128 {
            failures.pop_front();
        }
        failures.push_back(CleanupFailureSummary {
            job_kind: meta.kind.into(),
            generation: meta.generation,
            route_id_summary: meta
                .route_id
                .map(|route| format!("route-{:08x}", route as u32)),
            reason: failure,
        });
    }

    fn snapshot(&self) -> CleanupSupervisorSnapshot {
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
            worker_count: self.metrics.worker_count.load(Ordering::Acquire),
            queue_capacity: self.queue_capacity,
            queue_depth,
            active_jobs: self.metrics.active_jobs.load(Ordering::Acquire),
            submitted_jobs: self.metrics.submitted_jobs.load(Ordering::Acquire),
            completed_jobs: self.metrics.completed_jobs.load(Ordering::Acquire),
            failed_jobs: self.metrics.failed_jobs.load(Ordering::Acquire),
            timed_out_jobs: self.metrics.timed_out_jobs.load(Ordering::Acquire),
            panicked_jobs: self.metrics.panicked_jobs.load(Ordering::Acquire),
            saturated_jobs: self.metrics.saturated_jobs.load(Ordering::Acquire),
            last_failure: recent_failures.last().cloned(),
            recent_failures,
        }
    }

    #[cfg(test)]
    fn shutdown_for_test(&self) {
        self.stopping.store(true, Ordering::Release);
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

fn execute_job(runtime: &tokio::runtime::Runtime, job: &mut CleanupJob) -> CleanupJobOutcome {
    let Some(future) = job.future.take() else {
        return CleanupJobOutcome::Failed("cleanup future missing".into());
    };
    runtime.block_on(async move {
        let mut task = tokio::spawn(future);
        match tokio::time::timeout(job.timeout, &mut task).await {
            Ok(Ok(Ok(()))) => CleanupJobOutcome::Completed,
            Ok(Ok(Err(reason))) => CleanupJobOutcome::Failed(reason),
            Ok(Err(error)) if error.is_panic() => CleanupJobOutcome::Panicked,
            Ok(Err(error)) => CleanupJobOutcome::Failed(format!("cleanup task failed: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                CleanupJobOutcome::TimedOut
            }
        }
    })
}

fn supervisor() -> &'static Arc<CleanupSupervisor> {
    static SUPERVISOR: OnceLock<Arc<CleanupSupervisor>> = OnceLock::new();
    SUPERVISOR.get_or_init(CleanupSupervisor::start)
}

pub(crate) fn submit_cleanup<F, C>(
    meta: CleanupJobMeta,
    timeout: Duration,
    future: F,
    completion: C,
) where
    F: Future<Output = Result<(), String>> + Send + 'static,
    C: FnOnce(CleanupJobOutcome) + Send + 'static,
{
    supervisor().submit(CleanupJob {
        meta,
        timeout,
        future: Some(Box::pin(future)),
        completion: Some(Box::new(completion)),
    });
}

pub fn cleanup_supervisor_snapshot() -> CleanupSupervisorSnapshot {
    supervisor().snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn submit_to<F, C>(
        supervisor: &CleanupSupervisor,
        meta: CleanupJobMeta,
        timeout: Duration,
        future: F,
        completion: C,
    ) where
        F: Future<Output = Result<(), String>> + Send + 'static,
        C: FnOnce(CleanupJobOutcome) + Send + 'static,
    {
        supervisor.submit(CleanupJob {
            meta,
            timeout,
            future: Some(Box::pin(future)),
            completion: Some(Box::new(completion)),
        });
    }

    #[test]
    fn timed_out_and_panicked_jobs_always_complete_with_observable_errors() {
        let supervisor = CleanupSupervisor::start_with(2, 4);
        let before = supervisor.snapshot();
        let (timeout_tx, timeout_rx) = mpsc::channel();
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "timeout-test",
                generation: Some(7),
                route_id: Some(11),
            },
            Duration::from_millis(20),
            std::future::pending(),
            move |outcome| timeout_tx.send(outcome).expect("timeout outcome receiver"),
        );
        assert!(matches!(
            timeout_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CleanupJobOutcome::TimedOut
        ));

        let (panic_tx, panic_rx) = mpsc::channel();
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "panic-test",
                generation: Some(8),
                route_id: Some(12),
            },
            Duration::from_secs(1),
            async move {
                panic!("injected cleanup panic");
                #[allow(unreachable_code)]
                Ok(())
            },
            move |outcome| panic_tx.send(outcome).expect("panic outcome receiver"),
        );
        assert!(matches!(
            panic_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CleanupJobOutcome::Panicked
        ));

        let metrics_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while (supervisor.snapshot().panicked_jobs < before.panicked_jobs + 1
            || supervisor.snapshot().timed_out_jobs < before.timed_out_jobs + 1)
            && std::time::Instant::now() < metrics_deadline
        {
            std::thread::yield_now();
        }
        let after = supervisor.snapshot();
        assert!(after.timed_out_jobs > before.timed_out_jobs);
        assert!(after.panicked_jobs > before.panicked_jobs);
        assert!(after.failed_jobs >= before.failed_jobs + 2);
        let failure = after
            .recent_failures
            .iter()
            .find(|failure| failure.job_kind == "panic-test")
            .expect("panic failure summary");
        assert_eq!(failure.job_kind, "panic-test");
        assert_eq!(failure.generation, Some(8));
        assert_eq!(failure.route_id_summary.as_deref(), Some("route-0000000c"));
        assert!(!failure.reason.contains("token"));
        supervisor.shutdown_for_test();
    }

    #[test]
    fn recursive_submission_on_a_full_queue_fails_closed_without_deadlock() {
        struct OwnedResource(Arc<std::sync::atomic::AtomicBool>);

        impl Drop for OwnedResource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let supervisor = CleanupSupervisor::start_with(2, 4);
        let before = supervisor.snapshot();
        let recursive_gate = Arc::new(tokio::sync::Semaphore::new(0));
        let blocker_gate = Arc::new(tokio::sync::Semaphore::new(0));
        let queued_gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (nested_tx, nested_rx) = mpsc::channel();
        let job_recursive_gate = Arc::clone(&recursive_gate);
        let recursive_supervisor = Arc::clone(&supervisor);
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "recursive-parent-test",
                generation: None,
                route_id: None,
            },
            Duration::from_secs(5),
            async move {
                let _ = job_recursive_gate.acquire().await;
                submit_to(
                    &recursive_supervisor,
                    CleanupJobMeta {
                        kind: "recursive-child-test",
                        generation: None,
                        route_id: None,
                    },
                    Duration::from_secs(1),
                    async { Ok(()) },
                    move |outcome| nested_tx.send(outcome).expect("nested receiver"),
                );
                Ok(())
            },
            |_| {},
        );
        let job_blocker_gate = Arc::clone(&blocker_gate);
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "worker-blocker-test",
                generation: None,
                route_id: None,
            },
            Duration::from_secs(5),
            async move {
                let _ = job_blocker_gate.acquire().await;
                Ok(())
            },
            |_| {},
        );
        let active_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while supervisor.snapshot().active_jobs < 2 && std::time::Instant::now() < active_deadline {
            std::thread::yield_now();
        }
        assert_eq!(supervisor.snapshot().active_jobs, 2);

        for _ in 0..supervisor.queue_capacity {
            let gate = Arc::clone(&queued_gate);
            submit_to(
                &supervisor,
                CleanupJobMeta {
                    kind: "queued-pressure-test",
                    generation: None,
                    route_id: None,
                },
                Duration::from_secs(5),
                async move {
                    let _ = gate.acquire().await;
                    Ok(())
                },
                |_| {},
            );
        }
        assert_eq!(supervisor.snapshot().queue_depth, supervisor.queue_capacity);

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owned = OwnedResource(Arc::clone(&dropped));
        let (saturated_tx, saturated_rx) = mpsc::channel();
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "saturated-ownership-test",
                generation: None,
                route_id: None,
            },
            Duration::from_secs(1),
            async move {
                let _owned = owned;
                std::future::pending().await
            },
            move |outcome| saturated_tx.send(outcome).expect("saturated receiver"),
        );
        assert!(matches!(
            saturated_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CleanupJobOutcome::Saturated
        ));
        assert!(dropped.load(Ordering::Acquire));

        recursive_gate.add_permits(1);
        assert!(matches!(
            nested_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CleanupJobOutcome::Saturated
        ));
        let saturated = supervisor.snapshot();
        assert!(saturated.saturated_jobs > before.saturated_jobs);
        assert!(saturated.failed_jobs > before.failed_jobs);

        blocker_gate.add_permits(1);
        queued_gate.add_permits(supervisor.queue_capacity);
        let drain_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while (supervisor.snapshot().active_jobs != 0 || supervisor.snapshot().queue_depth != 0)
            && std::time::Instant::now() < drain_deadline
        {
            std::thread::yield_now();
        }
        assert_eq!(supervisor.snapshot().active_jobs, 0);
        assert_eq!(supervisor.snapshot().queue_depth, 0);
        supervisor.shutdown_for_test();
    }

    #[test]
    fn failure_snapshot_never_copies_the_job_error_payload() {
        let supervisor = CleanupSupervisor::start_with(1, 2);
        let secret = "route-token-secret sdp=v=0 credential=top-secret";
        let (outcome_tx, outcome_rx) = mpsc::channel();
        submit_to(
            &supervisor,
            CleanupJobMeta {
                kind: "redaction-test",
                generation: Some(3),
                route_id: Some(0x0123_4567_89ab_cdef),
            },
            Duration::from_secs(1),
            async move { Err(secret.into()) },
            move |outcome| outcome_tx.send(outcome).expect("failure receiver"),
        );
        assert!(matches!(
            outcome_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CleanupJobOutcome::Failed(message) if message == secret
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while supervisor.snapshot().recent_failures.is_empty()
            && std::time::Instant::now() < deadline
        {
            std::thread::yield_now();
        }

        let snapshot = supervisor.snapshot();
        let failure = snapshot.last_failure.expect("structured failure summary");
        assert_eq!(failure.job_kind, "redaction-test");
        assert_eq!(failure.generation, Some(3));
        assert_eq!(failure.route_id_summary.as_deref(), Some("route-89abcdef"));
        assert!(!failure.reason.contains("route-token-secret"));
        assert!(!failure.reason.contains("sdp="));
        assert!(!failure.reason.contains("top-secret"));
        supervisor.shutdown_for_test();
    }
}
