//! Native Windows input-desktop observation and fail-closed publication.

use crate::desktop::{
    trusted_desktop_cache, CachedDesktopStateSource, DesktopPublishError, TrustedDesktopPublisher,
};
use crate::runtime::{TrustedDesktopState, TrustedDesktopStateSource};
use mrd_agent_ipc::DesktopKind;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use thiserror::Error;
use tokio::sync::watch;

/// Failure while establishing or maintaining the native desktop watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum DesktopWatchError {
    /// The active input desktop could not be sampled.
    #[error("trusted input desktop probe failed")]
    DesktopProbe,
    /// The in-memory publication channel failed closed.
    #[error("trusted desktop publisher is unavailable")]
    SourceClosed,
    /// A required native watcher operation failed.
    #[error("native desktop watcher operation {operation} failed with status {status}")]
    Native {
        /// Stable operation label.
        operation: &'static str,
        /// Native error status.
        status: i32,
    },
    /// The watcher thread exited before reporting readiness.
    #[error("native desktop watcher exited before becoming ready")]
    WorkerUnavailable,
}

impl From<DesktopPublishError> for DesktopWatchError {
    fn from(_error: DesktopPublishError) -> Self {
        Self::SourceClosed
    }
}

/// Trusted event delivered by the platform adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeDesktopEvent {
    /// The active desktop may have changed and must be reprobed.
    DesktopSwitch,
    /// A terminal-services notification for a concrete session.
    Session {
        /// Session identifier carried by the WTS notification.
        session_id: u32,
        /// Trusted session transition.
        change: SessionChange,
    },
}

/// Session transitions with security meaning for desktop authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionChange {
    /// Interactive session locked.
    Lock,
    /// Interactive session disconnected.
    Disconnect,
    /// User logged off.
    Logoff,
    /// User logged on.
    Logon,
    /// Interactive session connected.
    Connect,
    /// Interactive session unlocked.
    Unlock,
    /// The session's remote-control status changed.
    RemoteControl,
    /// The terminal-services session was created.
    Create,
    /// The post-logon desktop is ready.
    DesktopReady,
    /// The terminal-services session is terminating.
    Terminate,
}

/// Whether the trusted Windows session may currently own input authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionAvailability {
    /// The session is actively connected and may be probed.
    Available,
    /// The session is active but locked on the Winlogon desktop.
    Locked,
    /// The session is not active; `OpenInputDesktop` would be only a would-be desktop.
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
enum AvailabilityLatch {
    Available,
    Unavailable(DesktopKind),
}

/// Sequential event processor shared by the native worker and deterministic tests.
pub(crate) struct DesktopEventProcessor<P>
where
    P: FnMut() -> Result<DesktopKind, DesktopWatchError>,
{
    session_id: u32,
    availability: AvailabilityLatch,
    probe: P,
    publisher: Option<TrustedDesktopPublisher>,
}

impl<P> DesktopEventProcessor<P>
where
    P: FnMut() -> Result<DesktopKind, DesktopWatchError>,
{
    /// Create an initially hidden cache and publish a probed baseline.
    pub(crate) fn start(
        session_id: u32,
        availability: SessionAvailability,
        probe: P,
    ) -> Result<(Self, CachedDesktopStateSource), DesktopWatchError> {
        let (publisher, source) = trusted_desktop_cache(DesktopKind::Unknown);
        let mut processor = Self {
            session_id,
            availability: match availability {
                SessionAvailability::Available => AvailabilityLatch::Available,
                SessionAvailability::Locked => {
                    AvailabilityLatch::Unavailable(DesktopKind::Winlogon)
                }
                SessionAvailability::Unavailable => {
                    AvailabilityLatch::Unavailable(DesktopKind::Unknown)
                }
            },
            probe,
            publisher: Some(publisher),
        };
        match processor.availability {
            AvailabilityLatch::Available => processor.publish_probe()?,
            AvailabilityLatch::Unavailable(kind) => processor.publish(kind)?,
        }
        Ok((processor, source))
    }

    /// Apply one ordered trusted platform event.
    pub(crate) fn process(&mut self, event: NativeDesktopEvent) -> Result<(), DesktopWatchError> {
        let result = match event {
            NativeDesktopEvent::DesktopSwitch => match self.availability {
                AvailabilityLatch::Available => self.publish_probe(),
                AvailabilityLatch::Unavailable(kind) => self.publish(kind),
            },
            NativeDesktopEvent::Session { session_id, .. } if session_id != self.session_id => {
                Ok(())
            }
            NativeDesktopEvent::Session { change, .. } => match change {
                SessionChange::Lock => {
                    self.availability = AvailabilityLatch::Unavailable(DesktopKind::Winlogon);
                    self.publish(DesktopKind::Winlogon)
                }
                SessionChange::Disconnect | SessionChange::Logoff | SessionChange::Terminate => {
                    self.availability = AvailabilityLatch::Unavailable(DesktopKind::Unknown);
                    self.publish(DesktopKind::Unknown)
                }
                SessionChange::Connect
                | SessionChange::Logon
                | SessionChange::Unlock
                | SessionChange::RemoteControl
                | SessionChange::Create
                | SessionChange::DesktopReady => {
                    self.availability = AvailabilityLatch::Available;
                    self.publish_probe()
                }
            },
        };
        if result.is_err() {
            self.shutdown();
        }
        result
    }

    /// Probe a resuming or switching desktop only after checking session
    /// availability on both sides of the native desktop probe.
    pub(crate) fn process_checked_desktop_probe(
        &mut self,
        availability: SessionAvailability,
        recheck: impl FnOnce() -> Result<SessionAvailability, DesktopWatchError>,
    ) -> Result<(), DesktopWatchError> {
        let result = match availability {
            SessionAvailability::Locked => {
                self.availability = AvailabilityLatch::Unavailable(DesktopKind::Winlogon);
                self.publish(DesktopKind::Winlogon)
            }
            SessionAvailability::Unavailable => {
                self.availability = AvailabilityLatch::Unavailable(DesktopKind::Unknown);
                self.publish(DesktopKind::Unknown)
            }
            SessionAvailability::Available => (|| {
                let observed = (self.probe)()?;
                match recheck()? {
                    SessionAvailability::Available => {
                        self.availability = AvailabilityLatch::Available;
                        self.publish(observed)
                    }
                    SessionAvailability::Locked => {
                        self.availability = AvailabilityLatch::Unavailable(DesktopKind::Winlogon);
                        self.publish(DesktopKind::Winlogon)
                    }
                    SessionAvailability::Unavailable => {
                        self.availability = AvailabilityLatch::Unavailable(DesktopKind::Unknown);
                        self.publish(DesktopKind::Unknown)
                    }
                }
            })(),
        };
        if result.is_err() {
            self.shutdown();
        }
        result
    }

    /// Permanently clear and close the source.
    pub(crate) fn shutdown(&mut self) {
        if let Some(mut publisher) = self.publisher.take() {
            publisher.fail_closed();
        }
    }

    fn publish_probe(&mut self) -> Result<(), DesktopWatchError> {
        let kind = (self.probe)()?;
        self.publish(kind)
    }

    fn publish(&mut self, kind: DesktopKind) -> Result<(), DesktopWatchError> {
        self.publisher
            .as_mut()
            .ok_or(DesktopWatchError::SourceClosed)?
            .publish_transition(kind)?;
        Ok(())
    }
}

/// Maximum accepted byte length of the native UOI desktop name.
pub(crate) const MAX_DESKTOP_NAME_BYTES: usize = 1024;

/// Decode a bounded, NUL-terminated native UOI_NAME buffer.
fn decode_desktop_name_bytes(bytes: &[u8]) -> Result<DesktopKind, DesktopWatchError> {
    if !(2..=MAX_DESKTOP_NAME_BYTES).contains(&bytes.len()) || !bytes.len().is_multiple_of(2) {
        return Err(DesktopWatchError::DesktopProbe);
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let Some((&0, name_units)) = units.split_last() else {
        return Err(DesktopWatchError::DesktopProbe);
    };
    if name_units.contains(&0) {
        return Err(DesktopWatchError::DesktopProbe);
    }
    let name = String::from_utf16(name_units).map_err(|_| DesktopWatchError::DesktopProbe)?;
    Ok(match name.as_str() {
        "Default" => DesktopKind::Default,
        "Winlogon" => DesktopKind::Winlogon,
        _ => DesktopKind::Unknown,
    })
}

/// Decode a raw `WM_WTSSESSION_CHANGE` payload without truncation.
fn decode_session_event(wparam: usize, lparam: isize) -> Option<NativeDesktopEvent> {
    let session_id = u32::try_from(lparam).ok()?;
    let change = match wparam {
        0x1 | 0x3 => SessionChange::Connect,
        0x2 | 0x4 => SessionChange::Disconnect,
        0x5 => SessionChange::Logon,
        0x6 => SessionChange::Logoff,
        0x7 => SessionChange::Lock,
        0x8 => SessionChange::Unlock,
        0x9 => SessionChange::RemoteControl,
        0xA => SessionChange::Create,
        0xB => SessionChange::Terminate,
        0xF => SessionChange::DesktopReady,
        _ => return None,
    };
    Some(NativeDesktopEvent::Session { session_id, change })
}

fn gate_resuming_session_event(
    event: NativeDesktopEvent,
    availability: SessionAvailability,
) -> NativeDesktopEvent {
    match (event, availability) {
        (
            NativeDesktopEvent::Session {
                session_id,
                change:
                    SessionChange::Connect
                    | SessionChange::Logon
                    | SessionChange::Unlock
                    | SessionChange::RemoteControl
                    | SessionChange::Create
                    | SessionChange::DesktopReady,
            },
            SessionAvailability::Locked,
        ) => NativeDesktopEvent::Session {
            session_id,
            change: SessionChange::Lock,
        },
        (
            NativeDesktopEvent::Session {
                session_id,
                change:
                    SessionChange::Connect
                    | SessionChange::Logon
                    | SessionChange::Unlock
                    | SessionChange::RemoteControl
                    | SessionChange::Create
                    | SessionChange::DesktopReady,
            },
            SessionAvailability::Unavailable,
        ) => NativeDesktopEvent::Session {
            session_id,
            change: SessionChange::Disconnect,
        },
        (event, _) => event,
    }
}

fn baseline_recheck_event(
    session_id: u32,
    before: SessionAvailability,
    after: SessionAvailability,
) -> Option<NativeDesktopEvent> {
    match (before, after) {
        (_, SessionAvailability::Unavailable) if before != SessionAvailability::Unavailable => {
            Some(NativeDesktopEvent::Session {
                session_id,
                change: SessionChange::Disconnect,
            })
        }
        (_, SessionAvailability::Locked) if before != SessionAvailability::Locked => {
            Some(NativeDesktopEvent::Session {
                session_id,
                change: SessionChange::Lock,
            })
        }
        (SessionAvailability::Unavailable, SessionAvailability::Available) => {
            Some(NativeDesktopEvent::Session {
                session_id,
                change: SessionChange::Connect,
            })
        }
        (SessionAvailability::Locked, SessionAvailability::Available) => {
            Some(NativeDesktopEvent::Session {
                session_id,
                change: SessionChange::Unlock,
            })
        }
        _ => None,
    }
}

impl<P> Drop for DesktopEventProcessor<P>
where
    P: FnMut() -> Result<DesktopKind, DesktopWatchError>,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Production trusted-desktop source backed by one native watcher thread.
pub(crate) struct WindowsTrustedDesktopStateSource {
    source: CachedDesktopStateSource,
    worker: Mutex<Option<NativeWorker>>,
}

impl WindowsTrustedDesktopStateSource {
    /// Start the native watcher and wait until its initial baseline is published.
    pub(crate) fn start(windows_session_id: u32) -> Result<Self, DesktopWatchError> {
        let (source, worker) = start_native_worker(windows_session_id)?;
        Ok(Self {
            source,
            worker: Mutex::new(Some(worker)),
        })
    }
}

impl TrustedDesktopStateSource for WindowsTrustedDesktopStateSource {
    fn current_state(&self) -> Option<TrustedDesktopState> {
        self.source.current_state()
    }

    fn subscribe(&self) -> watch::Receiver<()> {
        self.source.subscribe()
    }
}

impl Drop for WindowsTrustedDesktopStateSource {
    fn drop(&mut self) {
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            worker.stop_and_join();
        }
    }
}

#[derive(Debug)]
struct NativeWorker {
    window: NativeWindowToken,
    stop_requested: Arc<AtomicBool>,
    join: std::thread::JoinHandle<()>,
}

impl NativeWorker {
    fn stop_and_join(self) {
        self.stop_requested.store(true, AtomicOrdering::Release);
        post_native_shutdown(self.window);
        let _ = self.join.join();
    }
}

#[derive(Debug, Clone, Copy)]
struct NativeWindowToken {
    raw: isize,
    thread_id: u32,
    generation: usize,
}

fn start_native_worker(
    windows_session_id: u32,
) -> Result<(CachedDesktopStateSource, NativeWorker), DesktopWatchError> {
    native::start_native_worker(windows_session_id)
}

fn post_native_shutdown(window: NativeWindowToken) {
    native::post_native_shutdown(window);
}

mod native {
    use super::{
        baseline_recheck_event, decode_desktop_name_bytes, decode_session_event,
        CachedDesktopStateSource, DesktopEventProcessor, DesktopWatchError, NativeDesktopEvent,
        NativeWindowToken, NativeWorker, SessionAvailability, SessionChange,
        MAX_DESKTOP_NAME_BYTES,
    };
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        ffi::c_void,
        mem::size_of,
        panic::{catch_unwind, AssertUnwindSafe},
        ptr,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc::{self, SyncSender, TrySendError},
            Arc,
        },
        thread,
    };
    #[cfg(test)]
    use windows::Win32::UI::WindowsAndMessaging::SendMessageW;
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
            System::{
                LibraryLoader::GetModuleHandleW,
                RemoteDesktop::{
                    ProcessIdToSessionId, WTSActive, WTSConnectState, WTSFreeMemory,
                    WTSQuerySessionInformationW, WTSRegisterSessionNotification, WTSSessionInfoEx,
                    WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION, WTSINFOEXW,
                    WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSIONSTATE_LOCK,
                    WTS_SESSIONSTATE_UNLOCK,
                },
                StationsAndDesktops::{
                    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop,
                    DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, HDESK, UOI_NAME,
                },
                Threading::{GetCurrentProcessId, GetCurrentThreadId},
            },
            UI::{
                Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK},
                WindowsAndMessaging::{
                    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
                    KillTimer, PostMessageW, PostQuitMessage, PostThreadMessageW, RegisterClassW,
                    SetTimer, UnregisterClassW, EVENT_SYSTEM_DESKTOPSWITCH, MSG, WINDOW_EX_STYLE,
                    WINDOW_STYLE, WINEVENT_OUTOFCONTEXT, WM_APP, WM_WTSSESSION_CHANGE, WNDCLASSW,
                },
            },
        },
    };

    const WM_MRD_DESKTOP_SWITCH: u32 = WM_APP + 0x341;
    const WM_MRD_SHUTDOWN: u32 = WM_APP + 0x342;
    const WM_MRD_SESSION_CHANGE: u32 = WM_APP + 0x343;
    const MAX_PENDING_SESSION_EVENTS: usize = 64;
    const WATCHER_TIMER_ID: usize = 1;
    const WATCHER_TIMER_INTERVAL_MS: u32 = 1_000;
    static NEXT_WATCHER_GENERATION: AtomicUsize = AtomicUsize::new(1);

    thread_local! {
        static CALLBACK_WINDOW: Cell<isize> = const { Cell::new(0) };
        static CALLBACK_GENERATION: Cell<usize> = const { Cell::new(0) };
        static CALLBACK_FAILED: Cell<bool> = const { Cell::new(false) };
        static PENDING_SESSION_EVENTS: RefCell<VecDeque<(usize, isize)>> =
            const { RefCell::new(VecDeque::new()) };
    }

    type ReadyMessage = Result<(CachedDesktopStateSource, NativeWindowToken), DesktopWatchError>;

    pub(super) fn start_native_worker(
        windows_session_id: u32,
    ) -> Result<(CachedDesktopStateSource, NativeWorker), DesktopWatchError> {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<ReadyMessage>(1);
        let fallback = ready_tx.clone();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop_requested);
        let join = thread::Builder::new()
            .name("mrd-desktop-watch".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    native_worker_main(windows_session_id, ready_tx, worker_stop)
                }));
                let error = match outcome {
                    Ok(Ok(())) => return,
                    Ok(Err(error)) => error,
                    Err(_) => DesktopWatchError::WorkerUnavailable,
                };
                match fallback.try_send(Err(error)) {
                    Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
                }
            })
            .map_err(|_| DesktopWatchError::WorkerUnavailable)?;

        match ready_rx.recv() {
            Ok(Ok((source, window))) => Ok((
                source,
                NativeWorker {
                    window,
                    stop_requested,
                    join,
                },
            )),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(_) => {
                let _ = join.join();
                Err(DesktopWatchError::WorkerUnavailable)
            }
        }
    }

    pub(super) fn post_native_shutdown(window: NativeWindowToken) {
        if window.raw == 0 {
            return;
        }
        let hwnd = HWND(window.raw as *mut c_void);
        let _ = unsafe {
            PostMessageW(
                Some(hwnd),
                WM_MRD_SHUTDOWN,
                WPARAM(window.generation),
                LPARAM(0),
            )
        };
        let _ = unsafe {
            PostThreadMessageW(
                window.thread_id,
                WM_MRD_SHUTDOWN,
                WPARAM(window.generation),
                LPARAM(0),
            )
        };
    }

    #[cfg(test)]
    pub(super) fn send_test_wts(window: NativeWindowToken, code: usize, session_id: u32) {
        let hwnd = HWND(window.raw as *mut c_void);
        unsafe {
            SendMessageW(
                hwnd,
                WM_WTSSESSION_CHANGE,
                Some(WPARAM(code)),
                Some(LPARAM(session_id as isize)),
            );
        }
    }

    #[cfg(test)]
    pub(super) fn post_test_shutdown(window: NativeWindowToken, generation: usize) {
        let hwnd = HWND(window.raw as *mut c_void);
        let _ = unsafe { PostMessageW(Some(hwnd), WM_MRD_SHUTDOWN, WPARAM(generation), LPARAM(0)) };
    }

    fn native_worker_main(
        windows_session_id: u32,
        ready: SyncSender<ReadyMessage>,
        stop_requested: Arc<AtomicBool>,
    ) -> Result<(), DesktopWatchError> {
        if windows_session_id == 0 {
            return Err(DesktopWatchError::WorkerUnavailable);
        }
        let mut process_session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut process_session_id) }
            .map_err(|error| native_error("verify watcher session", error))?;
        if process_session_id != windows_session_id {
            return Err(DesktopWatchError::WorkerUnavailable);
        }
        let generation = next_generation()?;
        let resources = WatcherResources::create(generation)?;
        let availability = query_session_availability(windows_session_id)?;
        let (mut processor, source) =
            DesktopEventProcessor::start(windows_session_id, availability, probe_input_desktop)?;
        let rechecked_availability = query_session_availability(windows_session_id)?;
        if baseline_recheck_event(windows_session_id, availability, rechecked_availability)
            .is_some()
        {
            processor.process_checked_desktop_probe(rechecked_availability, || {
                query_session_availability(windows_session_id)
            })?;
        }
        let token = NativeWindowToken {
            raw: resources.window.0 as isize,
            thread_id: unsafe { GetCurrentThreadId() },
            generation,
        };
        ready
            .send(Ok((source, token)))
            .map_err(|_| DesktopWatchError::WorkerUnavailable)?;
        run_message_loop(
            &resources,
            generation,
            windows_session_id,
            stop_requested.as_ref(),
            &mut processor,
        )
    }

    fn next_generation() -> Result<usize, DesktopWatchError> {
        NEXT_WATCHER_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| DesktopWatchError::SourceClosed)
    }

    struct WatcherResources {
        window: HWND,
        hook: Option<HWINEVENTHOOK>,
        wts_registered: bool,
        timer_started: bool,
        class_name: Vec<u16>,
        instance: HINSTANCE,
    }

    impl WatcherResources {
        fn create(generation: usize) -> Result<Self, DesktopWatchError> {
            let module = unsafe { GetModuleHandleW(None) }
                .map_err(|error| native_error("module handle", error))?;
            let instance = HINSTANCE(module.0);
            let class_name = format!("MrdDesktopWatcher-{generation}\0")
                .encode_utf16()
                .collect::<Vec<_>>();
            let class = WNDCLASSW {
                lpfnWndProc: Some(watcher_window_proc),
                hInstance: instance,
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..WNDCLASSW::default()
            };
            if unsafe { RegisterClassW(&class) } == 0 {
                return Err(last_native_error("register window class"));
            }
            let window = match unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    PCWSTR(class_name.as_ptr()),
                    PCWSTR(class_name.as_ptr()),
                    WINDOW_STYLE::default(),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    Some(instance),
                    None,
                )
            } {
                Ok(window) => window,
                Err(error) => {
                    let _ =
                        unsafe { UnregisterClassW(PCWSTR(class_name.as_ptr()), Some(instance)) };
                    return Err(native_error("create watcher window", error));
                }
            };
            let mut resources = Self {
                window,
                hook: None,
                wts_registered: false,
                timer_started: false,
                class_name,
                instance,
            };
            if unsafe {
                SetTimer(
                    Some(window),
                    WATCHER_TIMER_ID,
                    WATCHER_TIMER_INTERVAL_MS,
                    None,
                )
            } == 0
            {
                return Err(last_native_error("start watcher timer"));
            }
            resources.timer_started = true;
            CALLBACK_WINDOW.with(|target| target.set(window.0 as isize));
            CALLBACK_GENERATION.with(|current| current.set(generation));
            CALLBACK_FAILED.with(|failed| failed.set(false));
            PENDING_SESSION_EVENTS.with(|events| events.borrow_mut().clear());
            unsafe { WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) }
                .map_err(|error| native_error("register session notifications", error))?;
            resources.wts_registered = true;
            let hook = unsafe {
                SetWinEventHook(
                    EVENT_SYSTEM_DESKTOPSWITCH,
                    EVENT_SYSTEM_DESKTOPSWITCH,
                    None,
                    Some(win_event_proc),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                )
            };
            if hook.is_invalid() {
                return Err(last_native_error("install desktop switch hook"));
            }
            resources.hook = Some(hook);
            Ok(resources)
        }
    }

    impl Drop for WatcherResources {
        fn drop(&mut self) {
            CALLBACK_WINDOW.with(|target| target.set(0));
            CALLBACK_GENERATION.with(|current| current.set(0));
            PENDING_SESSION_EVENTS.with(|events| events.borrow_mut().clear());
            if let Some(hook) = self.hook.take() {
                let _ = unsafe { UnhookWinEvent(hook) };
            }
            if self.wts_registered {
                let _ = unsafe { WTSUnRegisterSessionNotification(self.window) };
                self.wts_registered = false;
            }
            if self.timer_started {
                let _ = unsafe { KillTimer(Some(self.window), WATCHER_TIMER_ID) };
                self.timer_started = false;
            }
            let _ = unsafe { DestroyWindow(self.window) };
            let _ =
                unsafe { UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.instance)) };
        }
    }

    fn run_message_loop<P>(
        resources: &WatcherResources,
        generation: usize,
        windows_session_id: u32,
        stop_requested: &AtomicBool,
        processor: &mut DesktopEventProcessor<P>,
    ) -> Result<(), DesktopWatchError>
    where
        P: FnMut() -> Result<mrd_agent_ipc::DesktopKind, DesktopWatchError>,
    {
        let mut message = MSG::default();
        loop {
            if stop_requested.load(Ordering::Acquire) {
                return Ok(());
            }
            if callback_failed() {
                return Err(DesktopWatchError::WorkerUnavailable);
            }
            let status = unsafe { GetMessageW(&mut message, None, 0, 0) }.0;
            if status == -1 {
                return Err(last_native_error("watcher message loop"));
            }
            if status == 0 {
                let status = i32::try_from(message.wParam.0).unwrap_or(i32::MAX);
                return Err(DesktopWatchError::Native {
                    operation: "watcher message loop exited",
                    status,
                });
            }
            if stop_requested.load(Ordering::Acquire) {
                return Ok(());
            }
            if callback_failed() {
                return Err(DesktopWatchError::WorkerUnavailable);
            }
            match message.message {
                WM_MRD_SHUTDOWN if message.wParam.0 == generation => return Ok(()),
                WM_MRD_SHUTDOWN => continue,
                _ => {}
            }
            if message.hwnd == resources.window {
                match message.message {
                    WM_MRD_DESKTOP_SWITCH if message.wParam.0 == generation => {
                        let availability = query_session_availability(windows_session_id)?;
                        processor.process_checked_desktop_probe(availability, || {
                            query_session_availability(windows_session_id)
                        })?;
                        continue;
                    }
                    WM_MRD_DESKTOP_SWITCH => continue,
                    WM_MRD_SESSION_CHANGE if message.wParam.0 == generation => {
                        let raw =
                            PENDING_SESSION_EVENTS.with(|events| events.borrow_mut().pop_front());
                        if let Some((wparam, lparam)) = raw {
                            if let Some(event) = decode_session_event(wparam, lparam) {
                                if matches!(
                                    event,
                                    NativeDesktopEvent::Session {
                                        session_id,
                                        change:
                                            SessionChange::Connect
                                            | SessionChange::Logon
                                            | SessionChange::Unlock
                                            | SessionChange::RemoteControl
                                            | SessionChange::Create
                                            | SessionChange::DesktopReady,
                                    } if session_id == windows_session_id
                                ) {
                                    let availability =
                                        query_session_availability(windows_session_id)?;
                                    processor
                                        .process_checked_desktop_probe(availability, || {
                                            query_session_availability(windows_session_id)
                                        })?;
                                } else {
                                    processor.process(event)?;
                                }
                            }
                        }
                        continue;
                    }
                    WM_MRD_SESSION_CHANGE => continue,
                    _ => {}
                }
            }
            unsafe {
                DispatchMessageW(&message);
            }
        }
    }

    unsafe extern "system" fn watcher_window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let result = catch_unwind(AssertUnwindSafe(|| {
            if message == WM_WTSSESSION_CHANGE {
                return forward_session_event(hwnd, wparam.0, lparam.0).then_some(LRESULT(0));
            }
            Some(unsafe { DefWindowProcW(hwnd, message, wparam, lparam) })
        }));
        match result {
            Ok(Some(result)) => result,
            Ok(None) | Err(_) => callback_fail_stop(),
        }
    }

    fn forward_session_event(hwnd: HWND, wparam: usize, lparam: isize) -> bool {
        let raw = CALLBACK_WINDOW.with(Cell::get);
        let generation = CALLBACK_GENERATION.with(Cell::get);
        if raw == 0 || raw != hwnd.0 as isize || generation == 0 {
            return false;
        }
        let queued = PENDING_SESSION_EVENTS.with(|events| {
            let Ok(mut events) = events.try_borrow_mut() else {
                return false;
            };
            if events.len() >= MAX_PENDING_SESSION_EVENTS {
                return false;
            }
            events.push_back((wparam, lparam));
            true
        });
        queued
            && unsafe {
                PostMessageW(
                    Some(hwnd),
                    WM_MRD_SESSION_CHANGE,
                    WPARAM(generation),
                    LPARAM(0),
                )
                .is_ok()
            }
    }

    fn callback_fail_stop() -> LRESULT {
        let _ = CALLBACK_FAILED.try_with(|failed| failed.set(true));
        unsafe { PostQuitMessage(1) };
        LRESULT(0)
    }

    fn callback_failed() -> bool {
        CALLBACK_FAILED.try_with(Cell::get).unwrap_or(true)
    }

    unsafe extern "system" fn win_event_proc(
        _hook: HWINEVENTHOOK,
        event: u32,
        _window: HWND,
        _object_id: i32,
        _child_id: i32,
        _event_thread: u32,
        _event_time: u32,
    ) {
        let posted = catch_unwind(AssertUnwindSafe(|| {
            if event != EVENT_SYSTEM_DESKTOPSWITCH {
                return true;
            }
            CALLBACK_WINDOW.with(|target| {
                let raw = target.get();
                if raw == 0 {
                    return false;
                }
                let hwnd = HWND(raw as *mut c_void);
                unsafe {
                    PostMessageW(
                        Some(hwnd),
                        WM_MRD_DESKTOP_SWITCH,
                        WPARAM(CALLBACK_GENERATION.with(Cell::get)),
                        LPARAM(0),
                    )
                    .is_ok()
                }
            })
        }))
        .unwrap_or(false);
        if !posted {
            let _ = callback_fail_stop();
        }
    }

    fn query_session_availability(
        windows_session_id: u32,
    ) -> Result<SessionAvailability, DesktopWatchError> {
        let mut raw = PWSTR::null();
        let mut bytes = 0_u32;
        unsafe {
            WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                windows_session_id,
                WTSConnectState,
                &mut raw,
                &mut bytes,
            )
        }
        .map_err(|error| native_error("query session state", error))?;
        if raw.is_null() || bytes as usize != size_of::<WTS_CONNECTSTATE_CLASS>() {
            if !raw.is_null() {
                unsafe { WTSFreeMemory(raw.0.cast()) };
            }
            return Err(DesktopWatchError::WorkerUnavailable);
        }
        let memory = WtsMemory(raw);
        let state = unsafe { ptr::read_unaligned(memory.0 .0.cast::<WTS_CONNECTSTATE_CLASS>()) };
        if state != WTSActive {
            return Ok(SessionAvailability::Unavailable);
        }
        drop(memory);

        let mut raw = PWSTR::null();
        let mut bytes = 0_u32;
        unsafe {
            WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                windows_session_id,
                WTSSessionInfoEx,
                &mut raw,
                &mut bytes,
            )
        }
        .map_err(|error| native_error("query session lock state", error))?;
        if raw.is_null() || (bytes as usize) < size_of::<WTSINFOEXW>() {
            if !raw.is_null() {
                unsafe { WTSFreeMemory(raw.0.cast()) };
            }
            return Err(DesktopWatchError::WorkerUnavailable);
        }
        let memory = WtsMemory(raw);
        let info = unsafe { ptr::read_unaligned(memory.0 .0.cast::<WTSINFOEXW>()) };
        if info.Level != 1 {
            return Err(DesktopWatchError::WorkerUnavailable);
        }
        let level = unsafe { info.Data.WTSInfoExLevel1 };
        if level.SessionId != windows_session_id || level.SessionState != WTSActive {
            return Ok(SessionAvailability::Unavailable);
        }
        match u32::try_from(level.SessionFlags).ok() {
            Some(WTS_SESSIONSTATE_LOCK) => Ok(SessionAvailability::Locked),
            Some(WTS_SESSIONSTATE_UNLOCK) => Ok(SessionAvailability::Available),
            _ => Ok(SessionAvailability::Unavailable),
        }
    }

    struct WtsMemory(PWSTR);

    impl Drop for WtsMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WTSFreeMemory(self.0 .0.cast()) };
            }
        }
    }

    fn probe_input_desktop() -> Result<mrd_agent_ipc::DesktopKind, DesktopWatchError> {
        let desktop = unsafe {
            OpenInputDesktop(DESKTOP_CONTROL_FLAGS::default(), false, DESKTOP_READOBJECTS)
        }
        .map_err(|_| DesktopWatchError::DesktopProbe)?;
        let mut desktop = DesktopHandle(Some(desktop));
        let object = HANDLE(desktop.0.ok_or(DesktopWatchError::DesktopProbe)?.0);
        let mut needed = 0_u32;
        let _ = unsafe { GetUserObjectInformationW(object, UOI_NAME, None, 0, Some(&mut needed)) };
        let byte_len = needed as usize;
        if !(2..=MAX_DESKTOP_NAME_BYTES).contains(&byte_len) || !byte_len.is_multiple_of(2) {
            return Err(DesktopWatchError::DesktopProbe);
        }
        let mut units = vec![0_u16; byte_len / size_of::<u16>()];
        let mut returned = needed;
        unsafe {
            GetUserObjectInformationW(
                object,
                UOI_NAME,
                Some(units.as_mut_ptr().cast()),
                needed,
                Some(&mut returned),
            )
        }
        .map_err(|_| DesktopWatchError::DesktopProbe)?;
        let returned = returned as usize;
        if returned < 2 || returned > byte_len || !returned.is_multiple_of(2) {
            return Err(DesktopWatchError::DesktopProbe);
        }
        let bytes = unsafe { std::slice::from_raw_parts(units.as_ptr().cast::<u8>(), returned) };
        let kind = decode_desktop_name_bytes(bytes)?;
        desktop.close()?;
        Ok(kind)
    }

    struct DesktopHandle(Option<HDESK>);

    impl DesktopHandle {
        fn close(&mut self) -> Result<(), DesktopWatchError> {
            let desktop = self.0.ok_or(DesktopWatchError::DesktopProbe)?;
            unsafe { CloseDesktop(desktop) }.map_err(|_| DesktopWatchError::DesktopProbe)?;
            self.0 = None;
            Ok(())
        }
    }

    impl Drop for DesktopHandle {
        fn drop(&mut self) {
            if let Some(desktop) = self.0.take() {
                let _ = unsafe { CloseDesktop(desktop) };
            }
        }
    }

    fn native_error(operation: &'static str, error: windows::core::Error) -> DesktopWatchError {
        DesktopWatchError::Native {
            operation,
            status: error.code().0,
        }
    }

    fn last_native_error(operation: &'static str) -> DesktopWatchError {
        native_error(operation, windows::core::Error::from_thread())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        baseline_recheck_event, decode_desktop_name_bytes, decode_session_event,
        gate_resuming_session_event, DesktopEventProcessor, DesktopWatchError, NativeDesktopEvent,
        SessionAvailability, SessionChange, WindowsTrustedDesktopStateSource,
        MAX_DESKTOP_NAME_BYTES,
    };
    use crate::runtime::{TrustedDesktopState, TrustedDesktopStateSource};
    use mrd_agent_ipc::DesktopKind;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};
    use windows::Win32::System::{
        RemoteDesktop::ProcessIdToSessionId, Threading::GetCurrentProcessId,
    };

    const THIS_SESSION: u32 = 41;

    fn processor_with_probes(
        probes: impl IntoIterator<Item = Result<DesktopKind, DesktopWatchError>>,
    ) -> (
        DesktopEventProcessor<impl FnMut() -> Result<DesktopKind, DesktopWatchError>>,
        impl TrustedDesktopStateSource,
    ) {
        let mut probes = probes.into_iter().collect::<VecDeque<_>>();
        DesktopEventProcessor::start(THIS_SESSION, SessionAvailability::Available, move || {
            probes.pop_front().expect("unexpected native desktop probe")
        })
        .expect("baseline probe should succeed")
    }

    fn state(epoch: u64, kind: DesktopKind) -> Option<TrustedDesktopState> {
        Some(TrustedDesktopState {
            desktop_epoch: epoch,
            desktop_kind: kind,
        })
    }

    #[test]
    fn baseline_probe_is_published_with_a_nonzero_epoch() {
        let (_processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);

        let baseline = source.current_state().expect("baseline state");
        assert_ne!(baseline.desktop_epoch, 0);
        assert_eq!(baseline.desktop_kind, DesktopKind::Default);
    }

    #[test]
    fn unavailable_baseline_is_unknown_without_probing_the_would_be_desktop() {
        let (processor, source) = DesktopEventProcessor::start(
            THIS_SESSION,
            SessionAvailability::Unavailable,
            || -> Result<DesktopKind, DesktopWatchError> {
                panic!("an unavailable session must not probe OpenInputDesktop")
            },
        )
        .expect("unknown baseline should publish");
        let _processor = processor;

        let baseline = source.current_state().expect("baseline state");
        assert_ne!(baseline.desktop_epoch, 0);
        assert_eq!(baseline.desktop_kind, DesktopKind::Unknown);
    }

    #[test]
    fn nondefault_active_baseline_reprobes_after_a_desktop_switch() {
        let (mut processor, source) =
            processor_with_probes([Ok(DesktopKind::Winlogon), Ok(DesktopKind::Default)]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("desktop switch after non-default baseline");
        let returned = source.current_state().expect("returned state");

        assert_eq!(returned.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(returned.desktop_kind, DesktopKind::Default);
    }

    #[test]
    fn locked_baseline_is_winlogon_without_probing_a_would_be_desktop() {
        let (mut processor, source) = DesktopEventProcessor::start(
            THIS_SESSION,
            SessionAvailability::Locked,
            || -> Result<DesktopKind, DesktopWatchError> {
                panic!("a locked session must not probe OpenInputDesktop")
            },
        )
        .expect("locked baseline should publish");
        let baseline = source.current_state().expect("baseline state");

        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("desktop switch while locked");
        let repeated = source.current_state().expect("latched state");

        assert_eq!(baseline.desktop_kind, DesktopKind::Winlogon);
        assert_eq!(repeated.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(repeated.desktop_kind, DesktopKind::Winlogon);
    }

    #[test]
    fn repeated_trusted_desktop_switch_events_advance_the_epoch() {
        let (mut processor, source) = processor_with_probes([
            Ok(DesktopKind::Default),
            Ok(DesktopKind::Default),
            Ok(DesktopKind::Default),
        ]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("first transition");
        let first = source.current_state().expect("first state");
        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("second transition");
        let second = source.current_state().expect("second state");

        assert_eq!(first.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(second.desktop_epoch, first.desktop_epoch + 1);
        assert_eq!(second.desktop_kind, DesktopKind::Default);
    }

    #[test]
    fn default_nondefault_default_aba_receives_distinct_epochs() {
        let (mut processor, source) = processor_with_probes([
            Ok(DesktopKind::Default),
            Ok(DesktopKind::Winlogon),
            Ok(DesktopKind::Default),
        ]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("leave default desktop");
        let nondefault = source.current_state().expect("non-default state");
        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("return to default desktop");
        let returned = source.current_state().expect("returned state");

        assert_eq!(nondefault.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(nondefault.desktop_kind, DesktopKind::Winlogon);
        assert_eq!(returned.desktop_epoch, nondefault.desktop_epoch + 1);
        assert_eq!(returned.desktop_kind, DesktopKind::Default);
    }

    #[test]
    fn lock_is_published_as_winlogon_without_a_probe() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Lock,
            })
            .expect("lock transition");

        assert_eq!(
            source.current_state(),
            state(baseline.desktop_epoch + 1, DesktopKind::Winlogon)
        );
    }

    #[test]
    fn desktop_switch_cannot_restore_default_while_the_session_is_locked() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);

        processor
            .process(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Lock,
            })
            .expect("lock transition");
        let locked = source.current_state().expect("locked state");
        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("desktop switch while locked");
        let repeated = source.current_state().expect("repeated locked state");

        assert_eq!(repeated.desktop_epoch, locked.desktop_epoch + 1);
        assert_eq!(repeated.desktop_kind, DesktopKind::Winlogon);
    }

    #[test]
    fn desktop_switch_cannot_restore_default_while_the_session_is_disconnected() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);

        processor
            .process(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Disconnect,
            })
            .expect("disconnect transition");
        let disconnected = source.current_state().expect("disconnected state");
        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("desktop switch while disconnected");
        let repeated = source.current_state().expect("repeated unavailable state");

        assert_eq!(repeated.desktop_epoch, disconnected.desktop_epoch + 1);
        assert_eq!(repeated.desktop_kind, DesktopKind::Unknown);
    }

    #[test]
    fn checked_desktop_switch_never_probes_an_unavailable_session() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process_checked_desktop_probe(SessionAvailability::Unavailable, || {
                panic!("an unavailable session must not need a post-probe recheck")
            })
            .expect("unavailable transition");
        let unavailable = source.current_state().expect("unavailable state");

        assert_eq!(unavailable.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(unavailable.desktop_kind, DesktopKind::Unknown);
    }

    #[test]
    fn checked_desktop_switch_publishes_only_after_the_post_probe_recheck() {
        let (mut processor, source) =
            processor_with_probes([Ok(DesktopKind::Default), Ok(DesktopKind::Default)]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process_checked_desktop_probe(SessionAvailability::Available, || {
                assert_eq!(
                    source.current_state(),
                    Some(baseline),
                    "the probed Default desktop must remain unpublished until recheck",
                );
                Ok(SessionAvailability::Unavailable)
            })
            .expect("post-probe disconnect");
        let unavailable = source.current_state().expect("unavailable state");

        assert_eq!(unavailable.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(unavailable.desktop_kind, DesktopKind::Unknown);
    }

    #[test]
    fn checked_desktop_probe_maps_a_post_probe_lock_to_winlogon() {
        let (mut processor, source) =
            processor_with_probes([Ok(DesktopKind::Default), Ok(DesktopKind::Default)]);
        let baseline = source.current_state().expect("baseline state");

        processor
            .process_checked_desktop_probe(SessionAvailability::Available, || {
                assert_eq!(source.current_state(), Some(baseline));
                Ok(SessionAvailability::Locked)
            })
            .expect("post-probe lock");
        let locked = source.current_state().expect("locked state");

        assert_eq!(locked.desktop_epoch, baseline.desktop_epoch + 1);
        assert_eq!(locked.desktop_kind, DesktopKind::Winlogon);
    }

    #[test]
    fn checked_desktop_switch_recheck_failure_closes_the_source() {
        let (mut processor, source) =
            processor_with_probes([Ok(DesktopKind::Default), Ok(DesktopKind::Default)]);

        assert_eq!(
            processor.process_checked_desktop_probe(SessionAvailability::Available, || {
                Err(DesktopWatchError::DesktopProbe)
            }),
            Err(DesktopWatchError::DesktopProbe),
        );
        assert_eq!(source.current_state(), None);
        assert!(source.subscribe().has_changed().is_err());
    }

    #[test]
    fn disconnect_and_logoff_are_published_as_unknown() {
        for change in [SessionChange::Disconnect, SessionChange::Logoff] {
            let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);
            let baseline = source.current_state().expect("baseline state");

            processor
                .process(NativeDesktopEvent::Session {
                    session_id: THIS_SESSION,
                    change,
                })
                .expect("session transition");

            assert_eq!(
                source.current_state(),
                state(baseline.desktop_epoch + 1, DesktopKind::Unknown)
            );
        }
    }

    #[test]
    fn notifications_for_other_sessions_are_ignored() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);
        let baseline = source.current_state();

        processor
            .process(NativeDesktopEvent::Session {
                session_id: THIS_SESSION + 1,
                change: SessionChange::Unlock,
            })
            .expect("other session must be ignored");

        assert_eq!(source.current_state(), baseline);
    }

    #[test]
    fn reconnect_logon_unlock_and_desktop_ready_reprobe_the_input_desktop() {
        for (change, observed) in [
            (SessionChange::Connect, DesktopKind::Default),
            (SessionChange::Logon, DesktopKind::Default),
            (SessionChange::Unlock, DesktopKind::Winlogon),
            (SessionChange::DesktopReady, DesktopKind::Secure),
        ] {
            let (mut processor, source) =
                processor_with_probes([Ok(DesktopKind::Unknown), Ok(observed)]);
            let baseline = source.current_state().expect("baseline state");

            processor
                .process(NativeDesktopEvent::Session {
                    session_id: THIS_SESSION,
                    change,
                })
                .expect("session transition");

            assert_eq!(
                source.current_state(),
                state(baseline.desktop_epoch + 1, observed)
            );
        }
    }

    #[test]
    fn terminate_is_published_as_unknown_and_latches_unavailable() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);

        processor
            .process(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Terminate,
            })
            .expect("terminate transition");
        let terminated = source.current_state().expect("terminated state");
        processor
            .process(NativeDesktopEvent::DesktopSwitch)
            .expect("desktop switch after terminate");
        let repeated = source.current_state().expect("repeated unavailable state");

        assert_eq!(terminated.desktop_kind, DesktopKind::Unknown);
        assert_eq!(repeated.desktop_kind, DesktopKind::Unknown);
        assert_eq!(repeated.desktop_epoch, terminated.desktop_epoch + 1);
    }

    #[test]
    fn raw_wts_events_reject_invalid_session_ids_and_unknown_codes() {
        assert_eq!(
            decode_session_event(0x7fff_ffff, THIS_SESSION as isize),
            None
        );
        assert_eq!(decode_session_event(0x7, -1), None);
        if isize::BITS > 32 {
            assert_eq!(
                decode_session_event(0x7, (u32::MAX as u64 + 1) as isize),
                None
            );
        }
    }

    #[test]
    fn raw_wts_events_decode_security_relevant_transitions() {
        for (code, expected) in [
            (0x1, SessionChange::Connect),
            (0x3, SessionChange::Connect),
            (0x2, SessionChange::Disconnect),
            (0x4, SessionChange::Disconnect),
            (0x5, SessionChange::Logon),
            (0x6, SessionChange::Logoff),
            (0x7, SessionChange::Lock),
            (0x8, SessionChange::Unlock),
            (0x9, SessionChange::RemoteControl),
            (0xA, SessionChange::Create),
            (0xF, SessionChange::DesktopReady),
            (0xB, SessionChange::Terminate),
        ] {
            assert_eq!(
                decode_session_event(code, THIS_SESSION as isize),
                Some(NativeDesktopEvent::Session {
                    session_id: THIS_SESSION,
                    change: expected,
                })
            );
        }
        assert_eq!(decode_session_event(0xC, THIS_SESSION as isize), None);
    }

    #[test]
    fn resuming_wts_message_cannot_override_an_unavailable_native_session() {
        for change in [
            SessionChange::Connect,
            SessionChange::Logon,
            SessionChange::Unlock,
            SessionChange::RemoteControl,
            SessionChange::Create,
            SessionChange::DesktopReady,
        ] {
            assert_eq!(
                gate_resuming_session_event(
                    NativeDesktopEvent::Session {
                        session_id: THIS_SESSION,
                        change,
                    },
                    SessionAvailability::Unavailable,
                ),
                NativeDesktopEvent::Session {
                    session_id: THIS_SESSION,
                    change: SessionChange::Disconnect,
                },
            );
        }
    }

    #[test]
    fn baseline_recheck_closes_a_connection_state_race() {
        assert_eq!(
            baseline_recheck_event(
                THIS_SESSION,
                SessionAvailability::Available,
                SessionAvailability::Unavailable,
            ),
            Some(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Disconnect,
            }),
        );
        assert_eq!(
            baseline_recheck_event(
                THIS_SESSION,
                SessionAvailability::Unavailable,
                SessionAvailability::Available,
            ),
            Some(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Connect,
            }),
        );
        assert_eq!(
            baseline_recheck_event(
                THIS_SESSION,
                SessionAvailability::Available,
                SessionAvailability::Locked,
            ),
            Some(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Lock,
            }),
        );
        assert_eq!(
            baseline_recheck_event(
                THIS_SESSION,
                SessionAvailability::Locked,
                SessionAvailability::Available,
            ),
            Some(NativeDesktopEvent::Session {
                session_id: THIS_SESSION,
                change: SessionChange::Unlock,
            }),
        );
        assert_eq!(
            baseline_recheck_event(
                THIS_SESSION,
                SessionAvailability::Available,
                SessionAvailability::Available,
            ),
            None,
        );
    }

    fn desktop_name_bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    #[test]
    fn desktop_name_decoder_accepts_only_exact_known_names() {
        assert_eq!(
            decode_desktop_name_bytes(&desktop_name_bytes(&[
                b'D' as u16,
                b'e' as u16,
                b'f' as u16,
                b'a' as u16,
                b'u' as u16,
                b'l' as u16,
                b't' as u16,
                0,
            ])),
            Ok(DesktopKind::Default)
        );
        assert_eq!(
            decode_desktop_name_bytes(&desktop_name_bytes(&[
                b'W' as u16,
                b'i' as u16,
                b'n' as u16,
                b'l' as u16,
                b'o' as u16,
                b'g' as u16,
                b'o' as u16,
                b'n' as u16,
                0,
            ])),
            Ok(DesktopKind::Winlogon)
        );
        assert_eq!(
            decode_desktop_name_bytes(&desktop_name_bytes(&[
                b'S' as u16,
                b'e' as u16,
                b'c' as u16,
                b'u' as u16,
                b'r' as u16,
                b'e' as u16,
                0,
            ])),
            Ok(DesktopKind::Unknown),
            "production must not guess that an arbitrary desktop is Secure"
        );
    }

    #[test]
    fn desktop_name_decoder_rejects_oversize_odd_unterminated_and_invalid_utf16() {
        assert_eq!(
            decode_desktop_name_bytes(&vec![0; MAX_DESKTOP_NAME_BYTES + 2]),
            Err(DesktopWatchError::DesktopProbe)
        );
        assert_eq!(
            decode_desktop_name_bytes(&[0]),
            Err(DesktopWatchError::DesktopProbe)
        );
        assert_eq!(
            decode_desktop_name_bytes(&desktop_name_bytes(&[b'D' as u16])),
            Err(DesktopWatchError::DesktopProbe)
        );
        assert_eq!(
            decode_desktop_name_bytes(&desktop_name_bytes(&[0xD800, 0])),
            Err(DesktopWatchError::DesktopProbe)
        );
    }

    #[tokio::test]
    async fn probe_failure_clears_the_cache_and_closes_subscribers() {
        let (mut processor, source) = processor_with_probes([
            Ok(DesktopKind::Default),
            Err(DesktopWatchError::DesktopProbe),
        ]);
        let mut changes = source.subscribe();

        assert_eq!(
            processor.process(NativeDesktopEvent::DesktopSwitch),
            Err(DesktopWatchError::DesktopProbe)
        );

        assert_eq!(source.current_state(), None);
        assert!(changes.changed().await.is_err());
    }

    #[tokio::test]
    async fn clean_shutdown_clears_the_cache_and_closes_subscribers() {
        let (mut processor, source) = processor_with_probes([Ok(DesktopKind::Default)]);
        let mut changes = source.subscribe();

        processor.shutdown();

        assert_eq!(source.current_state(), None);
        assert!(changes.changed().await.is_err());
    }

    #[test]
    #[ignore = "requires an interactive Windows session"]
    fn native_watcher_starts_with_a_baseline_and_stops_cleanly() {
        let mut session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
            .expect("current process session");
        let source =
            WindowsTrustedDesktopStateSource::start(session_id).expect("native watcher start");
        let baseline = source.current_state().expect("native baseline");
        assert_ne!(baseline.desktop_epoch, 0);
        drop(source);
    }

    #[test]
    fn native_watcher_rejects_zero_session_and_joins_startup_worker() {
        assert!(matches!(
            WindowsTrustedDesktopStateSource::start(0),
            Err(DesktopWatchError::WorkerUnavailable),
        ));
    }

    #[test]
    fn native_watcher_rejects_a_session_other_than_its_process_session() {
        let mut session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
            .expect("current process session");
        let different = session_id.wrapping_add(1).max(1);

        assert_ne!(different, session_id);
        assert!(matches!(
            WindowsTrustedDesktopStateSource::start(different),
            Err(DesktopWatchError::WorkerUnavailable),
        ));
    }

    #[test]
    #[ignore = "requires an interactive Windows session"]
    fn native_wndproc_forwards_wts_and_rejects_stale_shutdown_generation() {
        let mut session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
            .expect("current process session");
        let source =
            WindowsTrustedDesktopStateSource::start(session_id).expect("native watcher start");
        let baseline = source.current_state().expect("native baseline");
        let token = source
            .worker
            .lock()
            .expect("worker lock")
            .as_ref()
            .expect("live worker")
            .window;

        super::native::post_test_shutdown(token, token.generation.wrapping_add(1));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(source.current_state(), Some(baseline));

        super::native::send_test_wts(token, 0x7, session_id);
        let locked = wait_for_native_state(&source, |state| {
            state.desktop_epoch > baseline.desktop_epoch
                && state.desktop_kind == DesktopKind::Winlogon
        });
        super::native::send_test_wts(token, 0x8, session_id);
        let resumed =
            wait_for_native_state(&source, |state| state.desktop_epoch > locked.desktop_epoch);
        assert_eq!(resumed.desktop_kind, baseline.desktop_kind);
        drop(source);
    }

    #[test]
    #[ignore = "requires an interactive Windows session"]
    fn native_watcher_repeated_start_stop_reclaims_thread_resources() {
        let mut session_id = 0_u32;
        unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) }
            .expect("current process session");
        for _ in 0..16 {
            let source =
                WindowsTrustedDesktopStateSource::start(session_id).expect("native watcher start");
            assert!(source.current_state().is_some());
            drop(source);
        }
    }

    fn wait_for_native_state(
        source: &WindowsTrustedDesktopStateSource,
        predicate: impl Fn(TrustedDesktopState) -> bool,
    ) -> TrustedDesktopState {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(state) = source.current_state().filter(|state| predicate(*state)) {
                return state;
            }
            assert!(Instant::now() < deadline, "native watcher did not publish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
