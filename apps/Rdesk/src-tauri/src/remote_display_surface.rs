#![allow(unexpected_cfgs)]

use serde::{Deserialize, Serialize};
use tauri::WebviewWindow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSurfaceRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSurfaceControlFrameSize {
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeRenderSurfaceSnapshot {
    pub label: String,
    pub backend: String,
    pub attached: bool,
    pub visible: bool,
    pub parent_hwnd: Option<String>,
    pub hwnd: Option<String>,
    pub rect: NativeSurfaceRect,
}

#[derive(Default)]
pub struct RemoteDisplaySurfaceManager {
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    surfaces: std::collections::HashMap<String, NativeRenderSurface>,
}

impl RemoteDisplaySurfaceManager {
    #[cfg(windows)]
    pub fn configure(
        &mut self,
        window: &WebviewWindow,
        rect: NativeSurfaceRect,
        enabled: bool,
        visible: bool,
        control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<NativeRenderSurfaceSnapshot, String> {
        let label = window.label().to_string();

        if !enabled {
            self.surfaces.remove(&label);
            return Ok(NativeRenderSurfaceSnapshot {
                label,
                backend: "web".to_string(),
                attached: false,
                visible: false,
                parent_hwnd: None,
                hwnd: None,
                rect,
            });
        }

        let parent_hwnd = window
            .hwnd()
            .map_err(|error| format!("get remote display HWND failed: {error}"))?;
        let parent_hwnd = parent_hwnd.0 as isize;
        let rect = normalize_rect(rect);

        if let Some(surface) = self.surfaces.get_mut(&label) {
            surface.move_to(rect, visible, control_frame_size)?;
            return Ok(surface.snapshot(label, rect));
        }

        let surface = NativeRenderSurface::create(parent_hwnd, rect, visible, control_frame_size)?;
        let snapshot = surface.snapshot(label.clone(), rect);
        self.surfaces.insert(label, surface);
        Ok(snapshot)
    }

    #[cfg(target_os = "macos")]
    pub fn configure(
        &mut self,
        window: &WebviewWindow,
        rect: NativeSurfaceRect,
        enabled: bool,
        visible: bool,
        _control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<NativeRenderSurfaceSnapshot, String> {
        let label = window.label().to_string();
        let rect = normalize_rect(rect);
        let mode = macos_native_surface_mode();
        if mode.uses_overlay_window() && macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} configure label={label} enabled={enabled} visible={visible} rect={rect:?} existing={}",
                self.surfaces.contains_key(&label)
            );
        }

        if !enabled {
            if let Some(surface) = self.surfaces.remove(&label) {
                surface.remove(window)?;
            }
            return Ok(NativeRenderSurfaceSnapshot {
                label,
                backend: "web".to_string(),
                attached: false,
                visible: false,
                parent_hwnd: None,
                hwnd: None,
                rect,
            });
        }

        let parent_ns_window = window
            .ns_window()
            .map_err(|error| format!("get remote display NSWindow failed: {error}"))?
            as isize;
        let webview_ns_view = window
            .ns_view()
            .map_err(|error| format!("get remote display WebView NSView failed: {error}"))?
            as isize;
        if mode.uses_overlay_window() && macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} handles label={label} parent={} webview={}",
                handle_hex(parent_ns_window),
                handle_hex(webview_ns_view)
            );
        }

        if let Some(surface) = self.surfaces.get_mut(&label) {
            surface.move_to(window, rect, visible)?;
            return Ok(surface.snapshot(label, rect));
        }

        let surface =
            NativeRenderSurface::create(window, parent_ns_window, webview_ns_view, rect, visible)?;
        let snapshot = surface.snapshot(label.clone(), rect);
        self.surfaces.insert(label, surface);
        Ok(snapshot)
    }

    #[cfg(target_os = "linux")]
    pub fn configure(
        &mut self,
        window: &WebviewWindow,
        rect: NativeSurfaceRect,
        enabled: bool,
        visible: bool,
        _control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<NativeRenderSurfaceSnapshot, String> {
        let label = window.label().to_string();
        let rect = normalize_rect(rect);

        if !enabled {
            self.surfaces.remove(&label);
            return Ok(NativeRenderSurfaceSnapshot {
                label,
                backend: "web".to_string(),
                attached: false,
                visible: false,
                parent_hwnd: None,
                hwnd: None,
                rect,
            });
        }

        let parent_hwnd = linux_parent_x11_window(window)?;
        if let Some(surface) = self.surfaces.get_mut(&label) {
            surface.move_to(rect, visible)?;
            return Ok(surface.snapshot(label, rect));
        }

        let surface = NativeRenderSurface::create(parent_hwnd, rect, visible)?;
        let snapshot = surface.snapshot(label.clone(), rect);
        self.surfaces.insert(label, surface);
        Ok(snapshot)
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    pub fn render_target_handle(&self, label: &str) -> Option<isize> {
        self.surfaces
            .get(label)
            .map(NativeRenderSurface::render_target_handle)
    }

    #[cfg(windows)]
    pub fn set_control_binding(
        &mut self,
        label: &str,
        session_id: Option<String>,
        pointer_enabled: bool,
        keyboard_enabled: bool,
    ) -> Result<Option<NativeSurfaceControlBindingSnapshot>, String> {
        let surface = self
            .surfaces
            .get_mut(label)
            .ok_or_else(|| format!("native render surface not found: {label}"))?;
        surface.set_control_binding(session_id, pointer_enabled, keyboard_enabled);
        Ok(surface.control_binding_snapshot())
    }

    #[cfg(windows)]
    pub fn control_binding(&self, label: &str) -> Option<NativeSurfaceControlBindingSnapshot> {
        self.surfaces
            .get(label)
            .and_then(NativeRenderSurface::control_binding_snapshot)
    }

    #[cfg(windows)]
    pub fn detach(&mut self, label: &str, _window: Option<&WebviewWindow>) -> Result<bool, String> {
        Ok(self.surfaces.remove(label).is_some())
    }

    #[cfg(target_os = "macos")]
    pub fn detach(&mut self, label: &str, window: Option<&WebviewWindow>) -> Result<bool, String> {
        let Some(surface) = self.surfaces.remove(label) else {
            return Ok(false);
        };

        if let Some(window) = window {
            surface.remove(window)?;
        }

        Ok(true)
    }

    #[cfg(target_os = "linux")]
    pub fn detach(&mut self, label: &str, _window: Option<&WebviewWindow>) -> Result<bool, String> {
        Ok(self.surfaces.remove(label).is_some())
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    pub fn render_target_handle(&self, _label: &str) -> Option<isize> {
        None
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    pub fn detach(
        &mut self,
        _label: &str,
        _window: Option<&WebviewWindow>,
    ) -> Result<bool, String> {
        Ok(false)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    pub fn configure(
        &mut self,
        window: &WebviewWindow,
        rect: NativeSurfaceRect,
        enabled: bool,
        _visible: bool,
        _control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<NativeRenderSurfaceSnapshot, String> {
        if enabled {
            return Err(
                "embedded native render surface is only available on Windows, macOS, and Linux/X11"
                    .to_string(),
            );
        }

        Ok(NativeRenderSurfaceSnapshot {
            label: window.label().to_string(),
            backend: "web".to_string(),
            attached: false,
            visible: false,
            parent_hwnd: None,
            hwnd: None,
            rect: normalize_rect(rect),
        })
    }
}

fn normalize_rect(rect: NativeSurfaceRect) -> NativeSurfaceRect {
    NativeSurfaceRect {
        x: rect.x.max(0),
        y: rect.y.max(0),
        width: rect.width.max(1),
        height: rect.height.max(1),
    }
}

fn handle_hex(handle: isize) -> String {
    format!("0x{:X}", handle as usize)
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct NativeSurfaceControlInput {
    pub session_id: String,
    pub event: mrd_ipc::ControlInputEvent,
    surface_id: usize,
    authorization: std::sync::Arc<NativeSurfaceControlAuthorization>,
    generation: u64,
    deadline: std::time::Instant,
}

#[cfg(windows)]
const NATIVE_SURFACE_RELIABLE_INPUT_CAPACITY: usize = 256;
#[cfg(windows)]
const NATIVE_SURFACE_REALTIME_INPUT_TTL: std::time::Duration =
    std::time::Duration::from_millis(250);
#[cfg(windows)]
const NATIVE_SURFACE_RELIABLE_INPUT_TTL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(windows)]
static NATIVE_SURFACE_CONTROL_EPOCH: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(windows)]
#[derive(Debug)]
pub struct NativeSurfaceControlAuthorization {
    session_id: String,
    pointer_enabled: bool,
    keyboard_enabled: bool,
    epoch: u64,
    active: std::sync::atomic::AtomicBool,
    generation: std::sync::atomic::AtomicU64,
}

#[cfg(windows)]
impl NativeSurfaceControlAuthorization {
    pub(crate) fn new(
        session_id: String,
        pointer_enabled: bool,
        keyboard_enabled: bool,
    ) -> std::sync::Arc<Self> {
        let epoch = NATIVE_SURFACE_CONTROL_EPOCH
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1)
            .max(1);
        std::sync::Arc::new(Self {
            session_id,
            pointer_enabled,
            keyboard_enabled,
            epoch,
            active: std::sync::atomic::AtomicBool::new(true),
            generation: std::sync::atomic::AtomicU64::new(1),
        })
    }

    fn allows(&self, event: &mrd_ipc::ControlInputEvent) -> bool {
        if !self.active.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        match event {
            mrd_ipc::ControlInputEvent::MouseMove { .. }
            | mrd_ipc::ControlInputEvent::MouseButton { .. }
            | mrd_ipc::ControlInputEvent::MouseWheel { .. }
            | mrd_ipc::ControlInputEvent::MouseHorizontalWheel { .. } => self.pointer_enabled,
            mrd_ipc::ControlInputEvent::Key { .. } => self.keyboard_enabled,
            mrd_ipc::ControlInputEvent::ReleaseAll => self.pointer_enabled || self.keyboard_enabled,
        }
    }

    fn current_generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    fn advance_generation(&self) -> u64 {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1)
            .max(1)
    }

    pub(crate) fn deactivate(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
        self.advance_generation();
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSurfaceControlBindingSnapshot {
    pub session_id: String,
    pub pointer_enabled: bool,
    pub keyboard_enabled: bool,
    pub epoch: u64,
}

#[cfg(windows)]
impl NativeSurfaceControlInput {
    fn new(
        surface_id: usize,
        authorization: std::sync::Arc<NativeSurfaceControlAuthorization>,
        generation: u64,
        event: mrd_ipc::ControlInputEvent,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            session_id: authorization.session_id.clone(),
            event,
            surface_id,
            authorization,
            generation,
            deadline: std::time::Instant::now() + ttl,
        }
    }

    fn is_cleanup(&self) -> bool {
        matches!(self.event, mrd_ipc::ControlInputEvent::ReleaseAll)
    }

    fn is_dispatchable(&self, now: std::time::Instant) -> bool {
        if self.is_cleanup() {
            return true;
        }
        if now > self.deadline {
            return false;
        }
        self.authorization
            .active
            .load(std::sync::atomic::Ordering::Acquire)
            && self.generation == self.authorization.current_generation()
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NativeSurfaceRealtimeKind {
    Move,
    Wheel,
    HorizontalWheel,
}

#[cfg(windows)]
fn native_surface_realtime_kind(
    event: &mrd_ipc::ControlInputEvent,
) -> Option<NativeSurfaceRealtimeKind> {
    match event {
        mrd_ipc::ControlInputEvent::MouseMove { .. } => Some(NativeSurfaceRealtimeKind::Move),
        mrd_ipc::ControlInputEvent::MouseWheel { .. } => Some(NativeSurfaceRealtimeKind::Wheel),
        mrd_ipc::ControlInputEvent::MouseHorizontalWheel { .. } => {
            Some(NativeSurfaceRealtimeKind::HorizontalWheel)
        }
        _ => None,
    }
}

#[cfg(windows)]
type NativeSurfaceRealtimeInputs =
    std::collections::HashMap<(usize, NativeSurfaceRealtimeKind), NativeSurfaceControlInput>;

#[cfg(windows)]
#[derive(Clone)]
pub struct NativeSurfaceControlInputForwarder {
    reliable: std::sync::mpsc::SyncSender<NativeSurfaceControlInput>,
    cleanup: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<usize, NativeSurfaceControlInput>>,
    >,
    realtime: std::sync::Arc<std::sync::Mutex<NativeSurfaceRealtimeInputs>>,
    wake: std::sync::mpsc::SyncSender<()>,
}

#[cfg(windows)]
pub struct NativeSurfaceControlInputReceiver {
    reliable: std::sync::mpsc::Receiver<NativeSurfaceControlInput>,
    cleanup: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<usize, NativeSurfaceControlInput>>,
    >,
    realtime: std::sync::Arc<std::sync::Mutex<NativeSurfaceRealtimeInputs>>,
    wake: std::sync::mpsc::Receiver<()>,
}

#[cfg(windows)]
fn native_surface_control_input_channel_with_capacity(
    reliable_capacity: usize,
) -> (
    NativeSurfaceControlInputForwarder,
    NativeSurfaceControlInputReceiver,
) {
    let (reliable_sender, reliable_receiver) =
        std::sync::mpsc::sync_channel(reliable_capacity.max(1));
    let (wake_sender, wake_receiver) = std::sync::mpsc::sync_channel(1);
    let cleanup = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let realtime = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    (
        NativeSurfaceControlInputForwarder {
            reliable: reliable_sender,
            cleanup: cleanup.clone(),
            realtime: realtime.clone(),
            wake: wake_sender,
        },
        NativeSurfaceControlInputReceiver {
            reliable: reliable_receiver,
            cleanup,
            realtime,
            wake: wake_receiver,
        },
    )
}

#[cfg(windows)]
pub fn native_surface_control_input_channel() -> (
    NativeSurfaceControlInputForwarder,
    NativeSurfaceControlInputReceiver,
) {
    native_surface_control_input_channel_with_capacity(NATIVE_SURFACE_RELIABLE_INPUT_CAPACITY)
}

#[cfg(windows)]
impl NativeSurfaceControlInputForwarder {
    fn wake(&self) {
        let _ = self.wake.try_send(());
    }

    fn enqueue_cleanup(
        &self,
        surface_id: usize,
        authorization: std::sync::Arc<NativeSurfaceControlAuthorization>,
    ) {
        let generation = authorization.advance_generation();
        let cleanup = NativeSurfaceControlInput::new(
            surface_id,
            authorization.clone(),
            generation,
            mrd_ipc::ControlInputEvent::ReleaseAll,
            NATIVE_SURFACE_RELIABLE_INPUT_TTL,
        );
        self.cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(surface_id, cleanup);
        self.realtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(queued_surface_id, _), _| *queued_surface_id != surface_id);
        self.wake();
    }

    pub(crate) fn submit(
        &self,
        surface_id: usize,
        authorization: std::sync::Arc<NativeSurfaceControlAuthorization>,
        event: mrd_ipc::ControlInputEvent,
    ) {
        if !authorization.allows(&event) {
            return;
        }
        if matches!(event, mrd_ipc::ControlInputEvent::ReleaseAll) {
            self.enqueue_cleanup(surface_id, authorization);
            return;
        }

        let generation = authorization.current_generation();
        if let Some(kind) = native_surface_realtime_kind(&event) {
            let input = NativeSurfaceControlInput::new(
                surface_id,
                authorization.clone(),
                generation,
                event,
                NATIVE_SURFACE_REALTIME_INPUT_TTL,
            );
            if let Ok(mut realtime) = self.realtime.try_lock() {
                realtime.insert((surface_id, kind), input);
                drop(realtime);
                self.wake();
            }
            return;
        }

        let input = NativeSurfaceControlInput::new(
            surface_id,
            authorization.clone(),
            generation,
            event,
            NATIVE_SURFACE_RELIABLE_INPUT_TTL,
        );
        match self.reliable.try_send(input) {
            Ok(()) => self.wake(),
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.enqueue_cleanup(surface_id, authorization);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
        }
    }

    #[cfg(test)]
    fn relay_existing(&self, input: NativeSurfaceControlInput) {
        if !input.is_dispatchable(std::time::Instant::now()) {
            return;
        }
        if input.is_cleanup() {
            self.cleanup
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(input.surface_id, input);
            self.wake();
            return;
        }
        if let Some(kind) = native_surface_realtime_kind(&input.event) {
            let key = (input.surface_id, kind);
            self.realtime
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(key, input);
            self.wake();
            return;
        }
        let surface_id = input.surface_id;
        let authorization = input.authorization.clone();
        match self.reliable.try_send(input) {
            Ok(()) => self.wake(),
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.enqueue_cleanup(surface_id, authorization);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
        }
    }
}

#[cfg(windows)]
impl NativeSurfaceControlInputReceiver {
    fn pop_cleanup(&self) -> Option<NativeSurfaceControlInput> {
        let mut cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let surface_id = cleanup.keys().next().copied()?;
        cleanup.remove(&surface_id)
    }

    fn pop_realtime(&self) -> Option<NativeSurfaceControlInput> {
        let mut realtime = self
            .realtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = realtime.keys().next().copied()?;
        realtime.remove(&key)
    }

    fn pop_dispatchable(&self) -> Option<NativeSurfaceControlInput> {
        let now = std::time::Instant::now();
        loop {
            if let Some(input) = self.pop_cleanup() {
                if input.is_dispatchable(now) {
                    return Some(input);
                }
                continue;
            }
            match self.reliable.try_recv() {
                Ok(input) if input.is_dispatchable(now) => return Some(input),
                Ok(input) => {
                    if now > input.deadline {
                        let generation = input.authorization.advance_generation();
                        let cleanup = NativeSurfaceControlInput::new(
                            input.surface_id,
                            input.authorization,
                            generation,
                            mrd_ipc::ControlInputEvent::ReleaseAll,
                            NATIVE_SURFACE_RELIABLE_INPUT_TTL,
                        );
                        self.cleanup
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(cleanup.surface_id, cleanup);
                    }
                    continue;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
            }
            while let Some(input) = self.pop_realtime() {
                if input.is_dispatchable(now) {
                    return Some(input);
                }
            }
            return None;
        }
    }

    #[cfg(test)]
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<NativeSurfaceControlInput> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(input) = self.pop_dispatchable() {
                return Some(input);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            match self
                .wake
                .recv_timeout(deadline.saturating_duration_since(now))
            {
                Ok(()) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return None,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    pub fn recv(&self) -> Option<NativeSurfaceControlInput> {
        loop {
            if let Some(input) = self.pop_dispatchable() {
                return Some(input);
            }
            if self.wake.recv().is_err() {
                return None;
            }
        }
    }
}

#[cfg(windows)]
static NATIVE_SURFACE_INPUT_FORWARDER: std::sync::OnceLock<NativeSurfaceControlInputForwarder> =
    std::sync::OnceLock::new();

#[cfg(windows)]
pub fn install_control_input_forwarder(forwarder: NativeSurfaceControlInputForwarder) -> bool {
    NATIVE_SURFACE_INPUT_FORWARDER.set(forwarder).is_ok()
}

#[cfg(windows)]
struct WindowsSurfaceInputContext {
    authorization: Option<std::sync::Arc<NativeSurfaceControlAuthorization>>,
    geometry: Option<WindowsSurfaceInputGeometry>,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsSurfaceInputGeometry {
    surface_width: i32,
    surface_height: i32,
    control_frame_width: i32,
    control_frame_height: i32,
}

#[cfg(windows)]
impl WindowsSurfaceInputGeometry {
    fn from_rect_and_control_frame(
        rect: NativeSurfaceRect,
        control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Option<Self> {
        let control_frame_size = control_frame_size?;
        if rect.width <= 0
            || rect.height <= 0
            || control_frame_size.width <= 0
            || control_frame_size.height <= 0
        {
            return None;
        }
        Some(Self {
            surface_width: rect.width,
            surface_height: rect.height,
            control_frame_width: control_frame_size.width,
            control_frame_height: control_frame_size.height,
        })
    }
}

#[cfg(windows)]
fn windows_mouse_coordinates_from_lparam(lparam: isize) -> (i32, i32) {
    let raw = lparam as u32;
    let x = i16::from_ne_bytes((raw as u16).to_ne_bytes()) as i32;
    let y = i16::from_ne_bytes(((raw >> 16) as u16).to_ne_bytes()) as i32;
    (x, y)
}

#[cfg(windows)]
fn windows_signed_high_word(value: usize) -> i32 {
    i16::from_ne_bytes(((value >> 16) as u16).to_ne_bytes()) as i32
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSurfaceInputSideEffect {
    Focus,
    CaptureMouse,
    ReleaseMouseCapture,
}

#[cfg(windows)]
fn windows_surface_input_side_effects_from_message(
    message: u32,
) -> Vec<WindowsSurfaceInputSideEffect> {
    use windows::Win32::UI::WindowsAndMessaging::{
        WM_CANCELMODE, WM_CAPTURECHANGED, WM_KILLFOCUS, WM_LBUTTONDOWN, WM_LBUTTONUP,
        WM_MBUTTONDOWN, WM_MBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_XBUTTONDOWN, WM_XBUTTONUP,
    };

    match message {
        WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN => vec![
            WindowsSurfaceInputSideEffect::Focus,
            WindowsSurfaceInputSideEffect::CaptureMouse,
        ],
        WM_LBUTTONUP | WM_RBUTTONUP | WM_MBUTTONUP | WM_XBUTTONUP | WM_KILLFOCUS
        | WM_CANCELMODE | WM_CAPTURECHANGED => {
            vec![WindowsSurfaceInputSideEffect::ReleaseMouseCapture]
        }
        _ => Vec::new(),
    }
}

#[cfg(windows)]
fn apply_windows_surface_input_side_effect(
    hwnd: windows::Win32::Foundation::HWND,
    side_effect: WindowsSurfaceInputSideEffect,
) {
    match side_effect {
        WindowsSurfaceInputSideEffect::Focus => unsafe {
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::SetFocus(hwnd);
        },
        WindowsSurfaceInputSideEffect::CaptureMouse => unsafe {
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::SetCapture(hwnd);
        },
        WindowsSurfaceInputSideEffect::ReleaseMouseCapture => unsafe {
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture();
        },
    }
}

#[cfg(all(windows, test))]
fn windows_surface_input_events_from_message(
    message: u32,
    wparam: usize,
    lparam: isize,
) -> Vec<mrd_ipc::ControlInputEvent> {
    windows_surface_input_events_from_message_with_geometry(message, wparam, lparam, None)
}

#[cfg(windows)]
fn windows_surface_input_events_from_message_with_geometry(
    message: u32,
    wparam: usize,
    lparam: isize,
    geometry: Option<WindowsSurfaceInputGeometry>,
) -> Vec<mrd_ipc::ControlInputEvent> {
    use windows::Win32::UI::WindowsAndMessaging::{
        WM_ACTIVATEAPP, WM_CANCELMODE, WM_CAPTURECHANGED, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS,
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE,
        WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDOWN,
        WM_XBUTTONUP,
    };

    match message {
        WM_MOUSEMOVE => {
            let (x, y) = windows_mouse_coordinates_from_lparam(lparam);
            let (x, y) = scale_windows_surface_input_point(x, y, geometry);
            vec![mrd_ipc::ControlInputEvent::MouseMove { x, y }]
        }
        WM_MOUSEWHEEL => vec![mrd_ipc::ControlInputEvent::MouseWheel {
            delta: windows_signed_high_word(wparam),
        }],
        WM_MOUSEHWHEEL => vec![mrd_ipc::ControlInputEvent::MouseHorizontalWheel {
            delta: windows_signed_high_word(wparam),
        }],
        WM_LBUTTONDOWN => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Left, true, geometry)
        }
        WM_LBUTTONUP => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Left, false, geometry)
        }
        WM_RBUTTONDOWN => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Right, true, geometry)
        }
        WM_RBUTTONUP => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Right, false, geometry)
        }
        WM_MBUTTONDOWN => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Middle, true, geometry)
        }
        WM_MBUTTONUP => {
            mouse_button_events(lparam, mrd_ipc::ControlInputButton::Middle, false, geometry)
        }
        WM_XBUTTONDOWN | WM_XBUTTONUP => {
            let button = match (wparam >> 16) & 0xffff {
                1 => mrd_ipc::ControlInputButton::X1,
                2 => mrd_ipc::ControlInputButton::X2,
                _ => return Vec::new(),
            };
            mouse_button_events(lparam, button, message == WM_XBUTTONDOWN, geometry)
        }
        WM_KEYDOWN | WM_SYSKEYDOWN => key_event(wparam, true).into_iter().collect(),
        WM_KEYUP | WM_SYSKEYUP => key_event(wparam, false).into_iter().collect(),
        WM_KILLFOCUS | WM_CANCELMODE | WM_CAPTURECHANGED => {
            vec![mrd_ipc::ControlInputEvent::ReleaseAll]
        }
        WM_ACTIVATEAPP if wparam == 0 => vec![mrd_ipc::ControlInputEvent::ReleaseAll],
        _ => Vec::new(),
    }
}

#[cfg(windows)]
fn mouse_button_events(
    lparam: isize,
    button: mrd_ipc::ControlInputButton,
    pressed: bool,
    geometry: Option<WindowsSurfaceInputGeometry>,
) -> Vec<mrd_ipc::ControlInputEvent> {
    let (x, y) = windows_mouse_coordinates_from_lparam(lparam);
    let (x, y) = scale_windows_surface_input_point(x, y, geometry);
    vec![
        mrd_ipc::ControlInputEvent::MouseMove { x, y },
        mouse_button_event(button, pressed),
    ]
}

#[cfg(windows)]
fn scale_windows_surface_input_point(
    x: i32,
    y: i32,
    geometry: Option<WindowsSurfaceInputGeometry>,
) -> (i32, i32) {
    let Some(geometry) = geometry else {
        return (x, y);
    };
    let scaled_x =
        scale_windows_surface_input_axis(x, geometry.surface_width, geometry.control_frame_width);
    let scaled_y =
        scale_windows_surface_input_axis(y, geometry.surface_height, geometry.control_frame_height);
    (scaled_x, scaled_y)
}

#[cfg(windows)]
fn scale_windows_surface_input_axis(value: i32, surface_extent: i32, frame_extent: i32) -> i32 {
    if surface_extent <= 0 || frame_extent <= 0 {
        return value;
    }
    let scaled = (i64::from(value) * i64::from(frame_extent)) / i64::from(surface_extent);
    scaled.clamp(0, i64::from(frame_extent - 1)) as i32
}

#[cfg(windows)]
fn mouse_button_event(
    button: mrd_ipc::ControlInputButton,
    pressed: bool,
) -> mrd_ipc::ControlInputEvent {
    mrd_ipc::ControlInputEvent::MouseButton { button, pressed }
}

#[cfg(windows)]
fn key_event(wparam: usize, pressed: bool) -> Option<mrd_ipc::ControlInputEvent> {
    let code = u16::try_from(wparam).ok()?;
    Some(mrd_ipc::ControlInputEvent::Key {
        key: mrd_ipc::ControlInputKey::VirtualKey { code },
        pressed,
    })
}

#[cfg(windows)]
unsafe fn windows_surface_input_context_mut(
    hwnd: windows::Win32::Foundation::HWND,
) -> Option<&'static mut WindowsSurfaceInputContext> {
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowLongPtrW, GWLP_USERDATA};
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowsSurfaceInputContext;
    ptr.as_mut()
}

#[cfg(windows)]
fn forward_windows_surface_input(
    hwnd: windows::Win32::Foundation::HWND,
    event: mrd_ipc::ControlInputEvent,
) {
    let Some(authorization) = (unsafe {
        windows_surface_input_context_mut(hwnd)
            .and_then(|context| context.authorization.as_ref().cloned())
    }) else {
        return;
    };
    let Some(forwarder) = NATIVE_SURFACE_INPUT_FORWARDER.get() else {
        return;
    };
    forwarder.submit(hwnd.0 as usize, authorization, event);
}

#[cfg(windows)]
fn windows_surface_input_geometry(
    hwnd: windows::Win32::Foundation::HWND,
) -> Option<WindowsSurfaceInputGeometry> {
    unsafe { windows_surface_input_context_mut(hwnd).and_then(|context| context.geometry) }
}

#[cfg(windows)]
fn release_windows_surface_input(hwnd: windows::Win32::Foundation::HWND) {
    forward_windows_surface_input(hwnd, mrd_ipc::ControlInputEvent::ReleaseAll);
}

#[cfg(windows)]
struct NativeRenderSurface {
    parent_hwnd: isize,
    hwnd: windows::Win32::Foundation::HWND,
    visible: bool,
}

#[cfg(windows)]
impl NativeRenderSurface {
    fn create(
        parent_hwnd: isize,
        rect: NativeSurfaceRect,
        visible: bool,
        control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<Self, String> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, LoadCursorW, RegisterClassW, SetWindowLongPtrW,
            SetWindowPos, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA, HMENU, IDC_ARROW, SWP_HIDEWINDOW,
            SWP_NOACTIVATE, SWP_SHOWWINDOW, WINDOW_EX_STYLE, WNDCLASSW, WS_CHILD, WS_CLIPCHILDREN,
            WS_CLIPSIBLINGS, WS_VISIBLE,
        };

        unsafe extern "system" fn wnd_proc(
            hwnd: HWND,
            message: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            for side_effect in windows_surface_input_side_effects_from_message(message) {
                apply_windows_surface_input_side_effect(hwnd, side_effect);
            }
            let events = windows_surface_input_events_from_message_with_geometry(
                message,
                wparam.0,
                lparam.0,
                windows_surface_input_geometry(hwnd),
            );
            if !events.is_empty() {
                for event in events {
                    forward_windows_surface_input(hwnd, event);
                }
                return LRESULT(0);
            }
            DefWindowProcW(hwnd, message, wparam, lparam)
        }

        fn wide(value: &str) -> Vec<u16> {
            OsStr::new(value)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let class_name = wide("RdeskRemoteDisplayNativeSurface");
        let title = wide("Rdesk Native Render Surface");
        let hmodule = unsafe { GetModuleHandleW(None) }
            .map_err(|error| format!("get module handle failed: {error}"))?;
        let hinstance = HINSTANCE(hmodule.0);
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }
            .map_err(|error| format!("load cursor failed: {error}"))?;

        let window_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            hCursor: cursor,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        unsafe {
            RegisterClassW(&window_class);
        }

        let style = if visible {
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN
        } else {
            WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN
        };

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                style,
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                HWND(parent_hwnd),
                HMENU(0),
                hinstance,
                None,
            )
        };
        if hwnd.0 == 0 {
            return Err("create native render surface failed".to_string());
        }

        let context = Box::new(WindowsSurfaceInputContext {
            authorization: None,
            geometry: WindowsSurfaceInputGeometry::from_rect_and_control_frame(
                rect,
                control_frame_size,
            ),
        });
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(context) as isize);
        }

        unsafe {
            SetWindowPos(
                hwnd,
                HWND(0),
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                SWP_NOACTIVATE
                    | if visible {
                        SWP_SHOWWINDOW
                    } else {
                        SWP_HIDEWINDOW
                    },
            )
            .map_err(|error| format!("position native render surface failed: {error}"))?;
        }

        Ok(Self {
            parent_hwnd,
            hwnd,
            visible,
        })
    }

    fn move_to(
        &mut self,
        rect: NativeSurfaceRect,
        visible: bool,
        control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) -> Result<(), String> {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            SetWindowPos, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_SHOWWINDOW,
        };

        unsafe {
            SetWindowPos(
                self.hwnd,
                HWND(0),
                rect.x,
                rect.y,
                rect.width,
                rect.height,
                SWP_NOACTIVATE
                    | if visible {
                        SWP_SHOWWINDOW
                    } else {
                        SWP_HIDEWINDOW
                    },
            )
            .map_err(|error| format!("position native render surface failed: {error}"))?;
        }
        self.visible = visible;
        self.set_control_input_geometry(rect, control_frame_size);
        Ok(())
    }

    fn snapshot(&self, label: String, rect: NativeSurfaceRect) -> NativeRenderSurfaceSnapshot {
        NativeRenderSurfaceSnapshot {
            label,
            backend: "d3d11".to_string(),
            attached: true,
            visible: self.visible,
            parent_hwnd: Some(handle_hex(self.parent_hwnd)),
            hwnd: Some(handle_hex(self.hwnd.0)),
            rect,
        }
    }

    fn render_target_handle(&self) -> isize {
        self.hwnd.0
    }

    fn set_control_binding(
        &mut self,
        session_id: Option<String>,
        pointer_enabled: bool,
        keyboard_enabled: bool,
    ) {
        unsafe {
            if let Some(context) = windows_surface_input_context_mut(self.hwnd) {
                let desired_session_id = session_id.filter(|_| pointer_enabled || keyboard_enabled);
                let unchanged = context.authorization.as_ref().is_some_and(|authorization| {
                    desired_session_id.as_deref() == Some(authorization.session_id.as_str())
                        && pointer_enabled == authorization.pointer_enabled
                        && keyboard_enabled == authorization.keyboard_enabled
                        && authorization
                            .active
                            .load(std::sync::atomic::Ordering::Acquire)
                });
                if unchanged {
                    return;
                }
                if let Some(previous) = context.authorization.take() {
                    if let Some(forwarder) = NATIVE_SURFACE_INPUT_FORWARDER.get() {
                        forwarder.submit(
                            self.hwnd.0 as usize,
                            previous.clone(),
                            mrd_ipc::ControlInputEvent::ReleaseAll,
                        );
                    }
                    previous.deactivate();
                }
                context.authorization = desired_session_id.map(|session_id| {
                    NativeSurfaceControlAuthorization::new(
                        session_id,
                        pointer_enabled,
                        keyboard_enabled,
                    )
                });
            }
        }
    }

    fn control_binding_snapshot(&self) -> Option<NativeSurfaceControlBindingSnapshot> {
        unsafe {
            windows_surface_input_context_mut(self.hwnd).and_then(|context| {
                context.authorization.as_ref().map(|authorization| {
                    NativeSurfaceControlBindingSnapshot {
                        session_id: authorization.session_id.clone(),
                        pointer_enabled: authorization.pointer_enabled,
                        keyboard_enabled: authorization.keyboard_enabled,
                        epoch: authorization.epoch,
                    }
                })
            })
        }
    }

    fn set_control_input_geometry(
        &mut self,
        rect: NativeSurfaceRect,
        control_frame_size: Option<NativeSurfaceControlFrameSize>,
    ) {
        unsafe {
            if let Some(context) = windows_surface_input_context_mut(self.hwnd) {
                context.geometry = WindowsSurfaceInputGeometry::from_rect_and_control_frame(
                    rect,
                    control_frame_size,
                );
            }
        }
    }
}

#[cfg(windows)]
impl Drop for NativeRenderSurface {
    fn drop(&mut self) {
        unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{SetWindowLongPtrW, GWLP_USERDATA};
            release_windows_surface_input(self.hwnd);
            let ptr =
                SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0) as *mut WindowsSurfaceInputContext;
            if !ptr.is_null() {
                let mut context = Box::from_raw(ptr);
                if let Some(authorization) = context.authorization.take() {
                    authorization.deactivate();
                }
                drop(context);
            }
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(self.hwnd);
        }
    }
}

#[cfg(target_os = "linux")]
struct NativeRenderSurface {
    parent_hwnd: isize,
    display: *mut x11::xlib::Display,
    window: x11::xlib::Window,
    visible: bool,
}

#[cfg(target_os = "linux")]
unsafe impl Send for NativeRenderSurface {}

#[cfg(target_os = "linux")]
impl NativeRenderSurface {
    fn create(parent_hwnd: isize, rect: NativeSurfaceRect, visible: bool) -> Result<Self, String> {
        use std::ptr;
        use x11::xlib;

        if parent_hwnd == 0 {
            return Err("remote display Linux parent X11 window is null".to_string());
        }

        unsafe {
            init_x11_threads();
            let display = (xlib::XOpenDisplay)(ptr::null());
            if display.is_null() {
                return Err(
                    "open X11 display failed; embedded Linux native render requires X11/XWayland"
                        .to_string(),
                );
            }

            let screen = (xlib::XDefaultScreen)(display);
            let black = (xlib::XBlackPixel)(display, screen);
            let window = (xlib::XCreateSimpleWindow)(
                display,
                parent_hwnd as xlib::Window,
                rect.x,
                rect.y,
                rect.width as u32,
                rect.height as u32,
                0,
                black,
                black,
            );
            if window == 0 {
                (xlib::XCloseDisplay)(display);
                return Err("create Linux native render child window failed".to_string());
            }

            (xlib::XSelectInput)(
                display,
                window,
                xlib::ExposureMask | xlib::StructureNotifyMask,
            );
            if visible {
                (xlib::XMapRaised)(display, window);
                (xlib::XRaiseWindow)(display, window);
            }
            (xlib::XFlush)(display);

            Ok(Self {
                parent_hwnd,
                display,
                window,
                visible,
            })
        }
    }

    fn move_to(&mut self, rect: NativeSurfaceRect, visible: bool) -> Result<(), String> {
        use x11::xlib;

        unsafe {
            if self.display.is_null() || self.window == 0 {
                return Err("Linux native render surface is detached".to_string());
            }
            (xlib::XMoveResizeWindow)(
                self.display,
                self.window,
                rect.x,
                rect.y,
                rect.width as u32,
                rect.height as u32,
            );
            if visible {
                (xlib::XMapRaised)(self.display, self.window);
                (xlib::XRaiseWindow)(self.display, self.window);
            } else {
                (xlib::XUnmapWindow)(self.display, self.window);
            }
            (xlib::XFlush)(self.display);
        }

        self.visible = visible;
        Ok(())
    }

    fn snapshot(&self, label: String, rect: NativeSurfaceRect) -> NativeRenderSurfaceSnapshot {
        NativeRenderSurfaceSnapshot {
            label,
            backend: "linux".to_string(),
            attached: true,
            visible: self.visible,
            parent_hwnd: Some(handle_hex(self.parent_hwnd)),
            hwnd: Some(handle_hex(self.window as isize)),
            rect,
        }
    }

    fn render_target_handle(&self) -> isize {
        self.window as isize
    }
}

#[cfg(target_os = "linux")]
impl Drop for NativeRenderSurface {
    fn drop(&mut self) {
        use x11::xlib;

        unsafe {
            if !self.display.is_null() {
                if self.window != 0 {
                    (xlib::XDestroyWindow)(self.display, self.window);
                    (xlib::XFlush)(self.display);
                }
                (xlib::XCloseDisplay)(self.display);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_parent_x11_window(window: &WebviewWindow) -> Result<isize, String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let handle = window
        .window_handle()
        .map_err(|error| format!("get remote display native window handle failed: {error}"))?;

    match handle.as_raw() {
        RawWindowHandle::Xlib(handle) => {
            if handle.window == 0 {
                Err("remote display Linux Xlib window handle is null".to_string())
            } else {
                Ok(handle.window as isize)
            }
        }
        RawWindowHandle::Xcb(handle) => Ok(handle.window.get() as isize),
        RawWindowHandle::Wayland(_) => Err(
            "embedded Linux native render currently requires X11/XWayland; switch the session to X11 or use Web View on Wayland"
                .to_string(),
        ),
        other => Err(format!(
            "embedded Linux native render requires an X11 window handle, got {other:?}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn init_x11_threads() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        let _ = x11::xlib::XInitThreads();
    });
}

#[cfg(all(test, windows))]
mod remote_display_surface_input_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::windows::ffi::OsStrExt;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        PeekMessageW, RegisterClassW, SendMessageW, SetForegroundWindow, ShowWindow,
        TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, HMENU, MSG, PM_REMOVE, SW_SHOW,
        WINDOW_EX_STYLE, WM_ACTIVATEAPP, WM_CAPTURECHANGED, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS,
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WNDCLASSW,
        WS_OVERLAPPED, WS_OVERLAPPEDWINDOW,
    };

    fn lparam(x: i16, y: i16) -> isize {
        ((u16::from_ne_bytes(y.to_ne_bytes()) as u32) << 16
            | u16::from_ne_bytes(x.to_ne_bytes()) as u32) as isize
    }

    #[test]
    fn native_input_realtime_flood_cannot_consume_reliable_or_cleanup_capacity() {
        let (forwarder, receiver) = native_surface_control_input_channel_with_capacity(2);
        let authorization =
            NativeSurfaceControlAuthorization::new("native-flood-session".to_string(), true, true);

        for x in 0..10_000 {
            forwarder.submit(
                17,
                authorization.clone(),
                mrd_ipc::ControlInputEvent::MouseMove { x, y: x },
            );
        }
        forwarder.submit(
            17,
            authorization.clone(),
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: false,
            },
        );

        let key_up = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("realtime flood must leave reliable capacity for key-up");
        assert_eq!(
            key_up.event,
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: false,
            }
        );

        for x in 0..10_000 {
            forwarder.submit(
                17,
                authorization.clone(),
                mrd_ipc::ControlInputEvent::MouseMove { x, y: x },
            );
        }
        forwarder.submit(17, authorization, mrd_ipc::ControlInputEvent::ReleaseAll);
        let release = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("realtime flood must never discard ReleaseAll");
        assert_eq!(release.event, mrd_ipc::ControlInputEvent::ReleaseAll);
    }

    #[test]
    fn native_input_rejects_unauthorized_scopes_and_stale_epochs() {
        let (forwarder, receiver) = native_surface_control_input_channel_with_capacity(2);
        let pointer_only =
            NativeSurfaceControlAuthorization::new("native-scope-session".to_string(), true, false);
        forwarder.submit(
            19,
            pointer_only.clone(),
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            },
        );
        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_none());

        forwarder.submit(
            19,
            pointer_only.clone(),
            mrd_ipc::ControlInputEvent::MouseButton {
                button: mrd_ipc::ControlInputButton::Left,
                pressed: true,
            },
        );
        pointer_only.deactivate();
        let replacement =
            NativeSurfaceControlAuthorization::new("native-scope-session".to_string(), true, false);
        forwarder.submit(
            19,
            replacement,
            mrd_ipc::ControlInputEvent::MouseButton {
                button: mrd_ipc::ControlInputButton::Left,
                pressed: false,
            },
        );

        let current = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("current authorization epoch must remain deliverable");
        assert_eq!(
            current.event,
            mrd_ipc::ControlInputEvent::MouseButton {
                button: mrd_ipc::ControlInputButton::Left,
                pressed: false,
            }
        );
        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_none());
    }

    #[test]
    fn native_input_reliable_overflow_fails_closed_with_priority_release() {
        let (forwarder, receiver) = native_surface_control_input_channel_with_capacity(1);
        let authorization = NativeSurfaceControlAuthorization::new(
            "native-overflow-session".to_string(),
            true,
            true,
        );
        for code in [0x41, 0x42] {
            forwarder.submit(
                23,
                authorization.clone(),
                mrd_ipc::ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code },
                    pressed: true,
                },
            );
        }

        let release = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("overflow must synthesize a priority cleanup");
        assert_eq!(release.event, mrd_ipc::ControlInputEvent::ReleaseAll);
        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_none());
    }

    #[test]
    fn native_input_expired_cleanup_is_never_dropped() {
        let (forwarder, receiver) = native_surface_control_input_channel_with_capacity(1);
        let authorization = NativeSurfaceControlAuthorization::new(
            "native-expired-cleanup-session".to_string(),
            true,
            true,
        );
        let mut cleanup = NativeSurfaceControlInput::new(
            29,
            authorization.clone(),
            authorization.current_generation(),
            mrd_ipc::ControlInputEvent::ReleaseAll,
            Duration::ZERO,
        );
        cleanup.deadline = std::time::Instant::now() - Duration::from_secs(1);
        authorization.deactivate();

        forwarder.relay_existing(cleanup);

        let release = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("expired cleanup must still leave the queue after authorization retires");
        assert_eq!(release.session_id, "native-expired-cleanup-session");
        assert_eq!(release.event, mrd_ipc::ControlInputEvent::ReleaseAll);
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    struct TestParentWindow(HWND);

    impl TestParentWindow {
        fn create() -> Self {
            unsafe extern "system" fn wnd_proc(
                hwnd: HWND,
                message: u32,
                wparam: WPARAM,
                lparam: LPARAM,
            ) -> windows::Win32::Foundation::LRESULT {
                unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
            }

            let class_name = wide("RdeskRemoteDisplayNativeSurfaceTestParent");
            let title = wide("Rdesk Native Surface Test Parent");
            let hmodule = unsafe { GetModuleHandleW(None) }.expect("get module handle");
            let hinstance = HINSTANCE(hmodule.0);
            let window_class = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            unsafe {
                RegisterClassW(&window_class);
            }

            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    PCWSTR(class_name.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    WS_OVERLAPPED,
                    0,
                    0,
                    128,
                    128,
                    HWND(0),
                    HMENU(0),
                    hinstance,
                    None,
                )
            };
            assert_ne!(hwnd.0, 0, "create parent window");
            Self(hwnd)
        }
    }

    impl Drop for TestParentWindow {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyWindow(self.0);
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct WindowsTestVirtualScreen {
        left: i32,
        top: i32,
        width: i32,
        height: i32,
    }

    struct CursorRestoreGuard {
        position: (i32, i32),
    }

    impl CursorRestoreGuard {
        fn new(position: (i32, i32)) -> Self {
            Self { position }
        }
    }

    impl Drop for CursorRestoreGuard {
        fn drop(&mut self) {
            let _ = force_cursor_position(self.position);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyboardSmokeEvent {
        KeyDown(u16),
        KeyUp(u16),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct KeyboardSmokeResult {
        key_down: bool,
        key_up: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct KeyboardSmokeFocusSnapshot {
        hwnd: isize,
        foreground: isize,
        focus: isize,
    }

    static KEYBOARD_SMOKE_EVENTS: OnceLock<Mutex<Vec<KeyboardSmokeEvent>>> = OnceLock::new();

    struct KeyboardSmokeWindow {
        hwnd: HWND,
    }

    impl KeyboardSmokeWindow {
        fn create() -> windows::core::Result<Self> {
            keyboard_smoke_events()
                .lock()
                .expect("clear keyboard smoke events")
                .clear();

            let class_name = wide(&format!(
                "RdeskNativeInputE2eKeyboardSmoke{}{}",
                std::process::id(),
                current_time_millis()
            ));
            let title = wide("Rdesk native input E2E smoke");
            unsafe {
                let hmodule = GetModuleHandleW(None)?;
                let hinstance = HINSTANCE(hmodule.0);
                let window_class = WNDCLASSW {
                    style: CS_HREDRAW | CS_VREDRAW,
                    lpfnWndProc: Some(keyboard_smoke_wnd_proc),
                    hInstance: hinstance,
                    lpszClassName: PCWSTR(class_name.as_ptr()),
                    ..Default::default()
                };
                if RegisterClassW(&window_class) == 0 {
                    return Err(windows::core::Error::from_win32());
                }

                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    PCWSTR(class_name.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    WS_OVERLAPPEDWINDOW,
                    CW_USEDEFAULT,
                    CW_USEDEFAULT,
                    320,
                    160,
                    HWND(0),
                    HMENU(0),
                    hinstance,
                    None,
                );
                if hwnd.0 == 0 {
                    return Err(windows::core::Error::from_win32());
                }
                let _ = ShowWindow(hwnd, SW_SHOW);
                let _ = windows::Win32::Graphics::Gdi::UpdateWindow(hwnd);
                pump_window_messages();
                Ok(Self { hwnd })
            }
        }

        fn focus(&mut self) {
            use windows::Win32::UI::Input::KeyboardAndMouse::{SetActiveWindow, SetFocus};

            unsafe {
                let _ = BringWindowToTop(self.hwnd);
                let _ = SetForegroundWindow(self.hwnd);
                let _ = SetActiveWindow(self.hwnd);
                let _ = SetFocus(self.hwnd);
            }
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                pump_window_messages();
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn wait_for_key_events(
            &mut self,
            virtual_key: u16,
            timeout: Duration,
        ) -> windows::core::Result<KeyboardSmokeResult> {
            let deadline = Instant::now() + timeout;
            loop {
                pump_window_messages();
                let result = keyboard_smoke_result(virtual_key);
                if result.key_down && result.key_up {
                    return Ok(result);
                }
                if Instant::now() >= deadline {
                    return Ok(result);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn focus_snapshot(&self) -> KeyboardSmokeFocusSnapshot {
            unsafe {
                KeyboardSmokeFocusSnapshot {
                    hwnd: self.hwnd.0,
                    foreground: windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow().0
                        as isize,
                    focus: windows::Win32::UI::Input::KeyboardAndMouse::GetFocus().0 as isize,
                }
            }
        }
    }

    impl Drop for KeyboardSmokeWindow {
        fn drop(&mut self) {
            unsafe {
                let _ = DestroyWindow(self.hwnd);
            }
            pump_window_messages();
        }
    }

    unsafe extern "system" fn keyboard_smoke_wnd_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> windows::Win32::Foundation::LRESULT {
        match message {
            WM_KEYDOWN => {
                keyboard_smoke_events()
                    .lock()
                    .expect("record key down")
                    .push(KeyboardSmokeEvent::KeyDown(wparam.0 as u16));
                windows::Win32::Foundation::LRESULT(0)
            }
            WM_KEYUP => {
                keyboard_smoke_events()
                    .lock()
                    .expect("record key up")
                    .push(KeyboardSmokeEvent::KeyUp(wparam.0 as u16));
                windows::Win32::Foundation::LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    fn keyboard_smoke_events() -> &'static Mutex<Vec<KeyboardSmokeEvent>> {
        KEYBOARD_SMOKE_EVENTS.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn keyboard_smoke_result(virtual_key: u16) -> KeyboardSmokeResult {
        let ime_process_key = windows::Win32::UI::Input::KeyboardAndMouse::VK_PROCESSKEY.0;
        let events = keyboard_smoke_events().lock().expect("read key events");
        KeyboardSmokeResult {
            key_down: events.iter().any(|event| {
                matches!(
                    *event,
                    KeyboardSmokeEvent::KeyDown(key)
                        if key == virtual_key || key == ime_process_key
                )
            }),
            key_up: events.iter().any(|event| {
                matches!(
                    *event,
                    KeyboardSmokeEvent::KeyUp(key)
                        if key == virtual_key || key == ime_process_key
                )
            }),
        }
    }

    fn pump_window_messages() {
        unsafe {
            let mut message = MSG::default();
            while PeekMessageW(&mut message, HWND(0), 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }

    fn current_time_millis() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    }

    fn current_virtual_screen() -> WindowsTestVirtualScreen {
        unsafe {
            WindowsTestVirtualScreen {
                left: windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows::Win32::UI::WindowsAndMessaging::SM_XVIRTUALSCREEN,
                ),
                top: windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows::Win32::UI::WindowsAndMessaging::SM_YVIRTUALSCREEN,
                ),
                width: windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows::Win32::UI::WindowsAndMessaging::SM_CXVIRTUALSCREEN,
                ),
                height: windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                    windows::Win32::UI::WindowsAndMessaging::SM_CYVIRTUALSCREEN,
                ),
            }
        }
    }

    fn current_cursor_position() -> windows::core::Result<(i32, i32)> {
        let mut point = windows::Win32::Foundation::POINT::default();
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut point)?;
        }
        Ok((point.x, point.y))
    }

    fn force_cursor_position(position: (i32, i32)) -> windows::core::Result<()> {
        unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(position.0, position.1) }
    }

    fn cursor_smoke_target(
        start: (i32, i32),
        screen: WindowsTestVirtualScreen,
        offset: i32,
    ) -> (i32, i32) {
        let min_x = screen.left;
        let min_y = screen.top;
        let max_x = screen.left + screen.width.saturating_sub(1);
        let max_y = screen.top + screen.height.saturating_sub(1);
        let add = (
            (start.0 + offset).clamp(min_x, max_x),
            (start.1 + offset).clamp(min_y, max_y),
        );
        if add != start {
            return add;
        }
        (
            (start.0 - offset).clamp(min_x, max_x),
            (start.1 - offset).clamp(min_y, max_y),
        )
    }

    fn wait_for_cursor_near(
        expected: (i32, i32),
        tolerance: i32,
        timeout: Duration,
    ) -> windows::core::Result<Option<(i32, i32)>> {
        let deadline = Instant::now() + timeout;
        loop {
            let current = current_cursor_position()?;
            if cursor_distance(current, expected) <= tolerance {
                return Ok(Some(current));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn cursor_distance(left: (i32, i32), right: (i32, i32)) -> i32 {
        left.0.abs_diff(right.0).max(left.1.abs_diff(right.1)) as i32
    }

    fn reserve_udp_port() -> u16 {
        std::net::UdpSocket::bind(("127.0.0.1", 0))
            .expect("reserve UDP port")
            .local_addr()
            .expect("reserved UDP addr")
            .port()
    }

    fn service_ipc_endpoint(name: &str) -> mrd_ipc::transport::IpcEndpoint {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        mrd_ipc::transport::IpcEndpoint::named_pipe(format!(
            r"\\.\pipe\rdesk-native-input-e2e-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    fn app_state_with_lan_port(port: u16, peer_port: u16) -> Arc<mrd_service::AppState> {
        let tray: mrd_service::app_state::TrayPortRef =
            Arc::new(std::sync::Mutex::new(mrd_service::NoOpTray::new()));
        Arc::new(mrd_service::AppState::with_tray_and_lan_discovery_config(
            tray,
            mrd_service::lan_discovery::LanDiscoveryConfig {
                enabled: true,
                discovery_port: port,
                probe_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), peer_port)],
                announce_interval: Duration::from_millis(50),
                peer_ttl: Duration::from_secs(5),
                allow_unsigned_diagnostics: false,
                broadcast_enabled: false,
            },
        ))
    }

    async fn wait_for_lan_peer(
        app_state: &Arc<mrd_service::AppState>,
        device_id: &mrd_proto::DeviceId,
    ) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if app_state
                .lan_discovery
                .peer_control_addr(device_id)
                .await
                .is_some()
            {
                return;
            }
            if Instant::now() >= deadline {
                let snapshot = app_state.lan_discovery.snapshot().await;
                panic!("LAN peer {device_id:?} not discovered; snapshot={snapshot:?}");
            }
            app_state.lan_discovery.request_probe();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_service_ipc(endpoint: mrd_ipc::transport::IpcEndpoint) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut client = mrd_ipc::client::IpcClient::with_endpoint(endpoint.clone());
            if let Ok(mrd_ipc::IpcResponse::ServiceHealth { status }) = client
                .send_request(mrd_ipc::IpcRequest::ServiceHealth)
                .await
            {
                if status.running && status.healthy {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!("service IPC endpoint did not become ready: {endpoint:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn recv_std_channel<T: Send + 'static>(
        receiver: Arc<Mutex<std::sync::mpsc::Receiver<T>>>,
        timeout: Duration,
        label: &str,
    ) -> T {
        let label = label.to_string();
        tokio::task::spawn_blocking(move || {
            receiver
                .lock()
                .expect("lock std receiver")
                .recv_timeout(timeout)
        })
        .await
        .expect("blocking receive task")
        .unwrap_or_else(|error| panic!("{label}: {error}"))
    }

    async fn send_release_all_over_service_ipc(
        endpoint: mrd_ipc::transport::IpcEndpoint,
        session_id: mrd_proto::SessionId,
    ) -> mrd_ipc::IpcResponse {
        let mut client = mrd_ipc::client::IpcClient::with_endpoint(endpoint);
        client
            .send_request(mrd_ipc::IpcRequest::SendControlInput {
                session_id,
                event: mrd_ipc::ControlInputEvent::ReleaseAll,
            })
            .await
            .expect("service IPC ReleaseAll response")
    }

    async fn send_key_over_service_ipc(
        endpoint: mrd_ipc::transport::IpcEndpoint,
        session_id: mrd_proto::SessionId,
        pressed: bool,
    ) -> mrd_ipc::IpcResponse {
        let mut client = mrd_ipc::client::IpcClient::with_endpoint(endpoint);
        client
            .send_request(mrd_ipc::IpcRequest::SendControlInput {
                session_id,
                event: mrd_ipc::ControlInputEvent::Key {
                    key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                    pressed,
                },
            })
            .await
            .expect("service IPC key response")
    }

    fn session_snapshot(
        session_id: mrd_proto::SessionId,
        source_device_id: Option<mrd_proto::DeviceId>,
        target_device_id: Option<mrd_proto::DeviceId>,
        sender_active: bool,
        receiver_active: bool,
    ) -> mrd_application::ports::SessionSnapshot {
        mrd_application::ports::SessionSnapshot {
            session_id,
            transport: "quic".to_string(),
            source_device_id,
            target_device_id,
            local_listen_addr: None,
            local_server_name: None,
            local_cert_der_b64: None,
            remote_listen_addr: None,
            remote_server_name: None,
            remote_cert_der_b64: None,
            lifecycle_state: mrd_application::ports::SessionLifecycleState::Connected,
            last_error: None,
            sender_active,
            receiver_active,
        }
    }

    #[test]
    fn remote_display_surface_input_maps_signed_mouse_coordinates() {
        assert_eq!(
            windows_mouse_coordinates_from_lparam(lparam(-2, 300)),
            (-2, 300)
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_MOUSEMOVE, 0, lparam(640, 360)),
            vec![mrd_ipc::ControlInputEvent::MouseMove { x: 640, y: 360 }]
        );
    }

    #[test]
    fn remote_display_surface_input_maps_button_and_wheel_messages() {
        assert_eq!(
            windows_surface_input_events_from_message(WM_LBUTTONDOWN, 0, lparam(0, 0)),
            vec![
                mrd_ipc::ControlInputEvent::MouseMove { x: 0, y: 0 },
                mrd_ipc::ControlInputEvent::MouseButton {
                    button: mrd_ipc::ControlInputButton::Left,
                    pressed: true,
                },
            ]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_LBUTTONUP, 0, lparam(0, 0)),
            vec![
                mrd_ipc::ControlInputEvent::MouseMove { x: 0, y: 0 },
                mrd_ipc::ControlInputEvent::MouseButton {
                    button: mrd_ipc::ControlInputButton::Left,
                    pressed: false,
                },
            ]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_MOUSEWHEEL, (120_u16 as usize) << 16, 0),
            vec![mrd_ipc::ControlInputEvent::MouseWheel { delta: 120 }]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_MOUSEHWHEEL, (120_u16 as usize) << 16, 0),
            vec![mrd_ipc::ControlInputEvent::MouseHorizontalWheel { delta: 120 }]
        );
    }

    #[test]
    fn remote_display_surface_input_moves_cursor_before_button_press() {
        assert_eq!(
            windows_surface_input_events_from_message(WM_LBUTTONDOWN, 0, lparam(640, 360)),
            vec![
                mrd_ipc::ControlInputEvent::MouseMove { x: 640, y: 360 },
                mrd_ipc::ControlInputEvent::MouseButton {
                    button: mrd_ipc::ControlInputButton::Left,
                    pressed: true,
                },
            ]
        );
    }

    #[test]
    fn remote_display_surface_input_scales_surface_coordinates_to_control_frame() {
        let geometry = WindowsSurfaceInputGeometry {
            surface_width: 1280,
            surface_height: 720,
            control_frame_width: 2560,
            control_frame_height: 1440,
        };

        assert_eq!(
            windows_surface_input_events_from_message_with_geometry(
                WM_MOUSEMOVE,
                0,
                lparam(640, 360),
                Some(geometry)
            ),
            vec![mrd_ipc::ControlInputEvent::MouseMove { x: 1280, y: 720 }]
        );
        assert_eq!(
            windows_surface_input_events_from_message_with_geometry(
                WM_LBUTTONDOWN,
                0,
                lparam(1279, 719),
                Some(geometry)
            ),
            vec![
                mrd_ipc::ControlInputEvent::MouseMove { x: 2558, y: 1438 },
                mrd_ipc::ControlInputEvent::MouseButton {
                    button: mrd_ipc::ControlInputButton::Left,
                    pressed: true,
                },
            ]
        );
    }

    #[test]
    fn remote_display_surface_input_focuses_and_captures_on_button_drag() {
        assert_eq!(
            windows_surface_input_side_effects_from_message(WM_LBUTTONDOWN),
            vec![
                WindowsSurfaceInputSideEffect::Focus,
                WindowsSurfaceInputSideEffect::CaptureMouse,
            ]
        );
        assert_eq!(
            windows_surface_input_side_effects_from_message(WM_LBUTTONUP),
            vec![WindowsSurfaceInputSideEffect::ReleaseMouseCapture]
        );
        assert_eq!(
            windows_surface_input_side_effects_from_message(WM_CAPTURECHANGED),
            vec![WindowsSurfaceInputSideEffect::ReleaseMouseCapture]
        );
    }

    #[test]
    fn remote_display_surface_input_maps_key_and_focus_loss_messages() {
        assert_eq!(
            windows_surface_input_events_from_message(WM_KEYDOWN, 0x41, 0),
            vec![mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            }]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_KEYUP, 0x41, 0),
            vec![mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: false,
            }]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_KILLFOCUS, 0, 0),
            vec![mrd_ipc::ControlInputEvent::ReleaseAll]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_CAPTURECHANGED, 0, 0),
            vec![mrd_ipc::ControlInputEvent::ReleaseAll]
        );
        assert_eq!(
            windows_surface_input_events_from_message(WM_ACTIVATEAPP, 0, 0),
            vec![mrd_ipc::ControlInputEvent::ReleaseAll]
        );
        assert!(
            windows_surface_input_events_from_message(WM_ACTIVATEAPP, 1, 0).is_empty(),
            "activating the app must not synthesize input"
        );
    }

    #[test]
    fn remote_display_surface_input_forwards_wndproc_events_with_session_id() {
        let (sender, receiver) = native_surface_control_input_channel();
        assert!(
            install_control_input_forwarder(sender),
            "native surface input forwarder should only be installed once in tests"
        );

        let parent = TestParentWindow::create();
        let parent_hwnd = parent.0;
        let mut surface = NativeRenderSurface::create(
            parent_hwnd.0,
            NativeSurfaceRect {
                x: 0,
                y: 0,
                width: 128,
                height: 128,
            },
            false,
            Some(NativeSurfaceControlFrameSize {
                width: 256,
                height: 256,
            }),
        )
        .expect("create native render surface");
        surface.set_control_binding(Some("native-forward-session".to_string()), true, true);

        unsafe {
            SendMessageW(
                surface.hwnd,
                WM_MOUSEMOVE,
                WPARAM(0),
                LPARAM(lparam(42, 24)),
            );
        }

        let input = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("forwarded native surface control input");
        assert_eq!(input.session_id, "native-forward-session");
        assert_eq!(
            input.event,
            mrd_ipc::ControlInputEvent::MouseMove { x: 84, y: 48 }
        );

        surface.set_control_binding(None, false, false);
        let release = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("removing a native control binding must release active input first");
        assert_eq!(release.session_id, "native-forward-session");
        assert_eq!(release.event, mrd_ipc::ControlInputEvent::ReleaseAll);

        unsafe {
            SendMessageW(
                surface.hwnd,
                WM_MOUSEMOVE,
                WPARAM(0),
                LPARAM(lparam(21, 12)),
            );
        }
        assert!(
            receiver.recv_timeout(Duration::from_millis(20)).is_none(),
            "an unbound native surface must not forward control input"
        );

        surface.set_control_binding(Some("native-forward-session".to_string()), true, true);
        drop(surface);

        let release = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("dropping native surface should release active control input");
        assert_eq!(release.session_id, "native-forward-session");
        assert_eq!(release.event, mrd_ipc::ControlInputEvent::ReleaseAll);
    }

    #[tokio::test]
    #[ignore = "manual smoke test: native WndProc -> Rdesk IPC forwarder -> service IPC -> LAN -> SendInput target window"]
    async fn remote_display_surface_native_input_smoke_reaches_lan_sendinput_target_window() {
        let start_cursor = current_cursor_position().expect("read starting cursor position");
        let _cursor_restore = CursorRestoreGuard::new(start_cursor);
        let cursor_target = cursor_smoke_target(start_cursor, current_virtual_screen(), 80);
        assert_ne!(cursor_target, start_cursor, "cursor smoke target must move");

        let mut keyboard_window =
            KeyboardSmokeWindow::create().expect("create keyboard smoke window");
        keyboard_window.focus();

        let controller_device_id = mrd_proto::DeviceId("native-controller-device".to_string());
        let target_device_id = mrd_proto::DeviceId("native-target-device".to_string());
        let session_id = mrd_proto::SessionId("native-input-full-e2e-smoke-session".to_string());

        let controller_port = reserve_udp_port();
        let target_port = reserve_udp_port();
        let controller_state = app_state_with_lan_port(controller_port, target_port);
        let target_state = app_state_with_lan_port(target_port, controller_port);
        controller_state.devices.lock().await.register(
            controller_device_id.clone(),
            "Native Controller Device".to_string(),
        );
        target_state
            .devices
            .lock()
            .await
            .register(target_device_id.clone(), "Native Target Device".to_string());
        controller_state.sessions.lock().await.insert(
            session_id.clone(),
            session_snapshot(
                session_id.clone(),
                None,
                Some(target_device_id.clone()),
                false,
                true,
            ),
        );
        target_state.sessions.lock().await.insert(
            session_id.clone(),
            session_snapshot(
                session_id.clone(),
                Some(controller_device_id.clone()),
                None,
                true,
                false,
            ),
        );

        mrd_service::lan_discovery::start_lan_discovery(target_state.clone())
            .await
            .expect("start target LAN discovery");
        mrd_service::lan_discovery::start_lan_discovery(controller_state.clone())
            .await
            .expect("start controller LAN discovery");
        wait_for_lan_peer(&controller_state, &target_device_id).await;
        let warmup = mrd_service::lan_discovery::request_lan_control_input(
            &controller_state,
            &session_id,
            mrd_ipc::ControlInputEvent::ReleaseAll,
        )
        .await
        .expect("warm up LAN control input channel");
        assert_eq!(warmup.lane, mrd_ipc::ControlInputLane::Cleanup);

        let endpoint = service_ipc_endpoint("full");
        let controller_server = mrd_service::ipc_server::IpcServer::new_with_endpoint(
            controller_state.clone(),
            endpoint.clone(),
        );
        let server_task = tokio::spawn(async move {
            let _ = controller_server.run().await;
        });
        wait_for_service_ipc(endpoint.clone()).await;
        let ipc_warmup =
            send_release_all_over_service_ipc(endpoint.clone(), session_id.clone()).await;
        assert_eq!(
            ipc_warmup,
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Cleanup,
                event_count: 0,
            }
        );
        let direct_key_down =
            send_key_over_service_ipc(endpoint.clone(), session_id.clone(), true).await;
        let direct_key_up =
            send_key_over_service_ipc(endpoint.clone(), session_id.clone(), false).await;
        assert_eq!(
            direct_key_down,
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Reliable,
                event_count: 1,
            }
        );
        assert_eq!(
            direct_key_up,
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Reliable,
                event_count: 1,
            }
        );
        let direct_key_events = keyboard_window
            .wait_for_key_events(0x41, Duration::from_secs(2))
            .expect("wait for direct service IPC key events");
        assert!(direct_key_events.key_down);
        assert!(direct_key_events.key_up);
        keyboard_smoke_events()
            .lock()
            .expect("clear direct IPC key events")
            .clear();
        keyboard_window.focus();

        let (forward_sender, forward_receiver) = native_surface_control_input_channel();
        let (worker_sender, worker_receiver) = native_surface_control_input_channel();
        let (observed_sender, observed_receiver) = std::sync::mpsc::channel();
        let (response_sender, response_receiver) = std::sync::mpsc::channel();
        let observed_receiver = Arc::new(Mutex::new(observed_receiver));
        let response_receiver = Arc::new(Mutex::new(response_receiver));
        assert!(
            install_control_input_forwarder(forward_sender),
            "native surface input forwarder should only be installed once in this smoke"
        );
        let _proxy = std::thread::spawn(move || {
            while let Some(input) = forward_receiver.recv() {
                let _ = observed_sender.send(input.clone());
                worker_sender.relay_existing(input);
            }
        });
        let _forwarder =
            crate::spawn_native_surface_control_input_forwarder_for_receiver_with_reporter(
                worker_receiver,
                endpoint,
                Some(response_sender),
            );

        let parent = TestParentWindow::create();
        let parent_hwnd = parent.0;
        let mut surface = NativeRenderSurface::create(
            parent_hwnd.0,
            NativeSurfaceRect {
                x: 0,
                y: 0,
                width: 128,
                height: 128,
            },
            false,
            None,
        )
        .expect("create native render surface");
        surface.set_control_binding(Some(session_id.0.clone()), true, true);

        keyboard_window.focus();
        unsafe {
            SendMessageW(surface.hwnd, WM_KEYDOWN, WPARAM(0x41), LPARAM(0));
            SendMessageW(surface.hwnd, WM_KEYUP, WPARAM(0x41), LPARAM(0));
        }
        let observed_down = recv_std_channel(
            observed_receiver.clone(),
            Duration::from_secs(1),
            "native key-down left WndProc forwarder",
        )
        .await;
        let observed_up = recv_std_channel(
            observed_receiver.clone(),
            Duration::from_secs(1),
            "native key-up left WndProc forwarder",
        )
        .await;
        assert_eq!(observed_down.session_id, session_id.0);
        assert_eq!(observed_up.session_id, session_id.0);
        assert_eq!(
            observed_down.event,
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            }
        );
        assert_eq!(
            observed_up.event,
            mrd_ipc::ControlInputEvent::Key {
                key: mrd_ipc::ControlInputKey::VirtualKey { code: 0x41 },
                pressed: false,
            }
        );
        let response_down = recv_std_channel(
            response_receiver.clone(),
            Duration::from_secs(10),
            "native key-down service IPC response",
        )
        .await;
        let response_up = recv_std_channel(
            response_receiver.clone(),
            Duration::from_secs(10),
            "native key-up service IPC response",
        )
        .await;
        assert_eq!(response_down.0, session_id.0);
        assert_eq!(response_up.0, session_id.0);
        assert_eq!(
            response_down.1.expect("native key-down IPC request"),
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Reliable,
                event_count: 1,
            }
        );
        assert_eq!(
            response_up.1.expect("native key-up IPC request"),
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Reliable,
                event_count: 1,
            }
        );

        let key_events = keyboard_window
            .wait_for_key_events(0x41, Duration::from_secs(5))
            .expect("wait for full native input smoke key events");
        assert!(key_events.key_down);
        assert!(key_events.key_up);
        unsafe {
            SendMessageW(
                surface.hwnd,
                WM_MOUSEMOVE,
                WPARAM(0),
                LPARAM(lparam(cursor_target.0 as i16, cursor_target.1 as i16)),
            );
        }
        let observed_mouse = recv_std_channel(
            observed_receiver.clone(),
            Duration::from_secs(1),
            "native mouse move left WndProc forwarder",
        )
        .await;
        assert_eq!(observed_mouse.session_id, session_id.0);
        assert_eq!(
            observed_mouse.event,
            mrd_ipc::ControlInputEvent::MouseMove {
                x: cursor_target.0,
                y: cursor_target.1,
            }
        );
        let mouse_response = recv_std_channel(
            response_receiver.clone(),
            Duration::from_secs(10),
            "native mouse move service IPC response",
        )
        .await;
        assert_eq!(mouse_response.0, session_id.0);
        assert_eq!(
            mouse_response.1.expect("native mouse move IPC request"),
            mrd_ipc::IpcResponse::ControlInputAccepted {
                session_id: session_id.clone(),
                lane: mrd_ipc::ControlInputLane::Realtime,
                event_count: 1,
            }
        );
        let moved = wait_for_cursor_near(cursor_target, 2, Duration::from_secs(2))
            .expect("wait for full native input smoke cursor move");
        assert!(
            moved.is_some(),
            "cursor did not move near target: target={cursor_target:?} start={start_cursor:?}"
        );

        let target_snapshot = target_state
            .control_input()
            .lock()
            .await
            .snapshot(session_id.clone());
        server_task.abort();
        eprintln!(
            "native input full smoke key_events={key_events:?} focus={:?} events={:?} reliable={:?} realtime={:?}",
            keyboard_window.focus_snapshot(),
            keyboard_smoke_events()
                .lock()
                .expect("read keyboard smoke events"),
            target_snapshot.reliable,
            target_snapshot.realtime
        );
        assert_eq!(target_snapshot.reliable.accepted_messages, 6);
        assert_eq!(target_snapshot.reliable.injected_messages, 4);
        assert_eq!(target_snapshot.reliable.failed_messages, 0);
        assert_eq!(target_snapshot.realtime.accepted_messages, 1);
        assert_eq!(target_snapshot.realtime.injected_messages, 1);
        assert_eq!(target_snapshot.realtime.failed_messages, 0);
    }
}

#[cfg(target_os = "macos")]
struct NativeRenderSurface {
    parent_ns_window: isize,
    webview_ns_view: isize,
    ns_view: isize,
    overlay_ns_window: Option<isize>,
    mode: MacosNativeSurfaceMode,
    rect: NativeSurfaceRect,
    visible: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosNativeSurfaceMode {
    ChildView,
    ChildWindow,
    TopLevelWindow,
}

#[cfg(target_os = "macos")]
impl MacosNativeSurfaceMode {
    fn uses_overlay_window(self) -> bool {
        matches!(
            self,
            MacosNativeSurfaceMode::ChildWindow | MacosNativeSurfaceMode::TopLevelWindow
        )
    }
}

#[cfg(target_os = "macos")]
struct MacosNativeSurfaceHandles {
    ns_view: isize,
    overlay_ns_window: Option<isize>,
}

#[cfg(target_os = "macos")]
impl NativeRenderSurface {
    fn create(
        window: &WebviewWindow,
        parent_ns_window: isize,
        webview_ns_view: isize,
        rect: NativeSurfaceRect,
        visible: bool,
    ) -> Result<Self, String> {
        let mode = macos_native_surface_mode();
        let handles = run_on_main_thread(window, move || unsafe {
            create_macos_native_surface(mode, parent_ns_window, webview_ns_view, rect, visible)
        })?;

        Ok(Self {
            parent_ns_window,
            webview_ns_view,
            ns_view: handles.ns_view,
            overlay_ns_window: handles.overlay_ns_window,
            mode,
            rect,
            visible,
        })
    }

    fn move_to(
        &mut self,
        window: &WebviewWindow,
        rect: NativeSurfaceRect,
        visible: bool,
    ) -> Result<(), String> {
        if self.overlay_ns_window.is_some() && macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {:?} move current_rect={:?} next_rect={rect:?} current_visible={} next_visible={visible}",
                self.mode, self.rect, self.visible
            );
        }
        if self.rect == rect && self.visible == visible {
            if self.overlay_ns_window.is_some() && macos_native_surface_debug_logging_enabled() {
                eprintln!(
                    "render-surface macos {:?} move skipped unchanged",
                    self.mode
                );
            }
            return Ok(());
        }
        let ns_view = self.ns_view;
        let overlay_ns_window = self.overlay_ns_window;
        let parent_ns_window = self.parent_ns_window;
        let webview_ns_view = self.webview_ns_view;
        let mode = self.mode;
        run_on_main_thread(window, move || unsafe {
            move_macos_native_surface(
                mode,
                parent_ns_window,
                webview_ns_view,
                ns_view,
                overlay_ns_window,
                rect,
                visible,
            )
        })?;
        self.rect = rect;
        self.visible = visible;
        Ok(())
    }

    fn remove(self, window: &WebviewWindow) -> Result<(), String> {
        let ns_view = self.ns_view;
        let overlay_ns_window = self.overlay_ns_window;
        let mode = self.mode;
        run_on_main_thread(window, move || unsafe {
            remove_macos_native_surface(self.parent_ns_window, ns_view, overlay_ns_window, mode);
            Ok(())
        })
    }

    fn snapshot(&self, label: String, rect: NativeSurfaceRect) -> NativeRenderSurfaceSnapshot {
        NativeRenderSurfaceSnapshot {
            label,
            backend: "macos".to_string(),
            attached: true,
            visible: self.visible,
            parent_hwnd: Some(handle_hex(self.parent_ns_window)),
            hwnd: Some(handle_hex(self.ns_view)),
            rect,
        }
    }

    fn render_target_handle(&self) -> isize {
        self.ns_view
    }
}

#[cfg(target_os = "macos")]
fn run_on_main_thread<T, F>(window: &WebviewWindow, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::channel();
    window
        .run_on_main_thread(move || {
            let _ = sender.send(f());
        })
        .map_err(|error| format!("schedule macOS native surface update failed: {error}"))?;

    receiver
        .recv()
        .map_err(|error| format!("macOS native surface update failed: {error}"))?
}

#[cfg(target_os = "macos")]
#[allow(deprecated, unexpected_cfgs)]
unsafe fn create_macos_native_surface(
    mode: MacosNativeSurfaceMode,
    parent_ns_window: isize,
    webview_ns_view: isize,
    rect: NativeSurfaceRect,
    visible: bool,
) -> Result<MacosNativeSurfaceHandles, String> {
    use cocoa::{
        appkit::{
            NSBackingStoreBuffered, NSView, NSWindow, NSWindowOrderingMode, NSWindowStyleMask,
        },
        base::{id, nil, NO, YES},
        foundation::{NSPoint, NSRect, NSSize},
    };
    use objc::{class, msg_send, sel, sel_impl};

    let ns_window = parent_ns_window as id;
    let webview = webview_ns_view as id;
    if ns_window == nil || webview == nil {
        return Err("remote display macOS parent pointer is null".to_string());
    }

    let content_view: id = msg_send![ns_window, contentView];
    if content_view == nil {
        return Err("remote display NSWindow has no contentView".to_string());
    }

    let frame = rect_to_content_view_frame(content_view, webview, rect);
    let fullscreen = macos_native_surface_fullscreen_enabled(mode);
    if mode.uses_overlay_window() {
        if macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} create rect={rect:?} frame=({}, {}, {}, {}) visible={visible} fullscreen={fullscreen}",
                frame.origin.x, frame.origin.y, frame.size.width, frame.size.height
            );
        }
        let window_frame: NSRect = msg_send![content_view, convertRect: frame toView: nil];
        let requested_screen_frame: NSRect =
            msg_send![ns_window, convertRectToScreen: window_frame];
        let surface_frame =
            macos_overlay_surface_frame(ns_window, requested_screen_frame, fullscreen);
        if macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} create surface_frame=({}, {}, {}, {}) requested_screen_frame=({}, {}, {}, {})",
                surface_frame.origin.x,
                surface_frame.origin.y,
                surface_frame.size.width,
                surface_frame.size.height,
                requested_screen_frame.origin.x,
                requested_screen_frame.origin.y,
                requested_screen_frame.size.width,
                requested_screen_frame.size.height
            );
        }
        let overlay_window: id = NSWindow::alloc(nil).initWithContentRect_styleMask_backing_defer_(
            surface_frame,
            NSWindowStyleMask::NSBorderlessWindowMask,
            NSBackingStoreBuffered,
            NO,
        );
        if overlay_window == nil {
            return Err("create macOS native render child NSWindow failed".to_string());
        }
        let child_frame = NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(surface_frame.size.width, surface_frame.size.height),
        );
        let view: id = NSView::alloc(nil).initWithFrame_(child_frame);
        if view == nil {
            let _: () = msg_send![overlay_window, release];
            return Err("create macOS native render child-window NSView failed".to_string());
        }

        let _: () = msg_send![overlay_window, setReleasedWhenClosed: NO];
        view.setWantsLayer(YES);
        view.setAutoresizingMask_(0);
        overlay_window.setContentView_(view);
        let _: () = msg_send![overlay_window, setOpaque: YES];
        if mode == MacosNativeSurfaceMode::ChildWindow {
            let _: () = msg_send![
                ns_window,
                addChildWindow: overlay_window
                ordered: NSWindowOrderingMode::NSWindowAbove
            ];
        }
        let activate_on_create = mode == MacosNativeSurfaceMode::TopLevelWindow
            && (fullscreen || macos_native_surface_activate_on_create_enabled());
        if activate_on_create {
            let app: id = msg_send![class!(NSApplication), sharedApplication];
            if app != nil {
                let _: () = msg_send![app, activateIgnoringOtherApps: YES];
            }
            let _: () = msg_send![ns_window, makeKeyAndOrderFront: nil];
        }
        if visible {
            if activate_on_create {
                let _: () = msg_send![overlay_window, orderFrontRegardless];
            } else {
                let _: () = msg_send![overlay_window, orderFront: nil];
            }
        } else {
            let _: () = msg_send![overlay_window, orderOut: nil];
        }
        // Keep one retain count owned by the surface manager until remove().
        let _: id = msg_send![view, retain];
        return Ok(MacosNativeSurfaceHandles {
            ns_view: view as isize,
            overlay_ns_window: Some(overlay_window as isize),
        });
    }

    let view: id = NSView::alloc(nil).initWithFrame_(frame);
    if view == nil {
        return Err("create macOS native render NSView failed".to_string());
    }

    view.setWantsLayer(YES);
    view.setAutoresizingMask_(0);
    let _: () = msg_send![view, setHidden: if visible { NO } else { YES }];
    let _: () = msg_send![view, setPostsFrameChangedNotifications: YES];
    let _: () = msg_send![
        content_view,
        addSubview: view
        positioned: NSWindowOrderingMode::NSWindowAbove
        relativeTo: nil
    ];

    // Keep one retain count owned by the surface manager until remove().
    let _: id = msg_send![view, retain];
    Ok(MacosNativeSurfaceHandles {
        ns_view: view as isize,
        overlay_ns_window: None,
    })
}

#[cfg(target_os = "macos")]
#[allow(deprecated, unexpected_cfgs)]
unsafe fn move_macos_native_surface(
    mode: MacosNativeSurfaceMode,
    parent_ns_window: isize,
    webview_ns_view: isize,
    ns_view: isize,
    overlay_ns_window: Option<isize>,
    rect: NativeSurfaceRect,
    visible: bool,
) -> Result<(), String> {
    use cocoa::{
        appkit::{NSView, NSWindowOrderingMode},
        base::{id, nil, NO, YES},
    };
    use objc::{msg_send, sel, sel_impl};

    let ns_window = parent_ns_window as id;
    let webview = webview_ns_view as id;
    let view = ns_view as id;
    if ns_window == nil || webview == nil || view == nil {
        return Err("macOS native surface pointer is null".to_string());
    }

    let content_view: id = msg_send![ns_window, contentView];
    if content_view == nil {
        return Err("remote display NSWindow has no contentView".to_string());
    }

    let frame = rect_to_content_view_frame(content_view, webview, rect);
    let fullscreen = macos_native_surface_fullscreen_enabled(mode);
    if let Some(overlay_ns_window) = overlay_ns_window {
        let overlay_window = overlay_ns_window as id;
        if overlay_window == nil {
            return Err("macOS native surface child window pointer is null".to_string());
        }
        if macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} move begin rect={rect:?} frame=({}, {}, {}, {}) visible={visible} fullscreen={fullscreen}",
                frame.origin.x, frame.origin.y, frame.size.width, frame.size.height
            );
        }
        let window_frame: cocoa::foundation::NSRect =
            msg_send![content_view, convertRect: frame toView: nil];
        let requested_screen_frame: cocoa::foundation::NSRect =
            msg_send![ns_window, convertRectToScreen: window_frame];
        let surface_frame =
            macos_overlay_surface_frame(ns_window, requested_screen_frame, fullscreen);
        if macos_native_surface_debug_logging_enabled() {
            eprintln!(
                "render-surface macos {mode:?} move surface_frame=({}, {}, {}, {}) requested_screen_frame=({}, {}, {}, {})",
                surface_frame.origin.x,
                surface_frame.origin.y,
                surface_frame.size.width,
                surface_frame.size.height,
                requested_screen_frame.origin.x,
                requested_screen_frame.origin.y,
                requested_screen_frame.size.width,
                requested_screen_frame.size.height
            );
        }
        let _: () = msg_send![overlay_window, setFrame: surface_frame display: YES];
        if macos_native_surface_debug_logging_enabled() {
            eprintln!("render-surface macos {mode:?} move setFrame ok");
        }
        view.setFrameOrigin(cocoa::foundation::NSPoint::new(0.0, 0.0));
        view.setFrameSize(surface_frame.size);
        if macos_native_surface_debug_logging_enabled() {
            eprintln!("render-surface macos {mode:?} move resize view ok");
        }
        if visible {
            if fullscreen {
                let _: () = msg_send![overlay_window, orderFrontRegardless];
            } else {
                let _: () = msg_send![overlay_window, orderFront: nil];
            }
        } else {
            let _: () = msg_send![overlay_window, orderOut: nil];
        }
        if macos_native_surface_debug_logging_enabled() {
            eprintln!("render-surface macos {mode:?} move visibility ok");
        }
        sync_macos_surface_layer_frame(view);
        if macos_native_surface_debug_logging_enabled() {
            eprintln!("render-surface macos {mode:?} move sync layer ok");
        }
        return Ok(());
    }

    view.setFrameOrigin(frame.origin);
    view.setFrameSize(frame.size);
    let _: () = msg_send![view, setHidden: if visible { NO } else { YES }];
    sync_macos_surface_layer_frame(view);
    let _: () = msg_send![
        content_view,
        addSubview: view
        positioned: NSWindowOrderingMode::NSWindowAbove
        relativeTo: nil
    ];
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(deprecated, unexpected_cfgs)]
unsafe fn remove_macos_native_surface(
    parent_ns_window: isize,
    ns_view: isize,
    overlay_ns_window: Option<isize>,
    mode: MacosNativeSurfaceMode,
) {
    use cocoa::{appkit::NSView, base::id};
    use objc::{msg_send, sel, sel_impl};

    if let Some(overlay_ns_window) = overlay_ns_window {
        let parent_window = parent_ns_window as id;
        let overlay_window = overlay_ns_window as id;
        if !parent_window.is_null() && !overlay_window.is_null() {
            if mode == MacosNativeSurfaceMode::ChildWindow {
                let _: () = msg_send![parent_window, removeChildWindow: overlay_window];
            }
            let _: () = msg_send![overlay_window, orderOut: cocoa::base::nil];
            let _: () = msg_send![overlay_window, close];
            let _: () = msg_send![overlay_window, release];
        }
    }

    let view = ns_view as id;
    if !view.is_null() {
        view.removeFromSuperview();
        let _: () = msg_send![view, release];
    }
}

#[cfg(target_os = "macos")]
fn macos_native_surface_mode() -> MacosNativeSurfaceMode {
    match std::env::var("MRD_MACOS_NATIVE_SURFACE_MODE")
        .ok()
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
    {
        Some(value) if matches!(value.as_str(), "child_window" | "window" | "overlay_window") => {
            MacosNativeSurfaceMode::ChildWindow
        }
        Some(value)
            if matches!(
                value.as_str(),
                "top_level_window" | "top-level-window" | "detached_window" | "dedicated_window"
            ) =>
        {
            MacosNativeSurfaceMode::TopLevelWindow
        }
        _ => MacosNativeSurfaceMode::ChildView,
    }
}

#[cfg(target_os = "macos")]
fn macos_native_surface_fullscreen_enabled(mode: MacosNativeSurfaceMode) -> bool {
    mode == MacosNativeSurfaceMode::TopLevelWindow
        && macos_env_flag_enabled("MRD_MACOS_NATIVE_SURFACE_FULLSCREEN")
}

#[cfg(target_os = "macos")]
fn macos_native_surface_debug_logging_enabled() -> bool {
    macos_env_flag_enabled("MRD_MACOS_NATIVE_SURFACE_DEBUG")
}

#[cfg(target_os = "macos")]
fn macos_native_surface_activate_on_create_enabled() -> bool {
    macos_env_flag_enabled("MRD_MACOS_NATIVE_SURFACE_ACTIVATE_ON_CREATE")
}

#[cfg(target_os = "macos")]
fn macos_env_flag_enabled(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn macos_overlay_surface_frame(
    ns_window: cocoa::base::id,
    requested_screen_frame: cocoa::foundation::NSRect,
    fullscreen: bool,
) -> cocoa::foundation::NSRect {
    if !fullscreen {
        return requested_screen_frame;
    }
    macos_window_screen_frame(ns_window).unwrap_or(requested_screen_frame)
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn macos_window_screen_frame(
    ns_window: cocoa::base::id,
) -> Option<cocoa::foundation::NSRect> {
    use cocoa::base::{id, nil};
    use objc::{class, msg_send, sel, sel_impl};

    let screen: id = if ns_window == nil {
        nil
    } else {
        msg_send![ns_window, screen]
    };
    let screen: id = if screen == nil {
        msg_send![class!(NSScreen), mainScreen]
    } else {
        screen
    };
    if screen == nil {
        return None;
    }
    Some(msg_send![screen, frame])
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn rect_to_content_view_frame(
    content_view: cocoa::base::id,
    webview: cocoa::base::id,
    rect: NativeSurfaceRect,
) -> cocoa::foundation::NSRect {
    use cocoa::{appkit::NSView, foundation::NSRect};
    use objc::{msg_send, sel, sel_impl};

    let webview_bounds: NSRect = NSView::bounds(webview);
    let webview_frame = rect_to_bottom_left_frame(rect, webview_bounds.size.height);
    msg_send![content_view, convertRect: webview_frame fromView: webview]
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn rect_to_bottom_left_frame(
    rect: NativeSurfaceRect,
    parent_height: f64,
) -> cocoa::foundation::NSRect {
    use cocoa::foundation::{NSPoint, NSRect, NSSize};

    let y = (parent_height - rect.y as f64 - rect.height as f64).max(0.0);
    NSRect::new(
        NSPoint::new(rect.x as f64, y),
        NSSize::new(rect.width as f64, rect.height as f64),
    )
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
unsafe fn sync_macos_surface_layer_frame(view: cocoa::base::id) {
    use cocoa::appkit::NSView;
    use objc::{msg_send, runtime::Object, sel, sel_impl};

    let layer: *mut Object = msg_send![view, layer];
    if layer.is_null() {
        return;
    }

    let bounds = NSView::bounds(view);
    let window: *mut Object = msg_send![view, window];
    let contents_scale = if window.is_null() {
        1.0
    } else {
        msg_send![window, backingScaleFactor]
    };
    let _: () = msg_send![layer, setFrame: bounds];
    let _: () = msg_send![layer, setContentsScale: contents_scale];
}

#[cfg(test)]
mod tests {
    use super::{normalize_rect, NativeSurfaceRect};

    #[test]
    fn native_surface_rect_is_clamped_to_visible_size() {
        let rect = normalize_rect(NativeSurfaceRect {
            x: -10,
            y: -20,
            width: 0,
            height: -1,
        });

        assert_eq!(rect.x, 0);
        assert_eq!(rect.y, 0);
        assert_eq!(rect.width, 1);
        assert_eq!(rect.height, 1);
    }

    #[cfg(target_os = "macos")]
    #[allow(deprecated)]
    #[test]
    fn macos_rect_is_converted_from_web_top_left_to_appkit_bottom_left() {
        let frame = super::rect_to_bottom_left_frame(
            NativeSurfaceRect {
                x: 20,
                y: 56,
                width: 800,
                height: 400,
            },
            900.0,
        );

        assert_eq!(frame.origin.x, 20.0);
        assert_eq!(frame.origin.y, 444.0);
        assert_eq!(frame.size.width, 800.0);
        assert_eq!(frame.size.height, 400.0);
    }
}
