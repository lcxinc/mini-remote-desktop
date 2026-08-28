use mrd_input::{InputButton, InputError, InputEvent, InputInjector, InputKey};
use mrd_ipc::{
    ControlChannelLaneSnapshot, ControlChannelReliability, ControlChannelSnapshot,
    ControlInputButton, ControlInputEvent, ControlInputKey, ControlInputLane,
};
use mrd_proto::SessionId;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlInputResult {
    pub lane: ControlInputLane,
    pub event_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub struct ControlInputTargetGeometry {
    pub frame_width: u32,
    pub frame_height: u32,
    pub source_width: u32,
    pub source_height: u32,
    pub origin_x: i32,
    pub origin_y: i32,
}

#[derive(Debug, Clone, Default)]
struct ControlLaneCounters {
    accepted_messages: u64,
    injected_messages: u64,
    failed_messages: u64,
    dropped_messages: u64,
    coalesced_messages: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlInputScope {
    Pointer,
    Keyboard,
}

#[derive(Debug, Default)]
struct SessionPressedInput {
    buttons: HashSet<InputButton>,
    keys: HashSet<InputKey>,
}

pub struct ControlInputRegistry {
    injector: Box<dyn InputInjector>,
    reliable: ControlLaneCounters,
    realtime: ControlLaneCounters,
    last_realtime_mouse_move_by_session: HashMap<SessionId, (i32, i32)>,
    pressed_by_session: HashMap<SessionId, SessionPressedInput>,
    migration_frozen_sessions: HashSet<SessionId>,
    button_holder_counts: HashMap<InputButton, usize>,
    key_holder_counts: HashMap<InputKey, usize>,
}

impl ControlInputRegistry {
    pub fn default_for_platform() -> Self {
        #[cfg(windows)]
        let injector: Box<dyn InputInjector> =
            Box::new(mrd_input::windows::WindowsSendInputInjector::new());

        #[cfg(not(windows))]
        let injector: Box<dyn InputInjector> = Box::new(mrd_input::UnsupportedInputInjector::new(
            "input injection is not implemented for this platform",
        ));

        Self::with_injector(injector)
    }

    pub fn with_injector<I>(injector: I) -> Self
    where
        I: InputInjector + 'static,
    {
        Self {
            injector: Box::new(injector),
            reliable: ControlLaneCounters::default(),
            realtime: ControlLaneCounters::default(),
            last_realtime_mouse_move_by_session: HashMap::new(),
            pressed_by_session: HashMap::new(),
            migration_frozen_sessions: HashSet::new(),
            button_holder_counts: HashMap::new(),
            key_holder_counts: HashMap::new(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.injector.is_available()
    }

    #[cfg(test)]
    pub fn handle_event(
        &mut self,
        event: &ControlInputEvent,
    ) -> Result<ControlInputResult, InputError> {
        self.handle_event_inner(None, event, None)
    }

    pub fn handle_session_event(
        &mut self,
        session_id: &SessionId,
        event: &ControlInputEvent,
    ) -> Result<ControlInputResult, InputError> {
        self.handle_event_inner(Some(session_id), event, None)
    }

    pub(crate) fn handle_authenticated_session_event(
        &mut self,
        session_id: &SessionId,
        scope: ControlInputScope,
        event: &ControlInputEvent,
    ) -> Result<ControlInputResult, InputError> {
        self.handle_event_inner(Some(session_id), event, Some(scope))
    }

    fn handle_event_inner(
        &mut self,
        session_id: Option<&SessionId>,
        event: &ControlInputEvent,
        release_scope: Option<ControlInputScope>,
    ) -> Result<ControlInputResult, InputError> {
        let lane = input_lane(event);
        counter_for_lane_mut(&mut self.reliable, &mut self.realtime, lane).accepted_messages += 1;

        if session_id.is_some_and(|session_id| {
            self.migration_frozen_sessions.contains(session_id)
                && !matches!(event, ControlInputEvent::ReleaseAll)
        }) {
            counter_for_lane_mut(&mut self.reliable, &mut self.realtime, lane).dropped_messages +=
                1;
            return Err(InputError::InvalidEvent(
                "control input is frozen during relay migration".into(),
            ));
        }

        if self.should_coalesce_realtime_event(session_id, event) {
            counter_for_lane_mut(&mut self.reliable, &mut self.realtime, lane)
                .coalesced_messages += 1;
            return Ok(ControlInputResult {
                lane,
                event_count: 0,
            });
        }

        let result: Result<u32, InputError> = match (session_id, event) {
            (Some(session_id), ControlInputEvent::ReleaseAll) => match release_scope {
                Some(scope) => self.release_session_scope(session_id, scope),
                None => self.release_session_all(session_id),
            },
            (None, ControlInputEvent::ReleaseAll) => Ok(0),
            (Some(session_id), event) => input_event_from_ipc(event)
                .and_then(|input| self.inject_session_input(session_id, input)),
            (None, event) => input_event_from_ipc(event)
                .and_then(|input| self.injector.inject(&input))
                .map(|()| 1),
        };

        match result {
            Ok(event_count) => {
                self.record_successful_realtime_event(session_id, event, release_scope);
                let counter = counter_for_lane_mut(&mut self.reliable, &mut self.realtime, lane);
                counter.injected_messages += u64::from(event_count);
                counter.last_error = None;
                Ok(ControlInputResult { lane, event_count })
            }
            Err(error) => {
                let counter = counter_for_lane_mut(&mut self.reliable, &mut self.realtime, lane);
                counter.failed_messages += 1;
                counter.last_error = Some(error.to_string());
                Err(error)
            }
        }
    }

    fn should_coalesce_realtime_event(
        &self,
        session_id: Option<&SessionId>,
        event: &ControlInputEvent,
    ) -> bool {
        let Some(session_id) = session_id else {
            return false;
        };
        match *event {
            ControlInputEvent::MouseMove { x, y } => self
                .last_realtime_mouse_move_by_session
                .get(session_id)
                .is_some_and(|last| *last == (x, y)),
            _ => false,
        }
    }

    fn record_successful_realtime_event(
        &mut self,
        session_id: Option<&SessionId>,
        event: &ControlInputEvent,
        release_scope: Option<ControlInputScope>,
    ) {
        let Some(session_id) = session_id else {
            return;
        };
        match *event {
            ControlInputEvent::MouseMove { x, y } => {
                self.last_realtime_mouse_move_by_session
                    .insert(session_id.clone(), (x, y));
            }
            ControlInputEvent::ReleaseAll
                if release_scope.is_none() || release_scope == Some(ControlInputScope::Pointer) =>
            {
                self.last_realtime_mouse_move_by_session.remove(session_id);
            }
            _ => {}
        }
    }

    fn inject_session_input(
        &mut self,
        session_id: &SessionId,
        event: InputEvent,
    ) -> Result<u32, InputError> {
        match event {
            InputEvent::MouseButton { button, pressed } => {
                self.transition_session_button(session_id, button, pressed)
            }
            InputEvent::Key { key, pressed } => {
                self.transition_session_key(session_id, key, pressed)
            }
            event => self.injector.inject(&event).map(|()| 1),
        }
    }

    fn transition_session_button(
        &mut self,
        session_id: &SessionId,
        button: InputButton,
        pressed: bool,
    ) -> Result<u32, InputError> {
        let held_by_session = self
            .pressed_by_session
            .get(session_id)
            .is_some_and(|state| state.buttons.contains(&button));
        if pressed == held_by_session {
            return Ok(0);
        }
        let holders = self.button_holder_counts.get(&button).copied().unwrap_or(0);
        let physical_transition = (pressed && holders == 0) || (!pressed && holders == 1);
        if physical_transition {
            self.injector
                .inject(&InputEvent::MouseButton { button, pressed })?;
        }
        if pressed {
            self.pressed_by_session
                .entry(session_id.clone())
                .or_default()
                .buttons
                .insert(button);
            self.button_holder_counts.insert(button, holders + 1);
        } else {
            if let Some(state) = self.pressed_by_session.get_mut(session_id) {
                state.buttons.remove(&button);
            }
            if holders <= 1 {
                self.button_holder_counts.remove(&button);
            } else {
                self.button_holder_counts.insert(button, holders - 1);
            }
            self.remove_empty_session_state(session_id);
        }
        Ok(u32::from(physical_transition))
    }

    fn transition_session_key(
        &mut self,
        session_id: &SessionId,
        key: InputKey,
        pressed: bool,
    ) -> Result<u32, InputError> {
        let held_by_session = self
            .pressed_by_session
            .get(session_id)
            .is_some_and(|state| state.keys.contains(&key));
        if pressed == held_by_session {
            return Ok(0);
        }
        let holders = self.key_holder_counts.get(&key).copied().unwrap_or(0);
        let physical_transition = (pressed && holders == 0) || (!pressed && holders == 1);
        if physical_transition {
            self.injector.inject(&InputEvent::Key { key, pressed })?;
        }
        if pressed {
            self.pressed_by_session
                .entry(session_id.clone())
                .or_default()
                .keys
                .insert(key);
            self.key_holder_counts.insert(key, holders + 1);
        } else {
            if let Some(state) = self.pressed_by_session.get_mut(session_id) {
                state.keys.remove(&key);
            }
            if holders <= 1 {
                self.key_holder_counts.remove(&key);
            } else {
                self.key_holder_counts.insert(key, holders - 1);
            }
            self.remove_empty_session_state(session_id);
        }
        Ok(u32::from(physical_transition))
    }

    pub(crate) fn release_session_scope(
        &mut self,
        session_id: &SessionId,
        scope: ControlInputScope,
    ) -> Result<u32, InputError> {
        if scope == ControlInputScope::Pointer {
            self.last_realtime_mouse_move_by_session.remove(session_id);
        }
        let Some(state) = self.pressed_by_session.get(session_id) else {
            return Ok(0);
        };
        let buttons = if scope == ControlInputScope::Pointer {
            state.buttons.iter().copied().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let keys = if scope == ControlInputScope::Keyboard {
            state.keys.iter().copied().collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut released = 0_u32;
        for button in buttons {
            released =
                released.saturating_add(self.transition_session_button(session_id, button, false)?);
        }
        for key in keys {
            released =
                released.saturating_add(self.transition_session_key(session_id, key, false)?);
        }
        Ok(released)
    }

    pub(crate) fn release_session_all(
        &mut self,
        session_id: &SessionId,
    ) -> Result<u32, InputError> {
        let pointer = self.release_session_scope(session_id, ControlInputScope::Pointer)?;
        let keyboard = self.release_session_scope(session_id, ControlInputScope::Keyboard)?;
        Ok(pointer.saturating_add(keyboard))
    }

    pub(crate) fn release_all_sessions(&mut self) -> Result<u32, InputError> {
        let mut pending = self
            .pressed_by_session
            .keys()
            .chain(self.last_realtime_mouse_move_by_session.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        pending.sort_by(|left, right| left.0.cmp(&right.0));
        let mut released = 0_u32;
        let mut last_error = None;
        for _ in 0..3 {
            let mut retry = Vec::new();
            for session_id in pending {
                match self.release_session_all(&session_id) {
                    Ok(count) => released = released.saturating_add(count),
                    Err(error) => {
                        last_error = Some(error);
                        retry.push(session_id);
                    }
                }
            }
            if retry.is_empty() {
                return Ok(released);
            }
            pending = retry;
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(released),
        }
    }

    /// Release every held input state and atomically reject new input for one migration.
    pub(crate) fn freeze_session_for_migration(
        &mut self,
        session_id: &SessionId,
    ) -> Result<u32, InputError> {
        let released = self.release_session_all(session_id);
        self.migration_frozen_sessions.insert(session_id.clone());
        released
    }

    /// Resume authenticated input after an exact migration generation commits or aborts safely.
    pub(crate) fn thaw_session_after_migration(&mut self, session_id: &SessionId) -> bool {
        self.migration_frozen_sessions.remove(session_id)
    }

    pub(crate) fn session_is_migration_frozen(&self, session_id: &SessionId) -> bool {
        self.migration_frozen_sessions.contains(session_id)
    }

    fn remove_empty_session_state(&mut self, session_id: &SessionId) {
        if self
            .pressed_by_session
            .get(session_id)
            .is_some_and(|state| state.buttons.is_empty() && state.keys.is_empty())
        {
            self.pressed_by_session.remove(session_id);
        }
    }

    pub fn snapshot(&self, session_id: SessionId) -> ControlChannelSnapshot {
        ControlChannelSnapshot {
            session_id,
            reliable: lane_snapshot(
                "ctrl_rel",
                ControlChannelReliability::ReliableOrdered,
                true,
                None,
                &self.reliable,
            ),
            realtime: lane_snapshot(
                "ctrl_rt",
                ControlChannelReliability::UnreliableRealtime,
                false,
                Some(0),
                &self.realtime,
            ),
        }
    }

    #[cfg(test)]
    pub fn injected_message_count(&self) -> u64 {
        self.reliable
            .injected_messages
            .saturating_add(self.realtime.injected_messages)
    }
}

impl Default for ControlInputRegistry {
    fn default() -> Self {
        Self::default_for_platform()
    }
}

fn input_lane(event: &ControlInputEvent) -> ControlInputLane {
    match event {
        ControlInputEvent::MouseMove { .. }
        | ControlInputEvent::MouseWheel { .. }
        | ControlInputEvent::MouseHorizontalWheel { .. } => ControlInputLane::Realtime,
        ControlInputEvent::MouseButton { .. } | ControlInputEvent::Key { .. } => {
            ControlInputLane::Reliable
        }
        ControlInputEvent::ReleaseAll => ControlInputLane::Cleanup,
    }
}

fn counter_for_lane_mut<'a>(
    reliable: &'a mut ControlLaneCounters,
    realtime: &'a mut ControlLaneCounters,
    lane: ControlInputLane,
) -> &'a mut ControlLaneCounters {
    match lane {
        ControlInputLane::Reliable | ControlInputLane::Cleanup => reliable,
        ControlInputLane::Realtime => realtime,
    }
}

fn lane_snapshot(
    name: &str,
    reliability: ControlChannelReliability,
    ordered: bool,
    max_retransmits: Option<u16>,
    counters: &ControlLaneCounters,
) -> ControlChannelLaneSnapshot {
    ControlChannelLaneSnapshot {
        name: name.to_string(),
        reliability,
        ordered,
        max_retransmits,
        queued_messages: 0,
        dropped_messages: counters.dropped_messages,
        coalesced_messages: counters.coalesced_messages,
        accepted_messages: counters.accepted_messages,
        injected_messages: counters.injected_messages,
        failed_messages: counters.failed_messages,
        last_error: counters.last_error.clone(),
    }
}

#[cfg(test)]
pub fn map_control_input_event_for_target_geometry(
    event: &ControlInputEvent,
    geometry: Option<ControlInputTargetGeometry>,
) -> ControlInputEvent {
    let Some(geometry) = geometry else {
        return event.clone();
    };
    match *event {
        ControlInputEvent::MouseMove { x, y } => {
            let x = scale_target_coordinate(
                x,
                geometry.frame_width,
                geometry.source_width,
                geometry.origin_x,
            );
            let y = scale_target_coordinate(
                y,
                geometry.frame_height,
                geometry.source_height,
                geometry.origin_y,
            );
            ControlInputEvent::MouseMove { x, y }
        }
        _ => event.clone(),
    }
}

#[cfg(test)]
fn scale_target_coordinate(
    coordinate: i32,
    frame_extent: u32,
    source_extent: u32,
    origin: i32,
) -> i32 {
    if frame_extent == 0 || source_extent == 0 {
        return coordinate;
    }
    let scaled = i64::from(coordinate) * i64::from(source_extent) / i64::from(frame_extent);
    let max_source = i64::from(source_extent.saturating_sub(1));
    let bounded = scaled.clamp(0, max_source) + i64::from(origin);
    bounded.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn input_event_from_ipc(event: &ControlInputEvent) -> Result<InputEvent, InputError> {
    match *event {
        ControlInputEvent::MouseMove { x, y } => Ok(InputEvent::MouseMove { x, y }),
        ControlInputEvent::MouseWheel { delta } => Ok(InputEvent::MouseWheel { delta }),
        ControlInputEvent::MouseHorizontalWheel { delta } => {
            Ok(InputEvent::MouseHorizontalWheel { delta })
        }
        ControlInputEvent::MouseButton { button, pressed } => Ok(InputEvent::MouseButton {
            button: input_button_from_ipc(button),
            pressed,
        }),
        ControlInputEvent::Key { key, pressed } => Ok(InputEvent::Key {
            key: input_key_from_ipc(key),
            pressed,
        }),
        ControlInputEvent::ReleaseAll => Err(InputError::InvalidEvent(
            "release_all is not a single input event".to_string(),
        )),
    }
}

fn input_button_from_ipc(button: ControlInputButton) -> InputButton {
    match button {
        ControlInputButton::Left => InputButton::Left,
        ControlInputButton::Right => InputButton::Right,
        ControlInputButton::Middle => InputButton::Middle,
        ControlInputButton::X1 => InputButton::Other(1),
        ControlInputButton::X2 => InputButton::Other(2),
    }
}

fn input_key_from_ipc(key: ControlInputKey) -> InputKey {
    match key {
        ControlInputKey::VirtualKey { code } => InputKey::VirtualKey(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Clone)]
    struct SharedRecordingInputInjector {
        events: Arc<StdMutex<Vec<InputEvent>>>,
    }

    impl InputInjector for SharedRecordingInputInjector {
        fn is_available(&self) -> bool {
            true
        }

        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(*event);
            Ok(())
        }
    }

    struct FailsOnceInputInjector {
        error_message: String,
        should_fail: bool,
    }

    struct FailsKeyReleaseInputInjector;

    impl InputInjector for FailsKeyReleaseInputInjector {
        fn is_available(&self) -> bool {
            true
        }

        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            if matches!(event, InputEvent::Key { pressed: false, .. }) {
                return Err(InputError::Platform("key release failed".into()));
            }
            Ok(())
        }
    }

    impl FailsOnceInputInjector {
        fn new(error_message: impl Into<String>) -> Self {
            Self {
                error_message: error_message.into(),
                should_fail: true,
            }
        }
    }

    impl InputInjector for FailsOnceInputInjector {
        fn is_available(&self) -> bool {
            true
        }

        fn inject(&mut self, _event: &InputEvent) -> Result<(), InputError> {
            if self.should_fail {
                self.should_fail = false;
                return Err(InputError::Platform(self.error_message.clone()));
            }
            Ok(())
        }
    }

    #[test]
    fn injected_message_count_combines_global_lane_totals() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = ControlInputRegistry::with_injector(SharedRecordingInputInjector {
            events: Arc::clone(&events),
        });

        assert_eq!(registry.injected_message_count(), 0);
        registry
            .handle_event(&ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            })
            .expect("inject reliable event");
        registry
            .handle_event(&ControlInputEvent::MouseMove { x: 10, y: 20 })
            .expect("inject realtime event");

        assert_eq!(registry.injected_message_count(), 2);
        assert_eq!(events.lock().expect("recorded events").len(), 2);
    }

    #[test]
    fn mouse_move_uses_realtime_lane() {
        assert_eq!(
            input_lane(&ControlInputEvent::MouseMove { x: 1, y: 2 }),
            ControlInputLane::Realtime
        );
    }

    #[test]
    fn mouse_wheel_uses_realtime_lane() {
        assert_eq!(
            input_lane(&ControlInputEvent::MouseWheel { delta: -120 }),
            ControlInputLane::Realtime
        );
    }

    #[test]
    fn horizontal_wheel_uses_realtime_lane() {
        assert_eq!(
            input_lane(&ControlInputEvent::MouseHorizontalWheel { delta: 120 }),
            ControlInputLane::Realtime
        );
    }

    #[test]
    fn duplicate_mouse_moves_are_coalesced_on_realtime_lane() {
        let mut registry =
            ControlInputRegistry::with_injector(mrd_input::RecordingInputInjector::available());
        let session_id = SessionId("control-session".to_string());

        let first = registry
            .handle_session_event(&session_id, &ControlInputEvent::MouseMove { x: 10, y: 20 })
            .expect("first mouse move");
        let duplicate = registry
            .handle_session_event(&session_id, &ControlInputEvent::MouseMove { x: 10, y: 20 })
            .expect("duplicate mouse move");
        let snapshot = registry.snapshot(session_id);

        assert_eq!(first.event_count, 1);
        assert_eq!(duplicate.event_count, 0);
        assert_eq!(snapshot.realtime.accepted_messages, 2);
        assert_eq!(snapshot.realtime.injected_messages, 1);
        assert_eq!(snapshot.realtime.coalesced_messages, 1);
    }

    #[test]
    fn mouse_move_coalescing_is_scoped_to_session() {
        let mut registry =
            ControlInputRegistry::with_injector(mrd_input::RecordingInputInjector::available());
        let first_session = SessionId("first-control-session".to_string());
        let second_session = SessionId("second-control-session".to_string());

        registry
            .handle_session_event(
                &first_session,
                &ControlInputEvent::MouseMove { x: 10, y: 20 },
            )
            .expect("first session mouse move");
        let second = registry
            .handle_session_event(
                &second_session,
                &ControlInputEvent::MouseMove { x: 10, y: 20 },
            )
            .expect("second session same mouse move");
        let snapshot = registry.snapshot(first_session);

        assert_eq!(second.event_count, 1);
        assert_eq!(snapshot.realtime.accepted_messages, 2);
        assert_eq!(snapshot.realtime.injected_messages, 2);
        assert_eq!(snapshot.realtime.coalesced_messages, 0);
    }

    #[test]
    fn terminal_release_clears_session_mouse_move_coalescing_state() {
        let mut registry =
            ControlInputRegistry::with_injector(mrd_input::RecordingInputInjector::available());
        let session_id = SessionId("reused-control-session".to_string());
        let move_event = ControlInputEvent::MouseMove { x: 10, y: 20 };

        registry
            .handle_session_event(&session_id, &move_event)
            .expect("initial mouse move");
        registry
            .release_session_all(&session_id)
            .expect("terminal session release");
        let reused = registry
            .handle_session_event(&session_id, &move_event)
            .expect("same coordinate after session reuse");

        assert_eq!(reused.event_count, 1);
    }

    #[test]
    fn migration_freeze_rejects_new_input_even_when_release_all_fails() {
        let mut registry = ControlInputRegistry::with_injector(FailsKeyReleaseInputInjector);
        let session_id = SessionId("migration-input-safety".into());
        registry
            .handle_session_event(
                &session_id,
                &ControlInputEvent::Key {
                    key: ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down before migration");

        assert_eq!(
            registry
                .freeze_session_for_migration(&session_id)
                .expect_err("failed ReleaseAll must surface"),
            InputError::Platform("key release failed".into())
        );
        assert!(registry.session_is_migration_frozen(&session_id));
        assert!(matches!(
            registry
                .handle_session_event(&session_id, &ControlInputEvent::MouseMove { x: 1, y: 2 },),
            Err(InputError::InvalidEvent(_))
        ));
    }

    #[test]
    fn key_uses_reliable_lane() {
        assert_eq!(
            input_lane(&ControlInputEvent::Key {
                key: ControlInputKey::VirtualKey { code: 0x41 },
                pressed: true,
            }),
            ControlInputLane::Reliable
        );
    }

    #[test]
    fn successful_input_clears_lane_last_error_after_recovery() {
        let mut registry =
            ControlInputRegistry::with_injector(FailsOnceInputInjector::new("temporary failure"));
        let session_id = SessionId("recovering-control-session".to_string());
        let key_down = ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x41 },
            pressed: true,
        };

        let failed = registry
            .handle_session_event(&session_id, &key_down)
            .expect_err("first injection should fail");
        assert_eq!(
            failed,
            InputError::Platform("temporary failure".to_string())
        );
        let failed_snapshot = registry.snapshot(session_id.clone());
        assert_eq!(failed_snapshot.reliable.failed_messages, 1);
        assert_eq!(
            failed_snapshot.reliable.last_error.as_deref(),
            Some("platform input injection failed: temporary failure")
        );

        let recovered = registry
            .handle_session_event(&session_id, &key_down)
            .expect("second injection should recover");
        let recovered_snapshot = registry.snapshot(session_id);

        assert_eq!(recovered.event_count, 1);
        assert_eq!(recovered_snapshot.reliable.failed_messages, 1);
        assert_eq!(recovered_snapshot.reliable.injected_messages, 1);
        assert_eq!(recovered_snapshot.reliable.last_error, None);
    }

    #[test]
    fn target_geometry_scales_frame_mouse_move_to_capture_source_coordinates() {
        let event = map_control_input_event_for_target_geometry(
            &ControlInputEvent::MouseMove { x: 640, y: 360 },
            Some(ControlInputTargetGeometry {
                frame_width: 1280,
                frame_height: 720,
                source_width: 2560,
                source_height: 1440,
                origin_x: 0,
                origin_y: 0,
            }),
        );

        assert_eq!(event, ControlInputEvent::MouseMove { x: 1280, y: 720 });
    }

    #[test]
    fn target_geometry_adds_display_origin_and_clamps_to_source_bounds() {
        let event = map_control_input_event_for_target_geometry(
            &ControlInputEvent::MouseMove { x: 1280, y: 720 },
            Some(ControlInputTargetGeometry {
                frame_width: 1280,
                frame_height: 720,
                source_width: 2560,
                source_height: 1440,
                origin_x: 1920,
                origin_y: -120,
            }),
        );

        assert_eq!(event, ControlInputEvent::MouseMove { x: 4479, y: 1319 });
    }

    #[test]
    fn target_geometry_leaves_non_pointer_events_unchanged() {
        let event = ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x41 },
            pressed: true,
        };

        assert_eq!(
            map_control_input_event_for_target_geometry(
                &event,
                Some(ControlInputTargetGeometry {
                    frame_width: 1280,
                    frame_height: 720,
                    source_width: 2560,
                    source_height: 1440,
                    origin_x: 1920,
                    origin_y: 0,
                }),
            ),
            event
        );
    }

    #[test]
    fn authenticated_release_is_scoped_to_pointer_or_keyboard() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = ControlInputRegistry::with_injector(SharedRecordingInputInjector {
            events: events.clone(),
        });
        let session_id = SessionId("scoped-release".to_string());
        registry
            .handle_session_event(
                &session_id,
                &ControlInputEvent::MouseButton {
                    button: ControlInputButton::Left,
                    pressed: true,
                },
            )
            .expect("button down");
        registry
            .handle_session_event(
                &session_id,
                &ControlInputEvent::Key {
                    key: ControlInputKey::VirtualKey { code: 0x41 },
                    pressed: true,
                },
            )
            .expect("key down");

        registry
            .release_session_scope(&session_id, ControlInputScope::Pointer)
            .expect("release pointer scope");
        assert_eq!(
            events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[
                InputEvent::MouseButton {
                    button: InputButton::Left,
                    pressed: true,
                },
                InputEvent::Key {
                    key: InputKey::VirtualKey(0x41),
                    pressed: true,
                },
                InputEvent::MouseButton {
                    button: InputButton::Left,
                    pressed: false,
                },
            ]
        );

        registry
            .release_session_scope(&session_id, ControlInputScope::Keyboard)
            .expect("release keyboard scope");
        assert_eq!(
            events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .last(),
            Some(&InputEvent::Key {
                key: InputKey::VirtualKey(0x41),
                pressed: false,
            })
        );
    }

    #[test]
    fn shared_pressed_key_is_released_only_after_last_session_releases_it() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let mut registry = ControlInputRegistry::with_injector(SharedRecordingInputInjector {
            events: events.clone(),
        });
        let first = SessionId("first-holder".to_string());
        let second = SessionId("second-holder".to_string());
        let key_down = ControlInputEvent::Key {
            key: ControlInputKey::VirtualKey { code: 0x41 },
            pressed: true,
        };
        registry
            .handle_session_event(&first, &key_down)
            .expect("first key down");
        registry
            .handle_session_event(&second, &key_down)
            .expect("second key down");
        registry
            .release_session_scope(&first, ControlInputScope::Keyboard)
            .expect("release first holder");
        assert_eq!(
            events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );

        registry
            .release_session_scope(&second, ControlInputScope::Keyboard)
            .expect("release final holder");
        assert_eq!(
            events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[
                InputEvent::Key {
                    key: InputKey::VirtualKey(0x41),
                    pressed: true,
                },
                InputEvent::Key {
                    key: InputKey::VirtualKey(0x41),
                    pressed: false,
                },
            ]
        );
    }
}
