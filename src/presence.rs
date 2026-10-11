mod manual;
pub use manual::ManualPresenceState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceStatus {
    Pending,

    Confirmed,

    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceInputKind {
    AlwaysPresent,

    PhysicalButton,

    VirtualButton,

    Other,
}

impl PresenceInputKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AlwaysPresent => "always-present",
            Self::PhysicalButton => "physical-button",
            Self::VirtualButton => "virtual-button",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceActiveLevel {
    LevelIndependent,

    ActiveHigh,

    ActiveLow,

    Unknown,
}

impl PresenceActiveLevel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LevelIndependent => "level-independent",
            Self::ActiveHigh => "active-high",
            Self::ActiveLow => "active-low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Adapter-declared metadata, not proof of a physical action or trusted input source.
pub struct PresenceInputInfo {
    pub kind: PresenceInputKind,

    pub active_level: PresenceActiveLevel,

    pub label: &'static str,

    pub has_debounce: bool,

    pub has_timeout: bool,
}

impl PresenceInputInfo {
    pub const fn always_present() -> Self {
        Self {
            kind: PresenceInputKind::AlwaysPresent,
            active_level: PresenceActiveLevel::LevelIndependent,
            label: "always-present",
            has_debounce: false,
            has_timeout: false,
        }
    }

    pub const fn virtual_button(label: &'static str) -> Self {
        Self {
            kind: PresenceInputKind::VirtualButton,
            active_level: PresenceActiveLevel::LevelIndependent,
            label,
            has_debounce: false,
            has_timeout: false,
        }
    }

    pub const fn low_active_button(
        label: &'static str,
        has_debounce: bool,
        has_timeout: bool,
    ) -> Self {
        Self {
            kind: PresenceInputKind::PhysicalButton,
            active_level: PresenceActiveLevel::ActiveLow,
            label,
            has_debounce,
            has_timeout,
        }
    }

    pub const fn unknown() -> Self {
        Self {
            kind: PresenceInputKind::Other,
            active_level: PresenceActiveLevel::Unknown,
            label: "unknown",
            has_debounce: false,
            has_timeout: false,
        }
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub fn write_presence_input_info(info: PresenceInputInfo, write: fn(&str)) {
    write("up input kind=");
    write(info.kind.label());
    write(" label=");
    write(info.label);
    write(" active=");
    write(info.active_level.label());
    write(" debounce=");
    write(bool_label(info.has_debounce));
    write(" timeout=");
    write(bool_label(info.has_timeout));
    write("\r\n");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceReason {
    MakeCredential,

    GetAssertion,

    Reset,

    Other,
}

impl PresenceReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::MakeCredential => "makeCredential",
            Self::GetAssertion => "getAssertion",
            Self::Reset => "reset",
            Self::Other => "other",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceUiHint {
    Idle,

    TouchRequired,

    TouchConfirmed,

    Attention,
}

impl PresenceUiHint {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::TouchRequired => "touch-required",
            Self::TouchConfirmed => "touch-confirmed",
            Self::Attention => "attention",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceUserAction {
    None,

    PressOrHold,

    ReleaseAllowed,

    StopWaiting,
}

impl PresenceUserAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PressOrHold => "press-or-hold",
            Self::ReleaseAllowed => "release-allowed",
            Self::StopWaiting => "stop-waiting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceEvent {
    WaitStarted {
        reason: PresenceReason,
        ui_hint: PresenceUiHint,
    },

    Confirmed {
        reason: PresenceReason,
        ui_hint: PresenceUiHint,
    },

    TimedOut {
        reason: PresenceReason,
        ui_hint: PresenceUiHint,
    },

    Cancelled {
        reason: PresenceReason,
        ui_hint: PresenceUiHint,
    },
}

impl PresenceEvent {
    pub const fn label(self) -> &'static str {
        match self {
            Self::WaitStarted { .. } => "wait-started",
            Self::Confirmed { .. } => "confirmed",
            Self::TimedOut { .. } => "timed-out",
            Self::Cancelled { .. } => "cancelled",
        }
    }

    pub const fn reason(self) -> PresenceReason {
        match self {
            Self::WaitStarted { reason, .. }
            | Self::Confirmed { reason, .. }
            | Self::TimedOut { reason, .. }
            | Self::Cancelled { reason, .. } => reason,
        }
    }

    pub const fn ui_hint(self) -> PresenceUiHint {
        match self {
            Self::WaitStarted { ui_hint, .. }
            | Self::Confirmed { ui_hint, .. }
            | Self::TimedOut { ui_hint, .. }
            | Self::Cancelled { ui_hint, .. } => ui_hint,
        }
    }

    pub const fn user_action(self) -> PresenceUserAction {
        match self {
            Self::WaitStarted { .. } => PresenceUserAction::PressOrHold,
            Self::Confirmed { .. } => PresenceUserAction::ReleaseAllowed,
            Self::TimedOut { .. } | Self::Cancelled { .. } => PresenceUserAction::StopWaiting,
        }
    }
}

pub fn presence_user_message(event: PresenceEvent, button_label: &str) -> heapless::String<96> {
    use core::fmt::Write;

    let mut message = heapless::String::new();
    match event.user_action() {
        PresenceUserAction::None => {
            let _ = write!(message, "No user-presence action is required.");
        }
        PresenceUserAction::PressOrHold => {
            let _ = write!(
                message,
                "Press and hold {button_label} for {}.",
                event.reason().label()
            );
        }
        PresenceUserAction::ReleaseAllowed => {
            let _ = write!(message, "You can release {button_label}.");
        }
        PresenceUserAction::StopWaiting => {
            let _ = write!(message, "Stop waiting for {button_label}.");
        }
    }
    message
}

pub trait PresenceObserver {
    fn on_presence_event(&mut self, event: PresenceEvent);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoPresenceObserver;

impl PresenceObserver for NoPresenceObserver {
    fn on_presence_event(&mut self, _event: PresenceEvent) {}
}

#[derive(Clone, Copy)]
pub struct TextPresenceObserver {
    write: fn(&str),
}

impl TextPresenceObserver {
    pub const fn new(write: fn(&str)) -> Self {
        Self { write }
    }
}

impl PresenceObserver for TextPresenceObserver {
    fn on_presence_event(&mut self, event: PresenceEvent) {
        (self.write)("up ");
        (self.write)(event.label());
        (self.write)(" reason=");
        (self.write)(event.reason().label());
        (self.write)(" hint=");
        (self.write)(event.ui_hint().label());
        (self.write)(" action=");
        (self.write)(event.user_action().label());
        (self.write)("\r\n");
    }
}

#[cfg(feature = "defmt-log")]
#[derive(Clone, Copy, Debug, Default)]
pub struct DefmtPresenceObserver;

#[cfg(feature = "defmt-log")]
impl PresenceObserver for DefmtPresenceObserver {
    fn on_presence_event(&mut self, event: PresenceEvent) {
        defmt::info!(
            "up {} reason={} hint={} action={}",
            event.label(),
            event.reason().label(),
            event.ui_hint().label(),
            event.user_action().label(),
        );
    }
}

/// Presence provider; poll must not block cancellation processing.
pub trait UserPresence {
    fn is_present(&mut self) -> bool;

    fn begin_wait(&mut self) {}

    fn poll(&mut self) -> PresenceStatus {
        if self.is_present() {
            PresenceStatus::Confirmed
        } else {
            PresenceStatus::Pending
        }
    }

    fn cancel(&mut self) {}

    fn wait_for_presence(&mut self) -> bool {
        self.is_present()
    }
}

pub trait UserPresenceInput: UserPresence {
    fn input_info(&self) -> PresenceInputInfo {
        PresenceInputInfo::unknown()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollCountPresenceConfig {
    pub stable_polls_required: u32,
    pub timeout_polls: u32,
    pub input_info: PresenceInputInfo,
    release_before_press: bool,
}

impl PollCountPresenceConfig {
    pub const fn low_active_button(
        label: &'static str,
        stable_polls_required: u32,
        timeout_polls: u32,
    ) -> Self {
        Self {
            stable_polls_required,
            timeout_polls,
            input_info: PresenceInputInfo::low_active_button(label, true, true),
            release_before_press: false,
        }
    }

    pub const fn requiring_release_before_press(mut self) -> Self {
        self.release_before_press = true;
        self
    }

    pub const fn state(self) -> PollCountPresenceState {
        let state = PollCountPresenceState::new(self.stable_polls_required, self.timeout_polls);
        if self.release_before_press {
            state.requiring_release_before_press()
        } else {
            state
        }
    }
}

#[derive(Clone, Copy, Debug)]
/// Debounce/timeout in caller-controlled poll counts, not elapsed time.
/// Caller ends the wait on TimedOut; timeout is not latched internally.
pub struct PollCountPresenceState {
    stable_polls_required: u32,
    timeout_polls: u32,
    stable_polls: u32,
    waited_polls: u32,
    confirmed: bool,
    release_before_press: bool,
    released: bool,
}

impl PollCountPresenceState {
    pub const fn new(stable_polls_required: u32, timeout_polls: u32) -> Self {
        Self {
            stable_polls_required,
            timeout_polls,
            stable_polls: 0,
            waited_polls: 0,
            confirmed: false,
            release_before_press: false,
            released: true,
        }
    }

    pub const fn requiring_release_before_press(mut self) -> Self {
        self.release_before_press = true;
        self.released = false;
        self
    }

    pub fn begin_wait(&mut self) {
        self.stable_polls = 0;
        self.waited_polls = 0;
        self.confirmed = false;
        self.released = !self.release_before_press;
    }

    pub fn poll(&mut self, active: bool) -> PresenceStatus {
        if self.confirmed {
            return PresenceStatus::Confirmed;
        }

        if !active {
            self.released = true;
        }

        if active && self.released {
            self.stable_polls = self
                .stable_polls
                .saturating_add(1)
                .min(self.stable_polls_required);
            if self.stable_polls >= self.stable_polls_required {
                self.confirmed = true;
                return PresenceStatus::Confirmed;
            }
        } else {
            self.stable_polls = 0;
        }

        self.waited_polls = self.waited_polls.saturating_add(1);
        if self.waited_polls >= self.timeout_polls {
            PresenceStatus::TimedOut
        } else {
            PresenceStatus::Pending
        }
    }

    pub fn cancel(&mut self) {
        self.begin_wait();
    }

    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    pub const fn ready_for_press(&self) -> bool {
        self.released && !self.confirmed
    }
}

#[derive(Clone, Copy, Debug)]
/// Uses caller-supplied monotonic ticks in one consistent unit.
/// Caller ends the wait on TimedOut; backwards ticks are not independently rejected.
pub struct TimedPresenceState {
    stable_ticks_required: u64,
    timeout_ticks: u64,
    wait_started: Option<u64>,
    stable_since: Option<u64>,
    confirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedPresenceConfig {
    pub stable_ticks_required: u64,
    pub timeout_ticks: u64,
    pub input_info: PresenceInputInfo,
}

impl TimedPresenceConfig {
    pub const fn low_active_button(
        label: &'static str,
        stable_ticks_required: u64,
        timeout_ticks: u64,
    ) -> Self {
        Self {
            stable_ticks_required,
            timeout_ticks,
            input_info: PresenceInputInfo::low_active_button(label, true, true),
        }
    }

    pub const fn state(self) -> TimedPresenceState {
        TimedPresenceState::new(self.stable_ticks_required, self.timeout_ticks)
    }
}

impl TimedPresenceState {
    pub const fn new(stable_ticks_required: u64, timeout_ticks: u64) -> Self {
        Self {
            stable_ticks_required,
            timeout_ticks,
            wait_started: None,
            stable_since: None,
            confirmed: false,
        }
    }

    pub fn begin_wait(&mut self, now: u64) {
        self.wait_started = Some(now);
        self.stable_since = None;
        self.confirmed = false;
    }

    pub fn poll(&mut self, now: u64, active: bool) -> PresenceStatus {
        if self.confirmed {
            return PresenceStatus::Confirmed;
        }

        let start = *self.wait_started.get_or_insert(now);
        if active {
            let stable_start = *self.stable_since.get_or_insert(now);
            if now.saturating_sub(stable_start) >= self.stable_ticks_required {
                self.confirmed = true;
                return PresenceStatus::Confirmed;
            }
        } else {
            self.stable_since = None;
        }

        if now.saturating_sub(start) >= self.timeout_ticks {
            PresenceStatus::TimedOut
        } else {
            PresenceStatus::Pending
        }
    }

    pub fn cancel(&mut self) {
        self.wait_started = None;
        self.stable_since = None;
        self.confirmed = false;
    }

    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

pub const DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS: u64 = 10;

pub const DEFAULT_GPIO_PRESENCE_STABLE_MILLIS: u64 = 30;

/// Bypasses physical confirmation; test/maintenance only, never real credentials.
pub struct AlwaysPresent;

impl UserPresence for AlwaysPresent {
    fn is_present(&mut self) -> bool {
        true
    }
}

impl UserPresenceInput for AlwaysPresent {
    fn input_info(&self) -> PresenceInputInfo {
        PresenceInputInfo::always_present()
    }
}

/// Currently confirms presence without a physical user action.
pub struct VirtualUserPresence {
    label: &'static str,
}

impl VirtualUserPresence {
    pub const fn new(label: &'static str) -> Self {
        Self { label }
    }
}

impl UserPresence for VirtualUserPresence {
    fn is_present(&mut self) -> bool {
        true
    }
}

impl UserPresenceInput for VirtualUserPresence {
    fn input_info(&self) -> PresenceInputInfo {
        PresenceInputInfo::virtual_button(self.label)
    }
}
