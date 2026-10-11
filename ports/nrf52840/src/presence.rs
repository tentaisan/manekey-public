#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::presence::{
    PollCountPresenceConfig, PollCountPresenceState, PresenceInputInfo, PresenceStatus,
    PresenceUiHint, UserPresence, UserPresenceInput, write_presence_input_info,
};
use manekey::user_interface::{TouchPromptLed, UiStatusOutput};

use crate::board::BOARD;

use crate::board::{led_off, led_on};

pub const USB_UP_TIMEOUT_POLLS: u32 = 10_000_000;

pub const BLE_UP_TIMEOUT_POLLS: u32 = 150;
const UP_STABLE_POLLS: u32 = 1;

const fn board_presence_config(
    release_before_press: bool,
    timeout_polls: u32,
) -> PollCountPresenceConfig {
    let config = PollCountPresenceConfig::low_active_button(
        BOARD.user_presence.label,
        UP_STABLE_POLLS,
        timeout_polls,
    );
    if release_before_press {
        config.requiring_release_before_press()
    } else {
        config
    }
}

/// Exclusive GPIO presence owner; timeout values count polls, not milliseconds.
/// LED state is a prompt, not proof of authorization.
pub struct NrfGpioUserPresence {
    log: fn(&str),
    state: PollCountPresenceState,
    waiting: bool,
    last_pin_low: bool,
    release_before_press: bool,
    prompt_led: Option<TouchPromptLed>,
}

#[cfg(feature = "up-always-present")]
pub type SelectedUserPresence = AlwaysPresent;

#[cfg(not(feature = "up-always-present"))]
pub type SelectedUserPresence = NrfGpioUserPresence;

#[cfg(feature = "up-always-present")]
pub fn selected_user_presence(
    _log: fn(&str),
    _release_before_press: bool,
    _timeout_polls: u32,
) -> SelectedUserPresence {
    AlwaysPresent
}

#[cfg(not(feature = "up-always-present"))]
pub fn selected_user_presence(
    log: fn(&str),
    release_before_press: bool,
    timeout_polls: u32,
) -> SelectedUserPresence {
    NrfGpioUserPresence::new(log, release_before_press, timeout_polls)
}

#[cfg(feature = "up-always-present")]
pub fn configure_selected_user_presence(log: fn(&str)) {
    write_presence_input_info(PresenceInputInfo::always_present(), log);
}

#[cfg(not(feature = "up-always-present"))]
pub fn configure_selected_user_presence(log: fn(&str)) {
    NrfGpioUserPresence::configure_board_pullup();

    write_presence_input_info(
        board_presence_config(false, USB_UP_TIMEOUT_POLLS).input_info,
        log,
    );
    log("up pin initial=");
    log(if NrfGpioUserPresence::pin_low() {
        "low\r\n"
    } else {
        "high\r\n"
    });
}

impl NrfGpioUserPresence {
    pub const fn new(log: fn(&str), release_before_press: bool, timeout_polls: u32) -> Self {
        Self {
            log,
            state: board_presence_config(release_before_press, timeout_polls).state(),
            waiting: false,
            last_pin_low: false,
            release_before_press,
            prompt_led: if release_before_press {
                Some(TouchPromptLed::new(led_on, led_off))
            } else {
                None
            },
        }
    }

    pub fn configure_board_pullup() {
        let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
        p0.dirclr
            .write(|w| unsafe { w.bits(BOARD.user_presence.mask()) });
        p0.pin_cnf[BOARD.user_presence.pin as usize].write(|w| {
            w.dir()
                .input()
                .input()
                .connect()
                .pull()
                .pullup()
                .drive()
                .s0s1()
                .sense()
                .disabled()
        });
    }

    pub fn pin_low() -> bool {
        let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
        p0.in_.read().bits() & BOARD.user_presence.mask() == 0
    }

    fn log(&self, message: &str) {
        (self.log)(message);
    }

    fn show_prompt(&mut self, ready: bool) {
        if let Some(output) = &mut self.prompt_led {
            output.set_ui_hint(if ready {
                PresenceUiHint::TouchRequired
            } else {
                PresenceUiHint::Idle
            });
        }
    }
}

impl UserPresence for NrfGpioUserPresence {
    fn is_present(&mut self) -> bool {
        if self.release_before_press {
            self.state.is_confirmed()
        } else {
            Self::pin_low()
        }
    }

    fn begin_wait(&mut self) {
        self.waiting = true;
        self.state.begin_wait();
        self.show_prompt(false);

        self.log("up wait begin state=");
        self.log(if Self::pin_low() {
            "low\r\n"
        } else {
            "high\r\n"
        });
    }

    fn poll(&mut self) -> PresenceStatus {
        if !self.waiting {
            self.begin_wait();
        }

        let pin_low = Self::pin_low();
        if pin_low != self.last_pin_low {
            self.last_pin_low = pin_low;
            self.log("up pin change=");
            self.log(if pin_low { "low\r\n" } else { "high\r\n" });
        }

        let was_confirmed = self.state.is_confirmed();
        let status = self.state.poll(pin_low);
        self.show_prompt(status == PresenceStatus::Pending && self.state.ready_for_press());
        if status == PresenceStatus::Confirmed && !was_confirmed {
            self.log("up confirmed\r\n");
        }
        if status == PresenceStatus::TimedOut {
            self.log("up timeout\r\n");
        }
        status
    }

    fn cancel(&mut self) {
        self.waiting = false;
        self.state.cancel();
        self.show_prompt(false);
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || (!self.release_before_press && Self::pin_low())
    }
}

impl UserPresenceInput for NrfGpioUserPresence {
    fn input_info(&self) -> PresenceInputInfo {
        board_presence_config(self.release_before_press, USB_UP_TIMEOUT_POLLS).input_info
    }
}
