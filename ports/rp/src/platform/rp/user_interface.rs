#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
use embedded_hal::digital::OutputPin;
#[cfg(any(
    all(
        any(feature = "chip-rp2040", feature = "chip-rp235xa"),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
use manekey::presence::PresenceUiHint;
use manekey::presence::{
    DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS, PresenceInputInfo,
    PresenceStatus, TimedPresenceConfig, TimedPresenceState, UserPresence, UserPresenceInput,
};
#[cfg(any(
    all(
        any(feature = "chip-rp2040", feature = "chip-rp235xa"),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
use manekey::user_interface::UiStatusOutput;
#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
use manekey::user_interface::{ButtonInput, TimedButtonPresence, UiClock};

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
const RP_ARM_GPIO15_PRESENCE_CONFIG: TimedPresenceConfig = TimedPresenceConfig::low_active_button(
    "gpio15",
    DEFAULT_GPIO_PRESENCE_STABLE_MILLIS * 1_000,
    DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS * 1_000_000,
);

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
/// Low-active GPIO presence with microsecond timing; legacy level queries do not imply debounce.
pub struct GpioUserPresence<'d> {
    button: embassy_rp::gpio::Input<'d>,
    state: TimedPresenceState,
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> GpioUserPresence<'d> {
    pub fn new(button: embassy_rp::gpio::Input<'d>) -> Self {
        Self {
            button,
            state: RP_ARM_GPIO15_PRESENCE_CONFIG.state(),
        }
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl UserPresence for GpioUserPresence<'_> {
    fn is_present(&mut self) -> bool {
        self.button.is_low()
    }

    fn begin_wait(&mut self) {
        self.state
            .begin_wait(embassy_time::Instant::now().as_micros());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state.poll(
            embassy_time::Instant::now().as_micros(),
            self.button.is_low(),
        )
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || self.button.is_low()
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl UserPresenceInput for GpioUserPresence<'_> {
    fn input_info(&self) -> PresenceInputInfo {
        RP_ARM_GPIO15_PRESENCE_CONFIG.input_info
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
pub const RP2350_RISCV_GPIO15_PRESENCE_CONFIG: TimedPresenceConfig =
    TimedPresenceConfig::low_active_button(
        "gpio15",
        DEFAULT_GPIO_PRESENCE_STABLE_MILLIS * 1_000,
        DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS * 1_000_000,
    );

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
pub const RP2350_RISCV_BOOTSEL_PRESENCE_CONFIG: TimedPresenceConfig =
    TimedPresenceConfig::low_active_button(
        "BOOTSEL",
        DEFAULT_GPIO_PRESENCE_STABLE_MILLIS * 1_000,
        60 * 1_000_000,
    );

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
/// TIMER0-based BOOTSEL presence; requires single-hart XIP ownership throughout sampling.
pub struct RiscvBootselPresence {
    state: TimedPresenceState,
}

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvBootselPresence {
    pub const fn new() -> Self {
        Self {
            state: RP2350_RISCV_BOOTSEL_PRESENCE_CONFIG.state(),
        }
    }

    fn now_us() -> u64 {
        let timer = unsafe { &*rp235x_hal::pac::TIMER0::ptr() };
        let mut high = timer.timerawh().read().bits();
        loop {
            let low = timer.timerawl().read().bits();
            let next_high = timer.timerawh().read().bits();
            if high == next_high {
                return (u64::from(high) << 32) | u64::from(low);
            }
            high = next_high;
        }
    }

    fn button_pressed() -> bool {
        riscv_bootsel_pressed_single_hart()
    }
}

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
impl UserPresence for RiscvBootselPresence {
    fn is_present(&mut self) -> bool {
        Self::button_pressed()
    }

    fn begin_wait(&mut self) {
        self.state.begin_wait(Self::now_us());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state.poll(Self::now_us(), Self::button_pressed())
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || Self::button_pressed()
    }
}

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
impl UserPresenceInput for RiscvBootselPresence {
    fn input_info(&self) -> PresenceInputInfo {
        RP2350_RISCV_BOOTSEL_PRESENCE_CONFIG.input_info
    }
}

#[cfg(all(
    feature = "riscv-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
/// RAM-resident QSPI sampler; caller must exclude other-hart, DMA and debugger XIP reads.
/// Keep RAM placement intact; local interrupt masking alone does not provide this exclusion.
pub fn riscv_bootsel_pressed_single_hart() -> bool {
    const QSPI_SS_STATUS: usize = 0x4003_0018;
    const QSPI_SS_CTRL: usize = QSPI_SS_STATUS + 4;
    const OEOVER_MASK: u32 = 0b11 << 14;
    const OEOVER_DISABLE: u32 = 0b10 << 14;

    const MSTATUS_MIE: usize = 1 << 3;

    let status: u32;
    let previous_mstatus: usize;
    unsafe {
        core::arch::asm!(
            "csrrc {previous}, mstatus, {mie}",
            previous = out(reg) previous_mstatus,
            mie = in(reg) MSTATUS_MIE,
            options(nomem, nostack)
        );
        core::arch::asm!(
            "lw {original}, 0({ctrl})",
            "and {disabled}, {original}, {clear_mask}",
            "or {disabled}, {disabled}, {disable}",
            "sw {disabled}, 0({ctrl})",
            "fence iorw, iorw",
            "1:",
            "addi {delay}, {delay}, -1",
            "bnez {delay}, 1b",
            "lw {status}, 0({status_addr})",
            "sw {original}, 0({ctrl})",
            "fence iorw, iorw",
            ctrl = in(reg) QSPI_SS_CTRL,
            status_addr = in(reg) QSPI_SS_STATUS,
            clear_mask = in(reg) !OEOVER_MASK,
            disable = in(reg) OEOVER_DISABLE,
            original = out(reg) _,
            disabled = out(reg) _,
            delay = inout(reg) 8192_u32 => _,
            status = out(reg) status,
            options(nostack),
        );
        if previous_mstatus & MSTATUS_MIE != 0 {
            core::arch::asm!(
                "csrs mstatus, {mie}",
                mie = in(reg) MSTATUS_MIE,
                options(nomem, nostack)
            );
        }
    }
    status & (1 << 17) == 0
}

#[cfg(all(
    feature = "riscv-pmp-trusted-bootsel-presence",
    target_arch = "riscv32",
    target_os = "none"
))]
/// BOOTSEL adapter with the same exclusive XIP sampling requirements.
pub type RiscvPmpBootselPresence = RiscvBootselPresence;

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
/// Low-active GPIO presence using TIMER0 microseconds; input errors are treated as unpressed.
pub struct RiscvGpioUserPresence<P> {
    button: P,
    timer: rp235x_hal::timer::Timer<rp235x_hal::timer::CopyableTimer0>,
    state: TimedPresenceState,
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl<P> RiscvGpioUserPresence<P> {
    pub fn new(
        button: P,
        timer: rp235x_hal::timer::Timer<rp235x_hal::timer::CopyableTimer0>,
    ) -> Self {
        Self {
            button,
            timer,
            state: RP2350_RISCV_GPIO15_PRESENCE_CONFIG.state(),
        }
    }

    fn now_us(&self) -> u64 {
        self.timer.get_counter().ticks()
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl<P: embedded_hal::digital::InputPin> UserPresence for RiscvGpioUserPresence<P> {
    fn is_present(&mut self) -> bool {
        self.button.is_low().unwrap_or(false)
    }

    fn begin_wait(&mut self) {
        self.state.begin_wait(self.now_us());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state
            .poll(self.now_us(), self.button.is_low().unwrap_or(false))
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || self.button.is_low().unwrap_or(false)
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl<P: embedded_hal::digital::InputPin> UserPresenceInput for RiscvGpioUserPresence<P> {
    fn input_info(&self) -> PresenceInputInfo {
        RP2350_RISCV_GPIO15_PRESENCE_CONFIG.input_info
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
/// Exclusive BOOTSEL owner using the HAL's QSPI sampling contract.
pub struct RpBootselButton {
    bootsel: embassy_rp::Peri<'static, embassy_rp::peripherals::BOOTSEL>,
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl ButtonInput for RpBootselButton {
    fn is_pressed(&mut self) -> bool {
        embassy_rp::bootsel::is_bootsel_pressed(self.bootsel.reborrow())
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
/// Microsecond clock for timed presence configuration.
pub struct RpEmbassyUiClock;

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl UiClock for RpEmbassyUiClock {
    fn now(&mut self) -> u64 {
        embassy_time::Instant::now().as_micros()
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
/// Timed BOOTSEL input; durations are expressed in microseconds.
pub type RpBootselPresence = TimedButtonPresence<RpBootselButton, RpEmbassyUiClock>;

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
pub const RP_BOOTSEL_PRESENCE_TIMEOUT_SECS: u64 = 60;

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
pub fn rp_bootsel_presence(
    bootsel: embassy_rp::Peri<'static, embassy_rp::peripherals::BOOTSEL>,
) -> RpBootselPresence {
    const CONFIG: TimedPresenceConfig = TimedPresenceConfig::low_active_button(
        "BOOTSEL",
        DEFAULT_GPIO_PRESENCE_STABLE_MILLIS * 1_000,
        RP_BOOTSEL_PRESENCE_TIMEOUT_SECS * 1_000_000,
    );
    TimedButtonPresence::new(RpBootselButton { bootsel }, RpEmbassyUiClock, CONFIG)
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
static CORE0_BOOTSEL_PRESSED: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
static CORE0_BOOTSEL_WAITING: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
const CORE0_BOOTSEL_CONFIG: TimedPresenceConfig = TimedPresenceConfig::low_active_button(
    "BOOTSEL",
    DEFAULT_GPIO_PRESENCE_STABLE_MILLIS * 1_000,
    RP_BOOTSEL_PRESENCE_TIMEOUT_SECS * 1_000_000,
);

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
/// Single core1 consumer of core0 BOOTSEL samples; requires the core0 sampler task and HAL XIP exclusion.
pub struct Core0BootselPresence {
    state: TimedPresenceState,
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
pub fn core0_bootsel_presence() -> Core0BootselPresence {
    Core0BootselPresence {
        state: CORE0_BOOTSEL_CONFIG.state(),
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
impl Core0BootselPresence {
    fn now() -> u64 {
        embassy_time::Instant::now().as_micros()
    }

    fn pressed() -> bool {
        CORE0_BOOTSEL_PRESSED.load(Ordering::Acquire)
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
impl UserPresence for Core0BootselPresence {
    fn is_present(&mut self) -> bool {
        Self::pressed()
    }

    fn begin_wait(&mut self) {
        CORE0_BOOTSEL_PRESSED.store(false, Ordering::Release);
        self.state.begin_wait(Self::now());
        CORE0_BOOTSEL_WAITING.store(true, Ordering::Release);
    }

    fn poll(&mut self) -> PresenceStatus {
        let status = self.state.poll(Self::now(), Self::pressed());
        if !matches!(status, PresenceStatus::Pending) {
            CORE0_BOOTSEL_WAITING.store(false, Ordering::Release);
        }
        status
    }

    fn cancel(&mut self) {
        CORE0_BOOTSEL_WAITING.store(false, Ordering::Release);
        CORE0_BOOTSEL_PRESSED.store(false, Ordering::Release);
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || Self::pressed()
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
impl UserPresenceInput for Core0BootselPresence {
    fn input_info(&self) -> PresenceInputInfo {
        CORE0_BOOTSEL_CONFIG.input_info
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    feature = "dual-core-transport",
    feature = "up-bootsel-experimental",
    target_arch = "arm",
    target_os = "none"
))]
#[embassy_executor::task]
pub async fn sample_bootsel_on_core0(
    mut bootsel: embassy_rp::Peri<'static, embassy_rp::peripherals::BOOTSEL>,
) {
    loop {
        if CORE0_BOOTSEL_WAITING.load(Ordering::Acquire) {
            let pressed = embassy_rp::bootsel::is_bootsel_pressed(bootsel.reborrow());
            CORE0_BOOTSEL_PRESSED.store(pressed, Ordering::Release);
            embassy_time::Timer::after_millis(5).await;
        } else {
            CORE0_BOOTSEL_PRESSED.store(false, Ordering::Release);
            embassy_time::Timer::after_millis(10).await;
        }
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
/// Exclusive GPIO25 LED output; not the wireless board's CYW43 LED.
pub struct RpGpio25Led {
    output: embassy_rp::gpio::Output<'static>,
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl RpGpio25Led {
    pub fn new(pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>) -> Self {
        Self {
            output: embassy_rp::gpio::Output::new(pin, embassy_rp::gpio::Level::Low),
        }
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl UiStatusOutput for RpGpio25Led {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        self.output
            .set_level(matches!(hint, PresenceUiHint::TouchRequired).into());
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
/// Exclusive GPIO25 LED output using the RISC-V HAL.
pub struct RiscvGpio25Led {
    output: rp235x_hal::gpio::Pin<
        rp235x_hal::gpio::bank0::Gpio25,
        rp235x_hal::gpio::FunctionSioOutput,
        rp235x_hal::gpio::PullDown,
    >,
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvGpio25Led {
    pub fn new(
        output: rp235x_hal::gpio::Pin<
            rp235x_hal::gpio::bank0::Gpio25,
            rp235x_hal::gpio::FunctionSioOutput,
            rp235x_hal::gpio::PullDown,
        >,
    ) -> Self {
        Self { output }
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl UiStatusOutput for RiscvGpio25Led {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        if matches!(hint, PresenceUiHint::TouchRequired) {
            let _ = self.output.set_high();
        } else {
            let _ = self.output.set_low();
        }
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
/// Dedicated SIO bit 25 output; core0 must initialize its pad and reserve it against competing writers.
pub struct RiscvSioGpio25Led;

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvSioGpio25Led {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl UiStatusOutput for RiscvSioGpio25Led {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        let sio = unsafe { &*rp235x_hal::pac::SIO::ptr() };
        if matches!(hint, PresenceUiHint::TouchRequired) {
            sio.gpio_out_set().write(|w| unsafe { w.bits(1 << 25) });
        } else {
            sio.gpio_out_clr().write(|w| unsafe { w.bits(1 << 25) });
        }
    }
}
