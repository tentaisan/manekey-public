use core::cell::Cell;
use cortex_m::asm;
use nrf52840_pac::Peripherals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Caller supplies a valid port (0 or 1) and pin index below 32.
pub struct BoardPin {
    pub port: u32,
    pub pin: u32,
    pub label: &'static str,
}

impl BoardPin {
    pub const fn new(port: u32, pin: u32, label: &'static str) -> Self {
        Self { port, pin, label }
    }

    pub const fn mask(self) -> u32 {
        1u32 << self.pin
    }

    pub const fn psel(self) -> u32 {
        (self.port << 5) | self.pin
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardProfile {
    pub name: &'static str,
    pub red_led: BoardPin,
    pub uart_tx: BoardPin,
    pub uart_rx: BoardPin,
    pub user_presence: BoardPin,
    pub nfc1: BoardPin,
    pub nfc2: BoardPin,
    pub app_flash_origin: u32,
    pub softdevice_ram_origin: u32,
}

pub const XIAO_NRF52840: BoardProfile = BoardProfile {
    name: "xiao-nrf52840",
    red_led: BoardPin::new(0, 26, "red-led/p0.26"),
    uart_tx: BoardPin::new(1, 11, "d6/p1.11"),
    uart_rx: BoardPin::new(1, 12, "d7/p1.12"),
    user_presence: BoardPin::new(0, 28, "d2/p0.28"),
    nfc1: BoardPin::new(0, 9, "nfc1/p0.09"),
    nfc2: BoardPin::new(0, 10, "nfc2/p0.10"),
    app_flash_origin: 0x0002_7000,
    softdevice_ram_origin: 0x2002_0000,
};

pub const BOARD: BoardProfile = XIAO_NRF52840;

pub fn init_led(peripherals: &Peripherals) {
    let led_mask = BOARD.red_led.mask();
    peripherals.P0.dirset.write(|w| unsafe { w.bits(led_mask) });
    peripherals.P0.outset.write(|w| unsafe { w.bits(led_mask) });
}

pub fn led_on() {
    let led_mask = BOARD.red_led.mask();
    let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
    p0.outclr.write(|w| unsafe { w.bits(led_mask) });
}

pub fn led_off() {
    let led_mask = BOARD.red_led.mask();
    let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
    p0.outset.write(|w| unsafe { w.bits(led_mask) });
}

pub fn blink_stage(count: usize) {
    for _ in 0..count {
        led_on();
        delay();
        led_off();
        delay();
    }
    long_gap();
}

/// Requires exclusive CLOCK ownership without an active SoftDevice; waits without a timeout.
pub fn start_hfclk(peripherals: &Peripherals) {
    peripherals.CLOCK.events_hfclkstarted.reset();
    peripherals
        .CLOCK
        .tasks_hfclkstart
        .write(|w| unsafe { w.bits(1) });
    while peripherals.CLOCK.events_hfclkstarted.read().bits() == 0 {
        asm::nop();
    }
}

/// Requires exclusive CLOCK ownership without an active SoftDevice; waits without a timeout.
pub fn start_lfclk(peripherals: &Peripherals) {
    peripherals
        .CLOCK
        .tasks_lfclkstop
        .write(|w| unsafe { w.bits(1) });
    peripherals.CLOCK.lfclksrc.write(|w| unsafe { w.bits(0) });
    peripherals.CLOCK.events_lfclkstarted.reset();
    peripherals
        .CLOCK
        .tasks_lfclkstart
        .write(|w| unsafe { w.bits(1) });
    while peripherals.CLOCK.events_lfclkstarted.read().bits() == 0 {
        asm::nop();
    }
}

pub fn bootloader_settle_delay() {
    for _ in 0..20_000_000 {
        asm::nop();
    }
}

/// Exclusively reserve UART0 and selected GPIO pins before initialization.
pub fn uart_init() {
    configure_output_high(BOARD.uart_tx);

    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart0.enable.write(|w| unsafe { w.bits(0) });
    uart0
        .psel
        .txd
        .write(|w| unsafe { w.bits(BOARD.uart_tx.psel()) });
    uart0.psel.rxd.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.psel.cts.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.psel.rts.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.baudrate.write(|w| unsafe { w.bits(0x01D7_E000) });
    uart0.config.write(|w| unsafe { w.bits(0) });
    uart0.enable.write(|w| unsafe { w.bits(4) });
    uart0.tasks_starttx.write(|w| unsafe { w.bits(1) });
}

pub fn uart_write_str(s: &str) {
    #[cfg(feature = "nrf-internal-uart")]
    if !crate::internal_uart::logging_enabled() {
        return;
    }
    for byte in s.as_bytes() {
        uart_write_byte(*byte);
    }
}

pub fn uart_init_duplex() {
    uart_init();
    let pin = BOARD.uart_rx;
    if pin.port == 0 {
        let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
        p0.dirclr.write(|w| unsafe { w.bits(pin.mask()) });
        p0.pin_cnf[pin.pin as usize].write(|w| unsafe { w.bits(12) });
    } else {
        let p1 = unsafe { &*nrf52840_pac::P1::ptr() };
        p1.dirclr.write(|w| unsafe { w.bits(pin.mask()) });
        p1.pin_cnf[pin.pin as usize].write(|w| unsafe { w.bits(12) });
    }
    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart0.psel.rxd.write(|w| unsafe { w.bits(pin.psel()) });
    uart0.events_rxdrdy.reset();
    uart0.tasks_startrx.write(|w| unsafe { w.bits(1) });
}

pub fn uart_try_read_byte() -> Option<u8> {
    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    if uart0.events_rxdrdy.read().bits() == 0 {
        return None;
    }
    uart0.events_rxdrdy.reset();
    Some(uart0.rxd.read().bits() as u8)
}

pub fn uart_write_u32(mut value: u32) {
    #[cfg(feature = "nrf-internal-uart")]
    if !crate::internal_uart::logging_enabled() {
        return;
    }
    let mut buf = [0u8; 10];
    let mut len = 0;

    if value == 0 {
        uart_write_byte(b'0');
        return;
    }

    while value != 0 {
        buf[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
    }

    while len != 0 {
        len -= 1;
        uart_write_byte(buf[len]);
    }
}

pub fn configure_output_high(pin: BoardPin) {
    let mask = pin.mask();
    if pin.port == 0 {
        let p0 = unsafe { &*nrf52840_pac::P0::ptr() };
        p0.dirset.write(|w| unsafe { w.bits(mask) });
        p0.outset.write(|w| unsafe { w.bits(mask) });
    } else {
        let p1 = unsafe { &*nrf52840_pac::P1::ptr() };
        p1.dirset.write(|w| unsafe { w.bits(mask) });
        p1.outset.write(|w| unsafe { w.bits(mask) });
    }
}

/// Blocking output without a timeout; caller serializes UART0 access.
pub fn uart_write_byte(byte: u8) {
    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart0.events_txdrdy.reset();
    uart0.txd.write(|w| unsafe { w.bits(byte as u32) });
    while uart0.events_txdrdy.read().bits() == 0 {}
}

fn delay() {
    for _ in 0..700_000 {
        asm::nop();
    }
}

fn long_gap() {
    for _ in 0..2_000_000 {
        asm::nop();
    }
}

/// Single-context GPIO owner; serialize all access, including initialization and interrupts.
pub struct RedLed {
    p0: Cell<Option<nrf52840_pac::P0>>,
    mask: Cell<u32>,
}

unsafe impl Sync for RedLed {}

impl RedLed {
    pub const fn new() -> Self {
        Self {
            p0: Cell::new(None),
            mask: Cell::new(0),
        }
    }

    pub fn init(&self, p0: nrf52840_pac::P0) {
        let mask = BOARD.red_led.mask();
        p0.dirset.write(|w| unsafe { w.bits(mask) });
        p0.outset.write(|w| unsafe { w.bits(mask) });
        self.mask.set(mask);
        self.p0.set(Some(p0));
    }

    pub fn on(&self) {
        if let Some(p0) = self.p0.take() {
            p0.outclr.write(|w| unsafe { w.bits(self.mask.get()) });
            self.p0.set(Some(p0));
        }
    }

    pub fn off(&self) {
        if let Some(p0) = self.p0.take() {
            p0.outset.write(|w| unsafe { w.bits(self.mask.get()) });
            self.p0.set(Some(p0));
        }
    }

    pub fn blink(&self, count: usize) {
        for _ in 0..count {
            self.on();
            medium_led_delay();
            self.off();
            medium_led_delay();
        }
        long_led_delay();
    }

    pub fn success_pulse(&self) {
        self.on();
        long_led_delay();
        self.off();
        long_led_delay();
    }

    pub fn error_fast(&self) -> ! {
        loop {
            self.on();
            short_led_delay();
            self.off();
            short_led_delay();
        }
    }

    pub fn error_slow(&self) -> ! {
        loop {
            self.on();
            long_led_delay();
            self.off();
            short_led_delay();
        }
    }

    pub fn fault_latch(&self) -> ! {
        self.on();
        loop {
            asm::nop();
        }
    }
}

fn short_led_delay() {
    for _ in 0..60_000 {
        asm::nop();
    }
}

fn medium_led_delay() {
    for _ in 0..250_000 {
        asm::nop();
    }
}

fn long_led_delay() {
    for _ in 0..1_200_000 {
        asm::nop();
    }
}
