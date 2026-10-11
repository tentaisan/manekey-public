const LED25_MASK: u32 = 1 << 25;

pub const TRAP_ENTRY_VISIBLE_DELAY: u32 = 200_000_000;
const ERROR_BLINK_DELAY: u32 = 2_000_000;

/// Terminal failure loop using initialized GPIO25; not the wireless board's CYW43 status LED.
pub fn blink_unexpected_trap() -> ! {
    led_off_raw();
    spin_delay(TRAP_ENTRY_VISIBLE_DELAY);
    loop {
        led_on_raw();
        spin_delay(ERROR_BLINK_DELAY);
        led_off_raw();
        spin_delay(ERROR_BLINK_DELAY);
    }
}

pub fn led_on_raw() {
    unsafe {
        (&*rp235x_hal::pac::SIO::ptr())
            .gpio_out_set()
            .write(|w| w.bits(LED25_MASK));
    }
}

pub fn led_off_raw() {
    unsafe {
        (&*rp235x_hal::pac::SIO::ptr())
            .gpio_out_clr()
            .write(|w| w.bits(LED25_MASK));
    }
}

pub fn spin_delay(iterations: u32) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}
