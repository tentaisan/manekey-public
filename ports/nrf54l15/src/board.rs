use cortex_m::peripheral::NVIC;

pub const USER_KEY: &str = "P0.00";
pub const USER_LED: &str = "P2.00";
pub const SAMD11_UART_RX: &str = "P1.08";
pub const SAMD11_UART_TX: &str = "P1.09";

/// Run before HAL/time-driver initialization with exclusive application GRTC_2 ownership.
pub fn prepare_cmsis_dap_reset() {
    NVIC::mask(embassy_nrf::interrupt::GRTC_2);
    NVIC::unpend(embassy_nrf::interrupt::GRTC_2);

    let grtc = embassy_nrf::pac::GRTC;
    for channel in 0..12 {
        grtc.events_compare(channel).write_value(0);
    }
    grtc.intenclr(2).write(|w| w.0 = 0x0fff);
}
