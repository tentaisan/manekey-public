use rp235x_hal as hal;

/// M-mode exclusive SHA initialization before backend construction; reset wait has no timeout.
pub(super) fn bring_up_sha256(resets: &mut hal::pac::RESETS) {
    resets.reset().modify(|_, w| w.sha256().set_bit());
    resets.reset().modify(|_, w| w.sha256().clear_bit());
    while resets.reset_done().read().sha256().bit_is_clear() {
        core::hint::spin_loop();
    }
}
