
pub use manekey::transport::usb::embassy::privileged_pump::{
    generation, receive, receive_ccid, send, send_ccid, take_abort,
};
ra_hal::bind_interrupts!(pub struct Irqs {
    IEL2 => ra_hal::usb::UsbInterruptHandler<ra_hal::peripherals::USBFS>;
});
pub fn start(driver: ra_hal::usb::Usbfs<'static, ra_hal::peripherals::USBFS>) {
    manekey::transport::usb::embassy::privileged_pump::start(
        driver,
        "ManeKey RA4M1 MPU HID CCID",
        "ra4m1-fido",
    );
    // RA HAL 0.3.1 multi-packet bulk needs single buffering, as in the normal profile.
    let r = ra_hal::pac::USBFS;
    for pipe in 1..=9 {
        r.pipesel()
            .modify(|v| v.set_pipesel(ra_hal::pac::usbfs::vals::Pipesel::from_bits(pipe)));
        if r.pipecfg().read().type_() == ra_hal::pac::usbfs::vals::Type::_01 {
            r.pipecfg().modify(|v| v.set_dblb(false));
        }
    }
    r.pipesel()
        .modify(|v| v.set_pipesel(ra_hal::pac::usbfs::vals::Pipesel::from_bits(0)));
}
#[cortex_m_rt::exception]
fn PendSV() {
    manekey::transport::usb::embassy::privileged_pump::pump();
}
