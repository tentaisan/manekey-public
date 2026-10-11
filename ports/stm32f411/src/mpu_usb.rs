use embassy_stm32::{bind_interrupts, peripherals, usb};
bind_interrupts!(pub struct Irqs { OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>; });
#[cfg(feature = "usb-ccid")]
pub use manekey::transport::usb::embassy::privileged_pump::{
    BulkPacket, receive_ccid, send_ccid, take_abort,
};
pub use manekey::transport::usb::embassy::privileged_pump::{generation, pump, receive, send};
/// Start the privileged USB pump once with exclusive peripheral/IRQ ownership; not an MPU policy installer.
pub fn start(driver: usb::Driver<'static, peripherals::USB_OTG_FS>) {
    manekey::transport::usb::embassy::privileged_pump::start(
        driver,
        "ManeKey F411 MPU experimental",
        "stm32f411-p0",
    );
}
