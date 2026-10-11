use usb_device::{UsbError, bus::UsbBus, class_prelude::UsbClass, device::UsbDevice};
use usbd_hid::hid_class::HIDClass;

use manekey::ctaphid::{Response, descriptor::REPORT_SIZE, framing::for_each_response_report};

pub use manekey::ctaphid::descriptor::REPORT_DESCRIPTOR as CTAPHID_REPORT_DESCRIPTOR;

/// Enqueue framed reports under exclusive USB ownership; no host receipt acknowledgement or timeout is provided.
pub fn write_response<B: UsbBus>(
    usb_dev: &mut UsbDevice<'_, B>,
    hid: &mut HIDClass<'_, B>,
    response: Response<'_>,
) {
    let _ = for_each_response_report(response, |packet| {
        push_packet(usb_dev, hid, packet);
        Ok::<(), ()>(())
    });

    for _ in 0..256 {
        let _ = usb_dev.poll(&mut [hid as &mut dyn UsbClass<B>]);
        core::hint::spin_loop();
    }
}

/// Poll while the IN endpoint blocks; fatal errors return without reporting delivery failure.
pub fn push_packet<B: UsbBus>(
    usb_dev: &mut UsbDevice<'_, B>,
    hid: &mut HIDClass<'_, B>,
    packet: &[u8; REPORT_SIZE],
) {
    loop {
        match hid.push_raw_input(packet) {
            Ok(_) => return,
            Err(UsbError::WouldBlock) => {
                let _ = usb_dev.poll(&mut [hid as &mut dyn UsbClass<B>]);
            }
            Err(_) => return,
        }
    }
}
