use cortex_m::asm;
use manekey::ctaphid::{
    Response,
    descriptor::{
        REPORT_DESCRIPTOR as CTAPHID_REPORT_DESCRIPTOR, REPORT_SIZE as CTAPHID_REPORT_SIZE,
        REPORT_SIZE_U16 as CTAPHID_REPORT_SIZE_U16,
    },
    framing::{for_each_message_report, for_each_response_report},
};
use nrf_usbd::UsbPeripheral;
use nrf52840_pac::USBD;
use usb_device::{
    UsbError,
    bus::{UsbBus, UsbBusAllocator},
    class_prelude::{
        ControlIn, ControlOut, DescriptorWriter, EndpointIn, EndpointOut, InterfaceNumber, UsbClass,
    },
    control,
    device::UsbDevice,
    endpoint::EndpointAddress,
};

const USB_CLASS_HID: u8 = 0x03;
const HID_DESC_DESCTYPE_HID: u8 = 0x21;
const HID_DESC_DESCTYPE_HID_REPORT: u8 = 0x22;
const HID_REQ_GET_IDLE: u8 = 0x02;
const HID_REQ_SET_IDLE: u8 = 0x0a;
const HID_REQ_GET_PROTOCOL: u8 = 0x03;
const HID_REQ_SET_PROTOCOL: u8 = 0x0b;

type UsbLog = fn(&'static str);

fn no_log(_message: &'static str) {}

/// Own the USBD peripheral exclusively, including DMA and interrupt access.
pub struct NrfUsbd(pub USBD);

pub fn release_bootloader_usb(usbd: &USBD) {
    usbd.usbpullup.write(|w| w.connect().disabled());
    usbd.intenclr.write(|w| unsafe { w.bits(u32::MAX) });
    usbd.enable.write(|w| w.enable().disabled());
    cortex_m::asm::delay(6_400_000);
}

unsafe impl UsbPeripheral for NrfUsbd {
    const REGISTERS: *const () = USBD::ptr() as *const ();
}

pub struct CtapHidClass<'a, B: UsbBus> {
    if_num: InterfaceNumber,
    out_ep: EndpointOut<'a, B>,
    in_ep: EndpointIn<'a, B>,
    log: UsbLog,
}

impl<'a, B: UsbBus> CtapHidClass<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>, poll_ms: u8) -> Self {
        Self::new_with_logger(alloc, poll_ms, no_log)
    }

    pub fn new_with_logger(alloc: &'a UsbBusAllocator<B>, poll_ms: u8, log: UsbLog) -> Self {
        Self {
            if_num: alloc.interface(),
            out_ep: alloc.interrupt(CTAPHID_REPORT_SIZE_U16, poll_ms),
            in_ep: alloc.interrupt(CTAPHID_REPORT_SIZE_U16, poll_ms),
            log,
        }
    }

    pub fn read(&self, data: &mut [u8]) -> usb_device::Result<usize> {
        self.out_ep.read(data)
    }

    pub fn write(&self, data: &[u8]) -> usb_device::Result<usize> {
        self.in_ep.write(data)
    }
}

impl<B: UsbBus> UsbClass<B> for CtapHidClass<'_, B> {
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.interface(self.if_num, USB_CLASS_HID, 0, 0)?;
        writer.write(
            HID_DESC_DESCTYPE_HID,
            &[
                0x10,
                0x01,
                0x00,
                0x01,
                HID_DESC_DESCTYPE_HID_REPORT,
                (CTAPHID_REPORT_DESCRIPTOR.len() & 0xff) as u8,
                ((CTAPHID_REPORT_DESCRIPTOR.len() >> 8) & 0xff) as u8,
            ],
        )?;
        writer.endpoint(&self.out_ep)?;
        writer.endpoint(&self.in_ep)?;
        Ok(())
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = xfer.request();
        if req.index != u8::from(self.if_num) as u16 {
            return;
        }

        match (req.request_type, req.request) {
            (control::RequestType::Standard, control::Request::GET_DESCRIPTOR) => {
                match (req.value >> 8) as u8 {
                    HID_DESC_DESCTYPE_HID_REPORT => {
                        (self.log)("ctrl report desc\r\n");
                        let _ = xfer.accept_with_static(CTAPHID_REPORT_DESCRIPTOR);
                    }
                    HID_DESC_DESCTYPE_HID => {
                        (self.log)("ctrl hid desc\r\n");
                        let _ = xfer.accept_with(&[
                            9,
                            HID_DESC_DESCTYPE_HID,
                            0x10,
                            0x01,
                            0x00,
                            0x01,
                            HID_DESC_DESCTYPE_HID_REPORT,
                            (CTAPHID_REPORT_DESCRIPTOR.len() & 0xff) as u8,
                            ((CTAPHID_REPORT_DESCRIPTOR.len() >> 8) & 0xff) as u8,
                        ]);
                    }
                    _ => {}
                }
            }
            (control::RequestType::Class, HID_REQ_GET_IDLE) => {
                let _ = xfer.accept_with(&[0]);
            }
            (control::RequestType::Class, HID_REQ_GET_PROTOCOL) => {
                let _ = xfer.accept_with(&[1]);
            }
            _ => {}
        }
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = xfer.request();
        if !(req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.if_num) as u16)
        {
            return;
        }

        match req.request {
            HID_REQ_SET_IDLE | HID_REQ_SET_PROTOCOL => {
                let _ = xfer.accept();
            }
            _ => {
                let _ = xfer.reject();
            }
        }
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr == self.out_ep.address() {
            (self.log)("ep out\r\n");
        }
    }

    fn endpoint_in_complete(&mut self, addr: EndpointAddress) {
        if addr == self.in_ep.address() {
            (self.log)("ep in done\r\n");
        }
    }
}

/// May block indefinitely on backpressure or stop after a partial write; no delivery acknowledgment.
pub fn write_response<B: UsbBus>(
    usb_dev: &mut UsbDevice<'_, B>,
    hid: &mut CtapHidClass<'_, B>,
    response: Response<'_>,
) {
    let _ = for_each_response_report(response, |packet| {
        push_packet(usb_dev, hid, packet);
        Ok::<(), ()>(())
    });

    poll_after_write(usb_dev, hid);
}

/// May block indefinitely on backpressure or stop after a partial write; no delivery acknowledgment.
pub fn write_message<B: UsbBus>(
    usb_dev: &mut UsbDevice<'_, B>,
    hid: &mut CtapHidClass<'_, B>,
    cid: u32,
    cmd: u8,
    data: &[u8],
) {
    let _ = for_each_message_report(cid, cmd, data, |packet| {
        push_packet(usb_dev, hid, packet);
        Ok::<(), ()>(())
    });

    poll_after_write(usb_dev, hid);
}

fn poll_after_write<B: UsbBus>(usb_dev: &mut UsbDevice<'_, B>, hid: &mut CtapHidClass<'_, B>) {
    for _ in 0..256 {
        let _ = usb_dev.poll(&mut [hid as &mut dyn UsbClass<B>]);
        asm::nop();
    }
}

fn push_packet<B: UsbBus>(
    usb_dev: &mut UsbDevice<'_, B>,
    hid: &mut CtapHidClass<'_, B>,
    packet: &[u8; CTAPHID_REPORT_SIZE],
) {
    loop {
        match hid.write(packet) {
            Ok(_) => return,
            Err(UsbError::WouldBlock) => {
                let _ = usb_dev.poll(&mut [hid as &mut dyn UsbClass<B>]);
            }
            Err(_) => return,
        }
    }
}
