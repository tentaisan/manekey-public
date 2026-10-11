use crate::{
    usb_ccid::CcidUsbClass,
    usb_hid::{CtapHidClass, NrfUsbd},
};
use manekey::{security::trusted_status, transport::boundary_link::CopyPacket};
use nrf_usbd::Usbd;
use static_cell::StaticCell;
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
type Bus = Usbd<NrfUsbd>;
pub type Packet = CopyPacket<64>;
/// Privileged, exclusive USBD pump with copied packets; does not install MPU protection.
/// Queue acceptance is not delivery; the reset generation wraps and can repeat.
pub struct UsbPump {
    device: UsbDevice<'static, Bus>,
    hid: CtapHidClass<'static, Bus>,
    ccid: CcidUsbClass<'static, Bus>,
    generation: u32,
    rx: Option<[u8; 64]>,
    tx: Option<[u8; 64]>,
    bulk_rx: Option<Packet>,
    bulk_tx: Option<Packet>,
    abort: Option<(u8, u8)>,
}
impl UsbPump {
    /// Initialize the static USB bus once; exclude other USBD and IRQ owners.
    pub fn new(usbd: nrf52840_pac::USBD) -> Self {
        crate::usb_hid::release_bootloader_usb(&usbd);
        static BUS: StaticCell<UsbBusAllocator<Bus>> = StaticCell::new();
        let bus = BUS.init(UsbBusAllocator::new(Usbd::new(NrfUsbd(usbd))));
        let hid = CtapHidClass::new(bus, 5);
        let ccid = CcidUsbClass::new(bus, manekey::frontend::ccid::CCID_RESPONSE_MAX as u32);
        let mut device = UsbDeviceBuilder::new(bus, UsbVidPid(0xcafe, 0x4011))
            .strings(&[StringDescriptors::default()
                .manufacturer("ManeKey")
                .product("ManeKey nRF52840 MPU")
                .serial_number("nrf52840-mpu")])
            .unwrap()
            .build();
        let _ = device.force_reset();
        Self {
            device,
            hid,
            ccid,
            generation: 1,
            rx: None,
            tx: None,
            bulk_rx: None,
            bulk_tx: None,
            abort: None,
        }
    }
    pub fn pump(&mut self) {
        let active = self.device.poll(&mut [&mut self.hid, &mut self.ccid]);
        if self.ccid.take_bus_reset() {
            self.generation = self.generation.wrapping_add(1);
            self.rx = None;
            self.tx = None;
            self.bulk_rx = None;
            self.bulk_tx = None;
            self.abort = None;
        }
        if let Some(abort) = self.ccid.take_control_abort() {
            self.abort = Some(abort);
            self.bulk_tx = None;
            self.bulk_rx = None;
        }
        if let Some(report) = self.tx.as_ref() {
            if self.hid.write(report).is_ok() {
                self.tx = None;
            }
        }
        if let Some(packet) = self.bulk_tx.as_ref() {
            if self.ccid.write_packet(packet.bytes().unwrap()).is_ok() {
                self.bulk_tx = None;
            }
        }
        if active && self.rx.is_none() {
            let mut report = [0; 64];
            if let Ok(64) = self.hid.read(&mut report) {
                self.rx = Some(report);
            }
        }
        if active && self.bulk_rx.is_none() {
            let mut packet = Packet::empty();
            if let Ok(len) = self.ccid.read_packet(&mut packet.data) {
                packet.len = len as u32;
                self.bulk_rx = Some(packet);
            }
        }
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn receive(&mut self) -> Option<[u8; 64]> {
        self.rx.take()
    }
    pub fn send(&mut self, report: [u8; 64]) -> u32 {
        if self.tx.is_some() {
            trusted_status::BUSY
        } else {
            self.tx = Some(report);
            trusted_status::OK
        }
    }
    pub fn receive_ccid(&mut self) -> Option<Packet> {
        self.bulk_rx.take()
    }
    pub fn send_ccid(&mut self, packet: Packet) -> u32 {
        if packet.bytes().is_none() {
            trusted_status::INVALID_REQUEST
        } else if self.bulk_tx.is_some() {
            trusted_status::BUSY
        } else {
            self.bulk_tx = Some(packet);
            trusted_status::OK
        }
    }
    pub fn take_abort(&mut self) -> u32 {
        self.abort
            .take()
            .map(|(slot, seq)| u32::from(slot) | (u32::from(seq) << 8))
            .unwrap_or(u32::MAX)
    }
}
