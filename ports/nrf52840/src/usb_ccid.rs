use manekey::frontend::ccid::{CCID_FUNCTIONAL_DESCRIPTOR_TYPE, functional_descriptor};
use usb_device::{
    bus::{UsbBus, UsbBusAllocator},
    class_prelude::{
        ControlOut, DescriptorWriter, EndpointIn, EndpointOut, InterfaceNumber, UsbClass,
    },
    control,
};

const USB_CLASS_SMART_CARD: u8 = 0x0b;
const CCID_REQUEST_ABORT: u8 = 0x01;

/// Single-slot CCID endpoints; accepted writes do not acknowledge peer delivery.
pub struct CcidUsbClass<'a, B: UsbBus> {
    if_num: InterfaceNumber,
    out_ep: EndpointOut<'a, B>,
    in_ep: EndpointIn<'a, B>,
    max_message_len: u32,
    abort: Option<(u8, u8)>,
    reset_pending: bool,
}

impl<'a, B: UsbBus> CcidUsbClass<'a, B> {
    pub fn new(alloc: &'a UsbBusAllocator<B>, max_message_len: u32) -> Self {
        Self {
            if_num: alloc.interface(),
            out_ep: alloc.bulk(64),
            in_ep: alloc.bulk(64),
            max_message_len,
            abort: None,
            reset_pending: false,
        }
    }

    pub fn read_packet(&self, data: &mut [u8]) -> usb_device::Result<usize> {
        self.out_ep.read(data)
    }

    pub fn write_packet(&self, data: &[u8]) -> usb_device::Result<usize> {
        self.in_ep.write(data)
    }

    pub fn take_control_abort(&mut self) -> Option<(u8, u8)> {
        self.abort.take()
    }

    pub fn take_bus_reset(&mut self) -> bool {
        core::mem::take(&mut self.reset_pending)
    }
}

impl<B: UsbBus> UsbClass<B> for CcidUsbClass<'_, B> {
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.interface(self.if_num, USB_CLASS_SMART_CARD, 0, 0)?;
        writer.write(
            CCID_FUNCTIONAL_DESCRIPTOR_TYPE,
            &functional_descriptor(self.max_message_len),
        )?;
        writer.endpoint(&self.out_ep)?;
        writer.endpoint(&self.in_ep)?;
        Ok(())
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = xfer.request();
        if req.request_type != control::RequestType::Class
            || req.recipient != control::Recipient::Interface
            || req.index != u8::from(self.if_num) as u16
        {
            return;
        }
        if req.request != CCID_REQUEST_ABORT || req.length != 0 {
            let _ = xfer.reject();
            return;
        }
        let slot = req.value as u8;
        let sequence = (req.value >> 8) as u8;
        if slot != 0
            || self
                .abort
                .is_some_and(|pending| pending != (slot, sequence))
        {
            let _ = xfer.reject();
            return;
        }
        self.abort = Some((slot, sequence));
        let _ = xfer.accept();
    }

    fn reset(&mut self) {
        self.abort = None;
        self.reset_pending = true;
    }
}
