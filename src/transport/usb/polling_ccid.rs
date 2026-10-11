use super::ccid_control::CcidAbortControl;
use crate::frontend::ccid::{CCID_FUNCTIONAL_DESCRIPTOR_TYPE, functional_descriptor};
use usb_device::{
    class_prelude::*,
    control::{Recipient, RequestType},
};

/// CCID endpoint adapter; callers provide USB polling and message processing.
pub struct PollingCcid<'a, B: UsbBus> {
    interface: InterfaceNumber,
    input: EndpointIn<'a, B>,
    output: EndpointOut<'a, B>,
    max_message: u32,
    abort: CcidAbortControl,
    reset_pending: bool,
}

impl<'a, B: UsbBus> PollingCcid<'a, B> {
    pub fn new(bus: &'a UsbBusAllocator<B>, max_message: u32) -> Self {
        Self {
            interface: bus.interface(),
            input: bus.bulk(64),
            output: bus.bulk(64),
            max_message,
            abort: CcidAbortControl::new(),
            reset_pending: false,
        }
    }
    pub fn read(&self, packet: &mut [u8]) -> usb_device::Result<usize> {
        self.output.read(packet)
    }
    pub fn write(&self, packet: &[u8]) -> usb_device::Result<usize> {
        self.input.write(packet)
    }
    pub fn take_abort(&mut self) -> Option<(u8, u8)> {
        self.abort.take()
    }
    pub fn take_reset(&mut self) -> bool {
        core::mem::take(&mut self.reset_pending)
    }
}

impl<B: UsbBus> UsbClass<B> for PollingCcid<'_, B> {
    fn get_configuration_descriptors(
        &self,
        writer: &mut DescriptorWriter,
    ) -> usb_device::Result<()> {
        writer.interface(self.interface, 0x0b, 0, 0)?;
        writer.write(
            CCID_FUNCTIONAL_DESCRIPTOR_TYPE,
            &functional_descriptor(self.max_message),
        )?;
        writer.endpoint(&self.output)?;
        writer.endpoint(&self.input)
    }
    fn reset(&mut self) {
        self.abort.reset();
        self.reset_pending = true;
    }
    fn control_out(&mut self, transfer: ControlOut<B>) {
        let request = transfer.request();
        if request.request_type != RequestType::Class
            || request.recipient != Recipient::Interface
            || request.index != u8::from(self.interface) as u16
        {
            return;
        }
        if self.abort.request(
            request.request,
            request.value,
            request.length,
            transfer.data(),
        ) {
            let _ = transfer.accept();
        } else {
            let _ = transfer.reject();
        }
    }
}
