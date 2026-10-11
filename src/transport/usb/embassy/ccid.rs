use crate::frontend::ccid::{
    CCID_FUNCTIONAL_DESCRIPTOR_TYPE, CCID_HEADER_LEN, functional_descriptor,
};
use embassy_usb::Builder;
use embassy_usb::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut};

use super::ccid_control::CcidControlShared;
pub use super::ccid_control::CcidUsbState;

const USB_CLASS_SMART_CARD: u8 = 0x0b;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcidUsbError {
    Disabled,
    Endpoint,
    MessageTooShort,
    MessageTooLong,
    LengthMismatch,
}

/// CCID endpoint adapter; message reads reject invalid lengths.
pub struct CcidUsbClass<'d, D: Driver<'d>> {
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
    control: &'d CcidControlShared,
    reset_generation: u32,
}

pub struct CcidUsbReader<'a, E> {
    endpoint: &'a mut E,
}
pub struct CcidUsbWriter<'a, E> {
    endpoint: &'a mut E,
}
#[derive(Clone, Copy)]
pub struct CcidUsbControlHandle<'d> {
    shared: &'d CcidControlShared,
}
impl CcidUsbControlHandle<'_> {
    pub fn take_abort(&self) -> Option<(u8, u8)> {
        self.shared.take_abort()
    }
}
impl<E: EndpointOut> CcidUsbReader<'_, E> {
    pub async fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, CcidUsbError> {
        self.endpoint.read(buffer).await.map_err(map_endpoint_error)
    }
    pub async fn read_message(&mut self, buffer: &mut [u8]) -> Result<usize, CcidUsbError> {
        read_message(self.endpoint, buffer).await
    }
}
impl<E: EndpointIn> CcidUsbWriter<'_, E> {
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<(), CcidUsbError> {
        self.endpoint
            .write(packet)
            .await
            .map_err(map_endpoint_error)
    }
    pub async fn write_message(&mut self, message: &[u8]) -> Result<(), CcidUsbError> {
        self.endpoint
            .write_transfer(message, true)
            .await
            .map_err(map_endpoint_error)
    }
}

impl<'d, D: Driver<'d>> CcidUsbClass<'d, D> {
    pub fn split(
        &mut self,
    ) -> (
        CcidUsbReader<'_, D::EndpointOut>,
        CcidUsbWriter<'_, D::EndpointIn>,
        CcidUsbControlHandle<'d>,
    ) {
        (
            CcidUsbReader {
                endpoint: &mut self.read_ep,
            },
            CcidUsbWriter {
                endpoint: &mut self.write_ep,
            },
            CcidUsbControlHandle {
                shared: self.control,
            },
        )
    }
    /// # Panics
    /// Panics if packet or message limits are smaller than CCID_HEADER_LEN.
    pub fn new(
        builder: &mut Builder<'d, D>,
        state: &'d mut CcidUsbState<'d>,
        max_packet_size: u16,
        max_message_len: u32,
    ) -> Self {
        assert!(max_packet_size >= CCID_HEADER_LEN as u16);
        assert!(max_message_len >= CCID_HEADER_LEN as u32);

        let mut function = builder.function(USB_CLASS_SMART_CARD, 0, 0);
        let mut interface = function.interface();
        let interface_number = interface.interface_number();
        let mut alt = interface.alt_setting(USB_CLASS_SMART_CARD, 0, 0, None);
        alt.descriptor(
            CCID_FUNCTIONAL_DESCRIPTOR_TYPE,
            &functional_descriptor(max_message_len),
        );
        let read_ep = alt.endpoint_bulk_out(None, max_packet_size);
        let write_ep = alt.endpoint_bulk_in(None, max_packet_size);
        drop(function);

        let control = state.register(builder, interface_number);

        Self {
            read_ep,
            write_ep,
            control,
            reset_generation: control.reset_generation(),
        }
    }

    pub async fn wait_connection(&mut self) {
        self.read_ep.wait_enabled().await;
    }

    pub fn take_control_abort(&self) -> Option<(u8, u8)> {
        self.control.take_abort()
    }

    pub fn take_bus_reset(&mut self) -> bool {
        let generation = self.control.reset_generation();
        if generation == self.reset_generation {
            false
        } else {
            self.reset_generation = generation;
            true
        }
    }

    pub async fn read_message(&mut self, buffer: &mut [u8]) -> Result<usize, CcidUsbError> {
        read_message(&mut self.read_ep, buffer).await
    }

    pub async fn write_message(&mut self, message: &[u8]) -> Result<(), CcidUsbError> {
        self.write_ep
            .write_transfer(message, true)
            .await
            .map_err(map_endpoint_error)
    }
}

async fn read_message<E: EndpointOut>(
    endpoint: &mut E,
    buffer: &mut [u8],
) -> Result<usize, CcidUsbError> {
    if buffer.len() < CCID_HEADER_LEN {
        return Err(CcidUsbError::MessageTooLong);
    }

    let mut used = endpoint.read(buffer).await.map_err(map_endpoint_error)?;
    if used < CCID_HEADER_LEN {
        return Err(CcidUsbError::MessageTooShort);
    }
    let payload_len = u32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    let expected = CCID_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(CcidUsbError::MessageTooLong)?;
    if expected > buffer.len() {
        return Err(CcidUsbError::MessageTooLong);
    }
    if used > expected {
        return Err(CcidUsbError::LengthMismatch);
    }

    while used < expected {
        let read = endpoint
            .read(&mut buffer[used..expected])
            .await
            .map_err(map_endpoint_error)?;
        if read == 0 {
            return Err(CcidUsbError::LengthMismatch);
        }
        used += read;
    }
    Ok(used)
}

fn map_endpoint_error(error: EndpointError) -> CcidUsbError {
    match error {
        EndpointError::Disabled => CcidUsbError::Disabled,
        EndpointError::BufferOverflow => CcidUsbError::Endpoint,
    }
}
