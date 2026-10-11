use crate::{
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedBackend},
    frontend::{
        ble::BleFidoIngressFrontend,
        ccid::{CCID_RESPONSE_MAX, CcidFrontend},
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    transport::{
        ble::{BleFidoFragmentQueue, BleFidoProfileHandler},
        boundary_link::CopyPacket,
        usb::ccid_bulk::CcidBulkAssembler,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeripheralEndpoint {
    Hid,
    Ccid,
    Ble,
}
pub enum UartInput {
    Idle,
    Lost,
    Byte(u8),
}

/// Supplies serialized copied packets, link generations and wrapping millisecond ticks.
/// Send acceptance is not peer delivery; uart_write must send the entire response or report loss.
pub trait PeripheralLink {
    fn now_ms(&mut self) -> u32;
    fn generation(&mut self, endpoint: PeripheralEndpoint) -> u32;
    fn receive(
        &mut self,
        endpoint: PeripheralEndpoint,
        generation: u32,
        packet: &mut CopyPacket<64>,
    ) -> bool;
    fn send(
        &mut self,
        endpoint: PeripheralEndpoint,
        generation: u32,
        packet: &CopyPacket<64>,
    ) -> bool;
    fn take_ccid_abort(&mut self) -> Option<(u8, u8)>;
    fn uart_read(&mut self) -> UartInput;
    fn uart_write(&mut self, response: &[u8]);
    fn maintenance(&mut self, _byte: u8) -> bool {
        false
    }
}

/// Cooperative frontend over a shared arbiter; platform adapters own IRQ/DMA isolation.
/// BLE_PACKET must fit the 64-byte link packet and satisfy BLE framing limits.
pub struct PeripheralFrontend<
    B: TrustedBackend,
    const BLE_PACKET: usize,
    const BLE_FRAGMENTS: usize,
> {
    arbiter: IngressArbiter<B>,
    internal: InterconnectCtap2Frontend<{ TRUSTED_REQUEST_MAX + 32 }>,
    response: [u8; TRUSTED_RESPONSE_MAX + 32],
    hid: CtaphidReportFrontend,
    hid_generation: u32,
    hid_poll: u32,
    ccid: CcidFrontend,
    ccid_request: CcidBulkAssembler<{ TRUSTED_REQUEST_MAX + 32 }>,
    ccid_response: [u8; CCID_RESPONSE_MAX],
    ccid_generation: u32,
    ccid_poll: u32,
    ccid_pending: usize,
    ccid_offset: usize,
    ble: BleFidoIngressFrontend,
    ble_sink: BleFidoFragmentQueue<BLE_FRAGMENTS, BLE_PACKET>,
    ble_generation: u32,
    ble_poll: u32,
    ble_offset: usize,
    packet: CopyPacket<64>,
}
impl<B: TrustedBackend, const P: usize, const F: usize> PeripheralFrontend<B, P, F> {
    pub const fn new(backend: B) -> Self {
        Self {
            arbiter: IngressArbiter::new(backend),
            internal: InterconnectCtap2Frontend::new(0),
            response: [0; TRUSTED_RESPONSE_MAX + 32],
            hid: CtaphidReportFrontend::new(),
            hid_generation: 0,
            hid_poll: 0,
            ccid: CcidFrontend::new(0),
            ccid_request: CcidBulkAssembler::new(),
            ccid_response: [0; CCID_RESPONSE_MAX],
            ccid_generation: 0,
            ccid_poll: 0,
            ccid_pending: 0,
            ccid_offset: 0,
            ble: BleFidoIngressFrontend::new(P, IngressId::new(IngressKind::Ble, 0)),
            ble_sink: BleFidoFragmentQueue::new(),
            ble_generation: 0,
            ble_poll: 0,
            ble_offset: 0,
            packet: CopyPacket::empty(),
        }
    }
    pub fn ble_settled(&self) -> bool {
        !self
            .arbiter
            .is_owned_by(IngressId::new(IngressKind::Ble, 0))
    }

    pub fn step(&mut self, link: &mut impl PeripheralLink) {
        let now = link.now_ms();
        let _ = self.internal.poll_cancel(&mut self.arbiter);
        let generation = link.generation(PeripheralEndpoint::Ble);
        if generation != self.ble_generation {
            self.ble.bind(&mut self.arbiter).on_disconnect();
            self.ble_sink.clear();
            self.ble_offset = 0;
            self.ble_generation = generation;
        }
        if self.ble_sink.fragments().count() == 0 {
            let _ = self
                .ble
                .bind(&mut self.arbiter)
                .settle_disconnected_backend();
            if link.receive(PeripheralEndpoint::Ble, generation, &mut self.packet) {
                if let Some(bytes) = self.packet.bytes() {
                    let _ = self
                        .ble
                        .bind(&mut self.arbiter)
                        .handle_control_point_write::<P>(bytes, &mut self.ble_sink);
                }
            } else if now.wrapping_sub(self.ble_poll) >= 100 {
                let _ = self
                    .ble
                    .bind(&mut self.arbiter)
                    .poll_status::<P>(&mut self.ble_sink);
                self.ble_poll = now;
            }
        }
        if let Some(bytes) = self.ble_sink.fragments().nth(self.ble_offset) {
            self.packet = CopyPacket::from_slice(bytes).unwrap();
            if link.send(PeripheralEndpoint::Ble, generation, &self.packet) {
                self.ble_offset += 1;
            }
        }
        if self.ble_offset != 0 && self.ble_offset == self.ble_sink.fragments().count() {
            self.ble_offset = 0;
            self.ble_sink.clear();
        }

        let hid_id = IngressId::new(IngressKind::UsbHid, 0);
        let generation = link.generation(PeripheralEndpoint::Hid);
        if generation != self.hid_generation {
            self.hid.on_link_lost(&mut self.arbiter, hid_id);
            self.hid_generation = generation;
        }
        if self.hid.current_report().is_none()
            && link.receive(PeripheralEndpoint::Hid, generation, &mut self.packet)
        {
            if self.packet.len == 64 {
                self.hid
                    .handle_report(&mut self.arbiter, hid_id, self.packet.data);
            }
        }
        if self.hid.current_report().is_none() && now.wrapping_sub(self.hid_poll) >= 100 {
            self.hid.poll(&mut self.arbiter, hid_id);
            self.hid_poll = now;
        }
        if let Some(report) = self.hid.current_report() {
            self.packet = CopyPacket::from_slice(report).unwrap();
            if link.send(PeripheralEndpoint::Hid, generation, &self.packet) {
                self.hid.advance_report();
            }
        }

        let generation = link.generation(PeripheralEndpoint::Ccid);
        if generation != self.ccid_generation {
            self.ccid.disconnect(&mut self.arbiter);
            self.ccid_request.reset();
            self.ccid_pending = 0;
            self.ccid_offset = 0;
            self.ccid_generation = generation;
        }
        if let Some((slot, sequence)) = link.take_ccid_abort() {
            self.ccid.begin_abort(&mut self.arbiter, slot, sequence);
            self.ccid_pending = 0;
            self.ccid_offset = 0;
            self.ccid_request.reset();
        }
        if self.ccid_pending == 0 {
            if link.receive(PeripheralEndpoint::Ccid, generation, &mut self.packet) {
                if let Some(bytes) = self.packet.bytes() {
                    match self.ccid_request.push(bytes) {
                        Ok(Some(message)) => {
                            self.ccid_pending = self
                                .ccid
                                .handle_message(&mut self.arbiter, message, &mut self.ccid_response)
                                .unwrap_or(0);
                            self.ccid_request.reset();
                            self.ccid_offset = 0;
                        }
                        Err(_) => self.ccid_request.reset(),
                        _ => {}
                    }
                }
            } else if now.wrapping_sub(self.ccid_poll) >= 100 {
                self.ccid_pending = self
                    .ccid
                    .poll(&mut self.arbiter, &mut self.ccid_response)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                self.ccid_poll = now;
            }
        }
        if self.ccid_pending != 0 {
            let end = (self.ccid_offset + 64).min(self.ccid_pending);
            self.packet =
                CopyPacket::from_slice(&self.ccid_response[self.ccid_offset..end]).unwrap();
            if link.send(PeripheralEndpoint::Ccid, generation, &self.packet) {
                self.ccid_offset = end;
                if self.packet.len < 64 {
                    self.ccid_pending = 0;
                    self.ccid_offset = 0;
                }
            }
        }
        for _ in 0..64 {
            let byte = match link.uart_read() {
                UartInput::Idle => break,
                UartInput::Lost => {
                    self.internal.disconnect(&mut self.arbiter);
                    break;
                }
                UartInput::Byte(byte) => byte,
            };
            if !self.internal.is_receiving() && link.maintenance(byte) {
                continue;
            }
            match self
                .internal
                .push_byte(&mut self.arbiter, byte, &mut self.response)
            {
                Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                    link.uart_write(&self.response[..len])
                }
                Err(_) => self.internal.disconnect(&mut self.arbiter),
                _ => {}
            }
        }
    }
}
