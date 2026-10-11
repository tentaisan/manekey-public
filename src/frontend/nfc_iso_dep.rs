use super::fido_apdu::{FidoApduFrontend, NfcApduOutcome, NfcApduReply};
use super::ingress::IngressArbiter;
use crate::ctaphid::trusted::TrustedBackend;

pub const FIDO_ATS: &[u8] = &[0x06, 0x77, 0x77, 0x81, 0x02, 0x80];

pub const FIDO_INF_MAX: usize = 127;

const I_BLOCK: u8 = 0x02;
const I_BLOCK_CHAINING: u8 = 0x10;
const BLOCK_NUMBER: u8 = 0x01;
const CID_PRESENT: u8 = 0x08;
const NAD_PRESENT: u8 = 0x04;
const R_BLOCK: u8 = 0xa2;
const S_DESELECT: u8 = 0xc2;
const S_WTX: u8 = 0xf2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsoDepFrame<'a> {
    Rats,

    IBlock {
        block_number: u8,
        chaining: bool,
        payload: &'a [u8],
    },

    RBlock {
        block_number: u8,
        nak: bool,
    },

    Wtx {
        multiplier: u8,
    },

    Deselect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsoDepError {
    EmptyFrame,
    UnsupportedFrame,
    UnsupportedCidOrNad,
    InvalidRats,
    InvalidWtx,
    UnexpectedBlockNumber,
    BufferTooSmall,
    ResponseNotLoaded,
    ResponseNotAwaitingAck,
}

pub fn parse_frame(frame: &[u8]) -> Result<IsoDepFrame<'_>, IsoDepError> {
    let Some((&pcb, rest)) = frame.split_first() else {
        return Err(IsoDepError::EmptyFrame);
    };
    if pcb == 0xe0 {
        return if rest.len() == 1 {
            Ok(IsoDepFrame::Rats)
        } else {
            Err(IsoDepError::InvalidRats)
        };
    }
    if pcb == S_DESELECT && rest.is_empty() {
        return Ok(IsoDepFrame::Deselect);
    }
    if pcb == S_WTX {
        return match rest {
            [multiplier] if *multiplier != 0 && *multiplier <= 59 => Ok(IsoDepFrame::Wtx {
                multiplier: *multiplier,
            }),
            _ => Err(IsoDepError::InvalidWtx),
        };
    }
    if pcb & 0xe2 == I_BLOCK {
        if pcb & (CID_PRESENT | NAD_PRESENT) != 0 {
            return Err(IsoDepError::UnsupportedCidOrNad);
        }
        return Ok(IsoDepFrame::IBlock {
            block_number: pcb & BLOCK_NUMBER,
            chaining: pcb & I_BLOCK_CHAINING != 0,
            payload: rest,
        });
    }
    if pcb & 0xe2 == R_BLOCK {
        if !rest.is_empty() || pcb & (CID_PRESENT | NAD_PRESENT) != 0 {
            return Err(IsoDepError::UnsupportedFrame);
        }
        return Ok(IsoDepFrame::RBlock {
            block_number: pcb & BLOCK_NUMBER,
            nak: pcb & 0x10 != 0,
        });
    }
    Err(IsoDepError::UnsupportedFrame)
}

/// Bounded copied APDU assembly; reset does not erase payload bytes.
pub struct IsoDepCommandAssembler<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
    next_block_number: u8,
}

impl<const CAPACITY: usize> IsoDepCommandAssembler<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
            next_block_number: 0,
        }
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.next_block_number = 0;
    }

    pub fn push_len(&mut self, frame: IsoDepFrame<'_>) -> Result<Option<usize>, IsoDepError> {
        let IsoDepFrame::IBlock {
            block_number,
            chaining,
            payload,
        } = frame
        else {
            return Err(IsoDepError::UnsupportedFrame);
        };
        if block_number != self.next_block_number {
            return Err(IsoDepError::UnexpectedBlockNumber);
        }
        let Some(end) = self.len.checked_add(payload.len()) else {
            self.reset();
            return Err(IsoDepError::BufferTooSmall);
        };
        if end > CAPACITY {
            self.reset();
            return Err(IsoDepError::BufferTooSmall);
        }
        self.bytes[self.len..end].copy_from_slice(payload);
        self.len = end;
        self.next_block_number ^= BLOCK_NUMBER;
        if chaining {
            return Ok(None);
        }
        let len = self.len;
        self.len = 0;
        self.next_block_number = 0;
        Ok(Some(len))
    }

    pub fn apdu(&self, len: usize) -> Result<&[u8], IsoDepError> {
        self.bytes.get(..len).ok_or(IsoDepError::BufferTooSmall)
    }

    pub const fn expected_block_number(&self) -> u8 {
        self.next_block_number
    }

    pub fn push<'a>(&'a mut self, frame: IsoDepFrame<'_>) -> Result<Option<&'a [u8]>, IsoDepError> {
        let Some(len) = self.push_len(frame)? else {
            return Ok(None);
        };
        Ok(Some(&self.bytes[..len]))
    }
}

impl<const CAPACITY: usize> Default for IsoDepCommandAssembler<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Copied ISO-DEP response with chained-block acknowledgment; reset does not erase bytes.
pub struct IsoDepResponseFragmenter<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
    offset: usize,
    block_number: u8,
    in_flight_len: usize,
    awaiting_ack: bool,
}

impl<const CAPACITY: usize> IsoDepResponseFragmenter<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
            offset: 0,
            block_number: 0,
            in_flight_len: 0,
            awaiting_ack: false,
        }
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.offset = 0;
        self.block_number = 0;
        self.in_flight_len = 0;
        self.awaiting_ack = false;
    }

    pub fn load(&mut self, apdu_response: &[u8]) -> Result<(), IsoDepError> {
        if apdu_response.len() > CAPACITY {
            return Err(IsoDepError::BufferTooSmall);
        }
        self.bytes[..apdu_response.len()].copy_from_slice(apdu_response);
        self.len = apdu_response.len();
        self.offset = 0;
        self.block_number = 0;
        self.in_flight_len = 0;
        self.awaiting_ack = false;
        Ok(())
    }

    pub fn load_reply(&mut self, data: &[u8], status_word: u16) -> Result<(), IsoDepError> {
        let Some(total) = data.len().checked_add(2) else {
            return Err(IsoDepError::BufferTooSmall);
        };
        if total > CAPACITY {
            return Err(IsoDepError::BufferTooSmall);
        }
        self.bytes[..data.len()].copy_from_slice(data);
        self.bytes[data.len()..total].copy_from_slice(&status_word.to_be_bytes());
        self.len = total;
        self.offset = 0;
        self.block_number = 0;
        self.in_flight_len = 0;
        self.awaiting_ack = false;
        Ok(())
    }

    pub const fn is_complete(&self) -> bool {
        self.offset == self.len && !self.awaiting_ack
    }

    pub fn next_into(&mut self, out: &mut [u8], inf_max: usize) -> Result<usize, IsoDepError> {
        if self.awaiting_ack {
            return Err(IsoDepError::ResponseNotAwaitingAck);
        }
        if self.offset >= self.len || inf_max == 0 {
            return Err(IsoDepError::ResponseNotLoaded);
        }
        let count = (self.len - self.offset).min(inf_max);
        if out.len() < count + 1 {
            return Err(IsoDepError::BufferTooSmall);
        }
        let chaining = self.offset + count < self.len;
        out[0] = I_BLOCK | self.block_number | if chaining { I_BLOCK_CHAINING } else { 0 };
        out[1..count + 1].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.in_flight_len = count;
        self.awaiting_ack = chaining;
        if !chaining {
            self.offset += count;
            self.block_number ^= BLOCK_NUMBER;
        }
        Ok(count + 1)
    }

    pub fn handle_r_block_into(
        &mut self,
        frame: IsoDepFrame<'_>,
        out: &mut [u8],
    ) -> Result<Option<usize>, IsoDepError> {
        let IsoDepFrame::RBlock { block_number, nak } = frame else {
            return Err(IsoDepError::UnsupportedFrame);
        };
        if !self.awaiting_ack || block_number != self.block_number {
            return Err(IsoDepError::UnexpectedBlockNumber);
        }
        if nak {
            let count = self.in_flight_len;
            if out.len() < count + 1 {
                return Err(IsoDepError::BufferTooSmall);
            }
            out[0] = I_BLOCK | self.block_number | I_BLOCK_CHAINING;
            out[1..count + 1].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            return Ok(Some(count + 1));
        }
        self.offset += self.in_flight_len;
        self.block_number ^= BLOCK_NUMBER;
        self.in_flight_len = 0;
        self.awaiting_ack = false;
        Ok(None)
    }

    pub fn encode_wtx_request(multiplier: u8, out: &mut [u8]) -> Result<usize, IsoDepError> {
        if multiplier == 0 || multiplier > 59 || out.len() < 2 {
            return Err(IsoDepError::InvalidWtx);
        }
        out[..2].copy_from_slice(&[S_WTX, multiplier]);
        Ok(2)
    }

    pub fn encode_deselect_response(&mut self, out: &mut [u8]) -> Result<usize, IsoDepError> {
        if out.is_empty() {
            return Err(IsoDepError::BufferTooSmall);
        }
        self.reset();
        out[0] = S_DESELECT;
        Ok(1)
    }
}

impl<const CAPACITY: usize> Default for IsoDepResponseFragmenter<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfcIsoDepAction {
    Transmit(usize),
    AwaitFrame,
    Ignored,
}

/// Protocol frontend over decoded frames; adapters own RF, CRC, timing and transmission.
pub struct NfcIsoDepFrontend<const APDU_CAPACITY: usize, const RESPONSE_CAPACITY: usize> {
    apdu: FidoApduFrontend,
    command: IsoDepCommandAssembler<APDU_CAPACITY>,
    response: IsoDepResponseFragmenter<RESPONSE_CAPACITY>,
}

impl<const APDU_CAPACITY: usize, const RESPONSE_CAPACITY: usize>
    NfcIsoDepFrontend<APDU_CAPACITY, RESPONSE_CAPACITY>
{
    pub const fn new(instance: u8) -> Self {
        Self {
            apdu: FidoApduFrontend::new(instance),
            command: IsoDepCommandAssembler::new(),
            response: IsoDepResponseFragmenter::new(),
        }
    }

    pub const fn ingress_id(&self) -> super::ingress::IngressId {
        self.apdu.ingress_id()
    }

    pub fn handle_frame<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        bytes: &[u8],
        out: &mut [u8],
        inf_max: usize,
    ) -> Result<NfcIsoDepAction, IsoDepError> {
        match parse_frame(bytes)? {
            IsoDepFrame::Rats => {
                if out.len() < FIDO_ATS.len() {
                    return Err(IsoDepError::BufferTooSmall);
                }
                out[..FIDO_ATS.len()].copy_from_slice(FIDO_ATS);
                Ok(NfcIsoDepAction::Transmit(FIDO_ATS.len()))
            }
            frame @ IsoDepFrame::IBlock { chaining, .. } => {
                let complete_len = self.command.push_len(frame)?;
                if chaining {
                    if out.is_empty() {
                        return Err(IsoDepError::BufferTooSmall);
                    }
                    out[0] = R_BLOCK | self.command.expected_block_number();
                    return Ok(NfcIsoDepAction::Transmit(1));
                }
                let Some(complete_len) = complete_len else {
                    return Ok(NfcIsoDepAction::AwaitFrame);
                };
                let apdu = self.command.apdu(complete_len)?;
                let outcome = self.apdu.handle_apdu(arbiter, apdu);
                Self::handle_apdu_outcome(&mut self.response, outcome, out, inf_max)
            }
            frame @ IsoDepFrame::RBlock { .. } => {
                if let Some(len) = self.response.handle_r_block_into(frame, out)? {
                    return Ok(NfcIsoDepAction::Transmit(len));
                }
                if self.response.is_complete() {
                    return Ok(NfcIsoDepAction::AwaitFrame);
                }
                Ok(NfcIsoDepAction::Transmit(
                    self.response.next_into(out, inf_max)?,
                ))
            }
            IsoDepFrame::Wtx { multiplier } => {
                if out.len() < 2 {
                    return Err(IsoDepError::BufferTooSmall);
                }
                out[..2].copy_from_slice(&[S_WTX, multiplier]);
                Ok(NfcIsoDepAction::Transmit(2))
            }
            IsoDepFrame::Deselect => {
                self.apdu.disconnect(arbiter);
                self.command.reset();
                Ok(NfcIsoDepAction::Transmit(
                    self.response.encode_deselect_response(out)?,
                ))
            }
        }
    }

    pub fn poll<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        out: &mut [u8],
        inf_max: usize,
    ) -> Result<NfcIsoDepAction, IsoDepError> {
        let Some(reply) = self.apdu.poll_deferred(arbiter) else {
            return Ok(NfcIsoDepAction::AwaitFrame);
        };
        Self::emit_reply(&mut self.response, reply, out, inf_max)
    }

    /// Clears link state and requests cancellation; continue poll_cancel until settled.
    pub fn field_lost<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) {
        self.apdu.disconnect(arbiter);
        self.command.reset();
        self.response.reset();
    }

    pub fn poll_cancel<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) -> bool {
        self.apdu.poll_cancel(arbiter)
    }

    fn handle_apdu_outcome(
        response: &mut IsoDepResponseFragmenter<RESPONSE_CAPACITY>,
        outcome: NfcApduOutcome<'_>,
        out: &mut [u8],
        inf_max: usize,
    ) -> Result<NfcIsoDepAction, IsoDepError> {
        match outcome {
            NfcApduOutcome::Reply(reply) => Self::emit_reply(response, reply, out, inf_max),
            NfcApduOutcome::Deferred => Ok(NfcIsoDepAction::AwaitFrame),
            NfcApduOutcome::Ignored => Ok(NfcIsoDepAction::Ignored),
        }
    }

    fn emit_reply(
        response: &mut IsoDepResponseFragmenter<RESPONSE_CAPACITY>,
        reply: NfcApduReply<'_>,
        out: &mut [u8],
        inf_max: usize,
    ) -> Result<NfcIsoDepAction, IsoDepError> {
        response.load_reply(reply.data, reply.status_word)?;
        Ok(NfcIsoDepAction::Transmit(response.next_into(out, inf_max)?))
    }
}

impl<const APDU_CAPACITY: usize, const RESPONSE_CAPACITY: usize> Default
    for NfcIsoDepFrontend<APDU_CAPACITY, RESPONSE_CAPACITY>
{
    fn default() -> Self {
        Self::new(0)
    }
}
