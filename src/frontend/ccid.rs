use super::fido_apdu::{FidoApduFrontend, NfcApduOutcome};
use super::ingress::IngressArbiter;
use crate::ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedBackend};

pub const CCID_HEADER_LEN: usize = 10;
pub const CCID_RESPONSE_MAX: usize = CCID_HEADER_LEN + TRUSTED_RESPONSE_MAX + 2;
pub const CCID_FUNCTIONAL_DESCRIPTOR_TYPE: u8 = 0x21;

pub const fn functional_descriptor(max_message_len: u32) -> [u8; 52] {
    let max_message_len = max_message_len.to_le_bytes();
    [
        0x10,
        0x01,
        0x00,
        0x07,
        0x02,
        0x00,
        0x00,
        0x00,
        0xa0,
        0x0f,
        0x00,
        0x00,
        0xa0,
        0x0f,
        0x00,
        0x00,
        0x00,
        0x80,
        0x25,
        0x00,
        0x00,
        0x16,
        0x40,
        0x05,
        0x00,
        0x00,
        0xfe,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x42,
        0x00,
        0x04,
        0x00,
        max_message_len[0],
        max_message_len[1],
        max_message_len[2],
        max_message_len[3],
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
    ]
}

const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6c;
const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6d;
const PC_TO_RDR_XFR_BLOCK: u8 = 0x6f;
const PC_TO_RDR_ABORT: u8 = 0x72;

const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
const RDR_TO_PC_PARAMETERS: u8 = 0x82;

const COMMAND_STATUS_FAILED: u8 = 0x40;
const COMMAND_STATUS_TIME_EXTENSION: u8 = 0x80;
const ICC_STATUS_ACTIVE: u8 = 0x00;
const ICC_STATUS_INACTIVE: u8 = 0x01;

const ERROR_CMD_ABORTED: u8 = 0xff;
const ERROR_ICC_MUTE: u8 = 0xfe;
const ERROR_SLOT_BUSY: u8 = 0xe0;
const ERROR_BAD_SLOT: u8 = 0x05;
const ERROR_CMD_NOT_SUPPORTED: u8 = 0x00;

const ATR_T1: &[u8] = &[0x3b, 0x80, 0x01, 0x81];
const DEFAULT_T1_PARAMETERS: [u8; 7] = [0x11, 0x10, 0x00, 0x4d, 0x00, 0xfe, 0x00];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CcidError {
    MessageTooShort,
    LengthMismatch,
    ResponseBufferTooSmall,
}

#[derive(Clone, Copy)]
struct Header<'a> {
    message_type: u8,
    slot: u8,
    sequence: u8,
    parameters: [u8; 3],
    payload: &'a [u8],
}

#[derive(Clone, Copy)]
struct PendingExchange {
    slot: u8,
    sequence: u8,
}

pub enum CcidApduOutcome<'a> {
    Reply(CcidApduReply<'a>),
    Deferred,
    Ignored,
}

pub struct CcidApduReply<'a> {
    pub data: &'a [u8],
    pub status_word: u16,
}

pub trait CcidApduHandler<C> {
    fn handle_apdu<'a>(&'a mut self, context: &mut C, apdu: &[u8]) -> CcidApduOutcome<'a>;
    fn poll_deferred<'a>(&'a mut self, context: &mut C) -> Option<CcidApduReply<'a>>;
    fn poll_cancel(&mut self, context: &mut C);
    fn owns_pending(&self, context: &C) -> bool;
    fn disconnect(&mut self, context: &mut C);
    fn cancel_exchange(&mut self, context: &mut C);
}

impl<T: TrustedBackend> CcidApduHandler<IngressArbiter<T>> for FidoApduFrontend {
    fn handle_apdu<'a>(
        &'a mut self,
        arbiter: &mut IngressArbiter<T>,
        apdu: &[u8],
    ) -> CcidApduOutcome<'a> {
        match FidoApduFrontend::handle_apdu(self, arbiter, apdu) {
            NfcApduOutcome::Reply(reply) => CcidApduOutcome::Reply(CcidApduReply {
                data: reply.data,
                status_word: reply.status_word,
            }),
            NfcApduOutcome::Deferred => CcidApduOutcome::Deferred,
            NfcApduOutcome::Ignored => CcidApduOutcome::Ignored,
        }
    }

    fn poll_deferred<'a>(
        &'a mut self,
        arbiter: &mut IngressArbiter<T>,
    ) -> Option<CcidApduReply<'a>> {
        FidoApduFrontend::poll_deferred(self, arbiter).map(|reply| CcidApduReply {
            data: reply.data,
            status_word: reply.status_word,
        })
    }

    fn poll_cancel(&mut self, arbiter: &mut IngressArbiter<T>) {
        let _ = FidoApduFrontend::poll_cancel(self, arbiter);
    }

    fn owns_pending(&self, arbiter: &IngressArbiter<T>) -> bool {
        FidoApduFrontend::owns_pending(self, arbiter)
    }

    fn disconnect(&mut self, arbiter: &mut IngressArbiter<T>) {
        FidoApduFrontend::disconnect(self, arbiter);
    }

    fn cancel_exchange(&mut self, arbiter: &mut IngressArbiter<T>) {
        FidoApduFrontend::cancel_exchange(self, arbiter);
    }
}

/// Single-slot CCID/APDU frontend; callers provide transport polling and complete response delivery.
pub struct CcidFrontend<A = FidoApduFrontend> {
    apdu: A,
    active: bool,
    pending: Option<PendingExchange>,
    abort: Option<PendingExchange>,
    parameters: [u8; 7],
}

impl CcidFrontend<FidoApduFrontend> {
    pub const fn new(instance: u8) -> Self {
        Self::with_apdu(FidoApduFrontend::new_ccid(instance))
    }
}

impl<A> CcidFrontend<A> {
    pub const fn with_apdu(apdu: A) -> Self {
        Self {
            apdu,
            active: false,
            pending: None,
            abort: None,
            parameters: DEFAULT_T1_PARAMETERS,
        }
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Response-buffer errors may occur after APDU processing; do not blindly retry the command.
    pub fn handle_message<C>(
        &mut self,
        context: &mut C,
        message: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CcidError>
    where
        A: CcidApduHandler<C>,
    {
        let header = parse_message(message)?;
        if header.slot != 0 {
            return write_empty(
                response,
                response_type(header.message_type),
                header.slot,
                header.sequence,
                COMMAND_STATUS_FAILED | self.icc_status(),
                ERROR_BAD_SLOT,
                0,
            );
        }

        if let Some(abort) = self.abort {
            if header.message_type == PC_TO_RDR_ABORT
                && header.slot == abort.slot
                && header.sequence == abort.sequence
            {
                self.abort = None;
                return write_empty(
                    response,
                    RDR_TO_PC_SLOT_STATUS,
                    header.slot,
                    header.sequence,
                    self.icc_status(),
                    0,
                    0,
                );
            }
            return write_empty(
                response,
                response_type(header.message_type),
                header.slot,
                header.sequence,
                COMMAND_STATUS_FAILED | self.icc_status(),
                ERROR_CMD_ABORTED,
                0,
            );
        }

        match header.message_type {
            PC_TO_RDR_ICC_POWER_ON => {
                self.apdu.disconnect(context);
                self.pending = None;
                self.active = true;
                write_response(
                    response,
                    RDR_TO_PC_DATA_BLOCK,
                    0,
                    header.sequence,
                    ICC_STATUS_ACTIVE,
                    0,
                    0,
                    ATR_T1,
                )
            }
            PC_TO_RDR_ICC_POWER_OFF => {
                self.apdu.disconnect(context);
                self.pending = None;
                self.active = false;
                write_empty(
                    response,
                    RDR_TO_PC_SLOT_STATUS,
                    0,
                    header.sequence,
                    ICC_STATUS_INACTIVE,
                    0,
                    0,
                )
            }
            PC_TO_RDR_GET_SLOT_STATUS => write_empty(
                response,
                RDR_TO_PC_SLOT_STATUS,
                0,
                header.sequence,
                self.icc_status(),
                0,
                0,
            ),
            PC_TO_RDR_GET_PARAMETERS => self.write_parameters(response, header.sequence),
            PC_TO_RDR_RESET_PARAMETERS => {
                self.parameters = DEFAULT_T1_PARAMETERS;
                self.write_parameters(response, header.sequence)
            }
            PC_TO_RDR_SET_PARAMETERS => {
                if header.parameters[0] != 1 || header.payload.len() != self.parameters.len() {
                    return self.write_failed_parameters(
                        response,
                        header.sequence,
                        ERROR_CMD_NOT_SUPPORTED,
                    );
                }
                self.parameters.copy_from_slice(header.payload);
                self.write_parameters(response, header.sequence)
            }
            PC_TO_RDR_XFR_BLOCK => self.transfer(context, header, response),
            PC_TO_RDR_ABORT => write_empty(
                response,
                RDR_TO_PC_SLOT_STATUS,
                0,
                header.sequence,
                COMMAND_STATUS_FAILED | self.icc_status(),
                ERROR_CMD_NOT_SUPPORTED,
                0,
            ),
            _ => write_empty(
                response,
                response_type(header.message_type),
                0,
                header.sequence,
                COMMAND_STATUS_FAILED | self.icc_status(),
                ERROR_CMD_NOT_SUPPORTED,
                0,
            ),
        }
    }

    pub fn poll<C>(
        &mut self,
        context: &mut C,
        response: &mut [u8],
    ) -> Result<Option<usize>, CcidError>
    where
        A: CcidApduHandler<C>,
    {
        let Some(pending) = self.pending else {
            self.apdu.poll_cancel(context);
            return Ok(None);
        };
        if let Some(reply) = self.apdu.poll_deferred(context) {
            self.pending = None;
            return write_apdu_reply(response, pending.slot, pending.sequence, reply).map(Some);
        }
        if self.apdu.owns_pending(context) {
            return write_empty(
                response,
                RDR_TO_PC_DATA_BLOCK,
                pending.slot,
                pending.sequence,
                COMMAND_STATUS_TIME_EXTENSION | self.icc_status(),
                1,
                0,
            )
            .map(Some);
        }

        self.pending = None;
        write_empty(
            response,
            RDR_TO_PC_DATA_BLOCK,
            pending.slot,
            pending.sequence,
            COMMAND_STATUS_FAILED | self.icc_status(),
            ERROR_CMD_ABORTED,
            0,
        )
        .map(Some)
    }

    pub fn disconnect<C>(&mut self, context: &mut C)
    where
        A: CcidApduHandler<C>,
    {
        self.apdu.disconnect(context);
        self.pending = None;
        self.abort = None;
        self.active = false;
    }

    /// Begins the control/bulk abort exchange; continue polling to settle backend cancellation.
    pub fn begin_abort<C>(&mut self, context: &mut C, slot: u8, sequence: u8) -> bool
    where
        A: CcidApduHandler<C>,
    {
        if slot != 0 {
            return false;
        }
        self.apdu.cancel_exchange(context);
        self.pending = None;
        self.abort = Some(PendingExchange { slot, sequence });
        true
    }

    fn transfer<C>(
        &mut self,
        context: &mut C,
        header: Header<'_>,
        response: &mut [u8],
    ) -> Result<usize, CcidError>
    where
        A: CcidApduHandler<C>,
    {
        if !self.active {
            return write_empty(
                response,
                RDR_TO_PC_DATA_BLOCK,
                0,
                header.sequence,
                COMMAND_STATUS_FAILED | ICC_STATUS_INACTIVE,
                ERROR_ICC_MUTE,
                0,
            );
        }
        if self.pending.is_some() {
            return write_empty(
                response,
                RDR_TO_PC_DATA_BLOCK,
                0,
                header.sequence,
                COMMAND_STATUS_FAILED | ICC_STATUS_ACTIVE,
                ERROR_SLOT_BUSY,
                0,
            );
        }
        if header.parameters[1] != 0 || header.parameters[2] != 0 {
            return write_empty(
                response,
                RDR_TO_PC_DATA_BLOCK,
                0,
                header.sequence,
                COMMAND_STATUS_FAILED | ICC_STATUS_ACTIVE,
                ERROR_CMD_NOT_SUPPORTED,
                0,
            );
        }

        match self.apdu.handle_apdu(context, header.payload) {
            CcidApduOutcome::Reply(reply) => write_apdu_reply(response, 0, header.sequence, reply),
            CcidApduOutcome::Deferred => {
                self.pending = Some(PendingExchange {
                    slot: 0,
                    sequence: header.sequence,
                });
                write_empty(
                    response,
                    RDR_TO_PC_DATA_BLOCK,
                    0,
                    header.sequence,
                    COMMAND_STATUS_TIME_EXTENSION | ICC_STATUS_ACTIVE,
                    1,
                    0,
                )
            }
            CcidApduOutcome::Ignored => write_apdu_status(response, 0, header.sequence, 0x6a82),
        }
    }

    fn icc_status(&self) -> u8 {
        if self.active {
            ICC_STATUS_ACTIVE
        } else {
            ICC_STATUS_INACTIVE
        }
    }

    fn write_parameters(&self, response: &mut [u8], sequence: u8) -> Result<usize, CcidError> {
        write_response(
            response,
            RDR_TO_PC_PARAMETERS,
            0,
            sequence,
            self.icc_status(),
            0,
            1,
            &self.parameters,
        )
    }

    fn write_failed_parameters(
        &self,
        response: &mut [u8],
        sequence: u8,
        error: u8,
    ) -> Result<usize, CcidError> {
        write_empty(
            response,
            RDR_TO_PC_PARAMETERS,
            0,
            sequence,
            COMMAND_STATUS_FAILED | self.icc_status(),
            error,
            1,
        )
    }
}

fn parse_message(message: &[u8]) -> Result<Header<'_>, CcidError> {
    if message.len() < CCID_HEADER_LEN {
        return Err(CcidError::MessageTooShort);
    }
    let length = u32::from_le_bytes([message[1], message[2], message[3], message[4]]) as usize;
    if length != message.len() - CCID_HEADER_LEN {
        return Err(CcidError::LengthMismatch);
    }
    Ok(Header {
        message_type: message[0],
        slot: message[5],
        sequence: message[6],
        parameters: [message[7], message[8], message[9]],
        payload: &message[CCID_HEADER_LEN..],
    })
}

fn response_type(command: u8) -> u8 {
    match command {
        PC_TO_RDR_ICC_POWER_ON | PC_TO_RDR_XFR_BLOCK => RDR_TO_PC_DATA_BLOCK,
        PC_TO_RDR_GET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS | PC_TO_RDR_SET_PARAMETERS => {
            RDR_TO_PC_PARAMETERS
        }
        _ => RDR_TO_PC_SLOT_STATUS,
    }
}

fn write_apdu_reply(
    response: &mut [u8],
    slot: u8,
    sequence: u8,
    reply: CcidApduReply<'_>,
) -> Result<usize, CcidError> {
    let payload_len = reply.data.len() + 2;
    let total = CCID_HEADER_LEN + payload_len;
    if response.len() < total {
        return Err(CcidError::ResponseBufferTooSmall);
    }
    write_header(
        response,
        RDR_TO_PC_DATA_BLOCK,
        payload_len,
        slot,
        sequence,
        ICC_STATUS_ACTIVE,
        0,
        0,
    );
    response[CCID_HEADER_LEN..CCID_HEADER_LEN + reply.data.len()].copy_from_slice(reply.data);
    let offset = CCID_HEADER_LEN + reply.data.len();
    response[offset..offset + 2].copy_from_slice(&reply.status_word.to_be_bytes());
    Ok(total)
}

fn write_apdu_status(
    response: &mut [u8],
    slot: u8,
    sequence: u8,
    status_word: u16,
) -> Result<usize, CcidError> {
    write_response(
        response,
        RDR_TO_PC_DATA_BLOCK,
        slot,
        sequence,
        ICC_STATUS_ACTIVE,
        0,
        0,
        &status_word.to_be_bytes(),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_response(
    response: &mut [u8],
    message_type: u8,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
    payload: &[u8],
) -> Result<usize, CcidError> {
    let total = CCID_HEADER_LEN + payload.len();
    if response.len() < total {
        return Err(CcidError::ResponseBufferTooSmall);
    }
    write_header(
        response,
        message_type,
        payload.len(),
        slot,
        sequence,
        status,
        error,
        parameter,
    );
    response[CCID_HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

#[allow(clippy::too_many_arguments)]
fn write_empty(
    response: &mut [u8],
    message_type: u8,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
) -> Result<usize, CcidError> {
    write_response(
        response,
        message_type,
        slot,
        sequence,
        status,
        error,
        parameter,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn write_header(
    response: &mut [u8],
    message_type: u8,
    payload_len: usize,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
) {
    response[0] = message_type;
    response[1..5].copy_from_slice(&(payload_len as u32).to_le_bytes());
    response[5] = slot;
    response[6] = sequence;
    response[7] = status;
    response[8] = error;
    response[9] = parameter;
}
