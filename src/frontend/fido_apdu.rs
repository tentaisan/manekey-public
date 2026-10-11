use super::ingress::{IngressArbiter, IngressId, IngressKind};
use crate::ctaphid::trusted::{
    TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedBackend, TrustedResult,
};

const FIDO_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
const FIDO2_VERSION: &[u8] = b"FIDO_2_0";

const INS_SELECT: u8 = 0xa4;
const INS_MSG: u8 = 0x10;
const INS_GET_RESPONSE: u8 = 0x11;
const INS_CONTROL: u8 = 0x12;
const INS_ISO_GET_RESPONSE: u8 = 0xc0;

const SW_SUCCESS: u16 = 0x9000;
const SW_STATUS: u16 = 0x9100;
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_CHAINING_ERROR: u16 = 0x6883;
const SW_FILE_NOT_FOUND: u16 = 0x6a82;
const SW_INCORRECT_P1_P2: u16 = 0x6a86;
const SW_INS_NOT_SUPPORTED: u16 = 0x6d00;
const SW_CLA_NOT_SUPPORTED: u16 = 0x6e00;

const CTAP_CHANNEL_BUSY: u8 = 0x06;
const CTAP_INVALID_LENGTH: u8 = 0x03;
const CTAP_KEEPALIVE_CANCEL: u8 = 0x2d;
const STATUS_PROCESSING: u8 = 0x01;
const STATUS_UP_NEEDED: u8 = 0x02;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfcApduReply<'a> {
    pub data: &'a [u8],
    pub status_word: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NfcApduOutcome<'a> {
    Reply(NfcApduReply<'a>),

    Deferred,

    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseEncoding {
    Short { le: usize },
    Extended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommandApdu<'a> {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &'a [u8],
    le: Option<usize>,
    extended: bool,
}

impl CommandApdu<'_> {
    fn response_encoding(self) -> ResponseEncoding {
        if self.extended {
            ResponseEncoding::Extended
        } else {
            ResponseEncoding::Short {
                le: self.le.unwrap_or(256).min(256),
            }
        }
    }
}

fn parse_apdu(apdu: &[u8]) -> Result<CommandApdu<'_>, u16> {
    if apdu.len() < 4 {
        return Err(SW_WRONG_LENGTH);
    }

    let mut command = CommandApdu {
        cla: apdu[0],
        ins: apdu[1],
        p1: apdu[2],
        p2: apdu[3],
        data: &[],
        le: None,
        extended: false,
    };
    if apdu.len() == 4 {
        return Ok(command);
    }

    let length = apdu[4] as usize;
    if length != 0 {
        if apdu.len() == 5 {
            command.le = Some(length);
            return Ok(command);
        }
        if apdu.len() != 5 + length && apdu.len() != 6 + length {
            return Err(SW_WRONG_LENGTH);
        }
        command.data = &apdu[5..5 + length];
        if apdu.len() == 6 + length {
            let le = apdu[5 + length] as usize;
            command.le = Some(if le == 0 { 256 } else { le });
        }
        return Ok(command);
    }

    if apdu.len() == 5 {
        command.le = Some(256);
        return Ok(command);
    }
    if apdu.len() < 7 {
        return Err(SW_WRONG_LENGTH);
    }

    command.extended = true;
    let extended_length = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
    if apdu.len() == 7 {
        command.le = Some(if extended_length == 0 {
            65_536
        } else {
            extended_length
        });
        return Ok(command);
    }
    if extended_length == 0
        || (apdu.len() != 7 + extended_length && apdu.len() != 9 + extended_length)
    {
        return Err(SW_WRONG_LENGTH);
    }
    command.data = &apdu[7..7 + extended_length];
    if apdu.len() == 9 + extended_length {
        let offset = 7 + extended_length;
        let le = u16::from_be_bytes([apdu[offset], apdu[offset + 1]]) as usize;
        command.le = Some(if le == 0 { 65_536 } else { le });
    }
    Ok(command)
}

/// Bounded FIDO APDU frontend shared by NFC and CCID; not a peripheral driver.
pub struct FidoApduFrontend {
    ingress: IngressId,
    selected: bool,
    request: [u8; TRUSTED_REQUEST_MAX],
    request_len: usize,
    chaining: bool,
    pending: bool,
    cancelling: bool,
    use_get_response: bool,
    response_encoding: ResponseEncoding,
    response: [u8; TRUSTED_RESPONSE_MAX],
    response_len: usize,
    response_offset: usize,
}

pub type NfcApduFrontend = FidoApduFrontend;

impl FidoApduFrontend {
    pub const fn new(instance: u8) -> Self {
        Self::with_ingress(IngressId::new(IngressKind::Nfc, instance))
    }

    pub(crate) const fn new_ccid(instance: u8) -> Self {
        Self::with_ingress(IngressId::new(IngressKind::UsbCcid, instance))
    }

    const fn with_ingress(ingress: IngressId) -> Self {
        Self {
            ingress,
            selected: false,
            request: [0; TRUSTED_REQUEST_MAX],
            request_len: 0,
            chaining: false,
            pending: false,
            cancelling: false,
            use_get_response: false,
            response_encoding: ResponseEncoding::Short { le: 256 },
            response: [0; TRUSTED_RESPONSE_MAX],
            response_len: 0,
            response_offset: 0,
        }
    }

    pub const fn ingress_id(&self) -> IngressId {
        self.ingress
    }

    pub const fn is_selected(&self) -> bool {
        self.selected
    }

    pub fn owns_pending<T: TrustedBackend>(&self, arbiter: &IngressArbiter<T>) -> bool {
        arbiter.is_owned_by(self.ingress)
    }

    pub fn handle_apdu<'a, T: TrustedBackend>(
        &'a mut self,
        arbiter: &mut IngressArbiter<T>,
        apdu: &[u8],
    ) -> NfcApduOutcome<'a> {
        let command = match parse_apdu(apdu) {
            Ok(command) => command,
            Err(status_word) => return self.empty_reply(status_word),
        };

        if command.cla == 0x00 && command.ins == INS_SELECT {
            return self.select(command, arbiter);
        }
        if !self.selected {
            return NfcApduOutcome::Ignored;
        }
        if self.chaining && !(command.ins == INS_MSG && matches!(command.cla, 0x80 | 0x90)) {
            self.clear_request();
            return self.empty_reply(SW_CHAINING_ERROR);
        }

        match (command.cla, command.ins) {
            (0x90, INS_MSG) => self.continue_command(command),
            (0x80, INS_MSG) => self.finish_command(command, arbiter),
            (0x80, INS_GET_RESPONSE) => self.get_response(command, arbiter),
            (0x80, INS_CONTROL) => self.control(command, arbiter),
            (0x80, INS_ISO_GET_RESPONSE) | (0x00, INS_ISO_GET_RESPONSE) => {
                self.iso_get_response(command)
            }
            (0x00 | 0x80 | 0x90, _) => self.empty_reply(SW_INS_NOT_SUPPORTED),
            _ => self.empty_reply(SW_CLA_NOT_SUPPORTED),
        }
    }

    pub fn poll_deferred<'a, T: TrustedBackend>(
        &'a mut self,
        arbiter: &mut IngressArbiter<T>,
    ) -> Option<NfcApduReply<'a>> {
        if !self.pending || self.use_get_response {
            return None;
        }
        let result = arbiter.poll(self.ingress)?;
        match result {
            TrustedResult::UserPresencePending => None,
            TrustedResult::Response(data) => {
                self.pending = false;
                if !self.store_response(data) {
                    return Some(self.single_byte_reply(CTAP_INVALID_LENGTH, SW_SUCCESS));
                }
                Some(self.emit_stored_response())
            }
            TrustedResult::Busy => None,
            TrustedResult::InvalidRequest => {
                self.pending = false;
                Some(self.single_byte_reply(CTAP_INVALID_LENGTH, SW_SUCCESS))
            }
        }
    }

    pub fn poll_cancel<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) -> bool {
        if !self.cancelling {
            return !arbiter.is_owned_by(self.ingress);
        }
        let _ = arbiter.poll(self.ingress);
        if !arbiter.is_owned_by(self.ingress) || arbiter.finish_cancel(self.ingress) {
            self.cancelling = false;
            return true;
        }
        false
    }

    /// Clears protocol state, not payload bytes; poll_cancel settles deferred backend cancellation.
    pub fn disconnect<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) {
        if arbiter.is_owned_by(self.ingress) {
            arbiter.cancel(self.ingress);
            self.cancelling = arbiter.is_owned_by(self.ingress);
        }
        self.selected = false;
        self.pending = false;
        self.clear_request();
        self.clear_response();
    }

    pub(crate) fn cancel_exchange<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) {
        if arbiter.is_owned_by(self.ingress) {
            arbiter.cancel(self.ingress);
            self.cancelling = arbiter.is_owned_by(self.ingress);
        }
        self.pending = false;
        self.clear_request();
        self.clear_response();
    }

    fn select<'a, T: TrustedBackend>(
        &'a mut self,
        command: CommandApdu<'_>,
        arbiter: &mut IngressArbiter<T>,
    ) -> NfcApduOutcome<'a> {
        if command.p1 != 0x04 || command.p2 != 0x00 {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if command.data != FIDO_AID {
            return self.empty_reply(SW_FILE_NOT_FOUND);
        }
        if arbiter.is_owned_by(self.ingress) {
            arbiter.cancel(self.ingress);
            self.cancelling = arbiter.is_owned_by(self.ingress);
        }
        self.selected = true;
        self.pending = false;
        self.clear_request();
        self.clear_response();
        self.response[..FIDO2_VERSION.len()].copy_from_slice(FIDO2_VERSION);
        self.response_len = FIDO2_VERSION.len();
        NfcApduOutcome::Reply(self.reply(0, self.response_len, SW_SUCCESS))
    }

    fn continue_command<'a>(&'a mut self, command: CommandApdu<'_>) -> NfcApduOutcome<'a> {
        if self.pending || self.cancelling {
            self.clear_request();
            return self.single_byte_outcome(CTAP_CHANNEL_BUSY, SW_SUCCESS);
        }
        if command.p1 != 0
            || command.p2 != 0
            || command.extended
            || command.data.is_empty()
            || command.le.is_some()
        {
            self.clear_request();
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if !self.append_request(command.data) {
            self.clear_request();
            return self.empty_reply(SW_WRONG_LENGTH);
        }
        self.chaining = true;
        self.empty_reply(SW_SUCCESS)
    }

    fn finish_command<'a, T: TrustedBackend>(
        &'a mut self,
        command: CommandApdu<'_>,
        arbiter: &mut IngressArbiter<T>,
    ) -> NfcApduOutcome<'a> {
        if self.pending || self.cancelling {
            self.clear_request();
            return self.single_byte_outcome(CTAP_CHANNEL_BUSY, SW_SUCCESS);
        }
        if command.p1 & 0x7f != 0 || command.p2 != 0 || command.data.is_empty() {
            self.clear_request();
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if self.chaining && command.extended {
            self.clear_request();
            return self.empty_reply(SW_CHAINING_ERROR);
        }
        if !self.append_request(command.data) {
            self.clear_request();
            return self.empty_reply(SW_WRONG_LENGTH);
        }

        self.response_encoding = command.response_encoding();
        self.use_get_response = command.p1 & 0x80 != 0;
        self.chaining = false;
        let request_len = self.request_len;
        let result = arbiter.submit_cbor(self.ingress, &self.request[..request_len]);
        self.request_len = 0;
        match result {
            TrustedResult::Response(data) => {
                if !self.store_response(data) {
                    return self.single_byte_outcome(CTAP_INVALID_LENGTH, SW_SUCCESS);
                }
                self.emit_stored_response_outcome()
            }
            TrustedResult::UserPresencePending => {
                self.pending = true;
                if self.use_get_response {
                    self.single_byte_outcome(STATUS_UP_NEEDED, SW_STATUS)
                } else {
                    NfcApduOutcome::Deferred
                }
            }
            TrustedResult::Busy => self.single_byte_outcome(CTAP_CHANNEL_BUSY, SW_SUCCESS),
            TrustedResult::InvalidRequest => {
                self.single_byte_outcome(CTAP_INVALID_LENGTH, SW_SUCCESS)
            }
        }
    }

    fn get_response<'a, T: TrustedBackend>(
        &'a mut self,
        command: CommandApdu<'_>,
        arbiter: &mut IngressArbiter<T>,
    ) -> NfcApduOutcome<'a> {
        if command.p2 != 0 || !command.data.is_empty() || !self.pending {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if command.p1 == 0x11 {
            arbiter.cancel(self.ingress);
            self.cancelling = arbiter.is_owned_by(self.ingress);
            self.pending = false;
            return self.single_byte_outcome(CTAP_KEEPALIVE_CANCEL, SW_SUCCESS);
        }
        if command.p1 != 0 {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }

        match arbiter.poll(self.ingress) {
            None | Some(TrustedResult::Busy) => {
                self.single_byte_outcome(STATUS_PROCESSING, SW_STATUS)
            }
            Some(TrustedResult::UserPresencePending) => {
                self.single_byte_outcome(STATUS_UP_NEEDED, SW_STATUS)
            }
            Some(TrustedResult::Response(data)) => {
                self.pending = false;
                if !self.store_response(data) {
                    return self.single_byte_outcome(CTAP_INVALID_LENGTH, SW_SUCCESS);
                }
                self.emit_stored_response_outcome()
            }
            Some(TrustedResult::InvalidRequest) => {
                self.pending = false;
                self.single_byte_outcome(CTAP_INVALID_LENGTH, SW_SUCCESS)
            }
        }
    }

    fn control<'a, T: TrustedBackend>(
        &'a mut self,
        command: CommandApdu<'_>,
        arbiter: &mut IngressArbiter<T>,
    ) -> NfcApduOutcome<'a> {
        if command.p1 != 0x01 || command.p2 != 0 || !command.data.is_empty() || command.le.is_some()
        {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if arbiter.is_owned_by(self.ingress) {
            arbiter.cancel(self.ingress);
            self.cancelling = arbiter.is_owned_by(self.ingress);
        }
        self.selected = false;
        self.pending = false;
        self.clear_request();
        self.clear_response();
        self.empty_reply(SW_SUCCESS)
    }

    fn iso_get_response<'a>(&'a mut self, command: CommandApdu<'_>) -> NfcApduOutcome<'a> {
        if command.p1 != 0 || command.p2 != 0 || !command.data.is_empty() || command.le.is_none() {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        if self.response_offset >= self.response_len {
            return self.empty_reply(SW_INCORRECT_P1_P2);
        }
        let le = command.le.unwrap_or(256).min(256);
        self.emit_short_response(le)
    }

    fn append_request(&mut self, data: &[u8]) -> bool {
        let Some(end) = self.request_len.checked_add(data.len()) else {
            return false;
        };
        if end > self.request.len() {
            return false;
        }
        self.request[self.request_len..end].copy_from_slice(data);
        self.request_len = end;
        true
    }

    fn store_response(&mut self, data: &[u8]) -> bool {
        if data.len() > self.response.len() {
            self.clear_response();
            return false;
        }
        self.response[..data.len()].copy_from_slice(data);
        self.response_len = data.len();
        self.response_offset = 0;
        true
    }

    fn emit_stored_response_outcome(&mut self) -> NfcApduOutcome<'_> {
        NfcApduOutcome::Reply(self.emit_stored_response())
    }

    fn emit_stored_response(&mut self) -> NfcApduReply<'_> {
        match self.response_encoding {
            ResponseEncoding::Extended => {
                self.response_offset = self.response_len;
                self.reply(0, self.response_len, SW_SUCCESS)
            }
            ResponseEncoding::Short { le } => match self.emit_short_response(le) {
                NfcApduOutcome::Reply(reply) => reply,
                NfcApduOutcome::Deferred | NfcApduOutcome::Ignored => unreachable!(),
            },
        }
    }

    fn emit_short_response(&mut self, le: usize) -> NfcApduOutcome<'_> {
        let start = self.response_offset;
        let end = (start + le).min(self.response_len);
        self.response_offset = end;
        let remaining = self.response_len - end;
        let status_word = if remaining == 0 {
            SW_SUCCESS
        } else {
            0x6100
                | if remaining >= 256 {
                    0
                } else {
                    remaining as u16
                }
        };
        NfcApduOutcome::Reply(self.reply(start, end, status_word))
    }

    fn single_byte_outcome(&mut self, value: u8, status_word: u16) -> NfcApduOutcome<'_> {
        NfcApduOutcome::Reply(self.single_byte_reply(value, status_word))
    }

    fn single_byte_reply(&mut self, value: u8, status_word: u16) -> NfcApduReply<'_> {
        self.response[0] = value;
        self.response_len = 1;
        self.response_offset = 1;
        self.reply(0, 1, status_word)
    }

    fn empty_reply(&self, status_word: u16) -> NfcApduOutcome<'_> {
        NfcApduOutcome::Reply(NfcApduReply {
            data: &[],
            status_word,
        })
    }

    fn reply(&self, start: usize, end: usize, status_word: u16) -> NfcApduReply<'_> {
        NfcApduReply {
            data: &self.response[start..end],
            status_word,
        }
    }

    fn clear_request(&mut self) {
        self.request_len = 0;
        self.chaining = false;
    }

    fn clear_response(&mut self) {
        self.response_len = 0;
        self.response_offset = 0;
    }
}
