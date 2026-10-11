use super::{BleFidoFragmentSink, CONTROL_POINT_LENGTH_MAX, CONTROL_POINT_LENGTH_MIN};
use crate::ctaphid::channel::{MAX_MESSAGE_SIZE, MAX_REQUEST_SIZE};

const MAX_CONTINUATION_FRAGMENTS: usize = 128;

pub mod command {
    pub const PING: u8 = 0x81;
    pub const KEEPALIVE: u8 = 0x82;
    pub const MSG: u8 = 0x83;
    pub const CANCEL: u8 = 0xbe;
    pub const ERROR: u8 = 0xbf;
}

pub mod keepalive_status {
    pub const PROCESSING: u8 = 0x01;
    pub const UP_NEEDED: u8 = 0x02;
}

pub mod error_code {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_PAR: u8 = 0x02;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const REQ_TIMEOUT: u8 = 0x05;
    pub const BUSY: u8 = 0x06;
    pub const OTHER: u8 = 0x7f;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleFidoError {
    InvalidMaxFragmentLen,

    EmptyFragment,

    FragmentTooLong,

    InvalidInit,

    InvalidCommand,

    InvalidLen,

    InvalidSeq,

    Busy,

    AdvDataTooLong,

    UnsupportedOffset,

    ContinuationLimitExceeded,
}

pub struct BleFidoMessage<'a> {
    pub cmd: u8,

    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BleFidoCopiedMessage {
    pub cmd: u8,
    pub len: usize,
}

/// Bounded message assembly; reset discards state but does not erase payload bytes.
pub struct BleFidoAssembler {
    max_fragment_len: usize,
    buf: [u8; MAX_REQUEST_SIZE],
    cmd: u8,
    len: usize,
    expected_len: usize,
    seq: u8,
    assembling: bool,
}

impl BleFidoAssembler {
    pub const fn new(max_fragment_len: usize) -> Self {
        Self {
            max_fragment_len,
            buf: [0; MAX_REQUEST_SIZE],
            cmd: 0,
            len: 0,
            expected_len: 0,
            seq: 0,
            assembling: false,
        }
    }

    pub fn reset(&mut self) {
        self.cmd = 0;
        self.len = 0;
        self.expected_len = 0;
        self.seq = 0;
        self.assembling = false;
    }

    pub fn push<'a>(
        &'a mut self,
        fragment: &[u8],
    ) -> Result<Option<BleFidoMessage<'a>>, BleFidoError> {
        validate_fragment_len(self.max_fragment_len)?;
        if fragment.is_empty() {
            self.reset();
            return Err(BleFidoError::EmptyFragment);
        }
        if fragment.len() > self.max_fragment_len {
            self.reset();
            return Err(BleFidoError::FragmentTooLong);
        }

        if fragment[0] & 0x80 != 0 {
            return self.push_init(fragment);
        }

        self.push_cont(fragment)
    }

    pub fn push_into(
        &mut self,
        fragment: &[u8],
        out: &mut [u8],
    ) -> Result<Option<BleFidoCopiedMessage>, BleFidoError> {
        let Some(msg) = self.push(fragment)? else {
            return Ok(None);
        };
        if msg.data.len() > out.len() {
            return Err(BleFidoError::InvalidLen);
        }
        out[..msg.data.len()].copy_from_slice(msg.data);
        Ok(Some(BleFidoCopiedMessage {
            cmd: msg.cmd,
            len: msg.data.len(),
        }))
    }

    fn push_init<'a>(
        &'a mut self,
        fragment: &[u8],
    ) -> Result<Option<BleFidoMessage<'a>>, BleFidoError> {
        if self.assembling {
            self.reset();
            return Err(BleFidoError::Busy);
        }
        if fragment.len() < 3 {
            self.reset();
            return Err(BleFidoError::InvalidInit);
        }

        let expected_len = u16::from_be_bytes([fragment[1], fragment[2]]) as usize;
        let init_data = &fragment[3..];
        if expected_len > MAX_REQUEST_SIZE || init_data.len() > expected_len {
            self.reset();
            return Err(BleFidoError::InvalidLen);
        }

        self.cmd = fragment[0];
        self.len = init_data.len();
        self.expected_len = expected_len;
        self.seq = 0;
        self.assembling = true;
        self.buf[..self.len].copy_from_slice(init_data);

        if self.len == self.expected_len {
            self.assembling = false;
            return Ok(Some(BleFidoMessage {
                cmd: self.cmd,
                data: &self.buf[..self.expected_len],
            }));
        }

        Ok(None)
    }

    fn push_cont<'a>(
        &'a mut self,
        fragment: &[u8],
    ) -> Result<Option<BleFidoMessage<'a>>, BleFidoError> {
        if !self.assembling || fragment[0] != self.seq {
            self.reset();
            return Err(BleFidoError::InvalidSeq);
        }

        let cont_data = &fragment[1..];
        let remaining = self.expected_len - self.len;
        if cont_data.len() > remaining {
            self.reset();
            return Err(BleFidoError::InvalidLen);
        }

        self.buf[self.len..self.len + cont_data.len()].copy_from_slice(cont_data);
        self.len += cont_data.len();

        if self.len == self.expected_len {
            self.assembling = false;
            return Ok(Some(BleFidoMessage {
                cmd: self.cmd,
                data: &self.buf[..self.expected_len],
            }));
        }

        if self.seq == (MAX_CONTINUATION_FRAGMENTS - 1) as u8 {
            self.reset();
            return Err(BleFidoError::ContinuationLimitExceeded);
        }
        self.seq += 1;

        Ok(None)
    }
}

/// Emits at most 128 continuation fragments; sink acceptance is not peer delivery.
pub fn encode_fragments<const MAX_FRAGMENT: usize>(
    cmd: u8,
    data: &[u8],
    max_fragment_len: usize,
    sink: &mut impl BleFidoFragmentSink,
) -> Result<usize, BleFidoError> {
    validate_fragment_len(max_fragment_len)?;
    if max_fragment_len > MAX_FRAGMENT {
        return Err(BleFidoError::InvalidMaxFragmentLen);
    }
    if data.len() > MAX_MESSAGE_SIZE || data.len() > u16::MAX as usize {
        return Err(BleFidoError::InvalidLen);
    }

    let mut fragment = [0u8; MAX_FRAGMENT];
    if cmd & 0x80 == 0 {
        return Err(BleFidoError::InvalidCommand);
    }

    fragment[0] = cmd;
    fragment[1..3].copy_from_slice(&(data.len() as u16).to_be_bytes());

    let mut offset = core::cmp::min(max_fragment_len - 3, data.len());
    let continuation_count = if offset == data.len() {
        0
    } else {
        (data.len() - offset).div_ceil(max_fragment_len - 1)
    };
    if continuation_count > MAX_CONTINUATION_FRAGMENTS {
        return Err(BleFidoError::ContinuationLimitExceeded);
    }
    fragment[3..3 + offset].copy_from_slice(&data[..offset]);
    sink.push_fragment(&fragment[..3 + offset])?;
    let mut count = 1;

    let mut seq = 0u8;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let chunk_len = core::cmp::min(max_fragment_len - 1, remaining);
        fragment[0] = seq;
        fragment[1..1 + chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);
        sink.push_fragment(&fragment[..1 + chunk_len])?;
        offset += chunk_len;
        seq = seq.wrapping_add(1) & 0x7f;
        count += 1;
    }

    Ok(count)
}

fn validate_fragment_len(max_fragment_len: usize) -> Result<(), BleFidoError> {
    if !(CONTROL_POINT_LENGTH_MIN..=CONTROL_POINT_LENGTH_MAX).contains(&max_fragment_len) {
        return Err(BleFidoError::InvalidMaxFragmentLen);
    }
    Ok(())
}

pub(super) fn encode_keepalive<const MAX_FRAGMENT: usize>(
    max_fragment_len: usize,
    sink: &mut impl BleFidoFragmentSink,
) -> Result<usize, BleFidoError> {
    encode_fragments::<MAX_FRAGMENT>(
        command::KEEPALIVE,
        &[keepalive_status::UP_NEEDED],
        max_fragment_len,
        sink,
    )
}

pub(super) fn encode_error<const MAX_FRAGMENT: usize>(
    code: u8,
    sink: &mut impl BleFidoFragmentSink,
) -> Result<usize, BleFidoError> {
    encode_fragments::<MAX_FRAGMENT>(command::ERROR, &[code], MAX_FRAGMENT, sink)
}
