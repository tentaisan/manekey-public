// SPDX-License-Identifier: Apache-2.0
#![no_std]

pub const MAGIC: [u8; 2] = *b"MK";

pub const VERSION: u8 = 1;

pub const HEADER_LEN: usize = 9;

pub const TRAILER_LEN: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InterconnectFrameKind {
    Data = 1,

    Cancel = 2,

    Reset = 3,

    Poll = 4,
}

impl TryFrom<u8> for InterconnectFrameKind {
    type Error = InterconnectFrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Cancel),
            3 => Ok(Self::Reset),
            4 => Ok(Self::Poll),
            _ => Err(InterconnectFrameError::InvalidKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// CRC-framed payload; CRC does not authenticate the sender or payload.
pub struct InterconnectFrame<'a> {
    kind: InterconnectFrameKind,
    channel: u8,
    sequence: u16,
    payload: &'a [u8],
}

impl<'a> InterconnectFrame<'a> {
    pub const fn new(
        kind: InterconnectFrameKind,
        channel: u8,
        sequence: u16,
        payload: &'a [u8],
    ) -> Self {
        Self {
            kind,
            channel,
            sequence,
            payload,
        }
    }

    pub const fn kind(self) -> InterconnectFrameKind {
        self.kind
    }

    pub const fn channel(self) -> u8 {
        self.channel
    }

    pub const fn sequence(self) -> u16 {
        self.sequence
    }

    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, InterconnectFrameError> {
        if self.payload.len() > u16::MAX as usize {
            return Err(InterconnectFrameError::PayloadTooLong);
        }
        let total = HEADER_LEN + self.payload.len() + TRAILER_LEN;
        if output.len() < total {
            return Err(InterconnectFrameError::OutputTooShort);
        }

        output[..2].copy_from_slice(&MAGIC);
        output[2] = VERSION;
        output[3] = self.kind as u8;
        output[4] = self.channel;
        output[5..7].copy_from_slice(&self.sequence.to_be_bytes());
        output[7..9].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        output[HEADER_LEN..HEADER_LEN + self.payload.len()].copy_from_slice(self.payload);
        let crc = crc16(&output[2..HEADER_LEN + self.payload.len()]);
        output[HEADER_LEN + self.payload.len()..total].copy_from_slice(&crc.to_be_bytes());
        Ok(total)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectFrameError {
    InvalidKind,
    InvalidVersion,
    PayloadTooLong,
    OutputTooShort,
    CrcMismatch,
}

pub struct InterconnectDecoder<const MAX_FRAME: usize> {
    frame: [u8; MAX_FRAME],
    used: usize,
    expected: Option<usize>,
}

impl<const MAX_FRAME: usize> InterconnectDecoder<MAX_FRAME> {
    /// # Panics
    /// Panics if MAX_FRAME is smaller than HEADER_LEN + TRAILER_LEN.
    pub const fn new() -> Self {
        assert!(MAX_FRAME >= HEADER_LEN + TRAILER_LEN);
        Self {
            frame: [0; MAX_FRAME],
            used: 0,
            expected: None,
        }
    }

    pub const fn reset(&mut self) {
        self.used = 0;
        self.expected = None;
    }

    pub const fn is_receiving(&self) -> bool {
        self.used != 0
    }

    pub fn push(
        &mut self,
        byte: u8,
    ) -> Result<Option<InterconnectFrame<'_>>, InterconnectFrameError> {
        if self.used == 0 && byte != MAGIC[0] {
            return Ok(None);
        }
        if self.used == 1 && byte != MAGIC[1] {
            self.used = usize::from(byte == MAGIC[0]);
            return Ok(None);
        }

        self.frame[self.used] = byte;
        self.used += 1;
        if self.used == HEADER_LEN {
            if self.frame[2] != VERSION {
                self.reset();
                return Err(InterconnectFrameError::InvalidVersion);
            }
            if let Err(error) = InterconnectFrameKind::try_from(self.frame[3]) {
                self.reset();
                return Err(error);
            }
            let payload_len = u16::from_be_bytes([self.frame[7], self.frame[8]]) as usize;
            if payload_len > MAX_FRAME.saturating_sub(HEADER_LEN + TRAILER_LEN) {
                self.reset();
                return Err(InterconnectFrameError::PayloadTooLong);
            }
            self.expected = Some(HEADER_LEN + payload_len + TRAILER_LEN);
        }

        if self.expected != Some(self.used) {
            return Ok(None);
        }

        let payload_len = u16::from_be_bytes([self.frame[7], self.frame[8]]) as usize;
        let crc_at = HEADER_LEN + payload_len;
        let expected_crc = u16::from_be_bytes([self.frame[crc_at], self.frame[crc_at + 1]]);
        let actual_crc = crc16(&self.frame[2..crc_at]);
        if actual_crc != expected_crc {
            self.reset();
            return Err(InterconnectFrameError::CrcMismatch);
        }

        let kind = InterconnectFrameKind::try_from(self.frame[3])?;
        let channel = self.frame[4];
        let sequence = u16::from_be_bytes([self.frame[5], self.frame[6]]);
        self.used = 0;
        self.expected = None;
        Ok(Some(InterconnectFrame::new(
            kind,
            channel,
            sequence,
            &self.frame[HEADER_LEN..crc_at],
        )))
    }
}

impl<const MAX_FRAME: usize> Default for InterconnectDecoder<MAX_FRAME> {
    fn default() -> Self {
        Self::new()
    }
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}
