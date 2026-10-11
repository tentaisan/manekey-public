use crate::ctaphid::{Packet, descriptor::REPORT_SIZE};

pub const INIT_HEADER_SIZE: usize = 7;

pub const CONT_HEADER_SIZE: usize = 5;

pub const INIT_PAYLOAD_SIZE: usize = REPORT_SIZE - INIT_HEADER_SIZE;

pub const CONT_PAYLOAD_SIZE: usize = REPORT_SIZE - CONT_HEADER_SIZE;

#[cfg(feature = "experimental-large-message-buffers")]
pub const MAX_MESSAGE_SIZE: usize = 4096;
#[cfg(all(
    not(feature = "experimental-large-message-buffers"),
    not(feature = "ctaphid-small-message-buffers")
))]
pub const MAX_MESSAGE_SIZE: usize = 1024;
#[cfg(all(
    not(feature = "experimental-large-message-buffers"),
    feature = "ctaphid-small-message-buffers"
))]
pub const MAX_MESSAGE_SIZE: usize = 384;

#[cfg(feature = "experimental-large-message-buffers")]
pub const MAX_REQUEST_SIZE: usize = 1024;
#[cfg(not(feature = "experimental-large-message-buffers"))]
pub const MAX_REQUEST_SIZE: usize = MAX_MESSAGE_SIZE;

pub const TRANSACTION_TIMEOUT_TICKS: u8 = 30;

#[derive(Debug)]

pub enum ChannelError {
    InvalidLen,

    InvalidSeq,

    ChannelBusy,

    MessageTimeout,
}

/// Single-message bounded reassembly; state reset does not erase payload bytes.
pub struct Channel {
    cid: u32,
    cmd: u8,

    buf: [u8; MAX_REQUEST_SIZE],
    len: usize,
    expected_len: usize,

    seq: u8,
    assembling: bool,
    elapsed_ticks: u8,
}

pub struct Message<'a> {
    pub cid: u32,

    pub cmd: u8,

    pub data: &'a [u8],
}

impl Channel {
    pub const fn new() -> Self {
        Self {
            cid: 0,
            cmd: 0,
            buf: [0; MAX_REQUEST_SIZE],
            len: 0,
            expected_len: 0,
            seq: 0,
            assembling: false,
            elapsed_ticks: 0,
        }
    }

    /// Advances one timeout tick; the caller controls polling cadence.
    pub fn poll_timeout(&mut self) -> Option<u32> {
        if !self.assembling {
            return None;
        }

        self.elapsed_ticks = self.elapsed_ticks.saturating_add(1);
        if self.elapsed_ticks < TRANSACTION_TIMEOUT_TICKS {
            return None;
        }

        self.assembling = false;
        self.elapsed_ticks = 0;
        Some(self.cid)
    }

    /// Requires report-sized packet payload slices, as produced by parse_packet.
    /// Short manually constructed payloads may panic.
    pub fn push<'a>(&'a mut self, pkt: Packet<'_>) -> Result<Option<Message<'a>>, ChannelError> {
        match pkt {
            Packet::Init {
                cid,
                cmd,
                len,
                data,
            } => {
                if self.assembling {
                    if cid != self.cid {
                        return Err(ChannelError::ChannelBusy);
                    }

                    self.assembling = false;
                }
                self.cid = cid;
                self.cmd = cmd & 0x7f;
                self.expected_len = len as usize;

                if self.expected_len > self.buf.len() {
                    self.assembling = false;
                    return Err(ChannelError::InvalidLen);
                }

                self.len = 0;
                self.seq = 0;
                self.assembling = true;
                self.elapsed_ticks = 0;

                let copy_len = core::cmp::min(57, self.expected_len);
                self.buf[..copy_len].copy_from_slice(&data[..copy_len]);
                self.len = copy_len;

                if self.len >= self.expected_len {
                    self.assembling = false;
                    self.elapsed_ticks = 0;
                    return Ok(Some(Message {
                        cid,
                        cmd: self.cmd,
                        data: &self.buf[..self.expected_len],
                    }));
                }
                Ok(None)
            }

            Packet::Cont { cid, seq, data } => {
                if !self.assembling || cid != self.cid || seq != self.seq {
                    self.assembling = false;
                    return Err(ChannelError::InvalidSeq);
                }

                let remaining = self.expected_len - self.len;
                let copy_len = core::cmp::min(59, remaining);

                self.buf[self.len..self.len + copy_len].copy_from_slice(&data[..copy_len]);

                self.len += copy_len;
                self.seq += 1;
                self.elapsed_ticks = 0;

                if self.len >= self.expected_len {
                    self.assembling = false;
                    self.elapsed_ticks = 0;

                    return Ok(Some(Message {
                        cid,
                        cmd: self.cmd,
                        data: &self.buf[..self.expected_len],
                    }));
                }
                Ok(None)
            }
        }
    }
}
