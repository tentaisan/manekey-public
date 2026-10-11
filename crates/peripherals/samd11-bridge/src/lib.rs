// SPDX-License-Identifier: Apache-2.0
#![no_std]

use manekey_interconnect::{
    InterconnectDecoder, InterconnectFrame, InterconnectFrameError, InterconnectFrameKind,
};

pub const CTAPHID_REPORT_SIZE: usize = 64;

pub const CTAPHID_CHANNEL: u8 = 1;

pub const FRAME_CAPACITY: usize = 80;

#[derive(Debug, Eq, PartialEq)]
pub enum Samd11CtaphidBridgeInput<'a> {
    Report(&'a [u8; CTAPHID_REPORT_SIZE]),

    LinkReset,

    Poll,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Samd11CtaphidBridgeError {
    Frame(InterconnectFrameError),
    UnexpectedChannel,
    UnexpectedKind,
    InvalidReportLength,
}

impl From<InterconnectFrameError> for Samd11CtaphidBridgeError {
    fn from(error: InterconnectFrameError) -> Self {
        Self::Frame(error)
    }
}

/// Framing adapter only; USB endpoints and peripheral drivers are external.
/// CRC and sequence fields do not authenticate peers or prevent replay.
pub struct Samd11CtaphidBridge {
    decoder: InterconnectDecoder<FRAME_CAPACITY>,
    next_tx_sequence: u16,
}

impl Samd11CtaphidBridge {
    pub const fn new() -> Self {
        Self {
            decoder: InterconnectDecoder::new(),
            next_tx_sequence: 0,
        }
    }

    pub fn encode_usb_report(
        &mut self,
        report: &[u8; CTAPHID_REPORT_SIZE],
        output: &mut [u8],
    ) -> Result<usize, Samd11CtaphidBridgeError> {
        let len = InterconnectFrame::new(
            InterconnectFrameKind::Data,
            CTAPHID_CHANNEL,
            self.next_tx_sequence,
            report,
        )
        .encode_into(output)?;
        self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
        Ok(len)
    }

    pub fn encode_report(
        &self,
        sequence: u16,
        report: &[u8; CTAPHID_REPORT_SIZE],
        output: &mut [u8],
    ) -> Result<usize, Samd11CtaphidBridgeError> {
        InterconnectFrame::new(
            InterconnectFrameKind::Data,
            CTAPHID_CHANNEL,
            sequence,
            report,
        )
        .encode_into(output)
        .map_err(Into::into)
    }

    pub fn encode_link_reset(
        &mut self,
        output: &mut [u8],
    ) -> Result<usize, Samd11CtaphidBridgeError> {
        let len = InterconnectFrame::new(
            InterconnectFrameKind::Reset,
            CTAPHID_CHANNEL,
            self.next_tx_sequence,
            &[],
        )
        .encode_into(output)?;
        self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
        Ok(len)
    }

    pub fn push_link_byte(
        &mut self,
        byte: u8,
    ) -> Result<Option<Samd11CtaphidBridgeInput<'_>>, Samd11CtaphidBridgeError> {
        let Some(frame) = self.decoder.push(byte)? else {
            return Ok(None);
        };
        if frame.channel() != CTAPHID_CHANNEL {
            return Err(Samd11CtaphidBridgeError::UnexpectedChannel);
        }
        match frame.kind() {
            InterconnectFrameKind::Data => {
                let report = frame
                    .payload()
                    .try_into()
                    .map_err(|_| Samd11CtaphidBridgeError::InvalidReportLength)?;
                Ok(Some(Samd11CtaphidBridgeInput::Report(report)))
            }
            InterconnectFrameKind::Reset => Ok(Some(Samd11CtaphidBridgeInput::LinkReset)),
            InterconnectFrameKind::Poll if frame.payload().is_empty() => {
                Ok(Some(Samd11CtaphidBridgeInput::Poll))
            }

            InterconnectFrameKind::Cancel | InterconnectFrameKind::Poll => {
                Err(Samd11CtaphidBridgeError::UnexpectedKind)
            }
        }
    }

    pub fn push(
        &mut self,
        byte: u8,
    ) -> Result<Option<Samd11CtaphidBridgeInput<'_>>, Samd11CtaphidBridgeError> {
        self.push_link_byte(byte)
    }
}

impl Default for Samd11CtaphidBridge {
    fn default() -> Self {
        Self::new()
    }
}
