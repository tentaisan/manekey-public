use super::ingress::{IngressArbiter, IngressId, IngressKind};
use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};
use crate::transport::interconnect::{
    InterconnectDecoder, InterconnectFrame, InterconnectFrameError, InterconnectFrameKind,
};

pub const INTERNAL_CTAP2_CHANNEL: u8 = 2;

#[derive(Debug, Eq, PartialEq)]
pub enum InternalCtapResult<'a> {
    Response(&'a [u8]),

    UserPresencePending,

    Busy,

    InvalidRequest,
}

impl<'a> From<TrustedResult<'a>> for InternalCtapResult<'a> {
    fn from(result: TrustedResult<'a>) -> Self {
        match result {
            TrustedResult::Response(response) => Self::Response(response),
            TrustedResult::UserPresencePending => Self::UserPresencePending,
            TrustedResult::Busy => Self::Busy,
            TrustedResult::InvalidRequest => Self::InvalidRequest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalTransportEvent<'a> {
    Ctap2Request(&'a [u8]),
    Poll,
    Cancel,
    LinkLost,
}

#[derive(Debug, Eq, PartialEq)]
pub enum InternalTransportResult<'a> {
    Response(&'a [u8]),
    UserPresencePending,
    Busy,
    InvalidRequest,
    CancelAccepted,
    NoResponse,
    LinkClosed,
}

impl<'a> From<InternalCtapResult<'a>> for InternalTransportResult<'a> {
    fn from(result: InternalCtapResult<'a>) -> Self {
        match result {
            InternalCtapResult::Response(response) => Self::Response(response),
            InternalCtapResult::UserPresencePending => Self::UserPresencePending,
            InternalCtapResult::Busy => Self::Busy,
            InternalCtapResult::InvalidRequest => Self::InvalidRequest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalCtapFrontend {
    ingress: IngressId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalTransport {
    frontend: InternalCtapFrontend,
}

/// Bounded CTAP2 link framing; CRC does not authenticate the peer.
/// Continue poll_cancel after disconnect when a backend remains owned.
pub struct InterconnectCtap2Frontend<const MAX_FRAME: usize> {
    decoder: InterconnectDecoder<MAX_FRAME>,
    transport: InternalTransport,
    channel: u8,
    cancelling: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectCtap2Outcome {
    Response { len: usize },

    UserPresencePending,

    Busy,

    InvalidRequest,

    CancelAccepted,

    NoResponse,

    LinkClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterconnectCtap2Error {
    Frame(InterconnectFrameError),
    UnexpectedChannel,
    UnexpectedPayload,
}

impl From<InterconnectFrameError> for InterconnectCtap2Error {
    fn from(error: InterconnectFrameError) -> Self {
        Self::Frame(error)
    }
}

impl<const MAX_FRAME: usize> InterconnectCtap2Frontend<MAX_FRAME> {
    pub const fn new(instance: u8) -> Self {
        Self::with_channel(instance, INTERNAL_CTAP2_CHANNEL)
    }

    pub const fn with_channel(instance: u8, channel: u8) -> Self {
        Self {
            decoder: InterconnectDecoder::new(),
            transport: InternalTransport::new(instance),
            channel,
            cancelling: false,
        }
    }

    pub const fn ingress_id(&self) -> IngressId {
        self.transport.ingress_id()
    }

    pub const fn channel(&self) -> u8 {
        self.channel
    }

    pub const fn is_receiving(&self) -> bool {
        self.decoder.is_receiving()
    }

    pub fn discard_partial_frame(&mut self) {
        self.decoder.reset();
    }

    pub fn poll_cancel<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) -> bool {
        let ingress = self.ingress_id();
        if !self.cancelling {
            return !arbiter.is_owned_by(ingress);
        }
        let _ = arbiter.poll(ingress);
        if !arbiter.is_owned_by(ingress) || arbiter.finish_cancel(ingress) {
            self.cancelling = false;
            return true;
        }
        false
    }

    pub fn disconnect<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>) {
        self.decoder.reset();
        let _ = self
            .transport
            .handle_event(arbiter, InternalTransportEvent::LinkLost);
        self.cancelling = arbiter.is_owned_by(self.ingress_id());
    }

    /// Encodes a completed response into output; encoding failure may follow backend completion.
    pub fn push_byte<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        byte: u8,
        output: &mut [u8],
    ) -> Result<Option<InterconnectCtap2Outcome>, InterconnectCtap2Error> {
        let _ = self.poll_cancel(arbiter);
        let Some(frame) = self.decoder.push(byte)? else {
            return Ok(None);
        };
        if frame.channel() != self.channel {
            return Err(InterconnectCtap2Error::UnexpectedChannel);
        }

        let sequence = frame.sequence();
        let event = match frame.kind() {
            InterconnectFrameKind::Data if !frame.payload().is_empty() => {
                InternalTransportEvent::Ctap2Request(frame.payload())
            }
            InterconnectFrameKind::Poll if frame.payload().is_empty() => {
                InternalTransportEvent::Poll
            }
            InterconnectFrameKind::Cancel if frame.payload().is_empty() => {
                InternalTransportEvent::Cancel
            }
            InterconnectFrameKind::Reset if frame.payload().is_empty() => {
                InternalTransportEvent::LinkLost
            }
            InterconnectFrameKind::Data => return Err(InterconnectCtap2Error::UnexpectedPayload),
            InterconnectFrameKind::Poll
            | InterconnectFrameKind::Cancel
            | InterconnectFrameKind::Reset => {
                return Err(InterconnectCtap2Error::UnexpectedPayload);
            }
        };

        let outcome = match self.transport.handle_event(arbiter, event) {
            InternalTransportResult::Response(payload) => {
                let len = InterconnectFrame::new(
                    InterconnectFrameKind::Data,
                    self.channel,
                    sequence,
                    payload,
                )
                .encode_into(output)?;
                InterconnectCtap2Outcome::Response { len }
            }
            InternalTransportResult::UserPresencePending => {
                InterconnectCtap2Outcome::UserPresencePending
            }
            InternalTransportResult::Busy => InterconnectCtap2Outcome::Busy,
            InternalTransportResult::InvalidRequest => InterconnectCtap2Outcome::InvalidRequest,
            InternalTransportResult::CancelAccepted => InterconnectCtap2Outcome::CancelAccepted,
            InternalTransportResult::NoResponse => InterconnectCtap2Outcome::NoResponse,
            InternalTransportResult::LinkClosed => InterconnectCtap2Outcome::LinkClosed,
        };

        if matches!(
            event,
            InternalTransportEvent::Cancel | InternalTransportEvent::LinkLost
        ) {
            self.cancelling = arbiter.is_owned_by(self.ingress_id());
        }
        Ok(Some(outcome))
    }
}

impl InternalTransport {
    pub const fn new(instance: u8) -> Self {
        Self {
            frontend: InternalCtapFrontend::new(instance),
        }
    }

    pub const fn ingress_id(self) -> IngressId {
        self.frontend.ingress_id()
    }

    pub fn handle_event<'a, T: TrustedBackend>(
        &self,
        arbiter: &'a mut IngressArbiter<T>,
        event: InternalTransportEvent<'_>,
    ) -> InternalTransportResult<'a> {
        match event {
            InternalTransportEvent::Ctap2Request(request) => {
                self.frontend.submit_cbor(arbiter, request).into()
            }
            InternalTransportEvent::Poll => self
                .frontend
                .poll(arbiter)
                .map(Into::into)
                .unwrap_or(InternalTransportResult::NoResponse),
            InternalTransportEvent::Cancel => self
                .frontend
                .cancel(arbiter)
                .then_some(InternalTransportResult::CancelAccepted)
                .unwrap_or(InternalTransportResult::NoResponse),
            InternalTransportEvent::LinkLost => {
                if self.frontend.owns_pending(arbiter) {
                    let _ = self.frontend.cancel(arbiter);
                }
                InternalTransportResult::LinkClosed
            }
        }
    }
}

impl InternalCtapFrontend {
    pub const fn new(instance: u8) -> Self {
        Self {
            ingress: IngressId::new(IngressKind::Internal, instance),
        }
    }

    pub const fn ingress_id(self) -> IngressId {
        self.ingress
    }

    pub fn submit_cbor<'a, T: TrustedBackend>(
        &self,
        arbiter: &'a mut IngressArbiter<T>,
        request: &[u8],
    ) -> InternalCtapResult<'a> {
        arbiter.submit_cbor(self.ingress, request).into()
    }

    pub fn poll<'a, T: TrustedBackend>(
        &self,
        arbiter: &'a mut IngressArbiter<T>,
    ) -> Option<InternalCtapResult<'a>> {
        arbiter.poll(self.ingress).map(Into::into)
    }

    pub fn cancel<T: TrustedBackend>(&self, arbiter: &mut IngressArbiter<T>) -> bool {
        arbiter.cancel(self.ingress)
    }

    pub fn finish_cancel<T: TrustedBackend>(&self, arbiter: &mut IngressArbiter<T>) -> bool {
        arbiter.finish_cancel(self.ingress)
    }

    pub fn owns_pending<T: TrustedBackend>(&self, arbiter: &IngressArbiter<T>) -> bool {
        arbiter.is_owned_by(self.ingress)
    }
}
