use crate::ctaphid::channel::MAX_REQUEST_SIZE;
use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};

mod profile;
pub use profile::*;

mod bond;
pub use bond::*;

mod framing;
pub use framing::*;

mod adapter;
pub use adapter::*;
pub mod boundary_slots;

/// Connection-local BLE framing and backend dispatch.
pub struct BleFidoProtocol {
    assembler: BleFidoAssembler,
    pending: bool,
    request: [u8; MAX_REQUEST_SIZE],
}

pub struct BleFidoFrontend<T: TrustedBackend> {
    protocol: BleFidoProtocol,
    trusted: T,
}

impl BleFidoProtocol {
    pub const fn new(max_fragment_len: usize) -> Self {
        Self {
            assembler: BleFidoAssembler::new(max_fragment_len),
            pending: false,
            request: [0; MAX_REQUEST_SIZE],
        }
    }

    pub fn handle_write_with_backend<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
        trusted: &mut impl TrustedBackend,
    ) -> Result<usize, BleFidoError> {
        let Some(msg) = self.assembler.push_into(fragment, &mut self.request)? else {
            return Ok(0);
        };
        self.handle_message::<MAX_FRAGMENT>(msg.cmd, msg.len, sink, trusted)
    }

    pub fn poll_with_backend<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
        trusted: &mut impl TrustedBackend,
    ) -> Result<usize, BleFidoError> {
        if !self.pending {
            return Ok(0);
        }

        match trusted.poll() {
            Some(TrustedResult::Response(data)) => {
                self.pending = false;
                encode_fragments::<MAX_FRAGMENT>(command::MSG, data, MAX_FRAGMENT, sink)
            }
            Some(TrustedResult::UserPresencePending) => {
                encode_keepalive::<MAX_FRAGMENT>(MAX_FRAGMENT, sink)
            }
            Some(TrustedResult::Busy) => encode_error::<MAX_FRAGMENT>(error_code::BUSY, sink),
            Some(TrustedResult::InvalidRequest) => {
                self.pending = false;
                encode_error::<MAX_FRAGMENT>(error_code::INVALID_LEN, sink)
            }
            None => {
                if !trusted.is_busy() {
                    self.pending = false;
                }
                Ok(0)
            }
        }
    }

    /// Clears connection state and requests cancellation; deferred completion requires polling.
    pub fn disconnect_with_backend(&mut self, trusted: &mut impl TrustedBackend) {
        self.assembler.reset();
        if self.pending {
            let _ = trusted.cancel();
            self.pending = false;
        }
    }

    pub fn settle_disconnected_backend(&mut self, trusted: &mut impl TrustedBackend) -> bool {
        if trusted.is_busy() {
            let _ = trusted.poll();
        }
        !trusted.is_busy()
    }

    fn handle_message<const MAX_FRAGMENT: usize>(
        &mut self,
        cmd: u8,
        len: usize,
        sink: &mut impl BleFidoFragmentSink,
        trusted: &mut impl TrustedBackend,
    ) -> Result<usize, BleFidoError> {
        match cmd {
            command::PING => encode_fragments::<MAX_FRAGMENT>(
                command::PING,
                &self.request[..len],
                MAX_FRAGMENT,
                sink,
            ),
            command::MSG => {
                if trusted.is_busy() || self.pending {
                    return encode_error::<MAX_FRAGMENT>(error_code::BUSY, sink);
                }
                match trusted.submit_cbor(&self.request[..len]) {
                    TrustedResult::Response(data) => {
                        encode_fragments::<MAX_FRAGMENT>(command::MSG, data, MAX_FRAGMENT, sink)
                    }
                    TrustedResult::UserPresencePending => {
                        self.pending = true;
                        encode_keepalive::<MAX_FRAGMENT>(MAX_FRAGMENT, sink)
                    }
                    TrustedResult::Busy => encode_error::<MAX_FRAGMENT>(error_code::BUSY, sink),
                    TrustedResult::InvalidRequest => {
                        encode_error::<MAX_FRAGMENT>(error_code::INVALID_LEN, sink)
                    }
                }
            }
            command::CANCEL => {
                if len != 0 {
                    return encode_error::<MAX_FRAGMENT>(error_code::INVALID_LEN, sink);
                }
                if self.pending {
                    let _ = trusted.cancel();
                    self.pending = trusted.is_busy();
                }

                Ok(0)
            }
            _ => encode_error::<MAX_FRAGMENT>(error_code::INVALID_CMD, sink),
        }
    }
}

impl<T: TrustedBackend> BleFidoFrontend<T> {
    pub const fn new(max_fragment_len: usize, trusted: T) -> Self {
        Self {
            protocol: BleFidoProtocol::new(max_fragment_len),
            trusted,
        }
    }

    pub fn handle_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.protocol
            .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut self.trusted)
    }

    pub fn poll<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.protocol
            .poll_with_backend::<MAX_FRAGMENT>(sink, &mut self.trusted)
    }

    pub fn settle_disconnected_backend(&mut self) -> bool {
        self.protocol.settle_disconnected_backend(&mut self.trusted)
    }
}

impl<T: TrustedBackend> BleFidoProfileHandler for BleFidoFrontend<T> {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.handle_write::<MAX_FRAGMENT>(fragment, sink)
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.poll::<MAX_FRAGMENT>(sink)
    }

    fn on_disconnect(&mut self) {
        self.protocol.disconnect_with_backend(&mut self.trusted);
    }

    fn settle_disconnected_backend(&mut self) -> bool {
        BleFidoFrontend::settle_disconnected_backend(self)
    }
}
