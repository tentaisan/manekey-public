use crate::{
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedBackend, TrustedResult},
    security::{
        SharedMemoryRegion, TrustedCallDescriptor, dispatch_trusted_call_from_shared,
        trusted_operation, trusted_status,
    },
};

#[repr(C)]
/// Shared call buffers; platform adapters provide exclusion and memory isolation.
pub struct SharedTrustedCallState {
    descriptor: TrustedCallDescriptor,
    request: [u8; TRUSTED_REQUEST_MAX as usize],
    response: [u8; TRUSTED_RESPONSE_MAX as usize],
}

impl SharedTrustedCallState {
    pub const fn new() -> Self {
        Self {
            descriptor: TrustedCallDescriptor {
                request_ptr: 0,
                request_len: 0,
                response_ptr: 0,
                response_capacity: 0,
                response_len: 0,
                status: 0,
            },
            request: [0; TRUSTED_REQUEST_MAX as usize],
            response: [0; TRUSTED_RESPONSE_MAX as usize],
        }
    }
}

impl Default for SharedTrustedCallState {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates and dispatches a descriptor in an allowed shared window.
pub trait TrustedCallGate {
    fn invoke(&mut self, descriptor_ptr: u32) -> u32;
}

pub struct LocalTrustedCallGate<'a, T: TrustedBackend> {
    shared_memory: SharedMemoryRegion,
    trusted: &'a mut T,
}

impl<T: TrustedBackend> TrustedCallGate for LocalTrustedCallGate<'_, T> {
    fn invoke(&mut self, descriptor_ptr: u32) -> u32 {
        unsafe {
            dispatch_trusted_call_from_shared(self.shared_memory, descriptor_ptr, self.trusted)
        }
    }
}

pub struct SharedTrustedCallBackend<'a, G: TrustedCallGate> {
    shared: &'a mut SharedTrustedCallState,
    gate: G,
    response_len: usize,
    pending: bool,
}

pub type LocalTrustedCallBackend<'a, T> = SharedTrustedCallBackend<'a, LocalTrustedCallGate<'a, T>>;

impl<'a, T: TrustedBackend> SharedTrustedCallBackend<'a, LocalTrustedCallGate<'a, T>> {
    /// Same-address-space adapter, not a hardware security boundary.
    /// # Safety
    /// Shared state must lie in shared_memory with 32-bit representable addresses.
    /// Keep the window valid and prevent concurrent trusted-backend reentry.
    pub unsafe fn new(
        shared_memory: SharedMemoryRegion,
        shared: &'a mut SharedTrustedCallState,
        trusted: &'a mut T,
    ) -> Self {
        unsafe {
            Self::with_gate(
                shared,
                LocalTrustedCallGate {
                    shared_memory,
                    trusted,
                },
            )
        }
    }
}

impl<'a, G: TrustedCallGate> SharedTrustedCallBackend<'a, G> {
    /// # Safety
    /// Exclusively own shared state inside the gate window with 32-bit representable addresses.
    /// The gate must validate/copy the descriptor without trusted-backend reentry.
    pub unsafe fn with_gate(shared: &'a mut SharedTrustedCallState, gate: G) -> Self {
        Self {
            shared,
            gate,
            response_len: 0,
            pending: false,
        }
    }

    fn invoke(&mut self, operation_code: u32, request: &[u8]) -> u32 {
        if request.len() > self.shared.request.len() {
            return trusted_status::INVALID_REQUEST;
        }

        self.shared.request[..request.len()].copy_from_slice(request);
        self.shared.descriptor = TrustedCallDescriptor {
            request_ptr: if request.is_empty() {
                0
            } else {
                self.shared.request.as_ptr() as u32
            },
            request_len: request.len() as u32,
            response_ptr: self.shared.response.as_mut_ptr() as u32,
            response_capacity: self.shared.response.len() as u32,
            response_len: 0,
            status: operation_code,
        };

        let descriptor_ptr = core::ptr::addr_of_mut!(self.shared.descriptor) as u32;
        let returned_status = self.gate.invoke(descriptor_ptr);
        self.shared.request[..request.len()].fill(0);
        self.response_len = usize::try_from(self.shared.descriptor.response_len)
            .ok()
            .filter(|len| *len <= self.shared.response.len())
            .unwrap_or(0);
        if returned_status == self.shared.descriptor.status {
            returned_status
        } else {
            trusted_status::INVALID_DESCRIPTOR
        }
    }

    fn result<'b>(&'b self, call_status: u32) -> TrustedResult<'b> {
        match call_status {
            trusted_status::OK => {
                TrustedResult::Response(&self.shared.response[..self.response_len])
            }
            trusted_status::USER_PRESENCE_PENDING => TrustedResult::UserPresencePending,
            trusted_status::BUSY => TrustedResult::Busy,
            _ => TrustedResult::InvalidRequest,
        }
    }
}

impl<G: TrustedCallGate> TrustedBackend for SharedTrustedCallBackend<'_, G> {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let status = self.invoke(trusted_operation::SUBMIT_CBOR, request);
        self.pending = status == trusted_status::USER_PRESENCE_PENDING;
        self.result(status)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let status = self.invoke(trusted_operation::SUBMIT_U2F, request);
        self.pending = status == trusted_status::USER_PRESENCE_PENDING;
        self.result(status)
    }

    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        if !self.pending {
            return None;
        }
        let status = self.invoke(trusted_operation::POLL, &[]);
        self.pending = status == trusted_status::USER_PRESENCE_PENDING;
        Some(self.result(status))
    }

    fn cancel(&mut self) -> bool {
        if !self.pending {
            return false;
        }
        let status = self.invoke(trusted_operation::CANCEL, &[]);
        self.pending = false;
        status == trusted_status::OK
    }

    fn is_busy(&self) -> bool {
        self.pending
    }
}
