use super::mailbox::{MailboxClientTransport, MailboxEndpoint, MailboxError, MailboxState};
use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};

pub struct CopiedBackendWorker<B: TrustedBackend> {
    backend: B,
    request: [u8; TRUSTED_REQUEST_MAX],
}
impl<B: TrustedBackend> CopiedBackendWorker<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            request: [0; TRUSTED_REQUEST_MAX],
        }
    }
    pub fn pump_once(
        &mut self,
        endpoint: &MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    ) -> Result<bool, MailboxError> {
        if endpoint.state()? != MailboxState::RequestReady {
            return Ok(false);
        }
        let len = endpoint.take_request(&mut self.request)?;
        let result = match endpoint.operation() {
            trusted_operation::SUBMIT_CBOR => self.backend.submit_cbor(&self.request[..len]),
            trusted_operation::SUBMIT_U2F => self.backend.submit_u2f(&self.request[..len]),
            trusted_operation::POLL => self.backend.poll().unwrap_or(TrustedResult::Busy),
            trusted_operation::CANCEL => {
                self.backend.cancel();
                self.request[..len].fill(0);
                endpoint.publish_status_response(trusted_status::OK, &[])?;
                return Ok(true);
            }
            _ => {
                self.request[..len].fill(0);
                endpoint.publish_status_response(trusted_status::INVALID_OPERATION, &[])?;
                return Ok(true);
            }
        };
        let published = match result {
            TrustedResult::Response(bytes) if bytes.len() <= TRUSTED_RESPONSE_MAX => {
                endpoint.publish_status_response(trusted_status::OK, bytes)
            }
            TrustedResult::Response(_) => {
                endpoint.publish_status_response(trusted_status::OUTPUT_TOO_SMALL, &[])
            }
            TrustedResult::UserPresencePending => {
                endpoint.publish_status_response(trusted_status::USER_PRESENCE_PENDING, &[])
            }
            TrustedResult::Busy => endpoint.publish_status_response(trusted_status::BUSY, &[]),
            TrustedResult::InvalidRequest => {
                endpoint.publish_status_response(trusted_status::INVALID_REQUEST, &[])
            }
        };
        self.request[..len].fill(0);
        published?;
        Ok(true)
    }
}
use crate::{
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
    security::{
        SharedMemoryRegion, TrustedCallDescriptor, descriptor_pointer_is_in_shared,
        trusted_operation, trusted_status,
    },
};

pub const NOT_READY: u32 = u32::MAX;
/// Synchronous validated copy gate; adapters own pointer checks, exclusion and hardware attribution.
pub trait MailboxCopyGate {
    fn submit(&mut self, descriptor: u32) -> u32;
    fn receive(&mut self, descriptor: u32) -> u32;
}
/// 32-bit descriptor ABI; addresses must be representable and mapped into the permitted shared window.
pub struct CopiedMailboxTransport<G> {
    gate: G,
    descriptor: TrustedCallDescriptor,
    request: [u8; TRUSTED_REQUEST_MAX],
    placeholder: [u8; 1],
}
impl<G> CopiedMailboxTransport<G> {
    pub const fn new(gate: G) -> Self {
        Self {
            gate,
            descriptor: TrustedCallDescriptor {
                request_ptr: 0,
                request_len: 0,
                response_ptr: 0,
                response_capacity: 0,
                response_len: 0,
                status: 0,
            },
            request: [0; TRUSTED_REQUEST_MAX],
            placeholder: [0],
        }
    }
}
impl<G: MailboxCopyGate> MailboxClientTransport for CopiedMailboxTransport<G> {
    fn submit_operation(&mut self, operation: u32, request: &[u8]) -> Result<(), MailboxError> {
        if request.len() > self.request.len() {
            return Err(MailboxError::InvalidTransition);
        }
        self.request[..request.len()].copy_from_slice(request);
        self.descriptor = TrustedCallDescriptor {
            request_ptr: self.request.as_ptr() as u32,
            request_len: request.len() as u32,
            response_ptr: self.placeholder.as_mut_ptr() as u32,
            response_capacity: 1,
            response_len: 0,
            status: operation,
        };
        let result = self
            .gate
            .submit(core::ptr::addr_of_mut!(self.descriptor) as u32);
        self.request[..request.len()].fill(0);
        if result == trusted_status::OK {
            Ok(())
        } else {
            Err(MailboxError::InvalidTransition)
        }
    }
    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError> {
        if response.is_empty() || response.len() > TRUSTED_RESPONSE_MAX {
            return Err(MailboxError::InvalidTransition);
        }
        self.descriptor = TrustedCallDescriptor {
            request_ptr: 0,
            request_len: 0,
            response_ptr: response.as_mut_ptr() as u32,
            response_capacity: response.len() as u32,
            response_len: 0,
            status: trusted_operation::POLL,
        };
        let result = self
            .gate
            .receive(core::ptr::addr_of_mut!(self.descriptor) as u32);
        if result == NOT_READY {
            return Ok(None);
        }
        if result != trusted_status::OK || self.descriptor.response_len as usize > response.len() {
            return Err(MailboxError::InvalidTransition);
        }
        Ok(Some((
            self.descriptor.status,
            self.descriptor.response_len as usize,
        )))
    }
}

unsafe fn descriptor(shared: SharedMemoryRegion, pointer: u32) -> Option<TrustedCallDescriptor> {
    if !descriptor_pointer_is_in_shared(shared, pointer) {
        return None;
    }
    let descriptor = unsafe { (pointer as *const TrustedCallDescriptor).read_volatile() };
    trusted_boundary::validate_trusted_call(shared, pointer, descriptor)
        .ok()
        .map(|call| call.descriptor)
}

/// # Safety
/// Supply a private endpoint and valid stable shared memory while the caller is stopped.
/// Exclude DMA/other writers and invalid aliases; no U pointer may outlive the copy.
pub unsafe fn submit_from_shared(
    shared: SharedMemoryRegion,
    pointer: u32,
    endpoint: &MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) -> u32 {
    let Some(d) = (unsafe { descriptor(shared, pointer) }) else {
        return trusted_status::INVALID_DESCRIPTOR;
    };
    if !matches!(
        d.status,
        trusted_operation::SUBMIT_CBOR
            | trusted_operation::SUBMIT_U2F
            | trusted_operation::POLL
            | trusted_operation::CANCEL
    ) {
        return trusted_status::INVALID_OPERATION;
    }
    let request = if d.request_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(d.request_ptr as *const u8, d.request_len as usize) }
    };
    if endpoint.submit_operation(d.status, request).is_ok() {
        trusted_status::OK
    } else {
        trusted_status::BUSY
    }
}

/// # Safety
/// Supply a private endpoint and exclusively writable shared descriptor/response while U is stopped.
/// Exclude DMA/other access and invalid aliases throughout the copy.
pub unsafe fn receive_to_shared(
    shared: SharedMemoryRegion,
    pointer: u32,
    endpoint: &MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) -> u32 {
    let Some(d) = (unsafe { descriptor(shared, pointer) }) else {
        return trusted_status::INVALID_DESCRIPTOR;
    };
    if d.status != trusted_operation::POLL || d.request_len != 0 {
        return trusted_status::INVALID_OPERATION;
    }
    if endpoint.state() != Ok(MailboxState::ResponseReady) {
        return NOT_READY;
    }
    let response = unsafe {
        core::slice::from_raw_parts_mut(d.response_ptr as *mut u8, d.response_capacity as usize)
    };
    let Ok((status, len)) = endpoint.take_status_response(response) else {
        return trusted_status::INVALID_RESPONSE;
    };
    let output = pointer as *mut TrustedCallDescriptor;
    unsafe {
        core::ptr::addr_of_mut!((*output).status).write_volatile(status);
        core::ptr::addr_of_mut!((*output).response_len).write_volatile(len as u32);
    }
    trusted_status::OK
}
