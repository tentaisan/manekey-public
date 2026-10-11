use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};
use trusted_boundary::{
    TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedCallDescriptor, operation, status,
};

/// NSC client; workspace and stack descriptors must remain within the authorized NS window.
pub struct ArmGatewayBackend {
    gateway_address: u32,
    request: [u8; TRUSTED_REQUEST_MAX as usize],
    response: [u8; TRUSTED_RESPONSE_MAX as usize],
    response_len: usize,
    pending: bool,
}

#[repr(C)]
/// Port-owned NS shared workspace; descriptor and payload must fit one authorized window.
pub struct ArmGatewaySharedBuffers {
    descriptor: TrustedCallDescriptor,
    request: [u8; TRUSTED_REQUEST_MAX as usize],
    response: [u8; TRUSTED_RESPONSE_MAX as usize],
}

impl ArmGatewaySharedBuffers {
    pub const fn new() -> Self {
        Self {
            descriptor: TrustedCallDescriptor {
                request_ptr: 0,
                request_len: 0,
                response_ptr: 0,
                response_capacity: 0,
                response_len: 0,
                status: operation::SUBMIT_CBOR,
            },
            request: [0; TRUSTED_REQUEST_MAX as usize],
            response: [0; TRUSTED_RESPONSE_MAX as usize],
        }
    }
}

/// Construction requires a valid NSC entry with the expected ABI and an authorized shared window.
/// Serialize all calls; exclude task/IRQ/DMA access to the workspace for the backend lifetime.
pub struct ArmSharedGatewayBackend<'a> {
    gateway_address: u32,
    shared: &'a mut ArmGatewaySharedBuffers,
    response_len: usize,
    pending: bool,
}

/// Construction requires a valid NSC service entry with the expected ABI and authorized workspace.
/// Use a dedicated serialized workspace, separate from concurrent CTAP/radio calls.
pub struct ArmSharedServiceGateway<'a> {
    gateway_address: u32,
    shared: &'a mut ArmGatewaySharedBuffers,
}

impl<'a> ArmSharedServiceGateway<'a> {
    pub const unsafe fn new(gateway_address: u32, shared: &'a mut ArmGatewaySharedBuffers) -> Self {
        Self {
            gateway_address: gateway_address | 1,
            shared,
        }
    }

    pub fn call(&mut self, operation_code: u32, output: &mut [u8]) -> bool {
        self.call_with_request(operation_code, &[], output)
    }

    /// Requires exact-length service output; failure leaves caller output unchanged.
    /// Workspace cleanup is not an all-path secret-erasure guarantee.
    pub fn call_with_request(
        &mut self,
        operation_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> bool {
        if input.len() > self.shared.request.len() {
            return false;
        }
        if output.is_empty() || output.len() > self.shared.response.len() {
            return false;
        }
        self.shared.request[..input.len()].copy_from_slice(input);
        self.shared.descriptor = TrustedCallDescriptor {
            request_ptr: if input.is_empty() {
                0
            } else {
                self.shared.request.as_ptr() as u32
            },
            request_len: input.len() as u32,
            response_ptr: self.shared.response.as_mut_ptr() as u32,
            response_capacity: output.len() as u32,
            response_len: 0,
            status: operation_code,
        };
        let returned_status: u32;
        unsafe {
            core::arch::asm!(
                "blx r4",
                in("r4") self.gateway_address,
                inout("r0") core::ptr::addr_of_mut!(self.shared.descriptor) as u32 => returned_status,
                out("r1") _, out("r2") _, out("r3") _, out("r12") _, out("lr") _,
            );
        }
        let response_len = usize::try_from(self.shared.descriptor.response_len)
            .ok()
            .filter(|len| *len == output.len())
            .unwrap_or(0);
        let accepted = returned_status == status::OK
            && self.shared.descriptor.status == status::OK
            && response_len == output.len();
        if accepted {
            output.copy_from_slice(&self.shared.response[..response_len]);
        }
        self.shared.request[..input.len()].fill(0);
        self.shared.response[..response_len].fill(0);
        accepted
    }
}

impl<'a> ArmSharedGatewayBackend<'a> {
    pub const unsafe fn new(gateway_address: u32, shared: &'a mut ArmGatewaySharedBuffers) -> Self {
        Self {
            gateway_address: gateway_address | 1,
            shared,
            response_len: 0,
            pending: false,
        }
    }

    fn invoke(&mut self, operation_code: u32, request: &[u8]) -> u32 {
        if request.len() > self.shared.request.len() {
            return status::INVALID_REQUEST;
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
        let returned_status: u32;
        unsafe {
            core::arch::asm!(
                "blx r4",
                in("r4") self.gateway_address,
                inout("r0") core::ptr::addr_of_mut!(self.shared.descriptor) as u32 => returned_status,
                out("r1") _,
                out("r2") _,
                out("r3") _,
                out("r12") _,
                out("lr") _,
            );
        }
        self.shared.request[..request.len()].fill(0);
        self.response_len = usize::try_from(self.shared.descriptor.response_len)
            .ok()
            .filter(|len| *len <= self.shared.response.len())
            .unwrap_or(0);
        if returned_status == self.shared.descriptor.status {
            returned_status
        } else {
            status::INVALID_DESCRIPTOR
        }
    }

    fn result(&self, call_status: u32) -> TrustedResult<'_> {
        match call_status {
            status::OK => TrustedResult::Response(&self.shared.response[..self.response_len]),
            status::USER_PRESENCE_PENDING => TrustedResult::UserPresencePending,
            status::BUSY => TrustedResult::Busy,
            _ => TrustedResult::InvalidRequest,
        }
    }
}

impl TrustedBackend for ArmSharedGatewayBackend<'_> {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let call_status = self.invoke(operation::SUBMIT_CBOR, request);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        self.result(call_status)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let call_status = self.invoke(operation::SUBMIT_U2F, request);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        self.result(call_status)
    }

    fn poll(&mut self) -> Option<TrustedResult<'_>> {
        if !self.pending {
            return None;
        }
        let call_status = self.invoke(operation::POLL, &[]);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        Some(self.result(call_status))
    }

    fn cancel(&mut self) -> bool {
        if !self.pending {
            return false;
        }
        let call_status = self.invoke(operation::CANCEL, &[]);
        self.pending = false;
        call_status == status::OK
    }

    fn is_busy(&self) -> bool {
        self.pending
    }
}

impl ArmGatewayBackend {
    /// # Safety
    /// Supply a valid Thumb NSC entry with the expected ABI and an authorized stable NS layout.
    /// All stack descriptors and backend buffers must be accessible to that service.
    pub const unsafe fn new(gateway_address: u32) -> Self {
        Self {
            gateway_address,
            request: [0; TRUSTED_REQUEST_MAX as usize],
            response: [0; TRUSTED_RESPONSE_MAX as usize],
            response_len: 0,
            pending: false,
        }
    }

    fn invoke(&mut self, operation_code: u32, request: &[u8]) -> u32 {
        if request.len() > self.request.len() {
            return status::INVALID_REQUEST;
        }
        self.request[..request.len()].copy_from_slice(request);
        let mut descriptor = TrustedCallDescriptor {
            request_ptr: if request.is_empty() {
                0
            } else {
                self.request.as_ptr() as u32
            },
            request_len: request.len() as u32,
            response_ptr: self.response.as_mut_ptr() as u32,
            response_capacity: self.response.len() as u32,
            response_len: 0,
            status: operation_code,
        };
        let returned_status: u32;
        unsafe {
            core::arch::asm!(
                "blx r4",
                in("r4") self.gateway_address,
                inout("r0") core::ptr::addr_of_mut!(descriptor) as u32 => returned_status,
                out("r1") _,
                out("r2") _,
                out("r3") _,
                out("r12") _,
                out("lr") _,
            );
        }
        self.request[..request.len()].fill(0);
        self.response_len = usize::try_from(descriptor.response_len)
            .ok()
            .filter(|len| *len <= self.response.len())
            .unwrap_or(0);
        if returned_status == descriptor.status {
            returned_status
        } else {
            status::INVALID_DESCRIPTOR
        }
    }

    fn result(&self, call_status: u32) -> TrustedResult<'_> {
        match call_status {
            status::OK => TrustedResult::Response(&self.response[..self.response_len]),
            status::USER_PRESENCE_PENDING => TrustedResult::UserPresencePending,
            status::BUSY => TrustedResult::Busy,
            _ => TrustedResult::InvalidRequest,
        }
    }
}

impl TrustedBackend for ArmGatewayBackend {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let call_status = self.invoke(operation::SUBMIT_CBOR, request);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        self.result(call_status)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        let call_status = self.invoke(operation::SUBMIT_U2F, request);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        self.result(call_status)
    }

    fn poll(&mut self) -> Option<TrustedResult<'_>> {
        if !self.pending {
            return None;
        }
        let call_status = self.invoke(operation::POLL, &[]);
        self.pending = call_status == status::USER_PRESENCE_PENDING;
        Some(self.result(call_status))
    }

    fn cancel(&mut self) -> bool {
        if !self.pending {
            return false;
        }
        let call_status = self.invoke(operation::CANCEL, &[]);
        self.pending = false;
        call_status == status::OK
    }

    fn is_busy(&self) -> bool {
        self.pending
    }
}
