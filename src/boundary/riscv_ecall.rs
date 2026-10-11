

use crate::ctaphid::trusted::{TrustedBackend, TrustedResult};
use trusted_boundary::{
    TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedCallDescriptor, operation, status,
};

core::arch::global_asm!(
    r#"
    .section .text.pmp_user_ecall_wrapper, "ax"
    .global manekey_riscv_pmp_trusted_ecall
    .align 2
manekey_riscv_pmp_trusted_ecall:
    .option push
    .option norvc
    ecall
    ret
    .option pop
"#
);

unsafe extern "C" {
    fn manekey_riscv_pmp_trusted_ecall(ecall_id: u32, descriptor_ptr: u32) -> u32;
}





#[repr(C)]
// Place the entire backend in memory authorized as shared by the M-mode monitor.
// The port owns trap routing/PMP and validates descriptor operation, ranges and
// buffer ownership. Keep shared inputs stable until the synchronous call returns.
pub struct RiscvPmpEcallBackend {
    ecall_id: u32,
    descriptor: TrustedCallDescriptor,
    request: [u8; TRUSTED_REQUEST_MAX as usize],
    response: [u8; TRUSTED_RESPONSE_MAX as usize],
    response_len: usize,
    pending: bool,
}

const _: () = assert!(
    core::mem::size_of::<RiscvPmpEcallBackend>()
        <= crate::boundary::riscv_pmp::SHARED_CALL_REGION_SOFT_LIMIT
);

impl RiscvPmpEcallBackend {

    pub const fn new(ecall_id: u32) -> Self {
        Self {
            ecall_id,
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
            response_len: 0,
            pending: false,
        }
    }


    pub const fn manekey() -> Self {
        Self::new(crate::boundary::riscv_pmp::TRUSTED_CALL_ECALL_ID)
    }

    fn invoke(&mut self, operation_code: u32, request: &[u8]) -> u32 {
        if request.len() > self.request.len() {
            return status::INVALID_REQUEST;
        }
        self.request[..request.len()].copy_from_slice(request);
        self.descriptor = TrustedCallDescriptor {
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
        let descriptor_ptr = core::ptr::addr_of_mut!(self.descriptor) as u32;
        // The U-mode trap-return landing path requires the 32-bit ecall/ret wrapper.
        let returned_status =
            unsafe { manekey_riscv_pmp_trusted_ecall(self.ecall_id, descriptor_ptr) };
        self.request[..request.len()].fill(0);
        self.response_len = usize::try_from(self.descriptor.response_len)
            .ok()
            .filter(|len| *len <= self.response.len())
            .unwrap_or(0);
        if returned_status == self.descriptor.status {
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

impl TrustedBackend for RiscvPmpEcallBackend {
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
