use crate::ctaphid::trusted::TrustedBackend;
use crate::security::{
    NONSECURE_SHARED_MEMORY, SharedMemoryRegion, TrustedCallDescriptor, TrustedCallError,
    ValidatedTrustedCall, dispatch_validated_trusted_call, trusted_call_error_status,
};

#[derive(Clone, Copy)]
/// Port-provided NS address range; this does not configure hardware attribution.
pub struct NonsecureMemoryRange {
    pub start: u32,
    pub end: u32,
}

impl NonsecureMemoryRange {
    pub const fn contains(self, address: u32, len: u32) -> bool {
        match address.checked_add(len) {
            Some(end) => address >= self.start && end <= self.end,
            None => false,
        }
    }
}

/// # Safety
/// Call in Secure Privileged state with a stable range matching SAU/IDAU attribution.
pub unsafe fn validate_nonsecure_readable(
    range: NonsecureMemoryRange,
    pointer: u32,
    len: usize,
) -> bool {
    validate_nonsecure_range(range, pointer, len, false)
}

/// # Safety
/// Call in Secure Privileged state with a stable range matching SAU/IDAU attribution.
pub unsafe fn validate_nonsecure_read_write(
    range: NonsecureMemoryRange,
    pointer: u32,
    len: usize,
) -> bool {
    validate_nonsecure_range(range, pointer, len, true)
}

fn validate_nonsecure_range(
    range: NonsecureMemoryRange,
    pointer: u32,
    len: usize,
    writable: bool,
) -> bool {
    use cortex_m::cmse::{AccessType, TestTarget};

    let Ok(len) = u32::try_from(len) else {
        return false;
    };
    if len == 0 || !range.contains(pointer, len) {
        return false;
    }
    let Some(target) =
        TestTarget::check_range(pointer as *mut u32, len as usize, AccessType::NonSecure)
    else {
        return false;
    };
    if writable {
        target.ns_read_and_writable()
    } else {
        target.ns_readable()
    }
}

/// # Safety
/// Call in Secure Privileged state with SAU enabled and the default shared layout valid.
/// Keep memory attribution/access stable through use of the returned descriptor.
pub unsafe fn read_trusted_call(
    descriptor_ptr: u32,
) -> Result<ValidatedTrustedCall, TrustedCallError> {
    unsafe { read_trusted_call_in(NONSECURE_SHARED_MEMORY, descriptor_ptr) }
}

/// # Safety
/// Call in Secure Privileged state; shared memory must match current hardware attribution.
/// Keep descriptor/payload access stable through use; validation does not exclude concurrent writers.
pub unsafe fn read_trusted_call_in(
    shared_memory: SharedMemoryRegion,
    descriptor_ptr: u32,
) -> Result<ValidatedTrustedCall, TrustedCallError> {
    let descriptor_size = core::mem::size_of::<TrustedCallDescriptor>();
    let descriptor_end = descriptor_ptr
        .checked_add(descriptor_size as u32)
        .filter(|end| {
            descriptor_ptr & 3 == 0
                && descriptor_ptr >= shared_memory.start
                && *end <= shared_memory.end
        })
        .ok_or(TrustedCallError::InvalidDescriptor)?;
    if !unsafe {
        validate_nonsecure_read_write(
            NonsecureMemoryRange {
                start: shared_memory.start,
                end: shared_memory.end,
            },
            descriptor_ptr,
            (descriptor_end - descriptor_ptr) as usize,
        )
    } {
        return Err(TrustedCallError::InvalidDescriptor);
    }

    let descriptor =
        unsafe { core::ptr::read_volatile(descriptor_ptr as *const TrustedCallDescriptor) };
    let validated =
        trusted_boundary::validate_trusted_call(shared_memory, descriptor_ptr, descriptor)?;

    if descriptor.request_len != 0 {
        if !unsafe {
            validate_nonsecure_readable(
                NonsecureMemoryRange {
                    start: shared_memory.start,
                    end: shared_memory.end,
                },
                descriptor.request_ptr,
                descriptor.request_len as usize,
            )
        } {
            return Err(TrustedCallError::InvalidRequest);
        }
    }
    if !unsafe {
        validate_nonsecure_read_write(
            NonsecureMemoryRange {
                start: shared_memory.start,
                end: shared_memory.end,
            },
            descriptor.response_ptr,
            descriptor.response_capacity as usize,
        )
    } {
        return Err(TrustedCallError::InvalidResponse);
    }
    Ok(validated)
}

/// # Safety
/// Call in Secure Privileged state with SAU enabled and the default shared layout valid.
/// Exclude backend reentry and concurrent descriptor/payload mutation throughout dispatch.
pub unsafe fn dispatch_trusted_call<T: TrustedBackend>(
    descriptor_ptr: u32,
    trusted: &mut T,
) -> u32 {
    unsafe { dispatch_trusted_call_in(NONSECURE_SHARED_MEMORY, descriptor_ptr, trusted) }
}

/// # Safety
/// Call in Secure Privileged state with matching stable SAU/IDAU/MPC/MPU attribution.
/// Exclude backend reentry and concurrent descriptor/payload mutation throughout dispatch.
pub unsafe fn dispatch_trusted_call_in<T: TrustedBackend>(
    shared_memory: SharedMemoryRegion,
    descriptor_ptr: u32,
    trusted: &mut T,
) -> u32 {
    let validated = match unsafe { read_trusted_call_in(shared_memory, descriptor_ptr) } {
        Ok(validated) => validated,
        Err(error) => return trusted_call_error_status(error),
    };
    unsafe { dispatch_validated_trusted_call(descriptor_ptr, validated.descriptor, trusted) }
}
