use manekey::{
    ctaphid::trusted::TrustedBackend,
    security::{SharedMemoryRegion, dispatch_trusted_call_from_shared},
};

pub fn shared_memory_region(start: *const u8, end: *const u8) -> SharedMemoryRegion {
    SharedMemoryRegion {
        start: start as u32,
        end: end as u32,
    }
}

/// Dispatch a bounded shared descriptor.
///
/// # Safety
/// Supply installed PMP shared bounds and valid mapped memory; exclude concurrent mutation, DMA and reentry.
/// Exclusively own the private M-mode backend.
pub unsafe fn dispatch_from_shared<T: TrustedBackend>(
    shared_memory: SharedMemoryRegion,
    descriptor_ptr: u32,
    trusted: &mut T,
) -> u32 {
    unsafe { dispatch_trusted_call_from_shared(shared_memory, descriptor_ptr, trusted) }
}
