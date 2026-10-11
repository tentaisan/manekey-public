




// Encodes one denied 32-byte subregion in a 256-byte region, rounding up.
// Caller owns the range, background map and region priority; this does not install it.
pub const fn stack_guard_region(stack_bottom: u32) -> Option<(u32, u32)> {
    let address = match stack_bottom.checked_add(31) {
        Some(value) => value & !31,
        None => return None,
    };
    let disabled = 0xff ^ (1 << ((address >> 5) & 7));
    Some((address & !255, (1 << 28) | (7 << 1) | (disabled << 8) | 1))
}



// Normal/non-cacheable memory only, not MMIO. Caller chooses region priority and
// must enforce the actual CPU's region capabilities and memory ownership.
pub const fn normal_region_rasr(
    base: u32,
    size_log2: u32,
    access: u32,
    execute_never: bool,
) -> Option<u32> {
    if size_log2 < 5 || size_log2 > 32 || !matches!(access, 0 | 1 | 2 | 3 | 5 | 6) {
        return None;
    }
    let mask = if size_log2 == 32 {
        u32::MAX
    } else {
        (1_u32 << size_log2) - 1
    };
    if base & mask != 0 {
        return None;
    }
    Some(((execute_never as u32) << 28) | (access << 24) | (1 << 19) | ((size_log2 - 1) << 1) | 1)
}




// Checks address arithmetic only; no memory is read or authenticated here.
// Caller owns a stable stack window and validates MPU attributes, stacked PC/SVC
// and any additional alignment padding before accessing the exception frame.
pub const fn checked_psp_frame(
    stack: u32,
    exception_return: u32,
    stack_start: u32,
    stack_end: u32,
) -> Option<u32> {
    let fp_bytes = match exception_return {
        0xffff_fffd => 0,
        0xffff_ffed => 72,
        _ => return None,
    };
    if stack_start >= stack_end || stack & 7 != 0 || stack < stack_start {
        return None;
    }
    match stack.checked_add(fp_bytes + 32) {
        Some(end) if end <= stack_end => Some(stack + fp_bytes),
        _ => None,
    }
}


#[cfg(all(target_arch = "arm", target_os = "none"))]
pub struct SvcTrustedCallGate;

#[cfg(all(target_arch = "arm", target_os = "none"))]
impl super::local_trusted_call::TrustedCallGate for SvcTrustedCallGate {
    fn invoke(&mut self, descriptor_ptr: u32) -> u32 {
        let result: u32;
        // The port owns SVC #0 and validates/copies the untrusted descriptor.
        unsafe {
            core::arch::asm!("svc #0", inout("r0") descriptor_ptr => result);
        }
        result
    }
}



















































































