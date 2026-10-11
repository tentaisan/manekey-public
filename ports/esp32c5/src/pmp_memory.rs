#[unsafe(no_mangle)]
#[unsafe(link_section = ".c5_pmp_user_text")]
/// Fill a valid writable byte range.
///
/// # Safety
/// dest must be valid and exclusively writable for len bytes in the current privilege mode.
pub unsafe extern "C" fn c5_pmp_user_memset(dest: *mut u8, value: i32, len: usize) -> *mut u8 {
    for offset in 0..len {
        unsafe { dest.add(offset).write_volatile(value as u8) };
    }
    dest
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".c5_pmp_user_text")]
/// Copy nonoverlapping byte ranges.
///
/// # Safety
/// Supply valid readable source and exclusively writable destination ranges of len bytes, without overlap.
pub unsafe extern "C" fn c5_pmp_user_memcpy(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    for offset in 0..len {
        unsafe {
            dest.add(offset)
                .write_volatile(src.add(offset).read_volatile())
        };
    }
    dest
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".c5_pmp_user_text")]
/// Copy possibly overlapping byte ranges.
///
/// # Safety
/// Supply valid readable source and exclusively writable destination ranges of len bytes.
pub unsafe extern "C" fn c5_pmp_user_memmove(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
    if (dest as usize) <= (src as usize) {
        for offset in 0..len {
            unsafe {
                dest.add(offset)
                    .write_volatile(src.add(offset).read_volatile())
            };
        }
    } else {
        for offset in (0..len).rev() {
            unsafe {
                dest.add(offset)
                    .write_volatile(src.add(offset).read_volatile())
            };
        }
    }
    dest
}
