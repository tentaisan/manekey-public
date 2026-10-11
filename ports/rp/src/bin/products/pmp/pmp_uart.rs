const UART0_DR: *mut u32 = 0x4007_0000 as *mut u32;
const UART0_FR: *const u32 = 0x4007_0018 as *const u32;
const UART_FR_TXFF: u32 = 1 << 5;

#[cfg(any(
    feature = "riscv-pmp-ble-monitor-frontend-io",
    feature = "riscv-pmp-usb-internal-ccid"
))]
/// Nonblocking byte-only UART0 service; require initialized exclusive UART ownership.
pub fn dispatch_byte_io(operation: u32, value: u32) -> u32 {
    use manekey::boundary::riscv_pmp::*;
    if !byte_io_request_is_valid(operation, value) {
        return BYTE_IO_DENIED;
    }

    unsafe {
        let flags = core::ptr::read_volatile(UART0_FR);
        if operation == BYTE_IO_READ {
            if flags & (1 << 4) != 0 {
                return BYTE_IO_EMPTY;
            }
            let data = core::ptr::read_volatile(UART0_DR);
            if data & 0xf00 != 0 {
                core::ptr::write_volatile(0x4007_0004 as *mut u32, 0);
                return BYTE_IO_RECEIVE_ERROR;
            }
            data & 0xff
        } else if flags & UART_FR_TXFF != 0 {
            BYTE_IO_WOULD_BLOCK
        } else {
            core::ptr::write_volatile(UART0_DR, value);
            0
        }
    }
}

/// Startup/terminal output on the same UART owner; never interleave with framed traffic.
pub fn uart_puts(s: &str) {
    for byte in s.bytes() {
        uart_put_byte(byte);
    }
}

pub fn uart_put_hex(value: u32) {
    uart_puts("0x");
    for shift in (0..=28).rev().step_by(4) {
        let nibble = ((value >> shift) & 0x0f) as u8;
        let byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        uart_put_byte(byte);
    }
}

pub fn uart_put_dec(value: u32) {
    if value >= 10 {
        uart_put_dec(value / 10);
    }
    uart_put_byte(b'0' + (value % 10) as u8);
}

fn uart_put_byte(byte: u8) {
    unsafe {
        while core::ptr::read_volatile(UART0_FR) & UART_FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        core::ptr::write_volatile(UART0_DR, byte as u32);
    }
}
