use core::{mem::MaybeUninit, panic::PanicInfo};

use cortex_m::asm;
use cortex_m_rt::{ExceptionFrame, exception};
use nrf_softdevice::raw;
use nrf52840::board::{BOARD, configure_output_high};
use nrf52840_pac::interrupt;

use super::{LED, SOFTDEVICE_VECTOR_BASE};

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    #[cfg(feature = "nrf-ble-mpu-product")]
    {
        let ipsr: u32;
        unsafe {
            core::arch::asm!("mrs {value},ipsr", value = out(reg) ipsr);
        }
        if ipsr == 0 && cortex_m::register::control::read().bits() & 1 != 0 {
            unsafe {
                core::arch::asm!("svc #15");
            }
            loop {
                cortex_m::asm::nop();
            }
        }
    }

    let _ = info;
    log("panic");
    LED.fault_latch();
}

#[exception]
unsafe fn HardFault(frame: &ExceptionFrame) -> ! {
    let _ = frame;
    LED.fault_latch();
}

#[exception]
unsafe fn DefaultHandler(irqn: i16) -> ! {
    let _ = irqn;
    LED.fault_latch();
}

macro_rules! forward_softdevice_interrupt {
    ($name:ident, $irq:expr) => {
        #[interrupt]
        unsafe fn $name() {
            forward_to_softdevice_vector($irq);
        }
    };
}

forward_softdevice_interrupt!(POWER_CLOCK, 0);
forward_softdevice_interrupt!(RADIO, 1);
forward_softdevice_interrupt!(TIMER0, 8);
forward_softdevice_interrupt!(RTC0, 11);
forward_softdevice_interrupt!(TEMP, 12);
forward_softdevice_interrupt!(RNG, 13);
forward_softdevice_interrupt!(ECB, 14);
forward_softdevice_interrupt!(CCM_AAR, 15);
forward_softdevice_interrupt!(SWI5_EGU5, 25);
forward_softdevice_interrupt!(MWU, 32);

/// Requires the matching installed S140 vector table and its reserved interrupt ownership.
fn forward_to_softdevice_vector(irq: u32) {
    let vector_address = SOFTDEVICE_VECTOR_BASE + (16 + irq) * 4;
    let handler = read_word(vector_address);
    if handler == 0 || handler == 0xffff_ffff {
        LED.fault_latch();
    }

    let softdevice_handler: unsafe extern "C" fn() = unsafe { core::mem::transmute(handler) };
    unsafe {
        softdevice_handler();
    }
}

/// Exclusively reserve UART0 and the board-selected GPIO pins.
pub(super) fn uart_init() {
    configure_output_high(BOARD.uart_tx);
    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart0.enable.write(|w| unsafe { w.bits(0) });
    uart0
        .psel
        .txd
        .write(|w| unsafe { w.bits(BOARD.uart_tx.psel()) });
    uart0.psel.rxd.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.psel.cts.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.psel.rts.write(|w| unsafe { w.bits(0xFFFF_FFFF) });
    uart0.baudrate.write(|w| unsafe { w.bits(0x01D7_E000) });
    uart0.config.write(|w| unsafe { w.bits(0) });
    uart0.enable.write(|w| unsafe { w.bits(4) });
    uart0.tasks_starttx.write(|w| unsafe { w.bits(1) });
}

pub(super) fn log(message: &str) {
    #[cfg(feature = "nrf-internal-uart")]
    if !nrf52840::internal_uart::logging_enabled() {
        return;
    }
    uart_write_str(message);
    uart_write_str("\r\n");
}

pub(super) fn log_word(label: &str, value: u32) {
    #[cfg(feature = "nrf-internal-uart")]
    if !nrf52840::internal_uart::logging_enabled() {
        return;
    }
    uart_write_str(label);
    uart_write_str("=0x");
    uart_write_hex(value);
    uart_write_str("\r\n");
}

fn uart_write_hex(value: u32) {
    for shift in (0..32).step_by(4).rev() {
        let nibble = ((value >> shift) & 0xF) as u8;
        let byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        uart_write_byte(byte);
    }
}

pub(super) fn uart_write_str(s: &str) {
    #[cfg(feature = "nrf-internal-uart")]
    if !nrf52840::internal_uart::logging_enabled() {
        return;
    }
    for byte in s.as_bytes() {
        uart_write_byte(*byte);
    }
}

fn uart_write_byte(byte: u8) {
    let uart0 = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart0.events_txdrdy.reset();
    uart0.txd.write(|w| unsafe { w.bits(byte as u32) });
    for _ in 0..200_000 {
        if uart0.events_txdrdy.read().bits() != 0 {
            return;
        }
    }
}

fn read_word(address: u32) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// Caller supplies the aligned valid vector table for the current privileged runtime.
pub(super) fn set_vtor(address: u32) {
    unsafe {
        core::ptr::write_volatile(0xE000_ED08 as *mut u32, address);
        asm::dsb();
        asm::isb();
    }
}

pub(super) fn init_softdevice_forwarding() -> u32 {
    let mut command = raw::sd_mbr_command_t {
        command: raw::NRF_MBR_COMMANDS_SD_MBR_COMMAND_INIT_SD,
        params: unsafe { MaybeUninit::zeroed().assume_init() },
    };
    unsafe { raw::sd_mbr_command(&mut command) }
}

pub(super) fn set_mbr_irq_forwarding(address: u32) -> u32 {
    let mut command = raw::sd_mbr_command_t {
        command: raw::NRF_MBR_COMMANDS_SD_MBR_COMMAND_IRQ_FORWARD_ADDRESS_SET,
        params: raw::sd_mbr_command_t__bindgen_ty_1 {
            irq_forward_address_set: raw::sd_mbr_command_irq_forward_address_set_t { address },
        },
    };
    unsafe { raw::sd_mbr_command(&mut command) }
}
