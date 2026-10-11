use manekey::boundary::riscv_pmp::{
    CYW43_GPIO_STATUS_DENIED, CYW43_GPIO_STATUS_OK, Cyw43GpioCommand,
};

const SIO_BASE: usize = 0xd000_0000;
const GPIO_OUT_OFFSET: usize = 0x10;

const GPIO_OUT_SET_OFFSET: usize = 0x18;
const GPIO_OUT_CLR_OFFSET: usize = 0x20;

/// M-mode fixed power/CS commands only; initialize and reserve these pins before user entry.
pub(super) fn dispatch_cyw43_gpio(command: u32) -> u32 {
    let Some((pin, high)) =
        Cyw43GpioCommand::decode(command).map(|command| command.pin_and_level())
    else {
        return CYW43_GPIO_STATUS_DENIED;
    };
    let mask = 1u32 << pin;
    let write_offset = if high {
        GPIO_OUT_SET_OFFSET
    } else {
        GPIO_OUT_CLR_OFFSET
    };
    unsafe {
        core::ptr::write_volatile((SIO_BASE + write_offset) as *mut u32, mask);
        let output = core::ptr::read_volatile((SIO_BASE + GPIO_OUT_OFFSET) as *const u32);
        if (output & mask != 0) == high {
            CYW43_GPIO_STATUS_OK
        } else {
            CYW43_GPIO_STATUS_DENIED
        }
    }
}
