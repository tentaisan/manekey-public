use embedded_hal::digital::{Error, ErrorKind, ErrorType, OutputPin};
#[cfg(all(target_arch = "riscv32", target_os = "none"))]
use manekey::boundary::riscv_pmp::CYW43_GPIO_ECALL_ID;
use manekey::boundary::riscv_pmp::{CYW43_GPIO_STATUS_OK, Cyw43GpioCommand};

#[cfg(all(target_arch = "riscv32", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .section .text.pmp_user_cyw43_gpio, "ax"
    .global manekey_rp_pmp_cyw43_gpio_ecall
    .align 2
manekey_rp_pmp_cyw43_gpio_ecall:
    .option push
    .option norvc
    ecall
    ret
    .option pop
"#
);

#[cfg(all(target_arch = "riscv32", target_os = "none"))]
unsafe extern "C" {
    fn manekey_rp_pmp_cyw43_gpio_ecall(ecall_id: u32, command: u32, reserved: u32) -> u32;
}

/// Gateway for fixed CYW43 power and chip-select commands only.
pub trait PmpCyw43GpioGateway {
    fn dispatch(&mut self, command: Cyw43GpioCommand) -> u32;
}

#[derive(Clone, Copy, Debug, Default)]
/// U-mode ecall client requiring the matching monitor ABI and image placement.
pub struct RiscvPmpCyw43GpioGateway;

#[cfg(all(target_arch = "riscv32", target_os = "none"))]
impl PmpCyw43GpioGateway for RiscvPmpCyw43GpioGateway {
    #[inline(always)]
    fn dispatch(&mut self, command: Cyw43GpioCommand) -> u32 {
        unsafe { manekey_rp_pmp_cyw43_gpio_ecall(CYW43_GPIO_ECALL_ID, command as u32, 0) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cyw43GpioRole {
    Power,
    ChipSelect,
}

impl Cyw43GpioRole {
    const fn command(self, high: bool) -> Cyw43GpioCommand {
        match (self, high) {
            (Self::Power, false) => Cyw43GpioCommand::PowerLow,
            (Self::Power, true) => Cyw43GpioCommand::PowerHigh,
            (Self::ChipSelect, false) => Cyw43GpioCommand::ChipSelectLow,
            (Self::ChipSelect, true) => Cyw43GpioCommand::ChipSelectHigh,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fixed GPIO command was rejected by the monitor.
pub struct PmpCyw43GpioError;

impl Error for PmpCyw43GpioError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

/// OutputPin restricted to CYW43 power or chip select; reserve physical pin ownership in the monitor.
pub struct PmpCyw43GpioPin<G> {
    role: Cyw43GpioRole,
    gateway: G,
}

impl<G> PmpCyw43GpioPin<G> {
    pub const fn power(gateway: G) -> Self {
        Self {
            role: Cyw43GpioRole::Power,
            gateway,
        }
    }

    pub const fn chip_select(gateway: G) -> Self {
        Self {
            role: Cyw43GpioRole::ChipSelect,
            gateway,
        }
    }
}

impl<G> ErrorType for PmpCyw43GpioPin<G>
where
    G: PmpCyw43GpioGateway,
{
    type Error = PmpCyw43GpioError;
}

impl<G> OutputPin for PmpCyw43GpioPin<G>
where
    G: PmpCyw43GpioGateway,
{
    #[unsafe(link_section = ".text.pmp_user_cyw43_gpio")]
    fn set_low(&mut self) -> Result<(), Self::Error> {
        self.set_level(false)
    }

    #[unsafe(link_section = ".text.pmp_user_cyw43_gpio")]
    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.set_level(true)
    }
}

impl<G> PmpCyw43GpioPin<G>
where
    G: PmpCyw43GpioGateway,
{
    #[inline(always)]
    fn set_level(&mut self, high: bool) -> Result<(), PmpCyw43GpioError> {
        if self.gateway.dispatch(self.role.command(high)) == CYW43_GPIO_STATUS_OK {
            Ok(())
        } else {
            Err(PmpCyw43GpioError)
        }
    }
}
