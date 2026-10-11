// PIO program derived from Embassy cyw43-pio; Copyright (c) Embassy project contributors.
// Underlying Pico SDK portions: Copyright (c) 2020 Raspberry Pi (Trading) Ltd.; BSD-3-Clause, see RP NOTICE.
// Upstream: https://github.com/embassy-rs/embassy/blob/0af1937a5ac77f52fea943b677088c38ef9e91c6/cyw43-pio/src/lib.rs
// Original program: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
// Modified for HAL setup, split-image publication and numeric PIO branch targets.
use hal::pio::{PIOBuilder, PIOExt, PinDir, ShiftDirection};
use manekey::boundary::riscv_pmp::{CYW43_GPIO_STATUS_OK, Cyw43GpioCommand};
#[cfg(feature = "riscv-pmp-ble-monitor-image")]
use manekey_rp::platform::rp2350::pmp::PMP_BLE_SHARED_ABI_BASE;
use manekey_rp::platform::rp2350::pmp_cyw43_gpio::{PmpCyw43GpioPin, RiscvPmpCyw43GpioGateway};
use manekey_rp::platform::rp2350::pmp_cyw43_pio_abi::{
    PmpCyw43PioDescriptor, PmpCyw43PioDescriptorSlot,
};
use manekey_rp::platform::rp2350::pmp_user_executor::PmpUserHandoff;

use manekey_rp::platform::rp2350::riscv_cyw43_pio::RiscvCyw43PioSpi;

use rp235x_hal as hal;

type Cyw43StateMachine = (hal::pac::PIO0, hal::pio::SM0);
type Cyw43ChipSelect = PmpCyw43GpioPin<RiscvPmpCyw43GpioGateway>;
type PmpCyw43Spi = RiscvCyw43PioSpi<Cyw43StateMachine, Cyw43ChipSelect>;

#[unsafe(link_section = ".bss.pmp_user_async")]
static CYW43_PIO_HANDOFF: PmpUserHandoff<PmpCyw43Spi> = PmpUserHandoff::new();

#[unsafe(link_section = ".bss.pmp_user_async")]
static CYW43_PIO_DESCRIPTOR: PmpCyw43PioDescriptorSlot = PmpCyw43PioDescriptorSlot::new();

/// Initialize and publish once before U entry; exclusively reserve PIO0/SM0 and CYW43 pins 23/24/25/29.
pub(super) fn init_cyw43_pio_handoff(
    pio0: hal::pac::PIO0,
    resets: &mut hal::pac::RESETS,
) -> Option<(u32, u32, u32, u32, u32)> {
    let (mut pio, sm0, _, _, _) = pio0.split(resets);
    let program = pio::pio_asm!(
        ".side_set 1",
        ".wrap_target",
        "out pins, 1 side 0",
        "jmp x-- 0 side 1",
        "set pindirs, 0 side 0",
        "nop side 0",
        "in pins, 1 side 1",
        "jmp y-- 4 side 0",
        "wait 1 pin 0 side 0",
        "irq 0 side 0",
        ".wrap",
    )
    .program;
    let Ok(installed) = pio.install(&program) else {
        return None;
    };
    let wrap_target = installed.wrap_target();
    let descriptor = PmpCyw43PioDescriptor::pio0_sm0(wrap_target);
    if !unsafe { CYW43_PIO_DESCRIPTOR.publish_before_user(descriptor) } {
        return None;
    }
    #[cfg(feature = "riscv-pmp-ble-monitor-image")]
    if !publish_split_descriptor(descriptor) {
        return None;
    }
    let (mut state_machine, rx, tx) = PIOBuilder::from_installed_program(installed)
        .set_pins(24, 1)
        .out_pins(24, 1)
        .in_pin_base(24)
        .side_set_pin_base(29)
        .clock_divisor_fixed_point(30, 0)
        .autopull(true)
        .autopush(true)
        .out_shift_direction(ShiftDirection::Left)
        .in_shift_direction(ShiftDirection::Left)
        .build(sm0);
    state_machine.set_pindirs([(24, PinDir::Output), (29, PinDir::Output)]);
    state_machine.set_pins([(24, hal::pio::PinState::Low), (29, hal::pio::PinState::Low)]);
    let chip_select = PmpCyw43GpioPin::chip_select(RiscvPmpCyw43GpioGateway);
    let spi = RiscvCyw43PioSpi::from_initialized_parts(
        state_machine.start(),
        rx,
        tx,
        chip_select,
        wrap_target,
    );
    #[cfg(feature = "riscv-pmp-ble-monitor-handoff-only")]
    {
        if !set_monitor_gpio(Cyw43GpioCommand::ChipSelectHigh)
            || !set_monitor_gpio(Cyw43GpioCommand::PowerLow)
            || !CYW43_PIO_HANDOFF.publish(spi)
        {
            return None;
        }
        return Some((0, 0, 0, 0, 0));
    }
}

pub(super) fn prepare_u_mode_raw_spi_probe() -> bool {
    #[cfg(feature = "riscv-pmp-ble-monitor-handoff-only")]
    {
        set_monitor_gpio(Cyw43GpioCommand::ChipSelectHigh)
            && set_monitor_gpio(Cyw43GpioCommand::PowerLow)
    }
    #[cfg(not(feature = "riscv-pmp-ble-monitor-handoff-only"))]
    {
        set_monitor_gpio(Cyw43GpioCommand::PowerHigh)
            && set_monitor_gpio(Cyw43GpioCommand::ChipSelectHigh)
    }
}

fn set_monitor_gpio(command: Cyw43GpioCommand) -> bool {
    super::pmp_gpio::dispatch_cyw43_gpio(command as u32) == CYW43_GPIO_STATUS_OK
}

/// M-mode startup only after PIO/pin attribution; retain exclusive control of GP24/GP29.
pub(super) fn reselect_nonsecure_pio_pins() {
    let io = unsafe { &*hal::pac::IO_BANK0::ptr() };

    io.gpio(24)
        .gpio_ctrl()
        .write(|register| unsafe { register.bits(6) });
    io.gpio(29)
        .gpio_ctrl()
        .write(|register| unsafe { register.bits(6) });
}

#[cfg(feature = "riscv-pmp-ble-monitor-image")]
/// Initialize once in the reserved shared ABI window before any payload reader; exclude all concurrent access.
fn publish_split_descriptor(descriptor: PmpCyw43PioDescriptor) -> bool {
    let slot = PMP_BLE_SHARED_ABI_BASE as *mut PmpCyw43PioDescriptorSlot;
    unsafe {
        slot.write_volatile(PmpCyw43PioDescriptorSlot::new());
        (&*slot).publish_before_user(descriptor)
    }
}
