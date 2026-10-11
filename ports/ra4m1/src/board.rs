
#[cfg(feature = "board-nano-r4")]
pub const RAM_END: u32 = 0x2000_7f00;
#[cfg(not(feature = "board-nano-r4"))]
pub const RAM_END: u32 = 0x2000_7fe0;
#[cfg(feature = "board-nano-r4")]
pub const PSP_ALLOCATION_BYTES: usize = 0xf00;
#[cfg(not(feature = "board-nano-r4"))]
pub const PSP_ALLOCATION_BYTES: usize = 0xff0;
#[cfg(feature = "board-nano-r4")]
pub const RESERVED_REGION_LOG2: u32 = 8;
#[cfg(not(feature = "board-nano-r4"))]
pub const RESERVED_REGION_LOG2: u32 = 5;
#[cfg(feature = "board-nano-r4")]
pub const UP_LABEL: &str = "Nano R4 D2/P105";
#[cfg(not(feature = "board-nano-r4"))]
pub const UP_LABEL: &str = "XIAO BOOT P201";
#[cfg(feature = "board-nano-r4")]
pub const LED_ACTIVE_LOW: bool = false;
#[cfg(not(feature = "board-nano-r4"))]
pub const LED_ACTIVE_LOW: bool = true;

#[cfg(feature = "board-nano-r4")]
pub type LedPin = ra_hal::peripherals::P204;
#[cfg(not(feature = "board-nano-r4"))]
pub type LedPin = ra_hal::peripherals::P011;

pub fn led(
    pin: ra_hal::Peri<'static, LedPin>,
) -> ra_hal::gpio::Output<'static, ra_hal::gpio::Basic> {
    use ra_hal::gpio::{DriveCapacity, Level, Output};
    let inactive = if LED_ACTIVE_LOW {
        Level::High
    } else {
        Level::Low
    };
    Output::new_basic(pin, inactive, DriveCapacity::Low)
}
