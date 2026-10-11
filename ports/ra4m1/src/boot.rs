use ra_hal::pac;
#[path = "board.rs"]
pub mod board;



pub fn prepare_app_interrupts() {
    cortex_m::interrupt::disable();
    unsafe {
        (*cortex_m::peripheral::SCB::PTR).vtor.write(0x4000);
        let nvic = &*cortex_m::peripheral::NVIC::PTR;
        nvic.icer[0].write(u32::MAX);
        nvic.icpr[0].write(u32::MAX);
    }
    // GPT init enables IEL1 before its first alarm. An inherited USB route
    // would dispatch that event to the GPT handler instead of the USB owner.
    for index in 0..32 {
        pac::ICU.ielsr(index).write_value(pac::icu::regs::Ielsr(0));
    }
}















