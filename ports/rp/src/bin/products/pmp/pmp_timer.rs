use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

use manekey::boundary::riscv_pmp::{TIMER_STATUS_DENIED, TIMER_STATUS_OK, timer_delay_is_valid};
use manekey_rp::platform::rp2350::riscv_embassy_time;
use rp235x_hal as hal;

static TIMER_EVENT_GENERATION: AtomicU32 = AtomicU32::new(0);
static TIMER_ARMED: AtomicBool = AtomicBool::new(false);

static EMBASSY_TIMER_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_embassy_timer_waker,
    wake_embassy_timer,
    wake_embassy_timer_by_ref,
    drop_embassy_timer_waker,
);

/// # Safety
/// Initialize once in M-mode after the trap vector and 1 MHz TIMER0, with exclusive timer/IRQ ownership.
pub(super) unsafe fn init_u_mode_timer_service() {
    unsafe { riscv_embassy_time::init() };
    unsafe {
        core::arch::asm!(
            "li t0, 0x80",
            "csrs mstatus, t0",
            out("t0") _,
            options(nomem, nostack),
        );
    }
}

/// One outstanding bounded-delay timer; reject stale observed generations.
pub(super) fn arm_timer(delay_us: u32, observed_generation: u32) -> u32 {
    if !timer_delay_is_valid(delay_us) || timer_generation() != observed_generation {
        return TIMER_STATUS_DENIED;
    }
    if TIMER_ARMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return TIMER_STATUS_DENIED;
    }
    let waker = unsafe { Waker::from_raw(RawWaker::new(ptr::null(), &EMBASSY_TIMER_WAKER_VTABLE)) };
    embassy_time_driver::schedule_wake(
        embassy_time_driver::now().wrapping_add(delay_us as u64),
        &waker,
    );
    TIMER_STATUS_OK
}

/// Request an earlier deadline for the current outstanding generation; does not extend its deadline.
pub(super) fn rearm_timer(delay_us: u32, observed_generation: u32) -> u32 {
    if !timer_delay_is_valid(delay_us)
        || timer_generation() != observed_generation
        || !TIMER_ARMED.load(Ordering::Acquire)
    {
        return TIMER_STATUS_DENIED;
    }
    let waker = unsafe { Waker::from_raw(RawWaker::new(ptr::null(), &EMBASSY_TIMER_WAKER_VTABLE)) };
    embassy_time_driver::schedule_wake(
        embassy_time_driver::now().wrapping_add(delay_us as u64),
        &waker,
    );
    TIMER_STATUS_OK
}

/// Service only monitor-owned TIMER0 and selected DMA IRQ0; reject other sources.
pub(super) fn handle_machine_external() -> bool {
    loop {
        match hal::xh3irq::get_next_interrupt() {
            Some(hal::pac::Interrupt::TIMER0_IRQ_0) => {
                riscv_embassy_time::handle_timer0_irq();
            }
            #[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
            Some(hal::pac::Interrupt::DMA_IRQ_0) => {
                let _ = manekey_rp::platform::rp2350::pmp_dma::handle_dma_irq0();

                return true;
            }
            Some(_) => return false,
            None => return true,
        }
    }
}

pub(super) fn timer_generation() -> u32 {
    TIMER_EVENT_GENERATION.load(Ordering::Acquire)
}

unsafe fn clone_embassy_timer_waker(_: *const ()) -> RawWaker {
    RawWaker::new(ptr::null(), &EMBASSY_TIMER_WAKER_VTABLE)
}

unsafe fn wake_embassy_timer(_: *const ()) {
    record_timer_event();
}

unsafe fn wake_embassy_timer_by_ref(_: *const ()) {
    record_timer_event();
}

fn record_timer_event() {
    TIMER_ARMED.store(false, Ordering::Release);
    TIMER_EVENT_GENERATION.fetch_add(1, Ordering::Release);
}

unsafe fn drop_embassy_timer_waker(_: *const ()) {}
