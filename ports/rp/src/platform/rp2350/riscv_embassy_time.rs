/* Scheduling portions follow Embassy embassy-rp/src/time_driver.rs.
 * Reference snapshot: 0af1937a5ac77f52fea943b677088c38ef9e91c6.
 * Copyright (c) Embassy project contributors; MIT OR Apache-2.0.
 * See root vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
 * Modified for Hazard3 PAC, critical-section state and machine IRQ routing.
 */

use core::cell::{Cell, RefCell};
use core::task::Waker;

use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use rp235x_hal as hal;

struct RiscvTimerDriver {
    timestamp: Mutex<Cell<u64>>,
    queue: Mutex<RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(static DRIVER: RiscvTimerDriver = RiscvTimerDriver {
    timestamp: Mutex::new(Cell::new(u64::MAX)),
    queue: Mutex::new(RefCell::new(Queue::new())),
});

fn timer() -> &'static hal::pac::timer0::RegisterBlock {
    unsafe { &*hal::pac::TIMER0::ptr() }
}

impl Driver for RiscvTimerDriver {
    fn now(&self) -> u64 {
        loop {
            let high = timer().timerawh().read().bits();
            let low = timer().timerawl().read().bits();
            let high_again = timer().timerawh().read().bits();
            if high == high_again {
                return ((high as u64) << 32) | low as u64;
            }
        }
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            if queue.schedule_wake(at, waker) {
                let mut next = queue.next_expiration(self.now());
                while !self.set_alarm(cs, next) {
                    next = queue.next_expiration(self.now());
                }
            }
        });
    }
}

impl RiscvTimerDriver {
    fn set_alarm(&self, cs: critical_section::CriticalSection<'_>, timestamp: u64) -> bool {
        self.timestamp.borrow(cs).set(timestamp);

        if timestamp == u64::MAX {
            return true;
        }

        timer()
            .alarm0()
            .write(|w| unsafe { w.bits(timestamp as u32) });

        if timestamp <= self.now() {
            timer().armed().write(|w| unsafe { w.bits(1) });
            self.timestamp.borrow(cs).set(u64::MAX);
            false
        } else {
            true
        }
    }

    fn check_alarm(&self) {
        critical_section::with(|cs| {
            timer().intr().write(|w| unsafe { w.bits(1) });
            let timestamp = self.timestamp.borrow(cs).get();
            if timestamp <= self.now() {
                self.trigger_alarm(cs);
            } else {
                timer()
                    .alarm0()
                    .write(|w| unsafe { w.bits(timestamp as u32) });
            }
        });
    }

    fn trigger_alarm(&self, cs: critical_section::CriticalSection<'_>) {
        let mut next = self
            .queue
            .borrow(cs)
            .borrow_mut()
            .next_expiration(self.now());
        while !self.set_alarm(cs, next) {
            next = self
                .queue
                .borrow(cs)
                .borrow_mut()
                .next_expiration(self.now());
        }
    }
}

/// # Safety
/// Call once after TIMER0 is initialized at 1 MHz; exclusively own alarm 0 and its machine IRQ.
/// This enables machine interrupts; queued wakers must be valid in the executing privilege mode.
pub unsafe fn init() {
    critical_section::with(|cs| DRIVER.timestamp.borrow(cs).set(u64::MAX));
    timer().intr().write(|w| unsafe { w.bits(1) });
    timer().inte().write(|w| unsafe { w.bits(1) });
    unsafe {
        hal::arch::interrupt_unmask(hal::pac::Interrupt::TIMER0_IRQ_0);
        hal::arch::interrupt_enable();
    }
}

/// Service only a verified TIMER0 IRQ 0 with wakers valid in the caller's privilege mode.
pub fn handle_timer0_irq() {
    DRIVER.check_alarm();
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "Rust" fn TIMER0_IRQ_0() {
    handle_timer0_irq();
}
