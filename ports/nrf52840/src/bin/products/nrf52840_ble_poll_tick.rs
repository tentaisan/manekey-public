use core::{
    cell::RefCell,
    future::poll_fn,
    sync::atomic::{AtomicU32, Ordering},
    task::{Poll, Waker},
};

use critical_section::Mutex;
use nrf52840_pac::{RTC2, interrupt};

#[cfg(not(feature = "nrf-multi-transport"))]
const POLL_INTERVAL_TICKS: u32 = 3_277;
#[cfg(feature = "nrf-multi-transport")]
const POLL_INTERVAL_TICKS: u32 = 33;
const RTC_COUNTER_MASK: u32 = 0x00ff_ffff;

static TICKS: AtomicU32 = AtomicU32::new(0);
static WAKER: Mutex<RefCell<Option<Waker>>> = Mutex::new(RefCell::new(None));

#[cfg(feature = "nrf-multi-transport")]
static WORKER_WAKER: Mutex<RefCell<Option<Waker>>> = Mutex::new(RefCell::new(None));
#[cfg(feature = "nrf-multi-transport")]
static USB_TICKS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "nrf-multi-transport")]
static USB_WAKER: Mutex<RefCell<Option<Waker>>> = Mutex::new(RefCell::new(None));

/// Initialize RTC2/IRQ once with exclusive ownership and an active LF clock.
pub(super) fn start(rtc: RTC2) {
    rtc.tasks_stop.write(|w| unsafe { w.bits(1) });
    rtc.tasks_clear.write(|w| unsafe { w.bits(1) });
    rtc.prescaler.write(|w| unsafe { w.bits(0) });
    rtc.events_compare[0].write(|w| unsafe { w.bits(0) });
    rtc.cc[0].write(|w| unsafe { w.bits(POLL_INTERVAL_TICKS) });
    rtc.intenset.write(|w| w.compare0().set());

    let mut core = unsafe { cortex_m::Peripherals::steal() };
    #[cfg(feature = "nrf-ble-mpu-product")]
    unsafe {
        core.NVIC.set_priority(interrupt::RTC2, 0xc0)
    };
    #[cfg(not(feature = "nrf-ble-mpu-product"))]
    unsafe {
        core.NVIC.set_priority(interrupt::RTC2, 7)
    };
    unsafe { cortex_m::peripheral::NVIC::unmask(interrupt::RTC2) };
    rtc.tasks_start.write(|w| unsafe { w.bits(1) });
}

pub(super) fn current() -> u32 {
    TICKS.load(Ordering::Acquire)
}

/// One waiter per channel; ticks wrap and do not count elapsed wall-clock time exactly.
pub(super) async fn wait_after(previous: u32) -> u32 {
    poll_fn(|cx| {
        let observed = current();
        if observed != previous {
            return Poll::Ready(observed);
        }
        critical_section::with(|cs| {
            *WAKER.borrow_ref_mut(cs) = Some(cx.waker().clone());
        });
        let current = current();
        if current != previous {
            Poll::Ready(current)
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(all(feature = "nrf-multi-transport", not(feature = "nrf-ble-mpu-product")))]
/// Reserve this wake registration for the single trusted worker.
pub(super) async fn worker_wait_after(previous: u32) -> u32 {
    poll_fn(|cx| {
        let observed = current();
        if observed != previous {
            return Poll::Ready(observed);
        }
        critical_section::with(|cs| {
            *WORKER_WAKER.borrow_ref_mut(cs) = Some(cx.waker().clone());
        });
        let current = current();
        if current != previous {
            Poll::Ready(current)
        } else {
            Poll::Pending
        }
    })
    .await
}

pub(super) fn clear_waiter() {
    critical_section::with(|cs| WAKER.borrow_ref_mut(cs).take());
}

#[cfg(feature = "nrf-multi-transport")]
pub(super) fn usb_current() -> u32 {
    USB_TICKS.load(Ordering::Acquire)
}

#[cfg(feature = "nrf-multi-transport")]
/// Reserve this wake registration for the single USB pump.
pub(super) async fn usb_wait_after(previous: u32) -> u32 {
    poll_fn(|cx| {
        let observed = usb_current();
        if observed != previous {
            return Poll::Ready(observed);
        }
        critical_section::with(|cs| {
            *USB_WAKER.borrow_ref_mut(cs) = Some(cx.waker().clone());
        });
        let current = usb_current();
        if current != previous {
            Poll::Ready(current)
        } else {
            Poll::Pending
        }
    })
    .await
}

#[interrupt]
fn RTC2() {
    let rtc = unsafe { &*RTC2::ptr() };
    if rtc.events_compare[0].read().bits() == 0 {
        return;
    }
    rtc.events_compare[0].write(|w| unsafe { w.bits(0) });
    let next = (rtc.counter.read().bits() + POLL_INTERVAL_TICKS) & RTC_COUNTER_MASK;
    rtc.cc[0].write(|w| unsafe { w.bits(next) });
    #[cfg(feature = "nrf-multi-transport")]
    {
        let ticks = USB_TICKS.fetch_add(1, Ordering::Release).wrapping_add(1);
        let waker = critical_section::with(|cs| USB_WAKER.borrow_ref_mut(cs).take());
        if let Some(waker) = waker {
            waker.wake();
        }
        if ticks % 100 != 0 {
            return;
        }
    }
    TICKS.fetch_add(1, Ordering::Release);
    let waker = critical_section::with(|cs| WAKER.borrow_ref_mut(cs).take());
    if let Some(waker) = waker {
        waker.wake();
    }
    #[cfg(feature = "nrf-multi-transport")]
    {
        let waker = critical_section::with(|cs| WORKER_WAKER.borrow_ref_mut(cs).take());
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
