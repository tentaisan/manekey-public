use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};
use critical_section::Mutex;
use heapless::Deque;
use nrf52840_pac::interrupt;

static RX: Mutex<RefCell<Deque<u8, 256>>> = Mutex::new(RefCell::new(Deque::new()));
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static BINARY: AtomicBool = AtomicBool::new(false);

pub fn logging_enabled() -> bool {
    !BINARY.load(Ordering::Relaxed)
}
/// Initialize once with exclusive UART0 and IRQ ownership; reserve the configured interrupt priority.
pub fn start() {
    crate::board::uart_init_duplex();
    BINARY.store(true, Ordering::Release);
    let uart = unsafe { &*nrf52840_pac::UART0::ptr() };
    uart.intenset.write(|w| w.rxdrdy().set().error().set());
    unsafe {
        let mut core = cortex_m::Peripherals::steal();
        core.NVIC.set_priority(interrupt::UARTE0_UART0, 0xc0);
        cortex_m::peripheral::NVIC::unmask(interrupt::UARTE0_UART0);
    }
}
pub fn read() -> Option<u8> {
    critical_section::with(|cs| RX.borrow_ref_mut(cs).pop_front())
}
pub fn take_overflow() -> bool {
    OVERFLOW.swap(false, Ordering::AcqRel)
}
/// Blocking byte output; completion does not acknowledge peer delivery.
pub fn write(bytes: &[u8]) {
    for &byte in bytes {
        crate::board::uart_write_byte(byte);
    }
}

#[interrupt]
fn UARTE0_UART0() {
    let uart = unsafe { &*nrf52840_pac::UART0::ptr() };
    if uart.events_error.read().bits() != 0 {
        uart.events_error.reset();
        let errors = uart.errorsrc.read().bits();
        uart.errorsrc.write(|w| unsafe { w.bits(errors) });
        OVERFLOW.store(true, Ordering::Release);
    }
    while let Some(byte) = crate::board::uart_try_read_byte() {
        critical_section::with(|cs| {
            let mut queue = RX.borrow_ref_mut(cs);
            if queue.push_back(byte).is_err() {
                queue.clear();
                OVERFLOW.store(true, Ordering::Release);
            }
        });
    }
}
