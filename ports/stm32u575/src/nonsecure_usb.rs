use core::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicU32, Ordering},
    task::Waker,
};
use critical_section::Mutex;
use embassy_stm32::pac::interrupt;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time_driver::Driver as TimeDriver;
use embassy_time_queue_utils::Queue;
use embassy_usb_driver::{Driver, EndpointAddress, EndpointAllocError, EndpointType};
use embassy_usb_synopsys_otg as otg;

static USB_STATE: otg::StateStorage<6> = otg::StateStorage::new(CriticalSectionRawMutex::new());
fn regs() -> otg::otg_v1::Otg {
    unsafe { otg::otg_v1::Otg::from_ptr(0x4204_0000 as *mut ()) }
}

#[embassy_stm32::pac::interrupt]
fn OTG_FS() {
    unsafe {
        otg::on_interrupt(regs(), &USB_STATE.as_state());
    }
}

/// NS OTG adapter; requires Secure-configured clocks/pins and matching peripheral/IRQ attribution.
/// Keep one exclusive driver/IRQ owner; startup AHB-idle polling has no timeout.
pub struct UsbDriver<'d>(otg::Driver<'d>);
impl<'d> UsbDriver<'d> {
    pub fn new(buffer: &'d mut [u8]) -> Self {
        let instance = otg::OtgInstance {
            regs: regs(),
            state: USB_STATE.as_state(),
            fifo_depth_words: 320,
            tx_fifo_count: 6,
            extra_rx_fifo_words: 30,
            phy_type: otg::PhyType::InternalFullSpeed,
            calculate_trdt_fn: |_| 0xd,
        };
        let mut config = otg::Config::default();
        config.vbus_detection = false;
        Self(otg::Driver::new(buffer, instance, config))
    }
}
impl<'d> Driver<'d> for UsbDriver<'d> {
    type EndpointOut = <otg::Driver<'d> as Driver<'d>>::EndpointOut;
    type EndpointIn = <otg::Driver<'d> as Driver<'d>>::EndpointIn;
    type ControlPipe = <otg::Driver<'d> as Driver<'d>>::ControlPipe;
    type Bus = <otg::Driver<'d> as Driver<'d>>::Bus;
    fn alloc_endpoint_in(
        &mut self,
        kind: EndpointType,
        address: Option<EndpointAddress>,
        size: u16,
        interval: u8,
    ) -> Result<Self::EndpointIn, EndpointAllocError> {
        self.0.alloc_endpoint_in(kind, address, size, interval)
    }
    fn alloc_endpoint_out(
        &mut self,
        kind: EndpointType,
        address: Option<EndpointAddress>,
        size: u16,
        interval: u8,
    ) -> Result<Self::EndpointOut, EndpointAllocError> {
        self.0.alloc_endpoint_out(kind, address, size, interval)
    }
    fn start(self, size: u16) -> (Self::Bus, Self::ControlPipe) {
        let (mut bus, control) = self.0.start(size);
        while !regs().grstctl().read().ahbidl() {
            core::hint::spin_loop();
        }
        bus.configure_as_device();
        match regs().cid().read().0 {
            0x0000_1200 | 0x0000_1100 | 0x0000_1000 => bus.config_v1(),
            0x0000_2000 | 0x0000_2100 | 0x0000_2300 | 0x0000_3000 | 0x0000_3100 => {
                bus.config_v2v3()
            }
            0x0000_5000 | 0x0000_6100 => bus.config_v5(),
            _ => panic!("Unexpected U575 OTG core"),
        }
        cortex_m::peripheral::NVIC::unpend(embassy_stm32::pac::Interrupt::OTG_FS);
        unsafe {
            cortex_m::peripheral::NVIC::unmask(embassy_stm32::pac::Interrupt::OTG_FS);
        }
        (bus, control)
    }
}

struct NsTime {
    milliseconds: Mutex<Cell<u64>>,
    queue: Mutex<RefCell<Queue>>,
}
embassy_time_driver::time_driver_impl!(static TIME: NsTime = NsTime {
    milliseconds: Mutex::new(Cell::new(0)), queue: Mutex::new(RefCell::new(Queue::new())),
});
impl TimeDriver for NsTime {
    fn now(&self) -> u64 {
        critical_section::with(|cs| self.milliseconds.borrow(cs).get()) * 32768 / 1000
    }
    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            queue.schedule_wake(at, waker);
            queue.next_expiration(self.now());
        });
    }
}
#[cortex_m_rt::exception]
fn SysTick() {
    critical_section::with(|cs| {
        TIME.milliseconds
            .borrow(cs)
            .set(TIME.milliseconds.borrow(cs).get() + 1);
        TIME.queue
            .borrow(cs)
            .borrow_mut()
            .next_expiration(TIME.now());
    });
}

struct RxRing {
    bytes: [u8; 1024],
    read: usize,
    write: usize,
}
static RX: Mutex<RefCell<RxRing>> = Mutex::new(RefCell::new(RxRing {
    bytes: [0; 1024],
    read: 0,
    write: 0,
}));
static RX_ERRORS: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
pub static TZ_UART_RX_FAULTS: AtomicU32 = AtomicU32::new(0);
#[embassy_stm32::pac::interrupt]
fn USART1() {
    let uart = embassy_stm32::pac::USART1;
    critical_section::with(|cs| {
        let mut ring = RX.borrow(cs).borrow_mut();
        loop {
            let status = uart.isr().read();
            if status.ore() || status.fe() || status.ne() || status.pe() {
                uart.icr().write(|r| {
                    r.set_ore(true);
                    r.set_fe(true);
                    r.set_ne(true);
                    r.set_pe(true);
                });
                RX_ERRORS.store(1, Ordering::Release);
                TZ_UART_RX_FAULTS.fetch_add(1, Ordering::Relaxed);
            }
            if !status.rxne() {
                break;
            }
            let byte = uart.rdr().read().dr() as u8;
            let next = (ring.write + 1) % ring.bytes.len();
            if next == ring.read {
                RX_ERRORS.store(1, Ordering::Release);
                TZ_UART_RX_FAULTS.fetch_add(1, Ordering::Relaxed);
            } else {
                let index = ring.write;
                ring.bytes[index] = byte;
                ring.write = next;
            }
        }
    });
}
/// Requires matching Secure-configured UART/IRQ attribution and exclusive receiver ownership.
pub fn start_uart() {
    cortex_m::peripheral::NVIC::unpend(embassy_stm32::pac::Interrupt::USART1);
    embassy_stm32::pac::USART1
        .cr1()
        .modify(|r| r.set_rxneie(true));
    unsafe {
        cortex_m::peripheral::NVIC::unmask(embassy_stm32::pac::Interrupt::USART1);
    }
}
pub fn read_uart() -> Result<Option<u8>, ()> {
    critical_section::with(|cs| {
        let mut ring = RX.borrow(cs).borrow_mut();
        if RX_ERRORS.swap(0, Ordering::AcqRel) != 0 {
            ring.read = ring.write;
            return Err(());
        }
        if ring.read == ring.write {
            return Ok(None);
        }
        let byte = ring.bytes[ring.read];
        ring.read = (ring.read + 1) % ring.bytes.len();
        Ok(Some(byte))
    })
}
/// Start once with exclusive NS SysTick ownership and the Secure-configured 16 MHz core clock.
pub fn start_time() {
    let mut core = cortex_m::Peripherals::take().unwrap();
    core.SYST
        .set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    core.SYST.set_reload(15_999);
    core.SYST.clear_current();
    core.SYST.enable_interrupt();
    core.SYST.enable_counter();
}
