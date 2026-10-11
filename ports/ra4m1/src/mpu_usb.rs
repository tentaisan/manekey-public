
use core::sync::atomic::{AtomicU32, Ordering};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use embassy_futures::select::{Either, select};
use embassy_usb::{
    Builder, Config, Handler,
    class::hid::{Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, State},
};
use manekey::ctaphid::descriptor::REPORT_DESCRIPTOR;
use static_cell::StaticCell;

ra_hal::bind_interrupts!(pub struct Irqs {
    IEL2 => IrqMarker, ra_hal::usb::UsbInterruptHandler<ra_hal::peripherals::USBFS>;
});
pub struct IrqMarker;
impl ra_hal::interrupt::typelevel::Handler<ra_hal::interrupt::typelevel::IEL2> for IrqMarker {
    unsafe fn on_interrupt() {


    }
}













#[derive(Default)]
struct Packets {
    rx: Option<[u8; 64]>,
    tx: Option<[u8; 64]>,
}
// SVC and PendSV cannot overlap through this thread's calls. Peripheral IRQs
// only update HAL state and never touch these slots.
struct Slots(RefCell<Packets>);
unsafe impl Sync for Slots {}
static SLOTS: Slots = Slots(RefCell::new(Packets { rx: None, tx: None }));
static GENERATION: AtomicU32 = AtomicU32::new(0);






fn disconnected() {
    *SLOTS.0.borrow_mut() = Packets::default();
    GENERATION.fetch_add(1, Ordering::Relaxed);
}
struct Events;
impl Handler for Events {
    fn reset(&mut self) {
        disconnected();
    }
    fn enabled(&mut self, enabled: bool) {
        if !enabled {
            disconnected();
        }
    }
    fn configured(&mut self, configured: bool) {
        if !configured {
            disconnected();
        }
    }
}
struct Buffers {
    config: [u8; 256],
    bos: [u8; 256],
    control: [u8; 128],
    state: State<'static>,
    events: Events,
}
static BUFFERS: StaticCell<Buffers> = StaticCell::new();

#[inline(never)]
pub fn start(driver: ra_hal::usb::Usbfs<'static, ra_hal::peripherals::USBFS>) {
    install(build(driver));
}

fn build(
    driver: ra_hal::usb::Usbfs<'static, ra_hal::peripherals::USBFS>,
) -> impl Future<Output = ()> {
    let buffers = BUFFERS.init_with(|| Buffers {
        config: [0; 256],
        bos: [0; 256],
        control: [0; 128],
        state: State::new(),
        events: Events,
    });
    let mut config = Config::new(0xcafe, 0x4011);
    config.manufacturer = Some("ManeKey");
    config.product = Some("ManeKey RA4M1 MPU HID");
    config.serial_number = Some("ra4m1-fido");
    config.max_power = 100;
    let mut builder = Builder::new(
        driver,
        config,
        &mut buffers.config,
        &mut buffers.bos,
        &mut [],
        &mut buffers.control,
    );
    builder.handler(&mut buffers.events);
    let mut hid = HidReaderWriter::<_, 64, 64>::new(
        &mut builder,
        &mut buffers.state,
        HidConfig {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            report_descriptor: REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: 64,
        },
    );
    let mut usb = builder.build();
    async move {
        let packets = async {
            let mut report = [0; 64];
            loop {
                hid.ready().await;
                let next = SLOTS.0.borrow_mut().tx.take();
                if let Some(next) = next {
                    if !matches!(
                        select(hid.write(&next), embassy_time::Timer::after_millis(1000)).await,
                        Either::First(Ok(()))
                    ) {


                        disconnected();
                    } else {


                    }
                    continue;
                }
                // Do not overwrite a report before its U-mode consumer copies it.
                if SLOTS.0.borrow().rx.is_some() {
                    poll_fn(|_| {
                        if SLOTS.0.borrow().rx.is_none() || SLOTS.0.borrow().tx.is_some() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    continue;
                }
                let transmit = poll_fn(|_| {
                    if SLOTS.0.borrow().tx.is_some() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                });
                match select(hid.read(&mut report), transmit).await {
                    Either::First(Ok(64)) => {


                        SLOTS.0.borrow_mut().rx = Some(report);
                    }
                    Either::First(Err(_)) => {
                        disconnected();
                        embassy_time::Timer::after_millis(5).await;
                    }
                    _ => {}
                }
            }
        };
        let mut bus = core::pin::pin!(usb.run());
        let mut packets = core::pin::pin!(packets);
        poll_fn(|cx| {


            let _ = bus.as_mut().poll(cx);


            let _ = packets.as_mut().poll(cx);


            Poll::<()>::Pending
        })
        .await;
    }
}

struct Pump {
    pointer: *mut (),
    poll: unsafe fn(*mut ()),
}
static mut PUMP: Option<Pump> = None;

#[repr(C, align(8))]
struct FutureStorage([core::mem::MaybeUninit<u8>; 2048]);
static FUTURE: StaticCell<FutureStorage> = StaticCell::new();



pub fn install<F: Future<Output = ()> + 'static>(future: F) {
    unsafe fn poll<F: Future<Output = ()>>(pointer: *mut ()) {
        let mut context = Context::from_waker(Waker::noop());
        let _ = unsafe { Pin::new_unchecked(&mut *pointer.cast::<F>()) }.poll(&mut context);
    }
    assert!(core::mem::size_of::<F>() <= 2048);
    assert!(core::mem::align_of::<F>() <= 8);
    let storage = FUTURE.init(FutureStorage([core::mem::MaybeUninit::uninit(); 2048]));
    let pointer = storage.0.as_mut_ptr().cast::<F>();
    // Initialized exactly once, aligned and sufficiently sized. The static
    // allocation is never moved or accessed again except by the exclusive pump.
    unsafe {
        pointer.write(future);
        PUMP = Some(Pump {
            pointer: pointer.cast(),
            poll: poll::<F>,
        });
    }
}
pub fn pump() {


    unsafe {
        if let Some(pump) = &*core::ptr::addr_of!(PUMP) {
            (pump.poll)(pump.pointer);
        }
    }


}
// The thread is stopped while PendSV runs. SVC cannot be issued by that
// stopped thread, and USB IRQs only touch the HAL, never these report slots.
#[cortex_m_rt::exception]
fn PendSV() {
    pump();
}
pub fn receive() -> Option<[u8; 64]> {
    SLOTS.0.borrow_mut().rx.take()
}
pub fn send(report: [u8; 64]) -> bool {
    let mut slots = SLOTS.0.borrow_mut();
    if slots.tx.is_some() {
        false
    } else {
        slots.tx = Some(report);


        true
    }
}
pub fn generation() -> u32 {
    GENERATION.load(Ordering::Relaxed)
}
