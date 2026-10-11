use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll, Waker},
};

#[cfg(feature = "privileged-usb-ccid")]
use crate::{
    security::trusted_status,
    transport::usb::embassy::{CcidUsbClass, CcidUsbState},
};
use embassy_usb::{
    Builder, Config, Handler,
    class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State},
};
use portable_atomic::AtomicU32;
use static_cell::StaticCell;

#[derive(Default)]
struct Packets {
    rx: Option<[u8; 64]>,
    tx: Option<[u8; 64]>,
}
struct Slots(RefCell<Packets>);

unsafe impl Sync for Slots {}
static SLOTS: Slots = Slots(RefCell::new(Packets { rx: None, tx: None }));
static GENERATION: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "privileged-usb-ccid")]
struct CcidPackets {
    rx: [u8; 64],
    tx: [u8; 64],
    rx_len: Option<usize>,
    tx_len: Option<usize>,
    abort: u32,
}
#[cfg(feature = "privileged-usb-ccid")]
struct CcidSlots(RefCell<CcidPackets>);
#[cfg(feature = "privileged-usb-ccid")]

unsafe impl Sync for CcidSlots {}
#[cfg(feature = "privileged-usb-ccid")]
static CCID: CcidSlots = CcidSlots(RefCell::new(CcidPackets {
    rx: [0; 64],
    tx: [0; 64],
    rx_len: None,
    tx_len: None,
    abort: u32::MAX,
}));
fn disconnected() {
    *SLOTS.0.borrow_mut() = Packets::default();
    GENERATION.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "privileged-usb-ccid")]
    {
        let mut ccid = CCID.0.borrow_mut();
        ccid.rx_len = None;
        ccid.tx_len = None;
        ccid.abort = u32::MAX;
    }
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
    control: [u8; 256],
    state: State<'static>,
    events: Events,
    #[cfg(feature = "privileged-usb-ccid")]
    ccid: CcidUsbState<'static>,
}
static BUFFERS: StaticCell<Buffers> = StaticCell::new();
struct Pump {
    pointer: *mut (),
    poll: unsafe fn(*mut ()),
}
static mut PUMP: Option<Pump> = None;
#[repr(C, align(8))]
struct FutureStorage([core::mem::MaybeUninit<u8>; FUTURE_CAPACITY]);
const FUTURE_CAPACITY: usize = 4096;

pub type BulkPacket = crate::transport::boundary_link::CopyPacket<64>;
static FUTURE: StaticCell<FutureStorage> = StaticCell::new();

/// Single-use initialization; all users must share one critical-section domain.
pub fn start<D: embassy_usb::driver::Driver<'static> + 'static>(
    driver: D,
    product: &'static str,
    serial: &'static str,
) {
    let buffers = BUFFERS.init_with(|| Buffers {
        config: [0; 256],
        bos: [0; 256],
        control: [0; 256],
        state: State::new(),
        events: Events,
        #[cfg(feature = "privileged-usb-ccid")]
        ccid: CcidUsbState::new(),
    });
    let mut config = Config::new(0xcafe, 0x4011);
    config.manufacturer = Some("ManeKey");
    config.product = Some(product);
    config.serial_number = Some(serial);
    config.composite_with_iads = false;
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
        embassy_usb::class::hid::Config {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            poll_ms: 5,
            max_packet_size: 64,
            request_handler: None,
            report_descriptor: crate::ctaphid::descriptor::REPORT_DESCRIPTOR,
        },
    );
    #[cfg(feature = "privileged-usb-ccid")]
    let mut ccid = CcidUsbClass::new(
        &mut builder,
        &mut buffers.ccid,
        64,
        crate::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let mut device = builder.build();
    install(async move {
        let packets = async {
            let mut report = [0; 64];
            loop {
                hid.ready().await;
                let tx = SLOTS.0.borrow_mut().tx.take();
                if let Some(tx) = tx {
                    if !matches!(
                        embassy_futures::select::select(
                            hid.write(&tx),
                            embassy_time::Timer::after_millis(1000)
                        )
                        .await,
                        embassy_futures::select::Either::First(Ok(()))
                    ) {
                        disconnected();
                    }
                    continue;
                }
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
                let tx_ready = poll_fn(|_| {
                    if SLOTS.0.borrow().tx.is_some() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                });
                match embassy_futures::select::select(hid.read(&mut report), tx_ready).await {
                    embassy_futures::select::Either::First(Ok(64)) => {
                        SLOTS.0.borrow_mut().rx = Some(report)
                    }
                    embassy_futures::select::Either::First(Err(_)) => {
                        disconnected();
                        embassy_time::Timer::after_millis(5).await;
                    }
                    _ => {}
                }
            }
        };
        #[cfg(feature = "privileged-usb-ccid")]
        {
            let bulk = async {
                let (mut reader, mut writer, control) = ccid.split();
                let rx = async {
                    let mut request = [0; 64];
                    loop {
                        poll_fn(|_| {
                            if CCID.0.borrow().rx_len.is_none() {
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        })
                        .await;
                        match reader.read_packet(&mut request).await {
                            Ok(len) => {
                                let mut slots = CCID.0.borrow_mut();
                                slots.rx[..len].copy_from_slice(&request[..len]);
                                slots.rx_len = Some(len);
                            }
                            Err(_) => {
                                disconnected();
                                embassy_time::Timer::after_millis(5).await;
                            }
                        }
                    }
                };
                let tx = async {
                    let mut response = [0; 64];
                    loop {
                        let len = poll_fn(|_| {
                            let mut slots = CCID.0.borrow_mut();
                            let Some(len) = slots.tx_len.take() else {
                                return Poll::Pending;
                            };
                            response[..len].copy_from_slice(&slots.tx[..len]);
                            Poll::Ready(len)
                        })
                        .await;
                        if !matches!(
                            embassy_futures::select::select(
                                writer.write_packet(&response[..len]),
                                embassy_time::Timer::after_millis(1000)
                            )
                            .await,
                            embassy_futures::select::Either::First(Ok(()))
                        ) {
                            disconnected();
                        }
                    }
                };
                let events = poll_fn(|_| {
                    if let Some((slot, sequence)) = control.take_abort() {
                        let mut slots = CCID.0.borrow_mut();
                        slots.abort = u32::from(slot) | (u32::from(sequence) << 8);
                        slots.tx_len = None;
                    }
                    Poll::<()>::Pending
                });
                embassy_futures::join::join(events, embassy_futures::join::join(rx, tx)).await;
            };
            embassy_futures::join::join(device.run(), embassy_futures::join::join(packets, bulk))
                .await;
        }
        #[cfg(not(feature = "privileged-usb-ccid"))]
        embassy_futures::join::join(device.run(), packets).await;
    });
}
fn install<F: Future + 'static>(future: F) {
    unsafe fn poll<F: Future>(ptr: *mut ()) {
        let mut cx = Context::from_waker(Waker::noop());
        let _ = unsafe { Pin::new_unchecked(&mut *ptr.cast::<F>()) }.poll(&mut cx);
    }
    assert!(core::mem::size_of::<F>() <= FUTURE_CAPACITY && core::mem::align_of::<F>() <= 8);
    let storage = FUTURE.init(FutureStorage(
        [core::mem::MaybeUninit::uninit(); FUTURE_CAPACITY],
    ));
    let ptr = storage.0.as_mut_ptr().cast::<F>();

    unsafe {
        ptr.write(future);
        critical_section::with(|_| {
            PUMP = Some(Pump {
                pointer: ptr.cast(),
                poll: poll::<F>,
            });
        });
    }
}

/// Advances pending USB I/O; call regularly.
pub fn pump() {
    critical_section::with(|_| unsafe {
        if let Some(pump) = &*core::ptr::addr_of!(PUMP) {
            (pump.poll)(pump.pointer);
        }
    });
}
pub fn receive() -> Option<[u8; 64]> {
    critical_section::with(|_| SLOTS.0.borrow_mut().rx.take())
}
/// Queues a report; true does not confirm peer delivery.
pub fn send(report: [u8; 64]) -> bool {
    critical_section::with(|_| {
        let mut slots = SLOTS.0.borrow_mut();
        if slots.tx.is_some() {
            false
        } else {
            slots.tx = Some(report);
            true
        }
    })
}
pub fn generation() -> u32 {
    GENERATION.load(Ordering::Relaxed)
}
#[cfg(feature = "privileged-usb-ccid")]
pub fn receive_ccid() -> Option<BulkPacket> {
    critical_section::with(|_| {
        let mut slots = CCID.0.borrow_mut();
        let len = slots.rx_len.take()?;
        let packet = BulkPacket {
            len: len as u32,
            data: slots.rx,
        };
        Some(packet)
    })
}
#[cfg(feature = "privileged-usb-ccid")]
/// Queues a packet; OK does not confirm peer delivery.
pub fn send_ccid(packet: BulkPacket) -> u32 {
    critical_section::with(|_| {
        let len = packet.len as usize;
        if len > 64 {
            return trusted_status::INVALID_REQUEST;
        }
        let mut slots = CCID.0.borrow_mut();
        if slots.tx_len.is_some() {
            return trusted_status::BUSY;
        }
        slots.tx = packet.data;
        slots.tx_len = Some(len);
        trusted_status::OK
    })
}
#[cfg(feature = "privileged-usb-ccid")]
pub fn take_abort() -> u32 {
    critical_section::with(|_| {
        let mut slots = CCID.0.borrow_mut();
        core::mem::replace(&mut slots.abort, u32::MAX)
    })
}
