

#![no_std]
#![no_main]
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use cortex_m_rt::entry;
#[cfg(not(feature = "physical-up"))]
use manekey::presence::AlwaysPresent;
#[cfg(not(feature = "mpu-usb-ccid"))]
use manekey::{
    boundary::local_trusted_call::{SharedTrustedCallBackend, SharedTrustedCallState},
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
};
use manekey::{
    ctaphid::{
        entropy::HmacDrbgEntropy,
        pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
        storage::Storage,
        trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
        user_verification::UnavailableUserVerification,
    },
    presence::NoPresenceObserver,
    security::{SharedMemoryRegion, dispatch_trusted_call_from_shared, trusted_status},
    user_interface::{AtomicUiStatus, UiPresenceObserver},
};
use static_cell::StaticCell;
#[path = "../../boot.rs"]
mod boot;
#[path = "../../data_flash.rs"]
mod data_flash;
#[path = "../../entropy.rs"]
mod entropy;






#[cfg(all(feature = "mpu-usb-hid", not(feature = "mpu-usb-ccid")))]
#[path = "../../mpu_usb.rs"]
mod mpu_usb;
#[cfg(feature = "mpu-usb-ccid")]
#[path = "../../mpu_usb_ccid.rs"]
mod mpu_usb;


#[cfg(all(feature = "mpu-usb-ccid", not(feature = "small-message-buffers")))]
compile_error!("RA4M1 MPU CCID requires the measured small-message-buffers profile");
#[cfg(all(feature = "mpu-usb-hid", not(feature = "mpu-usb-ccid")))]
use manekey::frontend::{
    ctaphid::CtaphidReportFrontend,
    ingress::{IngressId, IngressKind},
};
#[path = "../../key_store.rs"]
mod key_store;
#[path = "../../pin_crypto.rs"]
mod pin_crypto;
#[cfg(feature = "sce5-aes")]
#[path = "../../sce_aes.rs"]
mod sce_aes;
#[cfg(feature = "hardware-wrapped-keys")]
#[path = "../../sce_wrapped.rs"]
mod sce_wrapped;
#[path = "../../sci2.rs"]
mod sci2;
#[path = "../../storage.rs"]
mod storage;
#[cfg(feature = "physical-up")]
#[path = "../../ui.rs"]
mod ui;
#[cfg(feature = "hardware-wrapped-keys")]
#[path = "../../wrapped_keys.rs"]
mod wrapped_keys;

#[cfg(any(
    feature = "mldsa-native-experimental",
    feature = "dual-task",
    feature = "internal-uart",
    feature = "usb-ccid"
))]
compile_error!("MPU product requires small-buffer and its dedicated image/features");

#[cfg(feature = "physical-up")]
type Presence = ui::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = AlwaysPresent;

struct Clock;
impl PinUvAuthTokenClock for Clock {
    fn now_ms(&self) -> u64 {
        entropy::MILLISECONDS.load(Ordering::Relaxed) as u64
    }
}
type Pin = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<storage::Journal>,
    pin_crypto::ClientPin,
    Clock,
>;
type Dispatcher = TrustedDispatcher<
    storage::Journal,
    Presence,
    UnavailableUserVerification,
    Pin,
    key_store::Keys,
    HmacDrbgEntropy<entropy::SceEntropy>,
    UiPresenceObserver<NoPresenceObserver, &'static AtomicUiStatus>,
>;
struct Kernel {
    dispatcher: Dispatcher,
    uart: sci2::Sci2,
    #[cfg(feature = "physical-up")]
    led: ra_hal::gpio::Output<'static, ra_hal::gpio::Basic>,
}
static KERNEL: StaticCell<Kernel> = StaticCell::new();
static FLASH: StaticCell<storage::SharedFlash> = StaticCell::new();
#[cfg(not(feature = "physical-up"))]
static STATUS: AtomicUiStatus = AtomicUiStatus::new();
static mut KERNEL_PTR: *mut Kernel = core::ptr::null_mut();


const SHARED: SharedMemoryRegion = SharedMemoryRegion {
    start: 0x20006000,
    end: PSP_START,
};
#[cfg(not(feature = "mpu-usb-ccid"))]
const PSP_START: u32 = 0x20007000;
#[cfg(feature = "mpu-usb-ccid")]
const PSP_START: u32 = 0x20007800;
const PSP_BYTES: usize = boot::board::PSP_ALLOCATION_BYTES - (PSP_START as usize - 0x20007000);
const U_END: u32 = boot::board::RAM_END;




unsafe extern "C" {
    static _stack_end: u32;
}




















































#[cfg(not(feature = "mpu-usb-ccid"))]
#[repr(C, align(4096))]
struct Workspace {
    call: SharedTrustedCallState,
    response: [u8; TRUSTED_RESPONSE_MAX + 32],
    #[cfg(feature = "mpu-usb-hid")]
    hid: CtaphidReportFrontend,
    #[cfg(feature = "mpu-usb-hid")]
    report: [u8; 64],
}
#[cfg(feature = "mpu-usb-ccid")]
type Workspace = manekey::boundary::arm_m_frontend::Workspace;
#[cfg(feature = "mpu-usb-ccid")]
#[unsafe(link_section = ".mpu_shared")]
static mut WORKSPACE: Workspace = Workspace::new();
#[cfg(not(feature = "mpu-usb-ccid"))]
#[unsafe(link_section = ".mpu_shared")]
static mut WORKSPACE: Workspace = Workspace {
    call: SharedTrustedCallState::new(),
    response: [0; TRUSTED_RESPONSE_MAX + 32],
    #[cfg(feature = "mpu-usb-hid")]
    hid: CtaphidReportFrontend::new(),
    #[cfg(feature = "mpu-usb-hid")]
    report: [0; 64],
};
#[repr(C, align(8))]
struct Stack([u8; PSP_BYTES]);
#[unsafe(link_section = ".mpu_psp")]
#[used]
static mut STACK: Stack = Stack([0; PSP_BYTES]);

unsafe fn region(index: u32, base: u32, size_log2: u32, access: u32, xn: bool) {
    let rasr = manekey::boundary::armv7_m_mpu::normal_region_rasr(base, size_log2, access, xn)
        .expect("invalid MPU region");
    let mpu = unsafe { &*cortex_m::peripheral::MPU::PTR };
    unsafe {
        mpu.rnr.write(index);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
    }
}

#[entry]
fn main() -> ! {
    initialize();
    prepare_windows();
    unsafe {
        enter_unprivileged();
    }
}

// Release the initialization frame after moving service/driver state to statics.
#[inline(never)]
fn initialize() {



    boot::prepare_app_interrupts();
    let p = ra_hal::init(Default::default());
    let mut uart = sci2::Sci2::new(p.SCI2, p.P302, p.P301);
    #[cfg(feature = "mpu-usb-ccid")]
    uart.start_buffered();
    #[cfg(not(feature = "physical-up"))]
    uart.write(b"RA4M1 MPU Internal boot Always-UP\r\n");
    #[cfg(feature = "physical-up")]
    uart.write(b"RA4M1 MPU Internal boot physical-UP\r\n");






    #[cfg(not(feature = "physical-up"))]
    let (presence, status) = (AlwaysPresent, &STATUS);
    #[cfg(feature = "physical-up")]
    let (presence, status, led) = {
        use ra_hal::gpio::Input;
        #[cfg(feature = "board-nano-r4")]
        let button = Input::new_with_pull_up(p.P105, true);
        #[cfg(not(feature = "board-nano-r4"))]
        let button = Input::new_with_pull_up(p.P201, true);
        #[cfg(feature = "board-nano-r4")]
        let led = boot::board::led(p.P204);
        #[cfg(not(feature = "board-nano-r4"))]
        let led = boot::board::led(p.P011);
        (ui::physical_presence(button), &ui::STATUS, led)
    };
    entropy::start_watchdog();
    unsafe {
        cortex_m::interrupt::enable();
    }
    let mut rng = HmacDrbgEntropy::new(entropy::SceEntropy::new().unwrap()).unwrap();


    let flash = FLASH.init(core::cell::RefCell::new(unsafe {
        data_flash::DataFlash::new()
    }));
    let mut records = Storage::new(storage::Journal::credentials(flash));
    let keys = key_store::open(flash, &mut rng, &mut records).expect("RA managed keys");


    let kernel = KERNEL.init_with(|| Kernel {
        dispatcher: TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            presence,
            UnavailableUserVerification,
            Pin::new_with_crypto_and_clock(
                JournaledPinUvAuthStorage::new(storage::Journal::pin(flash)),
                pin_crypto::client_pin(),
                Clock,
            ),
            keys,
            rng,
            {
                #[cfg(feature = "mpu-usb-hid")]
                {
                    manekey::transport::USB_TRANSPORTS
                }
                #[cfg(not(feature = "mpu-usb-hid"))]
                {
                    &[]
                }
            },
            UiPresenceObserver::new(NoPresenceObserver, status),
        ),
        uart,
        #[cfg(feature = "physical-up")]
        led,
    });
    unsafe {
        KERNEL_PTR = kernel;
    }
    #[cfg(feature = "mpu-usb-hid")]
    {
        cortex_m::interrupt::disable();
        let driver = ra_hal::usb::Usbfs::new(p.USBFS, p.P914, p.P915, p.P407, mpu_usb::Irqs);
        mpu_usb::start(driver);
    }
    #[cfg(feature = "mpu-usb-hid")]
    unsafe {
        // USB must preempt the SVC pump; SysTick retains the highest priority.
        let mut core = cortex_m::Peripherals::steal();
        core.NVIC.set_priority(ra_hal::interrupt::IEL2, 0x40);
        core.SCB
            .set_priority(cortex_m::peripheral::scb::SystemHandler::PendSV, 0xf0);
        cortex_m::interrupt::enable();
    }
}

#[inline(never)]
fn prepare_windows() {
    // NOLOAD windows must be explicitly initialized before publication; no old
    // product stack or private state is exposed to the next unprivileged image.
    unsafe {
        #[cfg(feature = "mpu-usb-ccid")]
        core::ptr::addr_of_mut!(WORKSPACE).write(Workspace::new());
        #[cfg(not(feature = "mpu-usb-ccid"))]
        core::ptr::addr_of_mut!(WORKSPACE).write(Workspace {
            call: SharedTrustedCallState::new(),
            response: [0; TRUSTED_RESPONSE_MAX + 32],
            #[cfg(feature = "mpu-usb-hid")]
            hid: CtaphidReportFrontend::new(),
            #[cfg(feature = "mpu-usb-hid")]
            report: [0; 64],
        });







        for index in 0..(U_END - PSP_START) / 4 {
            (PSP_START as *mut u32)
                .add(index as usize)
                .write_volatile(0);
        }


        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!((mpu._type.read() >> 8) & 0xff, 8);
        mpu.ctrl.write(0);
        for i in 0..8 {
            mpu.rnr.write(i);
            mpu.rasr.write(0);
        }
        region(0, 0, 18, 6, false); // Code is public RO; no unprivileged code writes.
        region(1, 0x20000000, 15, 1, true); // All RAM private by default.
        region(2, SHARED.start, 12, 3, true);
        region(3, 0x20007000, 12, 3, true);
        region(4, U_END, boot::board::RESERVED_REGION_LOG2, 1, true);
        mpu.ctrl.write(5); // MMIO/Data Flash absent from U map; privileged default map only.
        (*cortex_m::peripheral::SCB::PTR)
            .shcsr
            .modify(|v| v | (1 << 16));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    unsafe { &mut (*KERNEL_PTR).uart }.write(b"RA4M1 MPU windows ready\r\n");
}

#[unsafe(naked)]
unsafe extern "C" fn enter_unprivileged() -> ! {
    core::arch::naked_asm!(
        "ldr r0, ={stack_top}",
        "msr psp, r0",
        "movs r0, #3",
        "msr control, r0",
        "isb",
        "b unprivileged_frontend",
        stack_top = const U_END,
    );
}

fn syscall<const N: u8>(arg0: u32, arg1: u32) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!("svc {number}", number = const N, inout("r0") arg0 => result, in("r1") arg1);
    }
    result
}
#[cfg(not(feature = "mpu-usb-ccid"))]
fn write_uart(bytes: &[u8]) {
    let _ = syscall::<2>(bytes.as_ptr() as u32, bytes.len() as u32);
}

#[unsafe(no_mangle)]
extern "C" fn unprivileged_frontend() -> ! {


    #[cfg(feature = "mpu-usb-ccid")]
    unsafe {
        manekey::boundary::arm_m_frontend::run(&mut *core::ptr::addr_of_mut!(WORKSPACE))
    }
    #[cfg(not(feature = "mpu-usb-ccid"))]
    old_frontend()
}
#[cfg(not(feature = "mpu-usb-ccid"))]
fn old_frontend() -> ! {
    let workspace = unsafe { &mut *core::ptr::addr_of_mut!(WORKSPACE) };
    let backend = unsafe {
        SharedTrustedCallBackend::with_gate(
            &mut workspace.call,
            manekey::boundary::armv7_m_mpu::SvcTrustedCallGate,
        )
    };
    let mut arbiter = IngressArbiter::new(backend);
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    #[cfg(feature = "mpu-usb-hid")]
    let usb_ingress = IngressId::new(IngressKind::UsbHid, 0);
    #[cfg(feature = "mpu-usb-hid")]
    let mut generation = syscall::<10>(0, 0);
    #[cfg(feature = "mpu-usb-hid")]
    let mut last_poll = syscall::<5>(0, 0);
    loop {
        let _ = frontend.poll_cancel(&mut arbiter);
        #[cfg(feature = "mpu-usb-hid")]
        {
            let next_generation = syscall::<10>(0, 0);
            if generation != next_generation {
                workspace.hid.on_link_lost(&mut arbiter, usb_ingress);
                generation = next_generation;
            }
            if workspace.hid.current_report().is_none()
                && syscall::<8>(workspace.report.as_mut_ptr() as u32, generation) == 64
            {
                workspace
                    .hid
                    .handle_report(&mut arbiter, usb_ingress, workspace.report);
            }
            let now = syscall::<5>(0, 0);
            // poll() replaces the egress queue, including with an empty result.
            // Drain every response first, even when crypto crossed a tick.
            if workspace.hid.current_report().is_none() && now.wrapping_sub(last_poll) >= 100 {
                workspace.hid.poll(&mut arbiter, usb_ingress);
                last_poll = now;
            }
            if let Some(report) = workspace.hid.current_report() {
                if syscall::<9>(report.as_ptr() as u32, generation) == trusted_status::OK {
                    workspace.hid.advance_report();
                }
            }
        }
        let value = syscall::<1>(0, 0);
        if value == u32::MAX {
            continue;
        }
        let byte = value as u8;















        match frontend.push_byte(&mut arbiter, byte, &mut workspace.response) {
            Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                write_uart(&workspace.response[..len])
            }
            Err(_) => frontend.disconnect(&mut arbiter),
            _ => {}
        }
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn SVCall() {
    core::arch::naked_asm!("mrs r0, psp", "mov r1, lr", "b svc_handler");
}

#[unsafe(no_mangle)]
extern "C" fn svc_handler(stack: u32, exception_return: u32) {
    // Only thread/PSP callers are admitted. The exception frame is untrusted;
    // check its complete basic/FP span before using stacked arguments or PC.
    let Some(frame) = manekey::boundary::armv7_m_mpu::checked_psp_frame(
        stack,
        exception_return,
        PSP_START,
        U_END,
    ) else {
        fail();
    };
    let frame = frame as *mut u32;
    let pc = unsafe { frame.add(6).read() };
    if pc & 1 != 0 || !(0x4002..0x40000).contains(&pc) {
        fail();
    }
    let instruction = unsafe { ((pc - 2) as *const u16).read() };
    if instruction & 0xff00 != 0xdf00 {
        fail();
    }
    let kernel = unsafe { &mut *KERNEL_PTR };






    #[cfg(feature = "mpu-usb-hid")]
    cortex_m::peripheral::SCB::set_pendsv();
    let arg0 = unsafe { frame.read() };
    let arg1 = unsafe { frame.add(1).read() };


    let result = match instruction & 0xff {
        0 => unsafe { dispatch_trusted_call_from_shared(SHARED, arg0, &mut kernel.dispatcher) },
        1 => {
            #[cfg(feature = "mpu-usb-ccid")]
            {
                kernel.uart.read_event()
            }
            #[cfg(not(feature = "mpu-usb-ccid"))]
            {
                kernel.uart.read().map(u32::from).unwrap_or(u32::MAX)
            }
        }
        2 => {
            // The CPU is paused in SVC, DMA is not used, and every transmitted
            // byte must be caller-readable shared/PSP or public code Flash.
            let end = arg0.checked_add(arg1);
            let allowed = arg1 <= (TRUSTED_RESPONSE_MAX + 32) as u32
                && end.is_some_and(|end| {
                    (arg0 >= SHARED.start && end <= U_END) || (arg0 >= 0x4000 && end <= 0x40000)
                });
            if allowed {
                kernel.uart.write(unsafe {
                    core::slice::from_raw_parts(arg0 as *const u8, arg1 as usize)
                });
                trusted_status::OK
            } else {
                trusted_status::INVALID_REQUEST
            }
        }













        5 => entropy::MILLISECONDS.load(Ordering::Relaxed),




        #[cfg(feature = "mpu-usb-hid")]
        8 | 9 => {
            // Fixed-size report only. Never let a driver retain a U pointer.
            if arg0 < SHARED.start || arg0.checked_add(64).is_none_or(|end| end > SHARED.end) {
                trusted_status::INVALID_REQUEST
            } else if arg1 != mpu_usb::generation() {
                trusted_status::BUSY
            } else if instruction & 0xff == 8 {
                if let Some(report) = mpu_usb::receive() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(report.as_ptr(), arg0 as *mut u8, 64);
                    }
                    64
                } else {
                    0
                }
            } else {
                let mut report = [0; 64];
                unsafe {
                    core::ptr::copy_nonoverlapping(arg0 as *const u8, report.as_mut_ptr(), 64);
                }
                if mpu_usb::send(report) {
                    trusted_status::OK
                } else {
                    trusted_status::BUSY
                }
            }
        }
        #[cfg(feature = "mpu-usb-hid")]
        10 => mpu_usb::generation(),
        #[cfg(feature = "mpu-usb-ccid")]
        11 | 12 => {
            type Packet = manekey::transport::boundary_link::CopyPacket<64>;
            if arg0 & 3 != 0
                || arg0 < SHARED.start
                || arg0
                    .checked_add(core::mem::size_of::<Packet>() as u32)
                    .is_none_or(|end| end > SHARED.end)
            {
                trusted_status::INVALID_REQUEST
            } else if arg1 != mpu_usb::generation() {
                trusted_status::BUSY
            } else if instruction & 0xff == 11 {
                if let Some(packet) = mpu_usb::receive_ccid() {
                    let received = packet.len + 1; // Shared ABI: zero means no packet, one is ZLP.
                    unsafe {
                        (arg0 as *mut Packet).write(packet);
                    }
                    received
                } else {
                    0
                }
            } else {
                let packet = unsafe { (arg0 as *const Packet).read() };
                mpu_usb::send_ccid(packet)
            }
        }
        #[cfg(feature = "mpu-usb-ccid")]
        13 => mpu_usb::take_abort(),
        _ => trusted_status::INVALID_OPERATION,
    };
    #[cfg(feature = "physical-up")]
    ui::update_led(&mut kernel.led);
    unsafe {
        frame.write(result);
    }
}

fn fail() -> ! {
    cortex_m::interrupt::disable();








    loop {
        cortex_m::asm::wfi();
    }
}

#[cortex_m_rt::exception]
unsafe fn MemoryManagement() {
    fail()
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {










    let _ = info;
    fail()
}
