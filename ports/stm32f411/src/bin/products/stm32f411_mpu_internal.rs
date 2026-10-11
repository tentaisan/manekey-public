#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU32, Ordering};
use cortex_m_rt::entry;
use embassy_stm32::{gpio, mode::Blocking, usart};
#[cfg(feature = "mpu-usb-hid")]
use manekey::frontend::{
    ctaphid::CtaphidReportFrontend,
    ingress::{IngressId, IngressKind},
};
#[cfg(not(feature = "physical-up"))]
use manekey::presence::AlwaysPresent;
use manekey::{
    boundary::local_trusted_call::{SharedTrustedCallBackend, SharedTrustedCallState},
    ctaphid::{
        crypto::SoftwareClientPinCrypto,
        entropy::HmacDrbgEntropy,
        pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
        storage::Storage,
        trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
        user_verification::UnavailableUserVerification,
    },
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    presence::{NoPresenceObserver, PresenceUiHint},
    security::{SharedMemoryRegion, dispatch_trusted_call_from_shared, trusted_status},
    user_interface::UiPresenceObserver,
};
use manekey_stm32f411::{
    entropy::ExperimentalEntropy,
    storage::{Journal, SharedFlash},
    ui::STATUS,
};
use static_cell::StaticCell;
#[cfg(feature = "dual-task")]
compile_error!("MPU image has a dedicated PSP/SVC scheduler");
#[cfg(all(feature = "usb-ccid", not(feature = "mpu-usb-hid")))]
compile_error!("select mpu-usb-ccid for MPU bulk transport");
#[cfg(feature = "usb-ccid")]
use manekey::frontend::ccid::{CCID_RESPONSE_MAX, CcidFrontend};
#[cfg(feature = "usb-ccid")]
use manekey::transport::usb::ccid_bulk::CcidBulkAssembler;
#[cfg(feature = "usb-ccid")]
use manekey_stm32f411::mpu_usb::BulkPacket;
#[cfg(feature = "physical-up")]
type Presence = manekey_stm32f411::ui::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = AlwaysPresent;
struct Clock;
impl PinUvAuthTokenClock for Clock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
type Dispatcher = TrustedDispatcher<
    Journal,
    Presence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<JournaledPinUvAuthStorage<Journal>, SoftwareClientPinCrypto, Clock>,
    manekey_stm32f411::key_store::KeyStore,
    HmacDrbgEntropy<ExperimentalEntropy>,
    UiPresenceObserver<NoPresenceObserver, &'static manekey::user_interface::AtomicUiStatus>,
>;
struct Kernel {
    dispatcher: Dispatcher,
    uart: usart::Uart<'static, Blocking>,
    led: gpio::Output<'static>,
}
static KERNEL: StaticCell<Kernel> = StaticCell::new();
static mut KERNEL_PTR: *mut Kernel = core::ptr::null_mut();
const SHARED: SharedMemoryRegion = SharedMemoryRegion {
    start: 0x20014000,
    end: 0x2001c000,
};
const PSP_START: u32 = 0x2001c100;
const PSP_END: u32 = 0x20020000;
#[unsafe(no_mangle)]
pub static MPU_STAGE: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    static _stack_end: u8;
    static _stack_start: u8;
}

fn msp_guard() -> u32 {
    (core::ptr::addr_of!(_stack_end) as u32 + 255) & !255
}

#[repr(C, align(8))]
struct Workspace {
    call: SharedTrustedCallState,
    response: [u8; TRUSTED_RESPONSE_MAX + 32],
    #[cfg(feature = "mpu-usb-hid")]
    hid: CtaphidReportFrontend,
    #[cfg(feature = "mpu-usb-hid")]
    report: [u8; 64],
    #[cfg(feature = "usb-ccid")]
    ccid: CcidFrontend,
    #[cfg(feature = "usb-ccid")]
    ccid_request: CcidBulkAssembler<CCID_RESPONSE_MAX>,
    #[cfg(feature = "usb-ccid")]
    ccid_response: [u8; CCID_RESPONSE_MAX],
    #[cfg(feature = "usb-ccid")]
    ccid_packet: BulkPacket,
}
const _: () = assert!(core::mem::size_of::<Workspace>() <= 32768);
#[unsafe(link_section = ".mpu_shared")]
static mut WORKSPACE: Workspace = Workspace {
    call: SharedTrustedCallState::new(),
    response: [0; TRUSTED_RESPONSE_MAX + 32],
    #[cfg(feature = "mpu-usb-hid")]
    hid: CtaphidReportFrontend::new(),
    #[cfg(feature = "mpu-usb-hid")]
    report: [0; 64],
    #[cfg(feature = "usb-ccid")]
    ccid: CcidFrontend::new(0),
    #[cfg(feature = "usb-ccid")]
    ccid_request: CcidBulkAssembler::new(),
    #[cfg(feature = "usb-ccid")]
    ccid_response: [0; CCID_RESPONSE_MAX],
    #[cfg(feature = "usb-ccid")]
    ccid_packet: BulkPacket {
        len: 0,
        data: [0; 64],
    },
};
#[unsafe(link_section = ".mpu_psp")]
#[used]
static mut STACK: [u8; 16384] = [0; 16384];

/// Configure one MPU region.
///
/// # Safety
/// Exclusively own the disabled MPU during configuration and supply valid aligned, nonoverlapping policy regions.
unsafe fn region(index: u32, base: u32, size: u32, ap: u32, xn: bool) {
    let rasr = manekey::boundary::armv7_m_mpu::normal_region_rasr(base, size, ap, xn).unwrap();
    let mpu = unsafe { &*cortex_m::peripheral::MPU::PTR };
    unsafe {
        mpu.rnr.write(index);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
    }
}
#[entry]
/// CPU MPU product with privileged physical peripherals and experimental, unqualified entropy.
/// Initialize reserved NOLOAD shared state each boot and preserve private/shared/PSP and IRQ ownership.
fn main() -> ! {
    let p = embassy_stm32::init(manekey_stm32f411::board::config());
    let mut uart =
        usart::Uart::new_blocking(p.USART2, p.PA2, p.PA3, usart::Config::default()).unwrap();
    uart.blocking_write(b"MK F411 MPU boot experimental entropy\r\n")
        .unwrap();
    #[cfg(feature = "physical-up")]
    let presence =
        manekey_stm32f411::ui::physical_presence(gpio::Input::new(p.PC13, gpio::Pull::Up));
    #[cfg(not(feature = "physical-up"))]
    let presence = AlwaysPresent;
    let mut source = ExperimentalEntropy::new(p.ADC1, p.TIM5);
    static FLASH: StaticCell<SharedFlash> = StaticCell::new();
    let flash = FLASH.init(critical_section::Mutex::new(core::cell::RefCell::new(
        embassy_stm32::flash::Flash::new_blocking(p.FLASH),
    )));
    manekey_stm32f411::storage::initialize_records(flash).expect("paired records");
    let mut records = Storage::new(Journal::credentials(flash));
    let keys =
        manekey_stm32f411::key_store::open(flash, &mut source, &mut records).expect("key store");
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_clock(
            JournaledPinUvAuthStorage::new(Journal::pin(flash)),
            Clock,
        ),
        keys,
        HmacDrbgEntropy::new(source).unwrap(),
        manekey::transport::USB_TRANSPORTS,
        UiPresenceObserver::new(NoPresenceObserver, &STATUS),
    );
    let kernel = KERNEL.init(Kernel {
        dispatcher,
        uart,
        led: gpio::Output::new(p.PA5, gpio::Level::Low, gpio::Speed::Low),
    });
    #[cfg(feature = "mpu-usb-hid")]
    {
        static OUT: StaticCell<[u8; 256]> = StaticCell::new();
        let mut config = embassy_stm32::usb::Config::default();
        config.vbus_detection = false;
        let driver = embassy_stm32::usb::Driver::new_fs(
            p.USB_OTG_FS,
            p.PA12,
            p.PA11,
            manekey_stm32f411::mpu_usb::Irqs,
            OUT.init([0; 256]),
            config,
        );
        manekey_stm32f411::mpu_usb::start(driver);
    }
    unsafe {
        KERNEL_PTR = kernel;

        let workspace = core::ptr::addr_of_mut!(WORKSPACE);

        workspace
            .cast::<u8>()
            .write_bytes(0, core::mem::size_of::<Workspace>());
        core::ptr::addr_of_mut!((*workspace).call).write(SharedTrustedCallState::new());
        #[cfg(feature = "mpu-usb-hid")]
        core::ptr::addr_of_mut!((*workspace).hid).write(CtaphidReportFrontend::new());
        #[cfg(feature = "usb-ccid")]
        core::ptr::addr_of_mut!((*workspace).ccid).write(CcidFrontend::new(0));
        #[cfg(feature = "usb-ccid")]
        core::ptr::addr_of_mut!((*workspace).ccid_request).write(CcidBulkAssembler::new());

        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!((mpu._type.read() >> 8) & 0xff, 8);
        mpu.ctrl.write(0);
        for i in 0..8 {
            mpu.rnr.write(i);
            mpu.rasr.write(0);
        }
        region(0, 0x08040000, 18, 6, false);
        region(1, 0x20000000, 17, 1, true);
        region(2, SHARED.start, 14, 3, true);
        region(3, SHARED.start + 16384, 14, 3, true);
        region(4, 0x2001c000, 14, 3, true);
        region(5, 0x2001c000, 8, 1, true);

        region(6, msp_guard(), 8, 0, true);
        mpu.ctrl.write(5);
        (*cortex_m::peripheral::SCB::PTR)
            .shcsr
            .modify(|v| v | (1 << 16));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    kernel
        .uart
        .blocking_write(b"MK F411 MPU ready private80K shared32K PSP16K guard256\r\n")
        .unwrap();
    MPU_STAGE.store(1, Ordering::Relaxed);
    unsafe { enter_user() }
}
#[unsafe(naked)]
/// Enter the initialized unprivileged PSP loop.
///
/// # Safety
/// Install matching MPU/PSP/SVC state first; no live startup stack object may be used after abandoning MSP.
unsafe extern "C" fn enter_user() -> ! {
    core::arch::naked_asm!("ldr r0, =_stack_start", "msr msp, r0", "ldr r0, ={top}", "msr psp, r0", "movs r0, #3", "msr control, r0", "isb", "b user_loop", top = const PSP_END);
}
fn syscall<const N: u8>(arg0: u32, arg1: u32) -> u32 {
    let result;
    unsafe {
        core::arch::asm!("svc {n}", n = const N, inout("r0") arg0 => result, in("r1") arg1);
    }
    result
}
#[unsafe(no_mangle)]
extern "C" fn user_loop() -> ! {
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
    let ingress = IngressId::new(IngressKind::UsbHid, 0);
    #[cfg(feature = "mpu-usb-hid")]
    let mut generation = syscall::<10>(0, 0);
    #[cfg(feature = "mpu-usb-hid")]
    let mut last_poll = syscall::<5>(0, 0);
    #[cfg(feature = "usb-ccid")]
    let mut ccid_pending = 0;
    #[cfg(feature = "usb-ccid")]
    let mut ccid_offset = 0;
    #[cfg(feature = "usb-ccid")]
    let mut ccid_poll = syscall::<5>(0, 0);
    loop {
        let _ = frontend.poll_cancel(&mut arbiter);
        #[cfg(feature = "mpu-usb-hid")]
        {
            let current = syscall::<10>(0, 0);
            if current != generation {
                workspace.hid.on_link_lost(&mut arbiter, ingress);
                #[cfg(feature = "usb-ccid")]
                {
                    workspace.ccid.disconnect(&mut arbiter);
                    workspace.ccid_request.reset();
                    ccid_pending = 0;
                    ccid_offset = 0;
                }
                generation = current;
            }
            if workspace.hid.current_report().is_none()
                && syscall::<8>(workspace.report.as_mut_ptr() as u32, generation) == 64
            {
                workspace
                    .hid
                    .handle_report(&mut arbiter, ingress, workspace.report);
            }
            let now = syscall::<5>(0, 0);
            if workspace.hid.current_report().is_none() && now.wrapping_sub(last_poll) >= 100 {
                workspace.hid.poll(&mut arbiter, ingress);
                last_poll = now;
            }
            if let Some(report) = workspace.hid.current_report() {
                if syscall::<9>(report.as_ptr() as u32, generation) == trusted_status::OK {
                    workspace.hid.advance_report();
                }
            }
        }
        #[cfg(feature = "usb-ccid")]
        {
            let abort = syscall::<13>(0, 0);
            if abort != u32::MAX {
                workspace
                    .ccid
                    .begin_abort(&mut arbiter, abort as u8, (abort >> 8) as u8);
                ccid_pending = 0;
                ccid_offset = 0;
                workspace.ccid_request.reset();
            }
            if ccid_pending == 0 {
                let len = syscall::<11>(
                    core::ptr::addr_of_mut!(workspace.ccid_packet) as u32,
                    generation,
                );
                if len > 0 && len <= 65 {
                    if let Ok(Some(message)) = workspace
                        .ccid_request
                        .push(&workspace.ccid_packet.data[..(len - 1) as usize])
                    {
                        ccid_pending = workspace
                            .ccid
                            .handle_message(&mut arbiter, message, &mut workspace.ccid_response)
                            .unwrap_or(0);
                        workspace.ccid_request.reset();
                        ccid_offset = 0;
                    }
                } else {
                    let now = syscall::<5>(0, 0);
                    if now.wrapping_sub(ccid_poll) >= 100 {
                        ccid_pending = workspace
                            .ccid
                            .poll(&mut arbiter, &mut workspace.ccid_response)
                            .ok()
                            .flatten()
                            .unwrap_or(0);
                        ccid_poll = now;
                    }
                }
            }
            if ccid_pending != 0 {
                let end = (ccid_offset + 64).min(ccid_pending);
                let len = end - ccid_offset;
                workspace.ccid_packet.len = len as u32;
                workspace.ccid_packet.data[..len]
                    .copy_from_slice(&workspace.ccid_response[ccid_offset..end]);
                if syscall::<12>(
                    core::ptr::addr_of!(workspace.ccid_packet) as u32,
                    generation,
                ) == trusted_status::OK
                {
                    ccid_offset = end;
                    if len < 64 {
                        ccid_pending = 0;
                        ccid_offset = 0;
                    }
                }
            }
        }
        let byte = syscall::<1>(0, 0);
        if byte == u32::MAX {
            continue;
        }
        match frontend.push_byte(&mut arbiter, byte as u8, &mut workspace.response) {
            Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                let _ = syscall::<2>(workspace.response.as_ptr() as u32, len as u32);
            }
            Err(_) => frontend.disconnect(&mut arbiter),
            _ => {}
        }
    }
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
/// SVC vector entry.
///
/// # Safety
/// Invoke only as an exception with the configured PSP frame and exclusive privileged kernel ownership.
unsafe extern "C" fn SVCall() {
    core::arch::naked_asm!("mrs r0, psp", "mov r1, lr", "b svc_handler");
}
#[unsafe(no_mangle)]
extern "C" fn svc_handler(stack: u32, exception_return: u32) {
    let frame = manekey::boundary::armv7_m_mpu::checked_psp_frame(
        stack,
        exception_return,
        PSP_START,
        PSP_END,
    )
    .unwrap_or_else(|| fail());
    let frame = frame as *mut u32;
    let pc = unsafe { frame.add(6).read() };
    if pc & 1 != 0 || !(0x08040002..0x08080000).contains(&pc) {
        fail();
    }
    let instruction = unsafe { ((pc - 2) as *const u16).read() };
    if instruction & 0xff00 != 0xdf00 {
        fail();
    }
    let arg0 = unsafe { frame.read() };
    let arg1 = unsafe { frame.add(1).read() };
    let kernel = unsafe { &mut *KERNEL_PTR };
    #[cfg(feature = "mpu-usb-hid")]
    if instruction & 0xff == 10 {
        manekey_stm32f411::mpu_usb::pump();
    }
    let result = match instruction & 0xff {
        0 => unsafe { dispatch_trusted_call_from_shared(SHARED, arg0, &mut kernel.dispatcher) },
        1 => {
            let regs = embassy_stm32::pac::USART2;
            let sr = regs.sr().read();
            if sr.rxne() || sr.ore() {
                let data = regs.dr().read().dr();

                if sr.ore() || sr.fe() || sr.ne() || sr.pe() {
                    u32::MAX
                } else {
                    u32::from(data)
                }
            } else {
                u32::MAX
            }
        }
        2 => {
            if arg1 <= (TRUSTED_RESPONSE_MAX + 32) as u32
                && arg0 >= SHARED.start
                && arg0.checked_add(arg1).is_some_and(|end| end <= SHARED.end)
            {
                let bytes =
                    unsafe { core::slice::from_raw_parts(arg0 as *const u8, arg1 as usize) };
                kernel
                    .uart
                    .blocking_write(bytes)
                    .map_or(trusted_status::INVALID_REQUEST, |_| trusted_status::OK)
            } else {
                trusted_status::INVALID_REQUEST
            }
        }
        5 => embassy_time::Instant::now().as_millis() as u32,
        #[cfg(feature = "mpu-usb-hid")]
        8 | 9 => {
            if arg0 < SHARED.start || arg0.checked_add(64).is_none_or(|end| end > SHARED.end) {
                trusted_status::INVALID_REQUEST
            } else if arg1 != manekey_stm32f411::mpu_usb::generation() {
                trusted_status::BUSY
            } else if instruction & 0xff == 8 {
                if let Some(report) = manekey_stm32f411::mpu_usb::receive() {
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
                if manekey_stm32f411::mpu_usb::send(report) {
                    trusted_status::OK
                } else {
                    trusted_status::BUSY
                }
            }
        }
        #[cfg(feature = "mpu-usb-hid")]
        10 => manekey_stm32f411::mpu_usb::generation(),
        #[cfg(feature = "usb-ccid")]
        11 | 12 => {
            if arg0 < SHARED.start
                || arg0 % core::mem::align_of::<BulkPacket>() as u32 != 0
                || arg0
                    .checked_add(core::mem::size_of::<BulkPacket>() as u32)
                    .is_none_or(|end| end > SHARED.end)
            {
                trusted_status::INVALID_REQUEST
            } else if arg1 != manekey_stm32f411::mpu_usb::generation() {
                trusted_status::BUSY
            } else if instruction & 0xff == 11 {
                if let Some(packet) = manekey_stm32f411::mpu_usb::receive_ccid() {
                    unsafe {
                        (arg0 as *mut BulkPacket).write(packet);
                    }

                    packet.len + 1
                } else {
                    0
                }
            } else {
                let packet = unsafe { (arg0 as *const BulkPacket).read() };
                manekey_stm32f411::mpu_usb::send_ccid(packet)
            }
        }
        #[cfg(feature = "usb-ccid")]
        13 => manekey_stm32f411::mpu_usb::take_abort(),

        _ => trusted_status::INVALID_OPERATION,
    };
    if STATUS.get() == PresenceUiHint::TouchRequired {
        kernel.led.set_high();
    } else {
        kernel.led.set_low();
    }

    unsafe {
        frame.write(result);
    }
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
/// Memory-fault vector entry.
///
/// # Safety
/// Invoke only as an exception with the configured PSP/exception-return contract.
unsafe extern "C" fn MemoryManagement() {
    core::arch::naked_asm!("mrs r0, psp", "mov r1, lr", "b memory_fault");
}
#[unsafe(no_mangle)]
extern "C" fn memory_fault(stack: u32, exception_return: u32) {
    let frame = manekey::boundary::armv7_m_mpu::checked_psp_frame(
        stack,
        exception_return,
        PSP_START,
        PSP_END,
    )
    .unwrap_or_else(|| fail()) as *mut u32;

    {
        let _ = frame;
        fail();
    }
}

fn fail() -> ! {
    MPU_STAGE.store(0xdead, Ordering::Relaxed);
    cortex_m::interrupt::disable();
    loop {
        cortex_m::asm::nop();
    }
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    fail()
}
