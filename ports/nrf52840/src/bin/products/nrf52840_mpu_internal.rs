#![no_std]
#![no_main]
use core::sync::atomic::{AtomicU32, Ordering};
use cortex_m_rt::entry;
use manekey::{
    boundary::{arm_m_frontend::Workspace, arm_m_mpu},
    ctaphid::{
        entropy::HmacDrbgEntropy,
        trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
        user_verification::UnavailableUserVerification,
    },
    presence::NoPresenceObserver,
    security::{SharedMemoryRegion, dispatch_trusted_call_from_shared, trusted_status},
    transport,
};
use nrf52840::{
    board,
    entropy::NrfRngEntropy,
    fido::{NrfDispatcher, selected_crypto_backends},
    internal_uart,
    mpu_usb::{Packet, UsbPump},
    presence::{SelectedUserPresence, configure_selected_user_presence, selected_user_presence},
    storage::selected_storage,
    usb_ingress,
};
use static_cell::StaticCell;
type Dispatcher = NrfDispatcher<SelectedUserPresence>;
struct Kernel {
    dispatcher: Dispatcher,
    usb: UsbPump,
}
static KERNEL: StaticCell<Kernel> = StaticCell::new();
static mut KERNEL_PTR: *mut Kernel = core::ptr::null_mut();
const SHARED_SIZE: usize = if cfg!(feature = "experimental-ml-dsa-fips204") {
    65536
} else {
    16384
};
#[repr(C, align(32768))]
struct Shared([core::mem::MaybeUninit<u8>; SHARED_SIZE]);

static mut SHARED: Shared = Shared([core::mem::MaybeUninit::uninit(); SHARED_SIZE]);
#[repr(C, align(32768))]
struct UserStack([u8; 32768]);
static mut USER_STACK: UserStack = UserStack([0; 32768]);
const _: () = assert!(core::mem::size_of::<Workspace>() <= SHARED_SIZE);

#[inline(never)]
fn initialize_workspace() {
    unsafe {
        core::ptr::addr_of_mut!(SHARED)
            .cast::<Workspace>()
            .write(Workspace::new());
    }
}
fn shared() -> SharedMemoryRegion {
    let start = core::ptr::addr_of_mut!(SHARED) as u32;
    SharedMemoryRegion {
        start,
        end: start + core::mem::size_of::<Shared>() as u32,
    }
}
fn stack() -> (u32, u32) {
    let start = core::ptr::addr_of_mut!(USER_STACK) as u32;
    (start, start + 32768)
}
/// # Safety
/// Privileged initialization only; supply valid aligned regions without exposing private state.
unsafe fn region(index: u32, base: u32, log2: u32, access: u32, xn: bool) {
    let mpu = unsafe { &*cortex_m::peripheral::MPU::PTR };
    let rasr = arm_m_mpu::normal_region_rasr(base, log2, access, xn).unwrap();
    unsafe {
        mpu.rnr.write(index);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
    }
}
#[entry]
/// BLE-less MPU product; reserve private Flash/RAM, copied shared workspace and guarded user stack.
/// Initialize static kernel and exclusive peripheral/IRQ owners before entering the unprivileged frontend.
fn main() -> ! {
    unsafe {
        (*cortex_m::peripheral::SCB::PTR)
            .vtor
            .write(board::BOARD.app_flash_origin);
    }
    let p = nrf52840_pac::Peripherals::take().unwrap();
    board::init_led(&p);
    board::uart_init();
    board::start_hfclk(&p);
    board::start_lfclk(&p);
    board::uart_write_str("nRF52840 MPU boot\r\n");
    configure_selected_user_presence(board::uart_write_str);
    usb_ingress::start_clock(p.RTC2);
    let mut records = selected_storage(p.NVMC, board::uart_write_str);
    let mut entropy = HmacDrbgEntropy::new(NrfRngEntropy::new(p.RNG)).unwrap();
    let (keys, pin) = selected_crypto_backends(
        p.FICR,
        p.RTC1,
        board::uart_write_str,
        &mut records,
        &mut entropy,
    );
    let kernel = KERNEL.init_with(|| Kernel {
        dispatcher: TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            selected_user_presence(board::uart_write_str, true, 600),
            UnavailableUserVerification,
            pin,
            keys,
            entropy,
            transport::USB_TRANSPORTS,
            NoPresenceObserver,
        ),
        usb: UsbPump::new(p.USBD),
    });
    let kr = kernel as *mut Kernel as u32;
    let s = shared();
    let (bottom, top) = stack();
    assert!(kr + core::mem::size_of::<Kernel>() as u32 <= s.start || kr >= s.end);
    unsafe {
        KERNEL_PTR = kernel;
        for address in (bottom..top).step_by(4) {
            (address as *mut u32).write_volatile(0xa5a5_a5a5);
        }
        initialize_workspace();
        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!((mpu._type.read() >> 8) & 255, 8);
        mpu.ctrl.write(0);
        for i in 0..8 {
            mpu.rnr.write(i);
            mpu.rasr.write(0);
        }
        region(0, 0, 20, 6, false);
        region(1, 0xe0000, 16, 1, true);
        region(2, 0x20000000, 18, 1, true);
        region(3, s.start, 15, 3, true);
        if s.end - s.start > 32768 {
            region(4, s.start + 32768, 15, 3, true);
        }
        region(5, bottom, 15, 3, true);
        let (base, rasr) = arm_m_mpu::stack_guard_region(bottom).unwrap();
        mpu.rnr.write(6);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
        mpu.ctrl.write(5);
        (*cortex_m::peripheral::SCB::PTR)
            .shcsr
            .modify(|v| v | (1 << 16) | (1 << 17));
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    board::uart_write_str("MPU U framing ready\r\n");
    unsafe {
        let mut core = cortex_m::Peripherals::steal();
        core.SCB
            .set_priority(cortex_m::peripheral::scb::SystemHandler::SVCall, 0xe0);
    }
    internal_uart::start();
    unsafe { enter(top) }
}
#[unsafe(naked)]
unsafe extern "C" fn enter(_top: u32) -> ! {
    core::arch::naked_asm!(
        "msr psp,r0",
        "movs r0,#3",
        "msr control,r0",
        "isb",
        "b user_frontend"
    );
}
#[unsafe(no_mangle)]
extern "C" fn user_frontend() -> ! {
    unsafe {
        manekey::boundary::arm_m_frontend::run(
            &mut *core::ptr::addr_of_mut!(SHARED).cast::<Workspace>(),
        )
    }
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn SVCall() {
    core::arch::naked_asm!("mrs r0,psp", "mov r1,lr", "b svc_handler");
}
fn checked(a: u32, len: u32, align: u32) -> bool {
    let s = shared();
    a % align == 0 && a >= s.start && a.checked_add(len).is_some_and(|end| end <= s.end)
}
#[unsafe(no_mangle)]
/// Privileged exception entry only; requires initialized kernel and the reserved PSP/shared-memory layout.
extern "C" fn svc_handler(psp: u32, exc: u32) {
    let (bottom, top) = stack();
    let Some(frame) = arm_m_mpu::checked_psp_frame(psp, exc, bottom, top) else {
        fatal()
    };
    let f = frame as *mut u32;
    let pc = unsafe { f.add(6).read() };
    let xpsr = unsafe { f.add(7).read() };
    if pc & 1 != 0
        || !(0x27002..0xe0000).contains(&pc)
        || xpsr & (1 << 24) == 0
        || xpsr & 0x1ff != 0
        || (xpsr & (1 << 9) != 0 && frame.checked_add(36).is_none_or(|end| end > top))
    {
        fatal();
    }
    let instr = unsafe { ((pc - 2) as *const u16).read() };
    if instr & 0xff00 != 0xdf00 {
        fatal();
    }
    let op = instr & 255;

    let a = unsafe { f.read() };
    let b = unsafe { f.add(1).read() };
    let kernel = unsafe { &mut *KERNEL_PTR };
    if op == 10 {
        kernel.usb.pump();
    }
    let generation = kernel.usb.generation();
    let result = match op {
        0 => unsafe { dispatch_trusted_call_from_shared(shared(), a, &mut kernel.dispatcher) },
        1 => {
            if internal_uart::take_overflow() {
                u32::MAX - 1
            } else {
                internal_uart::read().map(u32::from).unwrap_or(u32::MAX)
            }
        }
        2 if b <= (TRUSTED_RESPONSE_MAX + 32) as u32 && checked(a, b, 1) => {
            internal_uart::write(unsafe {
                core::slice::from_raw_parts(a as *const u8, b as usize)
            });
            trusted_status::OK
        }
        5 => usb_ingress::now_ms(),

        8 if checked(a, 64, 1) && b == generation => {
            if let Some(report) = kernel.usb.receive() {
                unsafe { core::ptr::copy_nonoverlapping(report.as_ptr(), a as *mut u8, 64) };
                64
            } else {
                0
            }
        }
        9 if checked(a, 64, 1) && b == generation => {
            let mut report = [0; 64];
            unsafe { core::ptr::copy_nonoverlapping(a as *const u8, report.as_mut_ptr(), 64) };
            kernel.usb.send(report)
        }
        10 => generation,
        11 if checked(a, core::mem::size_of::<Packet>() as u32, 4) && b == generation => {
            if let Some(packet) = kernel.usb.receive_ccid() {
                unsafe { (a as *mut Packet).write(packet) };
                packet.len + 1
            } else {
                0
            }
        }
        12 if checked(a, core::mem::size_of::<Packet>() as u32, 4) && b == generation => {
            kernel.usb.send_ccid(unsafe { (a as *const Packet).read() })
        }
        13 => kernel.usb.take_abort(),
        255 => fatal(),

        _ => trusted_status::INVALID_REQUEST,
    };
    unsafe { f.write(result) };
}
fn fatal() -> ! {
    loop {
        cortex_m::interrupt::disable();
        cortex_m::asm::wfi();
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    let ipsr: u32;
    unsafe {
        core::arch::asm!("mrs {value},ipsr",value=out(reg) ipsr);
    }
    if ipsr == 0 && cortex_m::register::control::read().bits() & 1 != 0 {
        unsafe {
            core::arch::asm!("svc #255");
        }
        loop {
            cortex_m::asm::nop();
        }
    }
    fatal()
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn MemoryManagement() {
    core::arch::naked_asm!("mrs r0,psp", "mov r1,lr", "b memory_fault");
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn BusFault() {
    core::arch::naked_asm!("mrs r0,psp", "mov r1,lr", "b memory_fault");
}
#[unsafe(no_mangle)]
extern "C" fn memory_fault(psp: u32, exc: u32) {
    fatal();
}
#[cortex_m_rt::exception]
unsafe fn HardFault(_: &cortex_m_rt::ExceptionFrame) -> ! {
    fatal()
}
