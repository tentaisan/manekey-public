#![no_std]
#![no_main]
#[cfg(not(any(
    feature = "up-always-present",
    all(feature = "up-bootsel-experimental", feature = "board-ui-experimental")
)))]
compile_error!("select explicit Always UP or BOOTSEL with the board LED UI");
#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
compile_error!(
    "RP2040 MPU product owns a single-core cooperative SVC runtime, not a mailbox worker"
);
use core::cell::RefCell;

use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::{bind_interrupts, peripherals};

use manekey::{
    boundary::{arm_m_frontend::Workspace, arm_m_mpu},
    ctaphid::{
        crypto::SoftwareClientPinCrypto,
        entropy::HmacDrbgEntropy,
        pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
        storage::Storage,
        trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
        user_verification::UnavailableUserVerification,
    },
    security::{SharedMemoryRegion, dispatch_trusted_call_from_shared, trusted_status},
    transport::usb::embassy::privileged_pump::{self as usb, BulkPacket},
};
use manekey_rp::platform::rp::{
    entropy::RoscEntropy,
    storage::{SharedFlashStorage, SharedPinUvAuthFlashStorage, SharedRpFlash},
};
use panic_probe as _;
use static_cell::StaticCell;
bind_interrupts!(struct Irqs { USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<peripherals::USB>; });
#[cfg(feature = "rp2040-mpu-ble")]
bind_interrupts!(struct BleIrqs {
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<peripherals::PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<peripherals::DMA_CH0>, embassy_rp::dma::InterruptHandler<peripherals::DMA_CH1>;
});
#[cfg(feature = "rp2040-mpu-ble")]
#[path = "ble/pico_cyw43_privileged_pump.rs"]
mod ble;

#[cfg(feature = "up-always-present")]
type Presence = manekey::presence::AlwaysPresent;
#[cfg(all(
    not(feature = "up-always-present"),
    feature = "up-bootsel-experimental"
))]
type Presence = manekey_rp::platform::rp::user_interface::RpBootselPresence;
#[cfg(all(feature = "board-ui-experimental", feature = "rp2040-mpu-ble"))]
type Observer = ble::PresenceObserver;
#[cfg(all(feature = "board-ui-experimental", not(feature = "rp2040-mpu-ble")))]
type Observer = manekey::user_interface::UiPresenceObserver<
    manekey::presence::NoPresenceObserver,
    manekey_rp::platform::rp::user_interface::RpGpio25Led,
>;
#[cfg(not(feature = "board-ui-experimental"))]
type Observer = manekey::presence::NoPresenceObserver;

#[cfg(all())]
type ClassicalKeys = manekey_rp::platform::rp::key_store::ClassicalKeys<
    manekey_rp::platform::rp::managed_flash::SharedManagedKeyFlashStorage<'static>,
>;
#[cfg(not(feature = "rp-ml-dsa-credential-experimental"))]
type Keys = ClassicalKeys;
#[cfg(feature = "rp-ml-dsa-credential-experimental")]
type Keys = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<
    ClassicalKeys,
    manekey_rp::platform::rp::crypto::MlDsa,
>;
struct Clock;
impl PinUvAuthTokenClock for Clock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
type Pin = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<SharedPinUvAuthFlashStorage<'static>>,
    SoftwareClientPinCrypto,
    Clock,
>;
type Dispatcher = TrustedDispatcher<
    SharedFlashStorage<'static>,
    Presence,
    UnavailableUserVerification,
    Pin,
    Keys,
    HmacDrbgEntropy<RoscEntropy>,
    Observer,
>;
struct Kernel {
    dispatcher: Dispatcher,
    uart: embassy_rp::uart::Uart<'static, embassy_rp::uart::Blocking>,
}
static FLASH: StaticCell<SharedRpFlash<'static>> = StaticCell::new();
static KERNEL: StaticCell<Kernel> = StaticCell::new();
static mut KERNEL_PTR: *mut Kernel = core::ptr::null_mut();
#[cfg(not(feature = "experimental-large-message-buffers"))]
#[repr(C, align(16384))]
struct Shared(core::mem::MaybeUninit<Workspace>);
#[cfg(feature = "experimental-large-message-buffers")]
#[repr(C, align(32768))]

struct Shared([core::mem::MaybeUninit<u8>; 65536]);
#[cfg(not(feature = "experimental-large-message-buffers"))]
#[cfg_attr(
    feature = "rp-flash-managed-keys",
    unsafe(link_section = ".mpu_shared")
)]
static mut SHARED_DATA: Shared = Shared(core::mem::MaybeUninit::uninit());
#[cfg(feature = "experimental-large-message-buffers")]
#[cfg_attr(
    feature = "rp-flash-managed-keys",
    unsafe(link_section = ".mpu_shared")
)]
static mut SHARED_DATA: Shared = Shared([core::mem::MaybeUninit::uninit(); 65536]);
#[repr(C, align(32768))]
struct Stack([u8; 32768]);
#[cfg_attr(feature = "rp-flash-managed-keys", unsafe(link_section = ".mpu_stack"))]
static mut USER_STACK: Stack = Stack([0; 32768]);
const SHARED_SIZE: u32 = if cfg!(feature = "experimental-large-message-buffers") {
    65536
} else {
    16384
};
const _: () = assert!(core::mem::size_of::<Workspace>() <= SHARED_SIZE as usize);
const _: () = assert!(core::mem::size_of::<Shared>() == SHARED_SIZE as usize);

unsafe extern "C" {
    static _stack_end: u8;
    static _stack_start: u8;
}

fn shared() -> SharedMemoryRegion {
    let start = core::ptr::addr_of_mut!(SHARED_DATA) as u32;
    SharedMemoryRegion {
        start,
        end: start + SHARED_SIZE,
    }
}
fn stack() -> (u32, u32) {
    let start = core::ptr::addr_of_mut!(USER_STACK) as u32;
    (start, start + 32768)
}
/// # Safety
/// Privileged startup only with exclusive disabled MPU ownership and aligned regions matching the intended priority layout.
unsafe fn region(index: u32, base: u32, log2: u32, access: u32, xn: bool) {
    assert!(log2 >= 8);
    let value = arm_m_mpu::normal_region_rasr(base, log2, access, xn).unwrap();
    let mpu = unsafe { &*cortex_m::peripheral::MPU::PTR };
    unsafe {
        mpu.rnr.write(index);
        mpu.rbar.write(base);
        mpu.rasr.write(value);
    }
}
#[cortex_m_rt::entry]
/// Single-core privileged startup with reserved kernel/shared/stack regions and exclusive HAL/Flash ownership.
/// CPU MPU does not isolate DMA masters; delegated transfers must use privileged-owned buffers.
fn main() -> ! {
    unsafe {
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!(SHARED_DATA).cast::<u8>(),
            0,
            SHARED_SIZE as usize,
        );
        core::ptr::write_bytes(core::ptr::addr_of_mut!(USER_STACK).cast::<u8>(), 0, 32768);
        core::ptr::addr_of_mut!(SHARED_DATA)
            .cast::<Workspace>()
            .write(Workspace::new());
    }
    let p = embassy_rp::init(Default::default());
    let mut config = embassy_rp::uart::Config::default();
    config.baudrate = 115200;
    let mut uart = embassy_rp::uart::Uart::new_blocking(p.UART0, p.PIN_0, p.PIN_1, config);
    uart.blocking_write(if cfg!(feature = "up-always-present") {
        b"MK RP2040 MPU boot Always-UP\r\n"
    } else {
        b"MK RP2040 MPU boot Physical-UP\r\n"
    })
    .unwrap();
    let mut flash = Flash::<_, Blocking, { 2 * 1024 * 1024 }>::new_blocking(p.FLASH);
    let mut id = [0; 8];
    flash.blocking_unique_id(&mut id).unwrap();

    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(not(feature = "up-always-present"))]
    let presence = manekey_rp::platform::rp::user_interface::rp_bootsel_presence(p.BOOTSEL);
    #[cfg(all(feature = "board-ui-experimental", feature = "rp2040-mpu-ble"))]
    let observer = ble::presence_observer();
    #[cfg(all(feature = "board-ui-experimental", not(feature = "rp2040-mpu-ble")))]
    let observer = Observer::new(
        manekey::presence::NoPresenceObserver,
        manekey_rp::platform::rp::user_interface::RpGpio25Led::new(p.PIN_25),
    );
    #[cfg(not(feature = "board-ui-experimental"))]
    let observer = manekey::presence::NoPresenceObserver;
    let flash = FLASH.init(SharedRpFlash::new(RefCell::new(flash)));
    let kernel = KERNEL.init_with(|| {
        let mut storage = Storage::new(SharedFlashStorage::new(flash));
        let mut entropy = HmacDrbgEntropy::new(RoscEntropy).unwrap();
        #[cfg(all())]
        let classical_keys = manekey_rp::platform::rp::key_store::open_classical(
            manekey_rp::platform::rp::managed_flash::SharedManagedKeyFlashStorage::new(flash),
            &mut storage,
            &mut entropy,
            manekey::ctaphid::hash::SoftwareSha256,
            cfg!(feature = "rp-flash-managed-key-setup"),
        )
        .expect("RP managed keys");
        #[cfg(feature = "rp-ml-dsa-credential-experimental")]
        let keys = Keys::new(classical_keys, manekey_rp::platform::rp::crypto::ml_dsa());
        #[cfg(not(feature = "rp-ml-dsa-credential-experimental"))]
        let keys = classical_keys;
        Kernel {
            dispatcher: TrustedDispatcher::new_with_transports_and_presence_observer(
                storage,
                presence,
                UnavailableUserVerification,
                Pin::new_with_crypto_and_clock(
                    JournaledPinUvAuthStorage::new(SharedPinUvAuthFlashStorage::new(flash)),
                    SoftwareClientPinCrypto,
                    Clock,
                ),
                keys,
                entropy,
                if cfg!(feature = "rp2040-mpu-ble") {
                    manekey::transport::USB_BLE_TRANSPORTS
                } else {
                    manekey::transport::USB_TRANSPORTS
                },
                observer,
            ),
            uart,
        }
    });
    let kernel_start = kernel as *mut Kernel as u32;
    let kernel_end = kernel_start + core::mem::size_of::<Kernel>() as u32;
    assert!(kernel_end <= shared().start || kernel_start >= shared().end);
    unsafe {
        KERNEL_PTR = kernel;
    }

    usb::start(
        embassy_rp::usb::Driver::new(p.USB, Irqs),
        "ManeKey RP2040 MPU",
        "rp2040-mpu",
    );
    #[cfg(feature = "rp2040-mpu-ble")]
    ble::start(
        ble::Hardware {
            pwr: p.PIN_23,
            cs: p.PIN_25,
            pio: p.PIO0,
            dio: p.PIN_24,
            clk: p.PIN_29,
            dma_tx: p.DMA_CH0,
            dma_rx: p.DMA_CH1,
        },
        flash,
    );
    unsafe {
        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!((mpu._type.read() >> 8) & 255, 8);
        mpu.ctrl.write(0);
        for i in 0..8 {
            mpu.rnr.write(i);
            mpu.rasr.write(0);
        }

        region(0, 0x10000000, 21, 1, false);

        region(1, 0x20000000, 19, 1, false);
        region(2, 0x10000000, 20, 6, false);

        #[cfg(feature = "experimental-large-message-buffers")]
        {
            region(3, shared().start, 15, 3, true);
            region(6, shared().start + 32768, 15, 3, true);
        }
        #[cfg(not(feature = "experimental-large-message-buffers"))]
        region(3, shared().start, 14, 3, true);
        region(4, stack().0, 15, 3, true);
        region(5, stack().0, 8, 0, true);
        mpu.ctrl.write(5);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    kernel
        .uart
        .blocking_write(b"MK RP2040 MPU U framing ready\r\n")
        .unwrap();

    unsafe {
        enter_user(stack().1);
    }
}
#[unsafe(naked)]
/// # Safety
/// Require initialized MPU/gateway/shared workspace and a valid aligned exclusive PSP stack before dropping privilege.
unsafe extern "C" fn enter_user(_top: u32) -> ! {
    core::arch::naked_asm!(
        "msr psp, r0",
        "movs r0, #3",
        "msr control, r0",
        "isb",
        "ldr r0, =user_loop",
        "bx r0"
    );
}
#[unsafe(no_mangle)]
extern "C" fn user_loop() -> ! {
    unsafe {
        manekey::boundary::arm_m_frontend::run(
            &mut *core::ptr::addr_of_mut!(SHARED_DATA).cast::<Workspace>(),
        );
    }
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn SVCall() {
    core::arch::naked_asm!("mrs r0, psp", "mov r1, lr", "ldr r2, =svc_handler", "bx r2");
}
fn checked_buffer(address: u32, length: u32, align: u32) -> bool {
    address % align == 0
        && address >= shared().start
        && address
            .checked_add(length)
            .is_some_and(|end| end <= shared().end)
}
#[unsafe(no_mangle)]
/// Exception-entry only; require the initialized sole kernel and exclude reentrant service polling or DMA mutation of shared buffers.
extern "C" fn svc_handler(psp: u32, exception_return: u32) {
    let (start, end) = stack();
    if exception_return != 0xfffffffd
        || arm_m_mpu::checked_psp_frame(psp, exception_return, start + 256, end).is_none()
    {
        fail(psp);
    }
    let frame = psp as *mut u32;
    let pc = unsafe { frame.add(6).read() };
    if pc & 1 != 0 || !(0x10000102..0x10100000).contains(&pc) {
        fail(pc);
    }
    let instruction = unsafe { ((pc - 2) as *const u16).read() };
    if instruction & 0xff00 != 0xdf00 {
        fail(pc);
    }
    let operation = instruction & 255;
    let xpsr = unsafe { frame.add(7).read() };
    if xpsr & (1 << 24) == 0
        || xpsr & 0x1ff != 0
        || (xpsr & (1 << 9) != 0 && psp.checked_add(36).is_none_or(|next| next > end))
    {
        fail(pc);
    }
    let a = unsafe { frame.read() };
    let b = unsafe { frame.add(1).read() };
    let kernel = unsafe { &mut *KERNEL_PTR };
    if operation == 10 {
        usb::pump();
    }
    #[cfg(feature = "rp2040-mpu-ble")]
    if operation == 16 {
        unsafe { ble::pump() };
    }
    let result = match operation {
        0 => {
            let result =
                unsafe { dispatch_trusted_call_from_shared(shared(), a, &mut kernel.dispatcher) };

            result
        }
        1 => embedded_hal_nb::serial::Read::read(&mut kernel.uart)
            .map(u32::from)
            .unwrap_or(u32::MAX),
        2 if b <= (TRUSTED_RESPONSE_MAX + 32) as u32 && checked_buffer(a, b, 1) => kernel
            .uart
            .blocking_write(unsafe { core::slice::from_raw_parts(a as *const u8, b as usize) })
            .map_or(trusted_status::INVALID_REQUEST, |_| trusted_status::OK),
        5 => embassy_time::Instant::now().as_millis() as u32,

        8 | 9 if checked_buffer(a, 64, 1) => {
            if b != usb::generation() {
                trusted_status::BUSY
            } else if operation == 8 {
                if let Some(report) = usb::receive() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(report.as_ptr(), a as *mut u8, 64);
                    }
                    64
                } else {
                    0
                }
            } else {
                let mut report = [0; 64];
                unsafe {
                    core::ptr::copy_nonoverlapping(a as *const u8, report.as_mut_ptr(), 64);
                }
                if usb::send(report) {
                    trusted_status::OK
                } else {
                    trusted_status::BUSY
                }
            }
        }
        10 => usb::generation(),
        11 | 12 if checked_buffer(a, core::mem::size_of::<BulkPacket>() as u32, 4) => {
            if b != usb::generation() {
                trusted_status::BUSY
            } else if operation == 11 {
                if let Some(packet) = usb::receive_ccid() {
                    unsafe {
                        (a as *mut BulkPacket).write(packet);
                    }
                    packet.len + 1
                } else {
                    0
                }
            } else {
                usb::send_ccid(unsafe { (a as *const BulkPacket).read() })
            }
        }
        13 => usb::take_abort(),
        #[cfg(feature = "rp2040-mpu-ble")]
        16 => ble::generation(),

        #[cfg(feature = "rp2040-mpu-ble")]
        17 | 18
            if checked_buffer(
                a,
                core::mem::size_of::<manekey::transport::ble::boundary_slots::BlePacket>() as u32,
                4,
            ) =>
        {
            use manekey::transport::ble::boundary_slots::BlePacket;
            if operation == 17 {
                if let Some(packet) = ble::receive(b) {
                    unsafe {
                        (a as *mut BlePacket).write(packet);
                    }
                    packet.len
                } else {
                    0
                }
            } else if ble::send(b, unsafe { (a as *const BlePacket).read() }) {
                trusted_status::OK
            } else {
                trusted_status::BUSY
            }
        }
        _ => trusted_status::INVALID_REQUEST,
    };
    unsafe {
        frame.write(result);
    }
}
fn fail(pc: u32) -> ! {
    let _ = pc;
    loop {
        cortex_m::asm::wfi();
    }
}
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn HardFault() {
    core::arch::naked_asm!(
        "mov r1, lr",
        "movs r2, #4",
        "tst r1, r2",
        "beq 2f",
        "mrs r0, psp",
        "b 3f",
        "2:",
        "mrs r0, msp",
        "3:",
        "ldr r2, =fault_handler",
        "bx r2"
    );
}
#[unsafe(no_mangle)]
/// Exception-entry only with the active linker stack bounds; production failures halt rather than recover.
extern "C" fn fault_handler(psp: u32, exception_return: u32) {
    let (start, end) = stack();

    let valid_frame = if exception_return == 0xfffffffd {
        arm_m_mpu::checked_psp_frame(psp, exception_return, start + 256, end).is_some()
    } else {
        matches!(exception_return, 0xfffffff1 | 0xfffffff9)
            && psp & 7 == 0
            && psp >= core::ptr::addr_of!(_stack_end) as u32
            && psp
                .checked_add(32)
                .is_some_and(|limit| limit <= core::ptr::addr_of!(_stack_start) as u32)
    };
    let pc = if valid_frame {
        unsafe { (psp as *const u32).add(6).read() }
    } else {
        psp
    };

    fail(pc)
}

#[cfg(not(feature = "rp-flash-managed-keys"))]
compile_error!("Public products require rp-flash-managed-keys");
