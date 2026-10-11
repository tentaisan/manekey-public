use super::{BLE_PACKET_LEN, SelectedDispatcher, log, log_word, nrf52840_ble_poll_tick};
use core::{
    arch::global_asm,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use manekey::{
    boundary::{
        arm_m_mpu, arm_m_thread_once,
        copied_mailbox::{self, CopiedBackendWorker, CopiedMailboxTransport, MailboxCopyGate},
        mailbox::MailboxEndpoint,
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
    frontend::peripheral::{PeripheralEndpoint, PeripheralFrontend, PeripheralLink, UartInput},
    security::{SharedMemoryRegion, trusted_status},
    transport::{
        ble::{
            BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler,
            boundary_slots::BleBoundarySlots,
        },
        boundary_link::CopyPacket,
    },
};
use nrf_softdevice::raw;
use nrf52840::{internal_uart, mpu_usb::UsbPump};
use static_cell::StaticCell;

const FRAGMENTS: usize = 1 + TRUSTED_RESPONSE_MAX
    .saturating_sub(BLE_PACKET_LEN - 3)
    .div_ceil(BLE_PACKET_LEN - 1);
type Backend = MailboxTrustedBackend<CopiedMailboxTransport<Gate>>;
type Frontend = PeripheralFrontend<Backend, BLE_PACKET_LEN, FRAGMENTS>;
pub(super) struct SharedArbiter;
static HANDLE: SharedArbiter = SharedArbiter;
#[repr(C, align(8192))]
struct UserWorkspace {
    frontend: Frontend,
}
static mut USER: UserWorkspace = UserWorkspace {
    frontend: Frontend::new(MailboxTrustedBackend::new(CopiedMailboxTransport::new(
        Gate,
    ))),
};
#[repr(C, align(4096))]
struct UserStack([u8; 4096]);
static mut STACK: UserStack = UserStack([0; 4096]);
static ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
struct Kernel {
    worker: CopiedBackendWorker<SelectedDispatcher>,
    ble: BleBoundarySlots<8, 20>,
    usb: Option<UsbPump>,
}
static KERNEL: StaticCell<Kernel> = StaticCell::new();
static mut KERNEL_PTR: *mut Kernel = core::ptr::null_mut();
static ACTIVE: AtomicBool = AtomicBool::new(false);

const _: () = assert!(core::mem::size_of::<UserWorkspace>() <= 5 * 8192);

fn shared() -> SharedMemoryRegion {
    let start = core::ptr::addr_of_mut!(USER) as u32;
    SharedMemoryRegion {
        start,
        end: start + core::mem::size_of::<UserWorkspace>() as u32,
    }
}
fn stack() -> (u32, u32) {
    let start = core::ptr::addr_of_mut!(STACK) as u32;
    (start, start + 4096)
}
fn checked(pointer: u32, len: u32, align: u32) -> bool {
    let region = shared();
    pointer & (align - 1) == 0
        && pointer >= region.start
        && pointer
            .checked_add(len)
            .is_some_and(|end| end <= region.end)
}
/// # Safety
/// Initialized privileged runtime only; serialize access and retain no borrow across a user turn.
/// IRQ handlers must not access this kernel.
unsafe fn kernel<'a>() -> &'a mut Kernel {
    unsafe { &mut *KERNEL_PTR }
}
/// Initialize private kernel once before MPU installation and frontend turns.
pub(super) fn initialize_backend(dispatcher: SelectedDispatcher) -> &'static SharedArbiter {
    let kernel = KERNEL.init(Kernel {
        worker: CopiedBackendWorker::new(dispatcher),
        ble: BleBoundarySlots::new(),
        usb: None,
    });
    let region = shared();
    let address = kernel as *mut Kernel as u32;
    assert!(
        address + core::mem::size_of::<Kernel>() as u32 <= region.start || address >= region.end
    );
    unsafe {
        KERNEL_PTR = kernel;
    }
    &HANDLE
}
unsafe fn region(index: u32, base: u32, log2: u32, access: u32, xn: bool) {
    let mpu = unsafe { &*cortex_m::peripheral::MPU::PTR };
    let rasr = arm_m_mpu::normal_region_rasr(base, log2, access, xn).unwrap();
    unsafe {
        mpu.rnr.write(index);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
    }
}
/// Privileged one-time MPU installation for the reserved S140/shared workspace/guarded-stack layout.
pub(super) fn initialize_permissions() {
    let (bottom, _) = stack();
    let window = shared();
    assert!(bottom >= 0x20020000 && window.start >= 0x20020000);
    assert!(bottom + 4096 <= window.start || bottom >= window.end);
    unsafe {
        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!((mpu._type.read() >> 8) & 255, 8);
        assert_eq!(mpu.ctrl.read(), 0);
        for i in 0..8 {
            mpu.rnr.write(i);
            mpu.rasr.write(0);
        }
        region(0, 0, 20, 6, false);
        region(1, 0xe0000, 16, 1, true);
        region(2, 0x20000000, 18, 1, true);

        let mut base = window.start;
        let mut index = 3;
        while base < window.end {
            assert!(index < 6);
            let remaining = window.end - base;
            let log2 = (13..=15)
                .rev()
                .find(|bits| base & ((1 << bits) - 1) == 0 && (1 << bits) <= remaining)
                .unwrap();
            region(index, base, log2, 3, true);
            base += 1 << log2;
            index += 1;
        }
        region(6, bottom, 12, 3, true);
        let (base, rasr) = arm_m_mpu::stack_guard_region(bottom).unwrap();
        mpu.rnr.write(7);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
        mpu.ctrl.write(5);
        let scb = &*cortex_m::peripheral::SCB::PTR;
        scb.shcsr.modify(|v| v | (1 << 16) | (1 << 17));
        scb.cpacr.modify(|v| (v & !(15 << 20)) | (5 << 20));
        for address in (bottom + 32..bottom + 4096).step_by(4) {
            (address as *mut u32).write_volatile(0xa5a5_a5a5);
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    log_word("mpu shared bytes", window.end - window.start);
    log_word(
        "mpu frontend bytes",
        core::mem::size_of::<Frontend>() as u32,
    );
    log("MPU S140 copied four-ingress frontend ready");
}

struct Gate;
fn call<const N: u8>(a: u32, b: u32, c: u32) -> u32 {
    let result;
    unsafe {
        core::arch::asm!("svc {n}", n = const N, inout("r0") a => result, in("r1") b, in("r2") c);
    }
    result
}
impl MailboxCopyGate for Gate {
    fn submit(&mut self, descriptor: u32) -> u32 {
        call::<1>(descriptor, 0, 0)
    }
    fn receive(&mut self, descriptor: u32) -> u32 {
        call::<2>(descriptor, 0, 0)
    }
}
struct Link;
fn endpoint(kind: PeripheralEndpoint) -> u32 {
    match kind {
        PeripheralEndpoint::Hid => 0,
        PeripheralEndpoint::Ccid => 1,
        PeripheralEndpoint::Ble => 2,
    }
}
impl PeripheralLink for Link {
    fn now_ms(&mut self) -> u32 {
        call::<5>(0, 0, 0)
    }
    fn generation(&mut self, kind: PeripheralEndpoint) -> u32 {
        call::<6>(endpoint(kind), 0, 0)
    }
    fn receive(
        &mut self,
        kind: PeripheralEndpoint,
        generation: u32,
        packet: &mut CopyPacket<64>,
    ) -> bool {
        call::<7>(endpoint(kind), packet as *mut _ as u32, generation) == trusted_status::OK
    }
    fn send(&mut self, kind: PeripheralEndpoint, generation: u32, packet: &CopyPacket<64>) -> bool {
        call::<8>(endpoint(kind), packet as *const _ as u32, generation) == trusted_status::OK
    }
    fn take_ccid_abort(&mut self) -> Option<(u8, u8)> {
        let value = call::<9>(0, 0, 0);
        (value != u32::MAX).then_some((value as u8, (value >> 8) as u8))
    }
    fn uart_read(&mut self) -> UartInput {
        match call::<3>(0, 0, 0) {
            u32::MAX => UartInput::Idle,
            value if value == u32::MAX - 1 => UartInput::Lost,
            value => UartInput::Byte(value as u8),
        }
    }
    fn uart_write(&mut self, bytes: &[u8]) {
        let _ = call::<4>(bytes.as_ptr() as u32, bytes.len() as u32, 0);
    }
}
unsafe extern "C" fn user_turn(_a: u32, _b: u32) -> ! {
    unsafe {
        (*core::ptr::addr_of_mut!(USER.frontend)).step(&mut Link);
    }
    call::<0>(0, 0, 0);
    loop {
        cortex_m::asm::nop();
    }
}
/// Serialized privileged turn; exclude reentry and release private borrows before user execution.
fn pump() {
    assert!(!ACTIVE.swap(true, Ordering::AcqRel));

    unsafe {
        arm_m_thread_once::run(user_turn, stack().1, 0, 0);
    }
    assert!(!ACTIVE.load(Ordering::Acquire));
    unsafe {
        let k = kernel();
        let _ = k.worker.pump_once(&ENDPOINT);

        if let Some(usb) = k.usb.as_mut() {
            usb.pump();
        }
    }
}

/// Single BLE owner using copied packets; queue acceptance is not peer delivery.
pub(super) struct SharedBleFrontend;
impl SharedBleFrontend {
    pub(super) const fn new(_: &'static SharedArbiter) -> Self {
        Self
    }
}
impl BleFidoProfileHandler for SharedBleFrontend {
    fn on_status_subscription(&mut self, enabled: bool) {
        unsafe {
            kernel().ble.subscription(enabled);
        }
    }
    fn handle_control_point_write<const P: usize>(
        &mut self,
        bytes: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        if !unsafe { kernel().ble.push_received(bytes) } {
            return Err(BleFidoError::Busy);
        }
        pump();
        self.poll_status::<P>(sink)
    }
    fn poll_status<const P: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        pump();
        let mut count = 0;
        for _ in 0..20 {
            let Some(packet) = (unsafe { kernel().ble.peek_notification().copied() }) else {
                break;
            };
            sink.push_fragment(packet.bytes().ok_or(BleFidoError::InvalidLen)?)?;
            let _ = unsafe { kernel().ble.next_notification() };
            count += 1;
        }
        Ok(count)
    }
    fn on_disconnect(&mut self) {
        unsafe {
            kernel().ble.reset(false);
        }
        pump();
    }
}
impl SharedBleFrontend {
    pub(super) fn settle_disconnected_backend(&mut self) -> bool {
        pump();
        unsafe { (*core::ptr::addr_of!(USER.frontend)).ble_settled() }
    }
}
#[embassy_executor::task]
/// Start once with exclusive USBD/UART IRQ ownership and initialized SoftDevice power/clock services.
pub(super) async fn usb_fido_task(usbd: nrf52840_pac::USBD, _arbiter: &'static SharedArbiter) {
    unsafe {
        cortex_m::Peripherals::steal()
            .NVIC
            .set_priority(nrf52840_pac::interrupt::UARTE0_UART0, 0x40);
    }
    let enabled = unsafe {
        raw::sd_power_usbdetected_enable(1)
            | raw::sd_power_usbpwrrdy_enable(1)
            | raw::sd_power_usbremoved_enable(1)
    };
    assert_eq!(enabled, 0);
    assert_eq!(unsafe { raw::sd_clock_hfclk_request() }, 0);
    let mut ticks = nrf52840_ble_poll_tick::usb_current();
    loop {
        let mut running = 0;
        let mut power = 0;
        let ready = unsafe {
            raw::sd_clock_hfclk_is_running(&mut running) == 0
                && raw::sd_power_usbregstatus_get(&mut power) == 0
        };

        if ready && running != 0 && power & 1 != 0 {
            break;
        }
        ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
    }
    unsafe {
        kernel().usb = Some(UsbPump::new(usbd));
    }
    loop {
        ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
        pump();
    }
}

fn frame(psp: u32, exc: u32) -> *mut u32 {
    assert!(ACTIVE.load(Ordering::Acquire));
    assert_eq!(exc, arm_m_thread_once::UNPRIVILEGED_PSP_RETURN);
    let (bottom, top) = stack();
    let address = arm_m_mpu::checked_psp_frame(psp, exc, bottom + 32, top).unwrap();
    let f = address as *mut u32;
    let (pc, xpsr) = unsafe { (*f.add(6), *f.add(7)) };

    assert!((0x27002..0xe0000).contains(&pc) && pc & 1 == 0);
    assert!(xpsr & (1 << 24) != 0 && xpsr & 0x1ff == 0);
    assert!(xpsr & (1 << 9) == 0 || address + 36 <= top);
    f
}
#[unsafe(no_mangle)]
/// Privileged exception entry only; requires the initialized copied-mailbox kernel and active user turn.
extern "C" fn nrf_mpu_product_svc(psp: u32, exc: u32) -> u32 {
    let f = frame(psp, exc);
    let instr = unsafe { ((*f.add(6) - 2) as *const u16).read() };
    assert_eq!(instr & 0xff00, 0xdf00);
    let (a, b, c) = unsafe { (*f, *f.add(1), *f.add(2)) };
    if instr & 255 == 0 {
        ACTIVE.store(false, Ordering::Release);
        return arm_m_thread_once::PRIVILEGED_MSP_RETURN;
    }
    let result = unsafe {
        match instr & 255 {
            1 => copied_mailbox::submit_from_shared(shared(), a, &ENDPOINT),
            2 => copied_mailbox::receive_to_shared(shared(), a, &ENDPOINT),
            3 => {
                if internal_uart::take_overflow() {
                    u32::MAX - 1
                } else {
                    internal_uart::read().map(u32::from).unwrap_or(u32::MAX)
                }
            }
            4 if b <= (TRUSTED_RESPONSE_MAX + 32) as u32 && checked(a, b, 1) => {
                internal_uart::write(core::slice::from_raw_parts(a as *const u8, b as usize));
                trusted_status::OK
            }
            5 => nrf52840_ble_poll_tick::usb_current(),
            6 => match a {
                0 | 1 => kernel().usb.as_ref().map_or(0, |usb| usb.generation()),
                2 => kernel().ble.generation(),
                _ => 0,
            },
            7 if checked(b, core::mem::size_of::<CopyPacket<64>>() as u32, 4) => {
                let k = kernel();
                let packet = match a {
                    0 if k.usb.as_ref().is_some_and(|u| u.generation() == c) => k
                        .usb
                        .as_mut()
                        .and_then(|u| u.receive())
                        .map(|report| CopyPacket {
                            len: 64,
                            data: report,
                        }),
                    1 if k.usb.as_ref().is_some_and(|u| u.generation() == c) => {
                        k.usb.as_mut().and_then(|u| u.receive_ccid())
                    }
                    2 => k.ble.receive(c),
                    _ => None,
                };
                if let Some(packet) = packet {
                    (b as *mut CopyPacket<64>).write(packet);
                    trusted_status::OK
                } else {
                    trusted_status::BUSY
                }
            }
            8 if checked(b, core::mem::size_of::<CopyPacket<64>>() as u32, 4) => {
                let packet = (b as *const CopyPacket<64>).read();
                let k = kernel();
                if packet.bytes().is_none() {
                    trusted_status::INVALID_REQUEST
                } else {
                    match a {
                        0 if packet.len == 64
                            && k.usb.as_ref().is_some_and(|u| u.generation() == c) =>
                        {
                            k.usb.as_mut().unwrap().send(packet.data)
                        }
                        1 if k.usb.as_ref().is_some_and(|u| u.generation() == c) => {
                            k.usb.as_mut().unwrap().send_ccid(packet)
                        }
                        2 if k.ble.send(c, packet) => trusted_status::OK,
                        _ => trusted_status::BUSY,
                    }
                }
            }
            9 => kernel().usb.as_mut().map_or(u32::MAX, |u| u.take_abort()),

            15 => fatal(),
            _ => trusted_status::INVALID_OPERATION,
        }
    };
    unsafe {
        f.write(result);
    }

    exc
}
pub(super) fn fatal() -> ! {
    super::LED.fault_latch()
}
#[unsafe(no_mangle)]
extern "C" fn nrf_mpu_product_fault(psp: u32, exc: u32) {
    fatal()
}
global_asm!(
    r#"
    .section .text.SVCall
    .global SVCall
    .type SVCall,%function
    .thumb_func
SVCall:
    tst lr,#4
    beq 1f
    mrs r0,psp
    mov r1,lr
    push {{r3,lr}}
    bl nrf_mpu_product_svc
    pop {{r3,lr}}
    movw r1,#0xfff9
    movt r1,#0xffff
    cmp r0,r1
    bne 2f
    movs r1,#0
    msr control,r1
    isb
2:  mov lr,r0
    bx lr
1:  mrs r12,msp
    tst lr,#0x10
    it eq
    addeq r12,r12,#72
    ldr r12,[r12,#24]
    subs r12,r12,#2
    ldrh r12,[r12]
    uxtb r12,r12
    cmp r12,#24
    beq 3f
    movw r12,#0x102c
    movt r12,#0
    ldr r12,[r12]
    bx r12
3:  movw r12,#0x002c
    movt r12,#0
    ldr r12,[r12]
    bx r12
    .section .text.MemoryManagement
    .global MemoryManagement
    .type MemoryManagement,%function
    .thumb_func
MemoryManagement:
    mrs r0,psp
    mov r1,lr
    b nrf_mpu_product_fault
    .section .text.BusFault
    .global BusFault
    .type BusFault,%function
    .thumb_func
BusFault:
    mrs r0,psp
    mov r1,lr
    b nrf_mpu_product_fault
"#
);
