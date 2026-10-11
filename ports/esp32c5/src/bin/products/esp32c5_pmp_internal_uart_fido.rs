#![no_std]
#![no_main]

#[cfg(feature = "ble")]
compile_error!("bare PMP product must not link BLE/RTOS");

use core::{
    arch::{asm, global_asm},
    mem::MaybeUninit,
    sync::atomic::{AtomicU32, Ordering},
};

use esp_backtrace as _;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    main,
    uart::{Config as UartConfig, Uart},
};
use esp_println::println;

use esp32c5::{
    adc_entropy::C5AdcEntropy,
    client_pin::{SharedEspShaPeripheral, new_shared_sha_peripheral},
    fido::{EspPmpUiTrustedDispatcher, build_pmp_internal_dispatcher_from_shared_flash},
    pmp_boundary::{self, BoundaryLayout, TorRegion},
    pmp_monitor, pmp_runtime,
    status_pixel::BlockingStatusPixel,
    storage::{SharedEspFlash, new_shared_esp_flash},
};
use manekey::{
    boundary::{
        riscv_ecall::RiscvPmpEcallBackend,
        riscv_event_mailbox::{RiscvUserEvent, RiscvUserEventMailbox},
        riscv_pmp::{TRUSTED_CALL_ECALL_ID, USER_EVENT_RETURN_ECALL_ID},
    },
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    security::trusted_status,
};

esp_bootloader_esp_idf::esp_app_desc!();

const UART_REQUEST_FRAME_MAX: usize = 1040;
const UART_RESPONSE_MAX: usize = 4096;
const C5_PMP_USER_STACK_SIZE: usize = 32 * 1024;
#[cfg(feature = "pmp-internal-uart-ml-dsa-fips204")]
const C5_PMP_MACHINE_TRAP_STACK_SIZE: usize = 192 * 1024;
#[cfg(feature = "pmp-internal-uart-ml-dsa-fips204-scratch")]
const C5_PMP_MACHINE_TRAP_STACK_SIZE: usize = 128 * 1024;
#[cfg(not(any(
    feature = "pmp-internal-uart-ml-dsa-fips204",
    feature = "pmp-internal-uart-ml-dsa-fips204-scratch"
)))]
const C5_PMP_MACHINE_TRAP_STACK_SIZE: usize = 96 * 1024;

#[repr(align(32))]
struct PmpStack<const SIZE: usize>([u8; SIZE]);

#[unsafe(link_section = ".c5_pmp_machine_private")]
#[unsafe(no_mangle)]
static mut TRUSTED_DISPATCHER: MaybeUninit<EspPmpUiTrustedDispatcher<BlockingStatusPixel>> =
    MaybeUninit::uninit();
#[unsafe(link_section = ".c5_pmp_machine_private")]
static mut PMP_SHARED_FLASH: MaybeUninit<SharedEspFlash<'static>> = MaybeUninit::uninit();
#[unsafe(link_section = ".c5_pmp_machine_private")]
static mut PMP_SHARED_SHA: MaybeUninit<SharedEspShaPeripheral> = MaybeUninit::uninit();
#[unsafe(link_section = ".c5_pmp_machine_private")]
static mut MACHINE_UART: MaybeUninit<Uart<'static, Blocking>> = MaybeUninit::uninit();
#[unsafe(link_section = ".c5_pmp_machine_private")]
#[unsafe(no_mangle)]
static C5_PMP_M_RETURN_SP: AtomicU32 = AtomicU32::new(0);
#[unsafe(link_section = ".c5_pmp_machine_private")]
#[unsafe(no_mangle)]
static C5_PMP_MACHINE_TRAP_TOP: AtomicU32 = AtomicU32::new(0);
#[unsafe(link_section = ".c5_pmp_machine_private")]
#[unsafe(no_mangle)]
static C5_PMP_UNEXPECTED_MCAUSE: AtomicU32 = AtomicU32::new(0);
#[unsafe(link_section = ".c5_pmp_machine_private")]
#[unsafe(no_mangle)]
static C5_PMP_UNEXPECTED_MEPC: AtomicU32 = AtomicU32::new(0);

#[unsafe(link_section = ".c5_pmp_machine_trap_stack")]
static mut C5_PMP_MACHINE_TRAP_STACK: PmpStack<C5_PMP_MACHINE_TRAP_STACK_SIZE> =
    PmpStack([0; C5_PMP_MACHINE_TRAP_STACK_SIZE]);

#[unsafe(link_section = ".c5_pmp_user_stack")]
static mut C5_PMP_USER_STACK: PmpStack<C5_PMP_USER_STACK_SIZE> =
    PmpStack([0; C5_PMP_USER_STACK_SIZE]);
#[unsafe(link_section = ".c5_pmp_product_shared")]
static mut USER_FRONTEND: InterconnectCtap2Frontend<UART_REQUEST_FRAME_MAX> =
    InterconnectCtap2Frontend::new(0);
#[unsafe(link_section = ".c5_pmp_product_shared")]
static mut USER_ARBITER: IngressArbiter<RiscvPmpEcallBackend> =
    IngressArbiter::new(RiscvPmpEcallBackend::manekey());
#[unsafe(link_section = ".c5_pmp_product_shared")]
#[unsafe(no_mangle)]
static USER_MAILBOX: RiscvUserEventMailbox<UART_RESPONSE_MAX> = RiscvUserEventMailbox::new();

global_asm!(
    r#"
    .section .text.c5_pmp_internal_trap, "ax"
    .balign 256
    .global c5_pmp_internal_trap_entry
c5_pmp_internal_trap_entry:
    csrr t0, mcause
    li t1, 0x80000fff
    and t0, t0, t1
    li t1, 8
    bne t0, t1, 4f

    csrrw sp, mscratch, sp
    li t1, 0x504dec10
    beq a0, t1, 2f
    li t1, 0x504dec22
    beq a0, t1, 3f
    j 4f
2:
    addi sp, sp, -16
    sw ra, 12(sp)
    mv a0, a1
    call c5_pmp_internal_trusted_call
    lw ra, 12(sp)
    addi sp, sp, 16
    csrrw sp, mscratch, sp
    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0
    mret
3:
    la t0, C5_PMP_M_RETURN_SP
    lw t1, 0(t0)
    la t0, C5_PMP_MACHINE_TRAP_TOP
    lw t2, 0(t0)
    csrw mscratch, t2
    la t0, c5_pmp_internal_after_user
    csrw mepc, t0
    li t0, 0x1800
    csrs mstatus, t0
    mv sp, t1
    mret
4:
    csrr t2, mcause
    csrr t3, mepc
    la t0, C5_PMP_UNEXPECTED_MCAUSE
    sw t2, 0(t0)
    la t0, C5_PMP_UNEXPECTED_MEPC
    sw t3, 0(t0)
    csrr t2, mstatus
    li t3, 0x1800
    and t2, t2, t3
    bnez t2, 5f
    la t0, USER_MAILBOX
    li t1, 7
    sw t1, 4(t0)
    sw zero, 8(t0)
    j 3b
5:
    # A fault in the trusted M handler cannot resume the untrusted event loop.
    csrci mstatus, 8
    wfi
    j 5b

    .section .text.c5_pmp_internal_after_user, "ax"
    .global c5_pmp_internal_after_user
c5_pmp_internal_after_user:
    tail c5_pmp_internal_after_user_rust

"#
);

unsafe extern "C" {
    fn c5_pmp_internal_trap_entry();

    static __c5_pmp_user_text_start: u8;
    static __c5_pmp_user_text_end: u8;
    static __c5_pmp_product_shared_start: u8;
    static __c5_pmp_product_shared_end: u8;
    static __c5_pmp_user_stack_start: u8;
    static __c5_pmp_user_stack_end: u8;
    static __c5_pmp_machine_private_start: u8;
    static __c5_pmp_machine_private_end: u8;
}

#[main]
/// BLE-less PMP product with experimental ADC entropy; excludes IRQ/DMA from the boundary claim.
/// Reinitialize reserved NOLOAD state each boot and preserve exclusive event ownership.
/// Physical peripherals and crypto remain M-mode-owned; UART writes are not peer delivery acknowledgment.
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    let entropy = manekey::ctaphid::entropy::HmacDrbgEntropy::new(
        C5AdcEntropy::new(peripherals.ADC1).expect("C5 ADC entropy configuration"),
    )
    .expect("C5 ADC entropy DRBG startup health");
    println!("C5 ADC entropy configured; ADC1 reserved, RF/RTOS absent");
    let (flash, sha) = unsafe {
        (&raw mut PMP_SHARED_FLASH)
            .write(MaybeUninit::new(new_shared_esp_flash(peripherals.FLASH)));
        (&raw mut PMP_SHARED_SHA)
            .write(MaybeUninit::new(new_shared_sha_peripheral(peripherals.SHA)));
        (
            (&raw const PMP_SHARED_FLASH)
                .cast::<SharedEspFlash<'static>>()
                .as_ref()
                .unwrap(),
            (&raw const PMP_SHARED_SHA)
                .cast::<SharedEspShaPeripheral>()
                .as_ref()
                .unwrap(),
        )
    };
    let dispatcher = build_pmp_internal_dispatcher_from_shared_flash(
        flash,
        peripherals.GPIO28,
        sha,
        peripherals.AES,
        BlockingStatusPixel::new(peripherals.RMT, peripherals.GPIO27),
        entropy,
    );
    let uart = Uart::new(
        peripherals.UART0,
        UartConfig::default().with_baudrate(115_200),
    )
    .expect("UART0 configuration")
    .with_tx(peripherals.GPIO11)
    .with_rx(peripherals.GPIO12);

    unsafe {
        (&raw mut TRUSTED_DISPATCHER).write(MaybeUninit::new(dispatcher));
        (&raw mut MACHINE_UART).write(MaybeUninit::new(uart));

        C5_PMP_M_RETURN_SP.store(0, Ordering::Release);
        C5_PMP_UNEXPECTED_MCAUSE.store(0, Ordering::Release);
        C5_PMP_UNEXPECTED_MEPC.store(0, Ordering::Release);

        pmp_runtime::install_machine_trap_stack(
            (&raw mut C5_PMP_MACHINE_TRAP_STACK.0).cast(),
            C5_PMP_MACHINE_TRAP_STACK_SIZE,
        );
        C5_PMP_MACHINE_TRAP_TOP.store(
            (&raw const C5_PMP_MACHINE_TRAP_STACK.0).cast::<u8>().addr() as u32
                + C5_PMP_MACHINE_TRAP_STACK_SIZE as u32,
            Ordering::Release,
        );
        pmp_runtime::install_direct_trap_vector(c5_pmp_internal_trap_entry as *const () as usize);
        let boundary = c5_boundary_layout();
        let user_stack = c5_user_stack_region();
        assert!(pmp_boundary::ecall_island_layout(boundary, user_stack).is_some());
        assert!(
            pmp_boundary::configure_ree0_sram_rw(),
            "C5 CPU_APM REE0 SRAM access"
        );
        pmp_boundary::install_product(boundary, user_stack);
    }
    println!("MANEKEY C5 PMP InternalTransport UART product");
    println!("M UART0=GPIO11 TX/GPIO12 RX; U=MK decoder/ingress; BLE/RTOS absent");
    println!("ecall=0x{TRUSTED_CALL_ECALL_ID:08x} return=0x{USER_EVENT_RETURN_ECALL_ID:08x}");

    start_machine_runtime()
}

#[unsafe(no_mangle)]
extern "C" fn c5_pmp_internal_machine_loop() -> ! {
    let uart = unsafe {
        (&raw mut MACHINE_UART)
            .cast::<Uart<'static, Blocking>>()
            .as_mut()
    }
    .expect("M-mode UART initialized");
    loop {
        flush_response(uart);
        let mut input = [0u8; 1];
        if uart.read(&mut input).is_err() {
            continue;
        }
        USER_MAILBOX.begin_input(input[0]);
        unsafe {
            let top = (&raw const C5_PMP_USER_STACK.0).cast::<u8>().addr() + C5_PMP_USER_STACK_SIZE;
            pmp_runtime::enter_user_mode(
                c5_pmp_internal_user_process_byte as *const () as usize,
                top,
            );
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn c5_pmp_internal_after_user_rust() -> ! {
    let cause = C5_PMP_UNEXPECTED_MCAUSE.swap(0, Ordering::AcqRel);

    if cause != 0 {
        let mepc = C5_PMP_UNEXPECTED_MEPC.swap(0, Ordering::AcqRel);
        println!("C5 PMP U trap mcause=0x{cause:08x} mepc=0x{mepc:08x}");
    }
    c5_pmp_internal_machine_loop()
}

fn start_machine_runtime() -> ! {
    let _ = C5_PMP_M_RETURN_SP.compare_exchange(
        0,
        current_stack_pointer(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    c5_pmp_internal_machine_loop()
}

fn flush_response(uart: &mut Uart<'static, Blocking>) {
    let len = USER_MAILBOX.take_response_len();
    if len == 0 {
        return;
    }
    let trap_stack = unsafe {
        manekey::boundary::pmp_stack::MachineTrapStack::new(
            (&raw mut C5_PMP_MACHINE_TRAP_STACK.0).cast(),
            C5_PMP_MACHINE_TRAP_STACK_SIZE,
            pmp_runtime::MACHINE_TRAP_STACK_GUARD_WORDS,
        )
    };
    assert!(trap_stack.guard_ok(), "C5 M trap stack guard corrupted");

    let response = unsafe { USER_MAILBOX.response() };
    let mut sent = 0;
    while sent < len {
        match uart.write(&response[sent..len]) {
            Ok(0) | Err(_) => return,
            Ok(written) => sent += written,
        }
    }
    let _ = uart.flush();
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".c5_pmp_user_text")]
/// Process the current shared input event.
///
/// # Safety
/// Enter only after initialization with the installed U-mode policy and stack; exclusively own shared state until the return ecall.
unsafe extern "C" fn c5_pmp_internal_user_process_byte() -> ! {
    let frontend = unsafe { (&raw mut USER_FRONTEND).as_mut() }.unwrap();
    let arbiter = unsafe { (&raw mut USER_ARBITER).as_mut() }.unwrap();
    let output = unsafe { USER_MAILBOX.response_mut() };
    let (event, len) = match frontend.push_byte(arbiter, USER_MAILBOX.input_byte(), output) {
        Ok(None) | Ok(Some(InterconnectCtap2Outcome::NoResponse)) => {
            (RiscvUserEvent::NoResponse, 0)
        }
        Ok(Some(InterconnectCtap2Outcome::Response { len })) => (RiscvUserEvent::Response, len),
        Ok(Some(InterconnectCtap2Outcome::UserPresencePending)) => {
            (RiscvUserEvent::UserPresencePending, 0)
        }
        Ok(Some(InterconnectCtap2Outcome::Busy)) => (RiscvUserEvent::Busy, 0),
        Ok(Some(InterconnectCtap2Outcome::InvalidRequest)) => (RiscvUserEvent::InvalidRequest, 0),
        Ok(Some(InterconnectCtap2Outcome::CancelAccepted)) => (RiscvUserEvent::Cancelled, 0),
        Ok(Some(InterconnectCtap2Outcome::LinkClosed)) => (RiscvUserEvent::LinkClosed, 0),
        Err(_) => (RiscvUserEvent::FrameError, 0),
    };
    USER_MAILBOX.publish(event, len);
    unsafe {
        asm!("li a0, {id}", "ecall", id = const USER_EVENT_RETURN_ECALL_ID, options(noreturn))
    }
}

#[unsafe(no_mangle)]
extern "C" fn c5_pmp_internal_trusted_call(descriptor_ptr: u32) -> u32 {
    let dispatcher = unsafe {
        (&raw mut TRUSTED_DISPATCHER)
            .cast::<EspPmpUiTrustedDispatcher<BlockingStatusPixel>>()
            .as_mut()
    };
    let Some(dispatcher) = dispatcher else {
        return trusted_status::BUSY;
    };
    unsafe { pmp_monitor::dispatch_from_shared(shared_memory_region(), descriptor_ptr, dispatcher) }
}

fn c5_boundary_layout() -> BoundaryLayout {
    BoundaryLayout {
        machine_private: TorRegion {
            start: (&raw const __c5_pmp_machine_private_start) as usize,
            end: (&raw const __c5_pmp_machine_private_end) as usize,
        },
        shared: TorRegion {
            start: (&raw const __c5_pmp_product_shared_start) as usize,
            end: (&raw const __c5_pmp_product_shared_end) as usize,
        },
        user_text: TorRegion {
            start: (&raw const __c5_pmp_user_text_start) as usize,
            end: (&raw const __c5_pmp_user_text_end) as usize,
        },
    }
}

fn c5_user_stack_region() -> TorRegion {
    TorRegion {
        start: (&raw const __c5_pmp_user_stack_start) as usize,
        end: (&raw const __c5_pmp_user_stack_end) as usize,
    }
}

fn shared_memory_region() -> manekey::security::SharedMemoryRegion {
    pmp_monitor::shared_memory_region(
        (&raw const __c5_pmp_product_shared_start).cast(),
        (&raw const __c5_pmp_product_shared_end).cast(),
    )
}

fn current_stack_pointer() -> u32 {
    let stack_pointer: usize;
    unsafe {
        asm!("mv {stack_pointer}, sp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack));
    }
    stack_pointer as u32
}
