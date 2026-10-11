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
    gpio::{Level, Output},
    main,
    rng::TrngSource,
    uart::{Config as UartConfig, Uart},
};
use esp_println::println;
use esp32c6::{
    client_pin::{SharedEspShaPeripheral, new_shared_sha_peripheral},
    fido::{EspPmpUiTrustedDispatcher, build_pmp_internal_dispatcher_from_shared_flash},
    pmp_boundary::{self, BoundaryLayout, TorRegion},
    pmp_monitor, pmp_runtime,
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
    user_interface::TouchPromptLed,
};

esp_bootloader_esp_idf::esp_app_desc!();

const UART_REQUEST_FRAME_MAX: usize = 1040;

const UART_RESPONSE_MAX: usize = 4096;

const C6_PMP_USER_STACK_SIZE: usize = 32 * 1024;

const C6_PMP_MACHINE_TRAP_STACK_SIZE: usize = 192 * 1024;

#[repr(align(32))]
struct PmpStack<const SIZE: usize>([u8; SIZE]);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut TRUSTED_DISPATCHER: MaybeUninit<EspPmpUiTrustedDispatcher<TouchPromptLed>> =
    MaybeUninit::uninit();
#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut PMP_SHARED_FLASH: MaybeUninit<SharedEspFlash<'static>> = MaybeUninit::uninit();
#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut PMP_SHARED_SHA: MaybeUninit<SharedEspShaPeripheral> = MaybeUninit::uninit();
#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut MACHINE_STATUS_LED: MaybeUninit<Output<'static>> = MaybeUninit::uninit();
#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut MACHINE_UART: MaybeUninit<Uart<'static, Blocking>> = MaybeUninit::uninit();
#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_machine_private")]
static C6_PMP_M_RETURN_SP: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_machine_private")]
static C6_PMP_MACHINE_TRAP_TOP: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_machine_private")]
static C6_PMP_UNEXPECTED_MCAUSE: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_machine_private")]
static C6_PMP_UNEXPECTED_MEPC: AtomicU32 = AtomicU32::new(0);

#[unsafe(link_section = ".c6_pmp_machine_trap_stack")]
static mut C6_PMP_MACHINE_TRAP_STACK: PmpStack<C6_PMP_MACHINE_TRAP_STACK_SIZE> =
    PmpStack([0; C6_PMP_MACHINE_TRAP_STACK_SIZE]);

#[unsafe(link_section = ".c6_pmp_user_stack")]
static mut C6_PMP_USER_STACK: PmpStack<C6_PMP_USER_STACK_SIZE> =
    PmpStack([0; C6_PMP_USER_STACK_SIZE]);
#[unsafe(link_section = ".c6_pmp_shared")]
static mut USER_FRONTEND: InterconnectCtap2Frontend<UART_REQUEST_FRAME_MAX> =
    InterconnectCtap2Frontend::new(0);
#[unsafe(link_section = ".c6_pmp_shared")]
static mut USER_ARBITER: IngressArbiter<RiscvPmpEcallBackend> =
    IngressArbiter::new(RiscvPmpEcallBackend::manekey());
#[unsafe(link_section = ".c6_pmp_shared")]
#[unsafe(no_mangle)]
static USER_MAILBOX: RiscvUserEventMailbox<UART_RESPONSE_MAX> = RiscvUserEventMailbox::new();

fn set_status_led(active: bool) {
    let led = unsafe {
        (&raw mut MACHINE_STATUS_LED)
            .cast::<Output<'static>>()
            .as_mut()
    };
    if let Some(led) = led {
        led.set_level(if active { Level::Low } else { Level::High });
    }
}

fn status_led_on() {
    set_status_led(true);
}

fn status_led_off() {
    set_status_led(false);
}

global_asm!(
    r#"
    .section .text.c6_pmp_internal_trap, "ax"
    .balign 256
    .global c6_pmp_internal_trap_entry
    .type c6_pmp_internal_trap_entry, @function
c6_pmp_internal_trap_entry:
    csrr t0, mcause
    li t1, 8
    bne t0, t1, 4f

    # Switch before invoking any trusted Rust. mscratch holds the dedicated
    # M-mode trap stack between U-mode entries and receives the U stack here.
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
    call c6_pmp_internal_trusted_call
    lw ra, 12(sp)
    addi sp, sp, 16
    csrrw sp, mscratch, sp
    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0
    mret

3:
    # The U-mode event is complete. Resume a fresh M-mode UART loop with its
    # saved normal stack; do not run that loop on the bounded trap stack.
    la t0, C6_PMP_M_RETURN_SP
    lw t1, 0(t0)
    la t0, C6_PMP_MACHINE_TRAP_TOP
    lw t2, 0(t0)
    csrw mscratch, t2
    la t0, c6_pmp_internal_after_user
    csrw mepc, t0
    li t0, 0x1800
    csrs mstatus, t0
    mv sp, t1
    mret

4:
    # A user fault must not leave the physical UART owner stuck on the trap
    # stack. Record only architectural diagnostics, then terminate this input
    # event through the same M-mode return path as a normal completion.
    csrr t2, mcause
    csrr t3, mepc
    la t0, C6_PMP_UNEXPECTED_MCAUSE
    sw t2, 0(t0)
    la t0, C6_PMP_UNEXPECTED_MEPC
    sw t3, 0(t0)
    la t0, USER_MAILBOX
    li t1, 8
    sw t1, 4(t0)
    sw zero, 8(t0)
    j 3b

    .section .text.c6_pmp_internal_after_user, "ax"
    .global c6_pmp_internal_after_user
    .type c6_pmp_internal_after_user, @function
c6_pmp_internal_after_user:
    tail c6_pmp_internal_after_user_rust
"#
);

unsafe extern "C" {
    fn c6_pmp_internal_trap_entry();

    static __c6_pmp_user_text_start: u8;
    static __c6_pmp_user_text_end: u8;
    static __c6_pmp_shared_start: u8;
    static __c6_pmp_shared_end: u8;
    static __c6_pmp_user_stack_start: u8;
    static __c6_pmp_user_stack_end: u8;
    static __c6_pmp_machine_private_start: u8;
    static __c6_pmp_machine_private_end: u8;
}

#[main]
/// BLE-less PMP product; M-mode owns physical peripherals, crypto and trap stack.
/// Reinitialize reserved NOLOAD state on every boot and preserve exclusive event ownership.
/// UART writes are not peer delivery acknowledgment.
fn main() -> ! {
    C6_PMP_M_RETURN_SP.store(0, Ordering::Release);
    C6_PMP_UNEXPECTED_MCAUSE.store(0, Ordering::Release);
    C6_PMP_UNEXPECTED_MEPC.store(0, Ordering::Release);
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let (shared_flash, shared_sha) = unsafe {
        (&raw mut PMP_SHARED_FLASH)
            .write(MaybeUninit::new(new_shared_esp_flash(peripherals.FLASH)));
        (&raw mut PMP_SHARED_SHA)
            .write(MaybeUninit::new(new_shared_sha_peripheral(peripherals.SHA)));
        (
            (&raw const PMP_SHARED_FLASH)
                .cast::<SharedEspFlash<'static>>()
                .as_ref()
                .expect("M-mode flash state"),
            (&raw const PMP_SHARED_SHA)
                .cast::<SharedEspShaPeripheral>()
                .as_ref()
                .expect("M-mode SHA state"),
        )
    };
    unsafe {
        (&raw mut MACHINE_STATUS_LED).write(MaybeUninit::new(Output::new(
            peripherals.GPIO15,
            Level::High,
            Default::default(),
        )));
    }
    let dispatcher = build_pmp_internal_dispatcher_from_shared_flash(
        shared_flash,
        peripherals.GPIO2,
        peripherals.AES,
        peripherals.ECC,
        shared_sha,
        TouchPromptLed::new(status_led_on, status_led_off),
    );
    let uart = Uart::new(
        peripherals.UART0,
        UartConfig::default().with_baudrate(115_200),
    )
    .expect("UART0 configuration")
    .with_tx(peripherals.GPIO16)
    .with_rx(peripherals.GPIO17);

    unsafe {
        (&raw mut TRUSTED_DISPATCHER).write(MaybeUninit::new(dispatcher));
        (&raw mut MACHINE_UART).write(MaybeUninit::new(uart));
        pmp_runtime::install_machine_trap_stack(
            (&raw mut C6_PMP_MACHINE_TRAP_STACK.0).cast(),
            C6_PMP_MACHINE_TRAP_STACK_SIZE,
        );
        C6_PMP_MACHINE_TRAP_TOP.store(
            (&raw const C6_PMP_MACHINE_TRAP_STACK.0).cast::<u8>().addr() as u32
                + C6_PMP_MACHINE_TRAP_STACK_SIZE as u32,
            Ordering::Release,
        );
        pmp_runtime::install_direct_trap_vector(c6_pmp_internal_trap_entry as *const () as usize);
        let boundary = c6_boundary_layout();
        let user_stack = c6_user_stack_region();
        assert!(
            pmp_boundary::ecall_island_layout(boundary, user_stack).is_some(),
            "invalid C6 PMP linker layout"
        );
        pmp_boundary::install_product(boundary, user_stack);
    }

    println!("MANEKEY C6 PMP InternalTransport UART product");
    println!("M UART=D6/GPIO16 TX,D7/GPIO17 RX; U=MK CTAP2 decoder/ingress");
    println!(
        "trusted ecall=0x{TRUSTED_CALL_ECALL_ID:08x} return ecall=0x{USER_EVENT_RETURN_ECALL_ID:08x}"
    );
    println!("PMP product boundary installed; U RAM=shared+stack, UART MMIO=M-mode");

    start_machine_runtime()
}

fn start_machine_runtime() -> ! {
    let _ = C6_PMP_M_RETURN_SP.compare_exchange(
        0,
        current_stack_pointer(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    c6_pmp_internal_machine_loop()
}

#[unsafe(no_mangle)]
extern "C" fn c6_pmp_internal_machine_loop() -> ! {
    let uart = unsafe {
        (&raw mut MACHINE_UART)
            .cast::<Uart<'static, Blocking>>()
            .as_mut()
    }
    .expect("M-mode UART initialized");
    loop {
        flush_user_response(uart);
        let mut input = [0_u8; 1];
        if uart.read(&mut input).is_err() {
            continue;
        }
        USER_MAILBOX.begin_input(input[0]);
        unsafe {
            let user_stack_top =
                (&raw const C6_PMP_USER_STACK.0).cast::<u8>().addr() + C6_PMP_USER_STACK_SIZE;
            pmp_runtime::enter_user_mode(
                c6_pmp_internal_user_process_byte as *const () as usize,
                user_stack_top,
            );
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn c6_pmp_internal_after_user_rust() -> ! {
    let mcause = C6_PMP_UNEXPECTED_MCAUSE.swap(0, Ordering::AcqRel);

    if mcause != 0 {
        let mepc = C6_PMP_UNEXPECTED_MEPC.swap(0, Ordering::AcqRel);
        println!("PMP user trap: mcause=0x{mcause:08x} mepc=0x{mepc:08x}");
    }
    c6_pmp_internal_machine_loop()
}

fn flush_user_response(uart: &mut Uart<'static, Blocking>) {
    let response_len = USER_MAILBOX.take_response_len();
    if response_len == 0 {
        return;
    }
    #[cfg(feature = "flash-managed-keys")]
    {
        let stack = unsafe {
            pmp_runtime::machine_trap_stack(
                (&raw mut C6_PMP_MACHINE_TRAP_STACK.0).cast(),
                C6_PMP_MACHINE_TRAP_STACK_SIZE,
            )
        };
        assert!(stack.guard_ok(), "C6 M trap stack guard corrupted");
    }
    let response = unsafe { USER_MAILBOX.response() };
    let mut sent = 0;
    let mut write_ok = true;
    while sent < response_len {
        match uart.write(&response[sent..response_len]) {
            Ok(0) | Err(_) => {
                write_ok = false;
                break;
            }
            Ok(written) => sent += written,
        }
    }
    if write_ok && sent == response_len {
        let _ = uart.flush();
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".c6_pmp_user_text")]
/// Process the current shared input event.
///
/// # Safety
/// Enter only after initialization with the installed U-mode policy and stack; exclusively own shared state until the return ecall.
unsafe extern "C" fn c6_pmp_internal_user_process_byte() -> ! {
    let byte = USER_MAILBOX.input_byte();
    let frontend = unsafe { (&raw mut USER_FRONTEND).as_mut() }.expect("shared frontend");
    let arbiter = unsafe { (&raw mut USER_ARBITER).as_mut() }.expect("shared arbiter");
    let output = unsafe { USER_MAILBOX.response_mut() };

    let outcome = frontend.push_byte(arbiter, byte, output);
    let (event, response_len) = match outcome {
        Ok(None) => (RiscvUserEvent::NoResponse, 0),
        Ok(Some(InterconnectCtap2Outcome::Response { len })) => (RiscvUserEvent::Response, len),
        Ok(Some(InterconnectCtap2Outcome::UserPresencePending)) => {
            (RiscvUserEvent::UserPresencePending, 0)
        }
        Ok(Some(InterconnectCtap2Outcome::Busy)) => (RiscvUserEvent::Busy, 0),
        Ok(Some(InterconnectCtap2Outcome::InvalidRequest)) => (RiscvUserEvent::InvalidRequest, 0),
        Ok(Some(InterconnectCtap2Outcome::CancelAccepted)) => (RiscvUserEvent::Cancelled, 0),
        Ok(Some(InterconnectCtap2Outcome::NoResponse)) => (RiscvUserEvent::NoResponse, 0),
        Ok(Some(InterconnectCtap2Outcome::LinkClosed)) => (RiscvUserEvent::LinkClosed, 0),
        Err(_) => (RiscvUserEvent::FrameError, 0),
    };
    USER_MAILBOX.publish(event, response_len);
    unsafe {
        asm!(
            "li a0, {return_id}",
            "ecall",
            return_id = const USER_EVENT_RETURN_ECALL_ID,
            options(noreturn),
        );
    }
}

#[unsafe(no_mangle)]
extern "C" fn c6_pmp_internal_trusted_call(descriptor_ptr: u32) -> u32 {
    let dispatcher = unsafe {
        (&raw mut TRUSTED_DISPATCHER)
            .cast::<EspPmpUiTrustedDispatcher<TouchPromptLed>>()
            .as_mut()
    };
    let Some(dispatcher) = dispatcher else {
        return trusted_status::BUSY;
    };
    unsafe { pmp_monitor::dispatch_from_shared(shared_memory_region(), descriptor_ptr, dispatcher) }
}

fn c6_boundary_layout() -> BoundaryLayout {
    BoundaryLayout {
        machine_private: TorRegion {
            start: (&raw const __c6_pmp_machine_private_start) as usize,
            end: (&raw const __c6_pmp_machine_private_end) as usize,
        },
        shared: TorRegion {
            start: (&raw const __c6_pmp_shared_start) as usize,
            end: (&raw const __c6_pmp_shared_end) as usize,
        },
        user_text: TorRegion {
            start: (&raw const __c6_pmp_user_text_start) as usize,
            end: (&raw const __c6_pmp_user_text_end) as usize,
        },
    }
}

fn c6_user_stack_region() -> TorRegion {
    TorRegion {
        start: (&raw const __c6_pmp_user_stack_start) as usize,
        end: (&raw const __c6_pmp_user_stack_end) as usize,
    }
}

fn shared_memory_region() -> manekey::security::SharedMemoryRegion {
    pmp_monitor::shared_memory_region(
        (&raw const __c6_pmp_shared_start).cast(),
        (&raw const __c6_pmp_shared_end).cast(),
    )
}

fn current_stack_pointer() -> u32 {
    let stack_pointer: usize;
    unsafe {
        asm!("mv {stack_pointer}, sp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack));
    }
    stack_pointer as u32
}
