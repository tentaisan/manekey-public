#![no_std]
#![no_main]

/* CYW43 initialization and advertising follow TrouBLE examples; Copyright (c) Embassy project contributors.
 * Comparison snapshot: trouble-host b6043f576b482d8a4ecd7d2634df48cba20bd7ba; see RP NOTICE for source paths.
 * Timer queue scheduling follows Embassy RP time_driver.rs, comparison snapshot 0af1937a5ac77f52fea943b677088c38ef9e91c6.
 * Original portions: MIT OR Apache-2.0; see vendor/cyw43-portable/LICENSE-MIT and LICENSE-APACHE.
 * Modified for descriptor-backed PIO, checked ecalls, shared ingress and monitor timer generations.
 */

use core::arch::global_asm;
#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
use core::cell::RefCell;
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use core::future::Future;
use core::panic::PanicInfo;
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use core::pin::Pin;
#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
use core::sync::atomic::AtomicU32;
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use cyw43_riscv::aligned_bytes;
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
extern crate cyw43_riscv as cyw43;
#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
use critical_section::Mutex;
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use embassy_futures::join::join;
#[cfg(feature = "riscv-pmp-ble-user-advertise-runtime")]
use embassy_futures::join::join3;
#[cfg(all(
    feature = "riscv-pmp-ble-user-hci-runtime",
    not(feature = "riscv-pmp-ble-user-advertise-runtime")
))]
use embassy_futures::select::{Either, select};
#[cfg(feature = "riscv-pmp-ble-user-security")]
use embassy_time::{Duration, Instant};
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use embassy_time_driver::Driver;
#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
use embassy_time_queue_utils::Queue;
#[cfg(not(feature = "riscv-pmp-ble-user-runner-runtime"))]
use embedded_hal::digital::OutputPin;
#[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
use manekey::boundary::riscv_ecall::RiscvPmpEcallBackend;
use manekey::boundary::riscv_pmp::BLE_SPLIT_ENTRY_ECALL_ID;

use manekey::boundary::riscv_pmp::BLE_SPLIT_ENTRY_EXPECTED_MASK;
#[cfg(feature = "riscv-pmp-ble-user-hci-runtime")]
use manekey::boundary::riscv_pmp::BLE_SPLIT_HCI_EXPECTED_MASK;
#[cfg(all(
    feature = "riscv-pmp-ble-user-runner-runtime",
    not(feature = "riscv-pmp-ble-user-hci-runtime")
))]
use manekey::boundary::riscv_pmp::BLE_SPLIT_RUNNER_EXPECTED_MASK;
#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
use manekey::boundary::riscv_pmp::{
    TIMER_ARM_ECALL_ID, TIMER_MAX_DELAY_US, TIMER_REARM_ECALL_ID, TIMER_STATUS_ECALL_ID,
    TIMER_STATUS_OK,
};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use manekey::ctaphid::descriptor::{
    CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS, REPORT_SIZE as CTAPHID_REPORT_SIZE,
};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use manekey::ctaphid::{CtaphidProtocol, Response, channel::MAX_MESSAGE_SIZE};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
#[cfg(feature = "riscv-pmp-ble-user-security")]
use manekey::transport::ble::BleBondAdmission;
#[cfg(feature = "riscv-pmp-ble-user-gatt-runtime")]
use manekey::transport::ble::BleBondStore;
#[cfg(all(
    feature = "riscv-pmp-ble-user-fido-runtime",
    not(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")
))]
use manekey::transport::ble::BleFidoFrontend;
#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
use manekey::transport::ble::{BLE_BOND_RECORD_LEN, StoredBleBond, StoredBleSecurityLevel};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use manekey::transport::ble::{BleFidoError, BleFidoFragmentSink, BleFidoProtocol};
#[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
use manekey::transport::ble::{
    BleFidoFragmentQueue, BleFidoProfileHandler, handle_control_point_write_at_offset_and_drain,
    notification_fragment_vec,
};

use manekey_rp::platform::rp2350::{
    pmp::PMP_BLE_SHARED_ABI_BASE,
    pmp_cyw43_gpio::{PmpCyw43GpioPin, RiscvPmpCyw43GpioGateway},
    pmp_cyw43_pio_abi::PmpCyw43PioDescriptorSlot,
    riscv_cyw43_pio::RiscvCyw43RawPioSpi,
};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use manekey_rp::platform::rp2350::{pmp_usb::PmpUsbBus, riscv_usb::CTAPHID_REPORT_DESCRIPTOR};
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
use static_cell::StaticCell;
#[cfg(feature = "riscv-pmp-ble-user-advertise-runtime")]
use trouble_host::prelude::*;
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use usb_device::{
    bus::UsbBusAllocator,
    class_prelude::UsbClass,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
use usbd_hid::hid_class::HIDClass;

#[cfg(feature = "riscv-pmp-ble-user-gatt-runtime")]
const BLE_PACKET_LEN: usize = 64;
#[cfg(feature = "riscv-pmp-ble-user-security")]
const BLE_SECURITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(all(
    feature = "riscv-pmp-ble-user-fido-runtime",
    not(feature = "experimental-large-message-buffers")
))]
const MAX_NOTIFY_FRAGMENTS: usize = 20;
#[cfg(all(
    feature = "riscv-pmp-ble-user-fido-runtime",
    feature = "experimental-large-message-buffers"
))]

const MAX_NOTIFY_FRAGMENTS: usize = 66;

#[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
type NotifySink = BleFidoFragmentQueue<MAX_NOTIFY_FRAGMENTS, BLE_PACKET_LEN>;

#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
struct PmpBleBondStore;

#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
impl BleBondStore for PmpBleBondStore {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(StoredBleBond),
    {
        let mut encoded = [0u8; BLE_BOND_RECORD_LEN];
        if pmp_ble_bond_ecall(
            manekey::boundary::riscv_pmp::BLE_BOND_OP_LOAD,
            encoded.as_mut_ptr() as u32,
        ) == manekey::boundary::riscv_pmp::BLE_BOND_STATUS_OK
            && let Some(bond) = StoredBleBond::decode(&encoded).filter(|bond| bond.is_bonded)
        {
            visit(bond);
        }
    }

    fn store_bond(&mut self, bond: StoredBleBond) -> bool {
        let encoded = bond.encode();
        pmp_ble_bond_ecall(
            manekey::boundary::riscv_pmp::BLE_BOND_OP_STORE,
            encoded.as_ptr() as u32,
        ) == manekey::boundary::riscv_pmp::BLE_BOND_STATUS_OK
    }

    fn clear_bonds(&mut self) -> bool {
        pmp_ble_bond_ecall(manekey::boundary::riscv_pmp::BLE_BOND_OP_CLEAR, 0)
            == manekey::boundary::riscv_pmp::BLE_BOND_STATUS_OK
    }
}

#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
fn pmp_ble_bond_ecall(operation: u32, buffer_ptr: u32) -> u32 {
    let mut result = manekey::boundary::riscv_pmp::BLE_BOND_ECALL_ID;
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") result,
            in("a1") operation,
            in("a2") buffer_ptr,
            options(nostack)
        );
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
fn stored_ble_bond_from_trouble(bond: &trouble_host::BondInformation) -> StoredBleBond {
    let security_level = match bond.security_level {
        SecurityLevel::NoEncryption => StoredBleSecurityLevel::NoEncryption,
        SecurityLevel::Encrypted => StoredBleSecurityLevel::Encrypted,
        SecurityLevel::EncryptedAuthenticated => StoredBleSecurityLevel::EncryptedAuthenticated,
    };
    StoredBleBond {
        ltk: bond.ltk.to_le_bytes(),
        bd_addr: bond.identity.addr.addr.into_inner(),
        bd_addr_kind: bond.identity.addr.kind.as_raw(),
        irk: bond.identity.irk.map(|irk| irk.to_le_bytes()),
        is_bonded: bond.is_bonded,
        security_level,
    }
}

#[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
fn stored_ble_bond_to_trouble(bond: StoredBleBond) -> trouble_host::BondInformation {
    let security_level = match bond.security_level {
        StoredBleSecurityLevel::NoEncryption => SecurityLevel::NoEncryption,
        StoredBleSecurityLevel::Encrypted => SecurityLevel::Encrypted,
        StoredBleSecurityLevel::EncryptedAuthenticated => SecurityLevel::EncryptedAuthenticated,
    };
    trouble_host::BondInformation::new(
        trouble_host::Identity {
            addr: Address::new(AddrKind::new(bond.bd_addr_kind), BdAddr::new(bond.bd_addr)),
            irk: bond
                .irk
                .and_then(trouble_host::IdentityResolvingKey::from_le_bytes),
        },
        trouble_host::LongTermKey::from_le_bytes(bond.ltk),
        security_level,
        bond.is_bonded,
    )
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
const USB_TRUSTED_POLL_INTERVAL_MS: u8 = 100;
#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
static MULTI_ARBITER: Mutex<RefCell<Option<IngressArbiter<RiscvPmpEcallBackend>>>> =
    Mutex::new(RefCell::new(None));

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
struct SharedBleFrontend {
    protocol: BleFidoProtocol,
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
impl SharedBleFrontend {
    const fn new() -> Self {
        Self {
            protocol: BleFidoProtocol::new(BLE_PACKET_LEN),
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
impl BleFidoProfileHandler for SharedBleFrontend {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol
                .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut backend)
        })
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol
                .poll_with_backend::<MAX_FRAGMENT>(sink, &mut backend)
        })
    }

    fn on_disconnect(&mut self) {
        critical_section::with(|cs| {
            let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
            let mut backend = slot.as_mut().unwrap().bind(BLE_INGRESS);
            self.protocol.disconnect_with_backend(&mut backend);
        });
    }
}

#[cfg(all(
    feature = "riscv-pmp-ble-user-gatt-runtime",
    not(feature = "riscv-pmp-ble-user-security")
))]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(all(
    feature = "riscv-pmp-ble-user-gatt-runtime",
    not(feature = "riscv-pmp-ble-user-security")
))]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb", write)]
    control_point: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb", notify)]
    status: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
    control_point_length: u16,
    #[characteristic(
        uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        write,
        value = 1u8
    )]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, value = "U2F_V2")]
    service_revision: &'static str,
}

#[cfg(feature = "riscv-pmp-ble-user-security")]
#[gatt_server]
struct Server {
    fido_service: FidoService,
}

#[cfg(feature = "riscv-pmp-ble-user-security")]
#[gatt_service(uuid = "fffd")]
struct FidoService {
    #[characteristic(
        uuid = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb",
        write,
        permissions(write = encrypted)
    )]
    control_point: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(
        uuid = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb",
        notify,
        permissions(cccd = encrypted)
    )]
    status: heapless::Vec<u8, BLE_PACKET_LEN>,
    #[characteristic(uuid = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb", read, value = BLE_PACKET_LEN as u16)]
    control_point_length: u16,
    #[characteristic(
        uuid = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb",
        read,
        write,
        value = 1u8
    )]
    service_revision_bitfield: u8,
    #[characteristic(uuid = "2a28", read, value = "U2F_V2")]
    service_revision: &'static str,
}

#[cfg(all(
    feature = "riscv-pmp-ble-user-single-hart-critical-section",
    feature = "riscv-dual-core-runtime"
))]
compile_error!("the PMP BLE cooperative critical section cannot be used with dual-core runtime");

#[cfg(feature = "riscv-pmp-ble-user-single-hart-critical-section")]
/// Cooperative single U-hart only; fences do not mask interrupts or exclude other harts.
/// Monitor traps must not access U runtime state or invoke U callbacks.
struct PmpBleSingleHartCriticalSection;

#[cfg(feature = "riscv-pmp-ble-user-single-hart-critical-section")]
critical_section::set_impl!(PmpBleSingleHartCriticalSection);

#[cfg(feature = "riscv-pmp-ble-user-single-hart-critical-section")]
unsafe impl critical_section::Impl for PmpBleSingleHartCriticalSection {
    unsafe fn acquire() -> critical_section::RawRestoreState {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        critical_section::RawRestoreState::default()
    }

    unsafe fn release(_: critical_section::RawRestoreState) {
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

const DATA_MAGIC: u32 = 0x51e7_dada;
#[cfg(any(any(), any(), feature = "riscv-pmp-ble-user-runner-runtime"))]
const TIMER0_TIMERAWL: *const u32 = 0x400b_0028 as *const u32;

#[unsafe(link_section = ".data.pmp_user_probe")]
static mut USER_DATA_PROBE: u32 = DATA_MAGIC;

#[unsafe(link_section = ".bss.pmp_user_probe")]
static mut USER_BSS_PROBE: u32 = 0;

global_asm!(
    r#"
    .section .init.pmp_user, "ax"
    .global __pmp_user_entry
    .align 2
__pmp_user_entry:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, _stack_start

    la t0, _sidata
    la t1, _sdata
    la t2, _edata
1:
    bgeu t1, t2, 2f
    lw t3, 0(t0)
    sw t3, 0(t1)
    addi t0, t0, 4
    addi t1, t1, 4
    j 1b

2:
    la t0, _sbss
    la t1, _ebss
3:
    bgeu t0, t1, 4f
    sw zero, 0(t0)
    addi t0, t0, 4
    j 3b

4:
    call pmp_user_main
5:
    j 5b
"#
);

#[cfg(any(any(), feature = "riscv-pmp-ble-user-runner-runtime", any(), any()))]
global_asm!(
    r#"
    .section .text.pmp_user_spi_diag, "ax"
    .global pmp_user_spi_diag_ecall
    .align 2
pmp_user_spi_diag_ecall:
    .option push
    .option norvc
    ecall
    ret
    .option pop
"#
);

#[cfg(any(any(), feature = "riscv-pmp-ble-user-runner-runtime", any(), any()))]
unsafe extern "C" {
    fn pmp_user_spi_diag_ecall(ecall_id: u32, stage: u32, value: u32) -> u32;
}

#[unsafe(no_mangle)]
/// Entry after matching monitor protection/handoff and linker data/BSS initialization; exclusively own U peripherals.
extern "C" fn pmp_user_main() -> ! {
    #[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
    critical_section::with(|cs| {
        *MULTI_ARBITER.borrow_ref_mut(cs) =
            Some(IngressArbiter::new(RiscvPmpEcallBackend::manekey()));
    });

    let mut result = 1;

    unsafe {
        if core::ptr::read_volatile(&raw const USER_DATA_PROBE) == DATA_MAGIC {
            result |= 1 << 1;
        }
        if core::ptr::read_volatile(&raw const USER_BSS_PROBE) == 0 {
            result |= 1 << 2;
        }
        core::ptr::write_volatile(&raw mut USER_BSS_PROBE, DATA_MAGIC);
        if core::ptr::read_volatile(&raw const USER_BSS_PROBE) == DATA_MAGIC {
            result |= 1 << 3;
        }
        let descriptor_slot = &*(PMP_BLE_SHARED_ABI_BASE as *const PmpCyw43PioDescriptorSlot);
        let descriptor = descriptor_slot.read_after_monitor();
        if descriptor.is_ok() {
            result |= 1 << 4;
        }
        #[cfg(not(feature = "riscv-pmp-ble-user-runner-runtime"))]
        let mut power = PmpCyw43GpioPin::power(RiscvPmpCyw43GpioGateway);
        #[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
        let power = PmpCyw43GpioPin::power(RiscvPmpCyw43GpioGateway);
        #[cfg(not(feature = "riscv-pmp-ble-user-runner-runtime"))]
        let mut chip_select = PmpCyw43GpioPin::chip_select(RiscvPmpCyw43GpioGateway);
        #[cfg(not(any(any(), any(), feature = "riscv-pmp-ble-user-runner-runtime")))]
        if power.set_high().is_ok()
            && power.set_low().is_ok()
            && chip_select.set_low().is_ok()
            && chip_select.set_high().is_ok()
        {
            result |= 1 << 5;
        }

        #[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
        {
            result |= 1 << 5;
        }
        if let Ok(descriptor) = descriptor {
            let chip_select = PmpCyw43GpioPin::chip_select(RiscvPmpCyw43GpioGateway);
            if let Ok(backend) =
                RiscvCyw43RawPioSpi::from_initialized_descriptor(descriptor, chip_select)
            {
                if backend.descriptor_probe_mask() == 0x1f {
                    result |= 1 << 6;
                }

                #[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
                if result == BLE_SPLIT_ENTRY_EXPECTED_MASK {
                    #[cfg(not(feature = "riscv-pmp-ble-user-dma-irq-backend"))]
                    let runner_ready = block_on(init_cyw43_runner_probe(power, backend));
                    #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
                    let runner_ready = block_on(async {
                        match embassy_futures::select::select(
                            init_cyw43_runner_probe(power, backend),
                            embassy_time::Timer::after(embassy_time::Duration::from_secs(10)),
                        )
                        .await
                        {
                            embassy_futures::select::Either::First(ready) => ready,
                            embassy_futures::select::Either::Second(()) => false,
                        }
                    });
                    if runner_ready {
                        result |= 1 << 7;

                        #[cfg(feature = "riscv-pmp-ble-user-hci-runtime")]
                        {
                            result |= 1 << 8;
                        }
                    }
                }
            }
        }

        #[cfg(not(any(any(), any(), feature = "riscv-pmp-ble-user-runner-runtime", any())))]
        let (terminal_result, terminal_expected) = (result, BLE_SPLIT_ENTRY_EXPECTED_MASK);

        #[cfg(all(
            feature = "riscv-pmp-ble-user-runner-runtime",
            not(feature = "riscv-pmp-ble-user-hci-runtime")
        ))]
        let (terminal_result, terminal_expected) = (result, BLE_SPLIT_RUNNER_EXPECTED_MASK);
        #[cfg(feature = "riscv-pmp-ble-user-hci-runtime")]
        let (terminal_result, terminal_expected) = (result, BLE_SPLIT_HCI_EXPECTED_MASK);
        core::arch::asm!(
            "ecall",
            "1:",
            "j 1b",
            in("a0") BLE_SPLIT_ENTRY_ECALL_ID,
            in("a1") terminal_result,
            in("a2") terminal_expected,
            options(noreturn),
        );
    }
}

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
static WIFI_FW_BYTES: &cyw43_riscv::Aligned<cyw43_riscv::A4, [u8]> =
    &cyw43_riscv::Aligned(*cyw43_firmware_riscv::CYW43_43439A0);
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
static BT_FW_BYTES: &cyw43_riscv::Aligned<cyw43_riscv::A4, [u8]> =
    &cyw43_riscv::Aligned(*cyw43_firmware_riscv::CYW43_43439A0_BTFW);
#[cfg(feature = "riscv-pmp-ble-user-hci-runtime")]
static WIFI_CLM_BYTES: &cyw43_riscv::Aligned<cyw43_riscv::A4, [u8]> =
    &cyw43_riscv::Aligned(*cyw43_firmware_riscv::CYW43_43439A0_CLM);
#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
static NVRAM_BYTES: &cyw43_riscv::Aligned<cyw43_riscv::A4, [u8]> = aligned_bytes!(env!(
    "MANEKEY_CYW43_NVRAM_VERIFIED",
    "Set MANEKEY_CYW43_NVRAM_FILE to the fixed upstream NVRAM file"
));

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
/// Product radio runner despite legacy name; initialize once with exclusive PIO/pins and monitor-owned fixed GPIO services.
async fn init_cyw43_runner_probe(
    power: PmpCyw43GpioPin<RiscvPmpCyw43GpioGateway>,
    spi: RiscvCyw43RawPioSpi<PmpCyw43GpioPin<RiscvPmpCyw43GpioGateway>>,
) -> bool {
    static STATE: StaticCell<cyw43_riscv::State> = StaticCell::new();
    let state = STATE.init(cyw43_riscv::State::new());
    let runtime =
        cyw43_riscv::new_with_bluetooth(state, power, spi, WIFI_FW_BYTES, BT_FW_BYTES, NVRAM_BYTES)
            .await;
    #[cfg(not(feature = "riscv-pmp-ble-user-hci-runtime"))]
    let _ = runtime;
    #[cfg(all(
        feature = "riscv-pmp-ble-user-hci-runtime",
        not(feature = "riscv-pmp-ble-user-advertise-runtime")
    ))]
    {
        let (_net, _bt, mut control, runner) = runtime;
        if !matches!(
            select(runner.run(), async {
                control.init(WIFI_CLM_BYTES).await;
            })
            .await,
            Either::Second(())
        ) {
            return false;
        }
    }
    #[cfg(feature = "riscv-pmp-ble-user-advertise-runtime")]
    {
        const CONNECTIONS_MAX: usize = 1;
        #[cfg(not(feature = "riscv-pmp-ble-user-gatt-runtime"))]
        const L2CAP_CHANNELS_MAX: usize = 1;
        #[cfg(feature = "riscv-pmp-ble-user-gatt-runtime")]
        const L2CAP_CHANNELS_MAX: usize = 2;

        let (_net, bt, mut control, runner) = runtime;
        let controller: ExternalController<_, 10> = ExternalController::new(bt);
        #[cfg(not(feature = "riscv-pmp-ble-user-security"))]
        let address = Address::random([0xc1, 0x7a, 0xf1, 0xd0, 0x02, 0x42]);

        #[cfg(feature = "riscv-pmp-ble-user-security")]
        let address = Address::random([0xc1, 0x7a, 0xf1, 0xd0, 0x02, 0xd2]);
        let mut resources: HostResources<
            _,
            DefaultPacketPool,
            CONNECTIONS_MAX,
            L2CAP_CHANNELS_MAX,
        > = HostResources::new();
        let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
        #[cfg(feature = "riscv-pmp-ble-user-security")]
        let stack = stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
        let host = stack.build();
        #[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
        let mut bond_store = PmpBleBondStore;
        #[cfg(not(feature = "riscv-pmp-ble-user-persistent-security"))]
        let mut bond_store = ();
        #[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
        bond_store.load_bonds(|bond| {
            let _ = host.add_bond_information(stored_ble_bond_to_trouble(bond));
        });
        let mut ble_runner = host.runner();
        let mut peripheral = host.peripheral();

        let _ = join3(
            runner.run(),
            async {
                loop {
                    let _ = ble_runner.run().await;
                }
            },
            async {
                control.init(WIFI_CLM_BYTES).await;
                #[cfg(not(feature = "riscv-pmp-ble-user-gatt-runtime"))]
                {
                    let mut adv_data = [0; 31];
                    let len = AdStructure::encode_slice(
                        &[
                            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                            AdStructure::CompleteLocalName(b"ManeKey PMP BLE"),
                        ],
                        &mut adv_data,
                    )
                    .unwrap();
                    let _advertiser = peripheral
                        .advertise(
                            &Default::default(),
                            Advertisement::NonconnectableScannableUndirected {
                                adv_data: &adv_data[..len],
                                scan_data: &[],
                            },
                        )
                        .await
                        .unwrap();

                    core::future::pending::<()>().await;
                }
                #[cfg(all(
                    feature = "riscv-pmp-ble-user-gatt-runtime",
                    not(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")
                ))]
                run_gatt(&host, &mut peripheral, &mut bond_store).await;
                #[cfg(all(
                    feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental",
                    not(feature = "riscv-pmp-ble-user-frontend-io")
                ))]
                let _ = join(
                    run_gatt(&host, &mut peripheral, &mut bond_store),
                    run_multi_usb(),
                )
                .await;
                #[cfg(feature = "riscv-pmp-ble-user-frontend-io")]
                let _ = join(
                    run_gatt(&host, &mut peripheral, &mut bond_store),
                    join3(run_multi_usb(), run_multi_internal(), async {
                        let mut previous = None;
                        loop {
                            let lit = frontend_io_ecall(
                                manekey::boundary::riscv_pmp::PRESENCE_PENDING_ECALL_ID,
                                0,
                                0,
                            ) == 1;
                            if previous != Some(lit) {
                                control.gpio_set(0, lit).await;
                                previous = Some(lit);
                            }
                            embassy_time::Timer::after_millis(10).await;
                        }
                    }),
                )
                .await;
            },
        )
        .await;
        false
    }
    #[cfg(not(feature = "riscv-pmp-ble-user-advertise-runtime"))]
    {
        true
    }
}

#[cfg(feature = "riscv-pmp-ble-user-frontend-io")]
fn frontend_io_ecall(id: u32, operation: u32, value: u32) -> u32 {
    let mut result = id;

    unsafe {
        core::arch::asm!("ecall", inlateout("a0") result,
            in("a1") operation, in("a2") value, options(nostack));
    }
    result
}

#[cfg(feature = "riscv-pmp-ble-user-frontend-io")]
/// Sole UART byte-service frontend; timeout abandons the response and does not imply full delivery.
async fn run_multi_internal() -> ! {
    use manekey::boundary::riscv_pmp::{
        BYTE_IO_ECALL_ID, BYTE_IO_READ, BYTE_IO_WOULD_BLOCK, BYTE_IO_WRITE,
    };
    use manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX;
    use manekey::frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome};
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut response = [0; TRUSTED_RESPONSE_MAX + 32];
    loop {
        critical_section::with(|cs| {
            frontend.poll_cancel(MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap());
        });
        for _ in 0..64 {
            let received = frontend_io_ecall(BYTE_IO_ECALL_ID, BYTE_IO_READ, 0);
            if received > u8::MAX as u32 {
                break;
            }
            let outcome = critical_section::with(|cs| {
                frontend.push_byte(
                    MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                    received as u8,
                    &mut response,
                )
            });
            if let Ok(Some(InterconnectCtap2Outcome::Response { len })) = outcome {
                'response: for chunk in response[..len].chunks(32) {
                    for byte in chunk {
                        let deadline =
                            embassy_time::Instant::now() + embassy_time::Duration::from_secs(5);
                        loop {
                            match frontend_io_ecall(BYTE_IO_ECALL_ID, BYTE_IO_WRITE, *byte as u32) {
                                0 => break,
                                BYTE_IO_WOULD_BLOCK if embassy_time::Instant::now() < deadline => {
                                    embassy_time::Timer::after_millis(1).await;
                                }
                                _ => break 'response,
                            }
                        }
                    }
                    embassy_time::Timer::after_millis(1).await;
                }
            }
        }
        embassy_time::Timer::after_millis(1).await;
    }
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
struct UsbEgress {
    cid: u32,
    cmd: u8,
    data: [u8; MAX_MESSAGE_SIZE],
    len: usize,
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
impl UsbEgress {
    const fn new() -> Self {
        Self {
            cid: 0,
            cmd: 0,
            data: [0; MAX_MESSAGE_SIZE],
            len: 0,
        }
    }

    fn capture(&mut self, response: Response<'_>) {
        let Response::Msg { cid, cmd, data } = response;
        self.cid = cid;
        self.cmd = cmd;
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }

    fn response(&self) -> Response<'_> {
        Response::Msg {
            cid: self.cid,
            cmd: self.cmd,
            data: &self.data[..self.len],
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
/// Sole USB/DPRAM polling owner after monitor initialization; transport timeouts may discard responses.
async fn run_multi_usb() -> ! {
    static USB_BUS: StaticCell<UsbBusAllocator<PmpUsbBus>> = StaticCell::new();
    static USB_HID: StaticCell<HIDClass<'static, PmpUsbBus>> = StaticCell::new();
    static USB_DEVICE: StaticCell<usb_device::device::UsbDevice<'static, PmpUsbBus>> =
        StaticCell::new();
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    static USB_CCID: StaticCell<
        manekey::transport::usb::polling_ccid::PollingCcid<'static, PmpUsbBus>,
    > = StaticCell::new();

    let bus = USB_BUS.init(UsbBusAllocator::new(unsafe {
        PmpUsbBus::from_preinitialized()
    }));
    let hid = USB_HID.init(HIDClass::new(
        bus,
        CTAPHID_REPORT_DESCRIPTOR,
        CTAPHID_POLL_MS,
    ));
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    let ccid = USB_CCID.init(manekey::transport::usb::polling_ccid::PollingCcid::new(
        bus,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    ));
    let identity =
        CtaphidUsbDeviceInfo::new("RP2350 RISC-V PMP USB + BLE FIDO", "riscv-pmp-usb-ble-fido");
    let usb_dev = USB_DEVICE.init(
        UsbDeviceBuilder::new(bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build(),
    );
    let mut protocol = CtaphidProtocol::new();
    let mut report = [0u8; CTAPHID_REPORT_SIZE];
    let mut egress = UsbEgress::new();
    let mut trusted_poll_ticks = 0u8;
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    let mut ccid_frontend = manekey::frontend::ccid::CcidFrontend::new(0);
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    let mut ccid_assembler = manekey::transport::usb::ccid_bulk::CcidBulkAssembler::<
        { manekey::frontend::ccid::CCID_RESPONSE_MAX },
    >::new();
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    let mut ccid_response = [0; manekey::frontend::ccid::CCID_RESPONSE_MAX];
    #[cfg(feature = "riscv-pmp-ble-user-ccid")]
    let (mut ccid_len, mut ccid_sent, mut ccid_zlp, mut ccid_ticks) = (0usize, 0usize, false, 0u8);

    loop {
        let mut has_response = false;
        #[cfg(feature = "riscv-pmp-ble-user-ccid")]
        let usb_event = usb_dev.poll(&mut [hid as &mut dyn UsbClass<PmpUsbBus>, ccid]);
        #[cfg(not(feature = "riscv-pmp-ble-user-ccid"))]
        let usb_event = usb_dev.poll(&mut [hid as &mut dyn UsbClass<PmpUsbBus>]);
        if usb_event && let Ok(CTAPHID_REPORT_SIZE) = hid.pull_raw_output(&mut report) {
            has_response = critical_section::with(|cs| {
                let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
                let mut backend = slot.as_mut().unwrap().bind(USB_INGRESS);
                if let Some(response) = protocol.handle_raw_with_backend(report, &mut backend) {
                    egress.capture(response);
                    true
                } else {
                    false
                }
            });
            usb_dev.bus().ensure_out_endpoint_available(1);
        }

        #[cfg(feature = "riscv-pmp-ble-user-ccid")]
        {
            if ccid.take_reset() {
                critical_section::with(|cs| {
                    ccid_frontend.disconnect(MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap())
                });
                ccid_assembler.reset();
                ccid_len = 0;
                ccid_sent = 0;
                ccid_zlp = false;
            }
            if let Some((slot, sequence)) = ccid.take_abort() {
                critical_section::with(|cs| {
                    ccid_frontend.begin_abort(
                        MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                        slot,
                        sequence,
                    )
                });
            }
            ccid_ticks = ccid_ticks.saturating_add(1);
            if ccid_len == 0 && !ccid_zlp {
                let mut packet = [0; 64];
                if let Ok(length) = ccid.read(&mut packet) {
                    if let Ok(Some(message)) = ccid_assembler.push(&packet[..length]) {
                        ccid_len = critical_section::with(|cs| {
                            ccid_frontend.handle_message(
                                MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                                message,
                                &mut ccid_response,
                            )
                        })
                        .unwrap_or(0);
                        ccid_sent = 0;
                        ccid_assembler.reset();
                    }
                } else if ccid_ticks >= USB_TRUSTED_POLL_INTERVAL_MS {
                    ccid_ticks = 0;
                    ccid_len = critical_section::with(|cs| {
                        ccid_frontend.poll(
                            MULTI_ARBITER.borrow_ref_mut(cs).as_mut().unwrap(),
                            &mut ccid_response,
                        )
                    })
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                    ccid_sent = 0;
                }
            }
            if ccid_len != 0 {
                let end = (ccid_sent + 64).min(ccid_len);
                if let Ok(length) = ccid.write(&ccid_response[ccid_sent..end]) {
                    ccid_sent += length;
                    if ccid_sent == ccid_len {
                        ccid_zlp = ccid_len % 64 == 0;
                        ccid_len = 0;
                    }
                }
            } else if ccid_zlp && ccid.write(&[]).is_ok() {
                ccid_zlp = false;
            }
        }

        trusted_poll_ticks = trusted_poll_ticks.saturating_add(1);
        if !has_response && trusted_poll_ticks >= USB_TRUSTED_POLL_INTERVAL_MS {
            trusted_poll_ticks = 0;
            has_response = critical_section::with(|cs| {
                let mut slot = MULTI_ARBITER.borrow_ref_mut(cs);
                let mut backend = slot.as_mut().unwrap().bind(USB_INGRESS);
                if let Some(response) = protocol.poll_with_backend(&mut backend) {
                    egress.capture(response);
                    true
                } else {
                    false
                }
            });
        }

        if has_response {
            let deadline = embassy_time::Instant::now() + embassy_time::Duration::from_secs(5);
            'response: for packet in manekey::ctaphid::framing::response_reports(egress.response())
            {
                loop {
                    match hid.push_raw_input(&packet) {
                        Ok(_) => break,
                        Err(usb_device::UsbError::WouldBlock) => {
                            #[cfg(feature = "riscv-pmp-ble-user-ccid")]
                            usb_dev.poll(&mut [hid as &mut dyn UsbClass<PmpUsbBus>, ccid]);
                            #[cfg(not(feature = "riscv-pmp-ble-user-ccid"))]
                            usb_dev.poll(&mut [hid as &mut dyn UsbClass<PmpUsbBus>]);
                            if embassy_time::Instant::now() >= deadline {
                                break 'response;
                            }
                            embassy_time::Timer::after_millis(1).await;
                        }
                        Err(_) => break 'response,
                    }
                }
                embassy_time::Timer::after_millis(1).await;
            }
            usb_dev.bus().clear_in_endpoint_complete(1);
            usb_dev.bus().ensure_out_endpoint_available(1);
        }

        embassy_time::Timer::after_millis(1).await;
    }
}

#[cfg(feature = "riscv-pmp-ble-user-gatt-runtime")]
async fn run_gatt<'values, C: Controller, B: BleBondStore>(
    host: &Stack<'_, C, DefaultPacketPool>,
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    bond_store: &mut B,
) -> ! {
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "ManeKey PMP BLE",
        appearance: &appearance::UNKNOWN,
    }))
    .unwrap();
    #[cfg(all(
        feature = "riscv-pmp-ble-user-fido-runtime",
        not(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")
    ))]
    let mut fido = BleFidoFrontend::new(BLE_PACKET_LEN, RiscvPmpEcallBackend::manekey());
    #[cfg(feature = "riscv-pmp-ble-user-multi-transport-ml-dsa-experimental")]
    let mut fido = SharedBleFrontend::new();
    #[cfg(feature = "riscv-pmp-ble-user-security")]
    let admission =
        BleBondAdmission::from_bonded_only(cfg!(feature = "riscv-pmp-ble-user-bonded-only"));

    loop {
        let mut adv_data = [0; 31];
        let len = AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::CompleteServiceUuids16(&[[0xfd, 0xff]]),
                AdStructure::CompleteLocalName(b"ManeKey PMP BLE"),
            ],
            &mut adv_data,
        )
        .unwrap();
        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..len],
                    scan_data: &[],
                },
            )
            .await
            .unwrap();

        let connection = advertiser
            .accept()
            .await
            .unwrap()
            .with_attribute_server(&server)
            .unwrap();
        #[cfg(feature = "riscv-pmp-ble-user-security")]
        let _ = connection.raw().set_bondable(admission.permits_new_bond());
        #[cfg(feature = "riscv-pmp-ble-user-security")]
        if !admission.permits_peer(connection.raw().is_bonded_peer()) {
            connection.raw().disconnect();
            drop(connection);
            embassy_time::Timer::after_millis(30).await;
            continue;
        }

        #[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
        let _ = run_gatt_fido_connection(
            host,
            &server,
            &connection,
            &mut fido,
            bond_store,
            #[cfg(feature = "riscv-pmp-ble-user-security")]
            admission,
        )
        .await;
    }
}

#[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
/// Best-effort enqueue without delivery acknowledgement; failures are discarded when the queue is cleared.
async fn flush_fido_notifications<P: PacketPool>(
    connection: &GattConnection<'_, '_, P>,
    status: &Characteristic<heapless::Vec<u8, BLE_PACKET_LEN>>,
    sink: &mut NotifySink,
) {
    for fragment in sink.fragments() {
        if let Ok(value) = notification_fragment_vec::<BLE_PACKET_LEN>(fragment)
            && status.notify(connection, &value, false).await.is_ok()
        {}
    }
    sink.clear();
}

#[cfg(feature = "riscv-pmp-ble-user-fido-runtime")]
/// Sole connection protocol owner; bond persistence failures do not fail pairing.
async fn run_gatt_fido_connection<C: Controller, P: PacketPool, B: BleBondStore>(
    _host: &Stack<'_, C, P>,
    server: &Server<'_>,
    connection: &GattConnection<'_, '_, P>,
    fido: &mut impl BleFidoProfileHandler,
    _bond_store: &mut B,
    #[cfg(feature = "riscv-pmp-ble-user-security")] admission: BleBondAdmission,
) -> Result<(), Error> {
    #[cfg(feature = "riscv-pmp-ble-user-security")]
    let security_deadline = Instant::now() + BLE_SECURITY_HANDSHAKE_TIMEOUT;
    #[cfg(feature = "riscv-pmp-ble-user-security")]
    let mut security_disconnect_requested = false;
    loop {
        match embassy_futures::select::select(
            connection.next(),
            embassy_time::Timer::after_millis(100),
        )
        .await
        {
            embassy_futures::select::Either::First(GattConnectionEvent::Disconnected {
                ..
            }) => {
                fido.on_disconnect();
                return Ok(());
            }
            #[cfg(feature = "riscv-pmp-ble-user-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingComplete {
                bond,
                ..
            }) => {
                if !admission.permits_new_bond() {
                    connection.raw().disconnect();
                    security_disconnect_requested = true;
                    continue;
                }
                #[cfg(feature = "riscv-pmp-ble-user-persistent-security")]
                if let Some(bond) = bond.as_ref().filter(|bond| bond.is_bonded) {
                    let _ = _bond_store.store_bond(stored_ble_bond_from_trouble(bond));
                }
                #[cfg(not(feature = "riscv-pmp-ble-user-persistent-security"))]
                let _ = (bond, &mut *_bond_store);
            }
            #[cfg(feature = "riscv-pmp-ble-user-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::PairingFailed(_)) => {
                connection.raw().disconnect();
                security_disconnect_requested = true;
            }
            #[cfg(feature = "riscv-pmp-ble-user-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::Encrypted { .. }) => {}
            #[cfg(feature = "riscv-pmp-ble-user-security")]
            embassy_futures::select::Either::First(GattConnectionEvent::BondLost) => {
                if admission.permits_new_bond() {
                    let _ = _host.remove_bond_information(connection.raw().peer_identity());
                    let _ = _bond_store.clear_bonds();
                }
                connection.raw().disconnect();
                security_disconnect_requested = true;
            }
            embassy_futures::select::Either::First(GattConnectionEvent::Gatt { event }) => {
                let mut sink = NotifySink::new();
                if let GattEvent::Write(write) = &event
                    && write.handle() == server.fido_service.control_point.handle
                {
                    write.with_data(|offset, data| {
                        let _ = handle_control_point_write_at_offset_and_drain::<BLE_PACKET_LEN>(
                            fido,
                            offset,
                            data,
                            &mut sink,
                            0,
                            || {},
                        );
                    });
                }
                if let Ok(reply) = event.accept() {
                    reply.send().await;
                }
                flush_fido_notifications(connection, &server.fido_service.status, &mut sink).await;
            }
            embassy_futures::select::Either::First(_) => {}
            embassy_futures::select::Either::Second(()) => {
                #[cfg(feature = "riscv-pmp-ble-user-security")]
                if Instant::now() >= security_deadline
                    && !connection
                        .raw()
                        .security_level()
                        .is_ok_and(|level| level.encrypted())
                {
                    if !security_disconnect_requested {
                        connection.raw().disconnect();
                        security_disconnect_requested = true;
                    }
                    continue;
                }
                let mut sink = NotifySink::new();
                let _ = fido.poll_status::<BLE_PACKET_LEN>(&mut sink);
                flush_fido_notifications(connection, &server.fido_service.status, &mut sink).await;
            }
        }
    }
}

#[cfg(all(
    feature = "riscv-pmp-ble-user-runner-runtime",
    not(feature = "riscv-pmp-ble-user-timer-runtime")
))]
struct BlockingUserTimerDriver;

#[cfg(all(
    feature = "riscv-pmp-ble-user-runner-runtime",
    not(feature = "riscv-pmp-ble-user-timer-runtime")
))]
embassy_time_driver::time_driver_impl!(static USER_TIME_DRIVER: BlockingUserTimerDriver = BlockingUserTimerDriver);

#[cfg(all(
    feature = "riscv-pmp-ble-user-runner-runtime",
    not(feature = "riscv-pmp-ble-user-timer-runtime")
))]
impl Driver for BlockingUserTimerDriver {
    fn now(&self) -> u64 {
        timer_now()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        while timer_now() < at {
            core::hint::spin_loop();
        }
        waker.wake_by_ref();
    }
}

#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
struct BoundaryUserTimerDriver {
    queue: Mutex<RefCell<Queue>>,
    generation: AtomicU32,
    armed: AtomicBool,
}

#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
embassy_time_driver::time_driver_impl!(static USER_TIME_DRIVER: BoundaryUserTimerDriver = BoundaryUserTimerDriver {
    queue: Mutex::new(RefCell::new(Queue::new())),
    generation: AtomicU32::new(0),
    armed: AtomicBool::new(false),
});

#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
impl Driver for BoundaryUserTimerDriver {
    fn now(&self) -> u64 {
        timer_now()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            if queue.schedule_wake(at, waker) {
                let next = queue.next_expiration(self.now());
                self.arm_next(next);
            }
        });
    }
}

#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
impl BoundaryUserTimerDriver {
    fn init(&self) {
        self.generation.store(
            timer_gateway(TIMER_STATUS_ECALL_ID, 0, 0),
            Ordering::Release,
        );
        self.armed.store(false, Ordering::Release);
    }

    fn service_monitor_event(&self) -> bool {
        let generation = timer_gateway(TIMER_STATUS_ECALL_ID, 0, 0);
        if generation == self.generation.load(Ordering::Acquire) {
            return false;
        }
        self.generation.store(generation, Ordering::Release);
        self.armed.store(false, Ordering::Release);
        critical_section::with(|cs| {
            let next = self
                .queue
                .borrow(cs)
                .borrow_mut()
                .next_expiration(self.now());
            self.arm_next(next);
        });
        true
    }

    fn arm_next(&self, at: u64) {
        if at == u64::MAX {
            return;
        }
        let delay = at
            .saturating_sub(self.now())
            .clamp(1, u64::from(TIMER_MAX_DELAY_US)) as u32;
        let generation = self.generation.load(Ordering::Acquire);
        let id = if self.armed.load(Ordering::Acquire) {
            TIMER_REARM_ECALL_ID
        } else {
            TIMER_ARM_ECALL_ID
        };
        if timer_gateway(id, delay, generation) == TIMER_STATUS_OK {
            self.armed.store(true, Ordering::Release);
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
fn timer_gateway(id: u32, arg0: u32, arg1: u32) -> u32 {
    unsafe { pmp_user_spi_diag_ecall(id, arg0, arg1) }
}

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
fn timer_now() -> u64 {
    const TIMER0_TIMERAWH: *const u32 = 0x400b_002c as *const u32;
    loop {
        let high = unsafe { TIMER0_TIMERAWH.read_volatile() };
        let low = unsafe { TIMER0_TIMERAWL.read_volatile() };
        let high_again = unsafe { TIMER0_TIMERAWH.read_volatile() };
        if high == high_again {
            return (u64::from(high) << 32) | u64::from(low);
        }
    }
}

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
static BLOCK_ON_READY: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
static DMA_IRQ_GENERATION: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
/// Non-reentrant single U-hart executor with one root future; use the matching monitor timer/IRQ generation ABI.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let waker = unsafe { Waker::from_raw(block_on_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    #[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
    USER_TIME_DRIVER.init();
    #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
    DMA_IRQ_GENERATION.store(
        manekey_rp::platform::rp2350::pmp_dma::user_dma_irq_generation(),
        Ordering::Release,
    );
    BLOCK_ON_READY.store(true, Ordering::Release);
    loop {
        if BLOCK_ON_READY.swap(false, Ordering::AcqRel) {
            if let Poll::Ready(output) = Future::poll(Pin::as_mut(&mut future), &mut context) {
                return output;
            }
        }
        #[cfg(feature = "riscv-pmp-ble-user-timer-runtime")]
        {
            #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
            service_dma_monitor_event();

            if !BLOCK_ON_READY.load(Ordering::Acquire) {
                unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
                if USER_TIME_DRIVER.service_monitor_event() {}
                #[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
                service_dma_monitor_event();
            }
        }
        #[cfg(not(feature = "riscv-pmp-ble-user-timer-runtime"))]
        core::hint::spin_loop();
    }
}

#[cfg(feature = "riscv-pmp-ble-user-dma-irq-backend")]
fn service_dma_monitor_event() -> bool {
    let generation = manekey_rp::platform::rp2350::pmp_dma::user_dma_irq_generation();
    let previous = DMA_IRQ_GENERATION.swap(generation, Ordering::AcqRel);
    if generation == previous {
        return false;
    }
    BLOCK_ON_READY.store(true, Ordering::Release);
    true
}

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
fn block_on_raw_waker() -> RawWaker {
    RawWaker::new(core::ptr::null(), &BLOCK_ON_WAKER_VTABLE)
}

#[cfg(feature = "riscv-pmp-ble-user-runner-runtime")]
static BLOCK_ON_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    |_| block_on_raw_waker(),
    |_| BLOCK_ON_READY.store(true, Ordering::Release),
    |_| BLOCK_ON_READY.store(true, Ordering::Release),
    |_| {},
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
