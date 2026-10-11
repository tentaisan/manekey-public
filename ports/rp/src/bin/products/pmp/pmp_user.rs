#[cfg(feature = "riscv-pmp-usb-frontend")]
use manekey::boundary::riscv_ecall::RiscvPmpEcallBackend;
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
use manekey::ctaphid::CtaphidFrontend;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use manekey::ctaphid::descriptor::CtaphidUsbDeviceInfo;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use manekey::ctaphid::descriptor::POLL_MS as CTAPHID_POLL_MS;
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
use manekey::ctaphid::descriptor::REPORT_SIZE as CTAPHID_REPORT_SIZE;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use manekey_rp::platform::rp2350::pmp_usb::PmpUsbBus;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use manekey_rp::platform::rp2350::riscv_usb::CTAPHID_REPORT_DESCRIPTOR;
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
use manekey_rp::platform::rp2350::riscv_usb::write_response;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use rp235x_hal as hal;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use static_cell::StaticCell;
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
use usb_device::class_prelude::UsbClass;
#[cfg(feature = "riscv-pmp-usb-frontend")]
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid},
};
#[cfg(feature = "riscv-pmp-usb-frontend")]
use usbd_hid::hid_class::HIDClass;

#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
#[path = "../riscv_usb_internal.rs"]
mod multi_transport;
#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
type PmpCcid = manekey::transport::usb::polling_ccid::PollingCcid<'static, PmpUsbBus>;
#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
#[unsafe(link_section = ".bss.pmp_shared")]
static PMP_USB_CCID: StaticCell<PmpCcid> = StaticCell::new();
#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
#[unsafe(link_section = ".bss.pmp_shared")]
static mut PMP_USB_CCID_PTR: *mut PmpCcid = core::ptr::null_mut();

#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
#[unsafe(link_section = ".bss.pmp_shared")]
static PMP_MULTI_BACKEND: StaticCell<RiscvPmpEcallBackend> = StaticCell::new();
#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
#[unsafe(link_section = ".bss.pmp_shared")]
static mut PMP_MULTI_BACKEND_PTR: *mut RiscvPmpEcallBackend = core::ptr::null_mut();

#[cfg(feature = "riscv-pmp-usb-frontend")]
pub(super) type PmpUsbBusAllocator = UsbBusAllocator<PmpUsbBus>;
#[cfg(feature = "riscv-pmp-usb-frontend")]
pub(super) type PmpUsbHid = HIDClass<'static, PmpUsbBus>;
#[cfg(feature = "riscv-pmp-usb-frontend")]
pub(super) type PmpUsbDevice = UsbDevice<'static, PmpUsbBus>;
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
pub(super) type PmpUsbCtaphid = CtaphidFrontend<RiscvPmpEcallBackend>;

#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
static PMP_USB_BUS: StaticCell<PmpUsbBusAllocator> = StaticCell::new();
#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
static PMP_USB_HID: StaticCell<PmpUsbHid> = StaticCell::new();
#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
static PMP_USB_DEVICE: StaticCell<PmpUsbDevice> = StaticCell::new();
#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
static PMP_USB_CTAPHID: StaticCell<PmpUsbCtaphid> = StaticCell::new();

#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
static mut PMP_USB_HID_PTR: *mut PmpUsbHid = core::ptr::null_mut();
#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
static mut PMP_USB_DEVICE_PTR: *mut PmpUsbDevice = core::ptr::null_mut();
#[unsafe(link_section = ".bss.pmp_shared")]
#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
static mut PMP_USB_CTAPHID_PTR: *mut PmpUsbCtaphid = core::ptr::null_mut();

#[cfg(feature = "riscv-pmp-usb-frontend")]
/// Initialize once in M-mode before U entry; reserve shared linker RAM and exclusive USB/DPRAM ownership.
pub(super) fn init_usb_frontend_objects(
    usb: hal::pac::USB,
    usb_dpram: hal::pac::USB_DPRAM,
    resets: &mut hal::pac::RESETS,
) {
    let usb_bus = PMP_USB_BUS
        .init_with(|| PmpUsbBusAllocator::new(PmpUsbBus::new(usb, usb_dpram, true, resets)));
    let hid = PMP_USB_HID
        .init_with(|| HIDClass::new(usb_bus, CTAPHID_REPORT_DESCRIPTOR, CTAPHID_POLL_MS));
    #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
    {
        let ccid = PMP_USB_CCID
            .init_with(|| PmpCcid::new(usb_bus, manekey::frontend::ccid::CCID_RESPONSE_MAX as u32));

        unsafe {
            PMP_USB_CCID_PTR = ccid;
        }
    }

    let product = "RP2350 RISC-V PMP FIDO";

    let serial = "riscv-pmp-fido";

    let identity = CtaphidUsbDeviceInfo::new(product, serial);
    let usb_dev = PMP_USB_DEVICE.init_with(|| {
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build()
    });
    #[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
    let ctaphid = PMP_USB_CTAPHID
        .init_with(|| CtaphidFrontend::with_trusted_backend(RiscvPmpEcallBackend::manekey()));
    #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
    let backend = PMP_MULTI_BACKEND.init_with(RiscvPmpEcallBackend::manekey);
    #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
    assert!(manekey::boundary::riscv_pmp::fixed_buffer_is_in_region(
        backend as *mut RiscvPmpEcallBackend as u32,
        core::mem::size_of::<RiscvPmpEcallBackend>(),
        (&raw const super::pmp_memory::__pmp_shared_start) as usize,
        (&raw const super::pmp_memory::__pmp_shared_end) as usize,
    ));
    unsafe {
        PMP_USB_HID_PTR = hid as *mut PmpUsbHid;
        PMP_USB_DEVICE_PTR = usb_dev as *mut PmpUsbDevice;
        #[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
        {
            PMP_USB_CTAPHID_PTR = ctaphid as *mut PmpUsbCtaphid;
        }
        #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
        {
            PMP_MULTI_BACKEND_PTR = backend;
        }
    }
}

pub(super) fn selected_u_mode_entry_addr() -> usize {
    if cfg!(feature = "riscv-pmp-ble-monitor-image") {
        return manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_FLASH_BASE;
    }

    {
        if cfg!(feature = "riscv-pmp-usb-frontend") {
            usb_frontend_entry_addr()
        } else {
            panic!("PMP runtime requires a monitor image or USB frontend")
        }
    }
}

pub(super) fn selected_u_mode_stack_top() -> usize {
    if cfg!(feature = "riscv-pmp-ble-monitor-image") {
        manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_STACK_TOP
    } else {
        unsafe { super::pmp_machine::u_stack_top() }
    }
}

pub(super) fn usb_frontend_entry_addr() -> usize {
    _pmp_u_usb_frontend_entry as *const () as usize
}

#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.pmp_user_rust_ecall")]
/// Product service ABI wrapper; require the matching monitor and enabled service despite its legacy name.
pub(super) extern "C" fn diag_ecall(id: u32, arg0: u32, arg1: u32) -> u32 {
    let returned: u32;
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") id => returned,
            in("a1") arg0,
            in("a2") arg1,
        );
    }
    returned
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.pmp_user_usb_frontend")]
#[cfg(feature = "riscv-pmp-usb-frontend")]
extern "C" fn _pmp_u_usb_frontend_entry() -> ! {
    #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
    {
        use manekey::boundary::riscv_pmp::*;
        let (hid, usb) = unsafe { usb_frontend_transport() };
        let ccid = unsafe { &mut *PMP_USB_CCID_PTR };
        multi_transport::run_with_clock(
            multi_transport::BorrowedBackend(unsafe { &mut *PMP_MULTI_BACKEND_PTR }),
            &mut || {},
            || {
                let timer = unsafe { &*hal::pac::TIMER0::ptr() };
                let low = timer.timelr().read().bits();
                let high = timer.timehr().read().bits();
                ((high as u64) << 32) | low as u64
            },
            usb,
            hid,
            ccid,
            &mut |usb, consumed, sent| {
                if sent {
                    usb.bus().clear_in_endpoint_complete(1);
                }
                if consumed || sent {
                    usb.bus().ensure_out_endpoint_available(1);
                }
            },
            |buffer| {
                let mut length = 0;
                for byte in buffer {
                    let value = byte_io_ecall(BYTE_IO_READ, 0);
                    if value > 255 {
                        break;
                    }
                    *byte = value as u8;
                    length += 1;
                }
                length
            },
            |bytes| {
                for byte in bytes {
                    while byte_io_ecall(BYTE_IO_WRITE, *byte as u32) == BYTE_IO_WOULD_BLOCK {
                        core::hint::spin_loop();
                    }
                }
            },
        );
    }
    #[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
    usb_hid_loop()
}

#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
fn byte_io_ecall(operation: u32, value: u32) -> u32 {
    let mut result = manekey::boundary::riscv_pmp::BYTE_IO_ECALL_ID;

    unsafe {
        core::arch::asm!("ecall", inlateout("a0") result,
            in("a1") operation, in("a2") value, options(nostack));
    }
    result
}

#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
fn usb_hid_loop() -> ! {
    let mut report = [0u8; CTAPHID_REPORT_SIZE];

    loop {
        let sent_response = {
            let (hid, usb_dev, ctaphid) = unsafe { usb_frontend_objects() };
            let mut sent_response = false;
            if usb_dev.poll(&mut [hid as &mut dyn UsbClass<PmpUsbBus>]) {
                if let Ok(CTAPHID_REPORT_SIZE) = hid.pull_raw_output(&mut report) {
                    if let Some(response) = ctaphid.handle_report(&report) {
                        write_response(usb_dev, hid, response);
                        usb_dev.bus().clear_in_endpoint_complete(1);
                        sent_response = true;
                    }

                    usb_dev.bus().ensure_out_endpoint_available(1);
                }
            }
            sent_response
        };

        if sent_response {
            continue;
        }

        let ctaphid = unsafe { usb_frontend_ctaphid() };
        if let Some(response) = ctaphid.poll_trusted_only() {
            let (hid, usb_dev) = unsafe { usb_frontend_transport() };
            write_response(usb_dev, hid, response);
            usb_dev.bus().clear_in_endpoint_complete(1);
            usb_dev.bus().ensure_out_endpoint_available(1);
        }
    }
}

#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
/// # Safety
/// Require live initialized shared objects, sole frontend ownership and no overlapping mutable borrows.
unsafe fn usb_frontend_objects() -> (
    &'static mut PmpUsbHid,
    &'static mut PmpUsbDevice,
    &'static mut PmpUsbCtaphid,
) {
    unsafe {
        (
            &mut *PMP_USB_HID_PTR,
            &mut *PMP_USB_DEVICE_PTR,
            &mut *PMP_USB_CTAPHID_PTR,
        )
    }
}

#[cfg(feature = "riscv-pmp-usb-frontend")]
/// # Safety
/// Require initialized shared HID/device pointers and end prior mutable borrows before re-entry.
unsafe fn usb_frontend_transport() -> (&'static mut PmpUsbHid, &'static mut PmpUsbDevice) {
    unsafe { (&mut *PMP_USB_HID_PTR, &mut *PMP_USB_DEVICE_PTR) }
}

#[cfg(all(
    feature = "riscv-pmp-usb-frontend",
    not(feature = "riscv-pmp-usb-internal-ccid")
))]
/// # Safety
/// Require initialized shared CTAPHID and sole frontend ownership; end every earlier mutable borrow.
unsafe fn usb_frontend_ctaphid() -> &'static mut PmpUsbCtaphid {
    unsafe { &mut *PMP_USB_CTAPHID_PTR }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.pmp_user_usb_frontend")]
#[cfg(not(feature = "riscv-pmp-usb-frontend"))]
extern "C" fn _pmp_u_usb_frontend_entry() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
