#[cfg(feature = "flash-managed-keys")]
use esp_hal::riscv::register::pmpaddr5;
use esp_hal::riscv::register::{
    Permission, Range, pmpaddr3, pmpaddr4, pmpaddr6, pmpaddr7, pmpaddr9, pmpaddr10, pmpaddr12,
    pmpaddr13, pmpaddr14, pmpcfg0, pmpcfg1, pmpcfg2, pmpcfg3,
};
use manekey::boundary::riscv_pmp::{EcallIslandLayout, napot_csr_addr};

pub const MACHINE_PRIVATE_TOR_LOWER_ENTRY: usize = 3;
pub const MACHINE_PRIVATE_TOR_ENTRY: usize = 4;
pub const SHARED_TOR_LOWER_ENTRY: usize = 6;
pub const SHARED_TOR_ENTRY: usize = 7;
pub const USER_TEXT_TOR_LOWER_ENTRY: usize = 9;
pub const USER_TEXT_TOR_ENTRY: usize = 10;
pub const USER_STACK_TOR_LOWER_ENTRY: usize = 12;
pub const USER_STACK_TOR_ENTRY: usize = 13;
pub const MACHINE_MMIO_DENY_ENTRY: usize = 14;

pub const BOOT_BROAD_RAM_ALLOW_ENTRY: usize = 5;

pub const C6_PERIPHERAL_MMIO_BASE: usize = 0x6000_0000;
pub const C6_PERIPHERAL_MMIO_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy)]
pub struct TorRegion {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy)]
pub struct BoundaryLayout {
    pub machine_private: TorRegion,
    pub shared: TorRegion,
    pub user_text: TorRegion,
}

#[derive(Clone, Copy)]
pub struct BoundaryReadback {
    pub machine_private_lower: usize,
    pub machine_private_top: usize,
    pub shared_lower: usize,
    pub shared_top: usize,
    pub user_text_lower: usize,
    pub user_text_top: usize,
}

pub fn ecall_island_layout(
    layout: BoundaryLayout,
    user_stack: TorRegion,
) -> Option<EcallIslandLayout> {
    let user_text_size = layout.user_text.end.checked_sub(layout.user_text.start)?;
    let shared_size = layout.shared.end.checked_sub(layout.shared.start)?;
    let user_stack_size = user_stack.end.checked_sub(user_stack.start)?;
    let common = EcallIslandLayout::new(
        layout.user_text.start,
        user_text_size,
        layout.shared.start,
        shared_size,
        user_stack.start,
        user_stack_size,
    );
    common.is_valid().then_some(common)
}

/// Encode a caller-aligned TOR bound; low address bits are discarded.
pub const fn tor_addr(addr: usize) -> usize {
    addr >> 2
}

/// Install base ranges; the broad boot RAM allow remains active.
///
/// # Safety
/// Own the selected unlocked PMP entries and provide valid aligned bounds compatible with existing entries.
/// Install a working trap path before changing U-mode access.
pub unsafe fn install(layout: BoundaryLayout) -> BoundaryReadback {
    unsafe {
        pmpaddr3::write(tor_addr(layout.machine_private.start));
        pmpcfg0::set_pmp(3, Range::OFF, Permission::NONE, false);
        pmpaddr4::write(tor_addr(layout.machine_private.end));
        pmpcfg1::set_pmp(0, Range::TOR, Permission::NONE, false);

        pmpaddr6::write(tor_addr(layout.shared.start));
        pmpcfg1::set_pmp(2, Range::OFF, Permission::NONE, false);
        pmpaddr7::write(tor_addr(layout.shared.end));
        pmpcfg1::set_pmp(3, Range::TOR, Permission::RW, false);

        pmpaddr9::write(tor_addr(layout.user_text.start));
        pmpcfg2::set_pmp(1, Range::OFF, Permission::NONE, false);
        pmpaddr10::write(tor_addr(layout.user_text.end));
        pmpcfg2::set_pmp(2, Range::TOR, Permission::RX, false);
    }

    readback()
}

/// Install the BLE-less policy; physical peripherals remain M-mode-owned.
///
/// # Safety
/// Meet install's requirements and own the additional stack, boot-allow and MMIO entries.
/// Place every U-mode RAM object in shared or user_stack, keep ranges aligned and valid, and keep MPRV disabled.
pub unsafe fn install_product(layout: BoundaryLayout, user_stack: TorRegion) -> BoundaryReadback {
    let readback = unsafe { install(layout) };
    unsafe {
        pmpaddr12::write(tor_addr(user_stack.start));
        pmpcfg3::set_pmp(0, Range::OFF, Permission::NONE, false);
        pmpaddr13::write(tor_addr(user_stack.end));
        pmpcfg3::set_pmp(1, Range::TOR, Permission::RW, false);

        pmpcfg1::set_pmp(1, Range::OFF, Permission::NONE, false);
        #[cfg(feature = "flash-managed-keys")]
        {
            pmpaddr5::write(napot_csr_addr(0x423e_0000, 64 * 1024));
            pmpcfg1::set_pmp(1, Range::NAPOT, Permission::NONE, false);
            assert_eq!(pmpaddr5::read(), napot_csr_addr(0x423e_0000, 64 * 1024));
            assert_eq!((pmpcfg1::read().bits >> 8) & 0xff, 0x18);
        }

        pmpaddr14::write(napot_csr_addr(
            C6_PERIPHERAL_MMIO_BASE,
            C6_PERIPHERAL_MMIO_SIZE,
        ));
        pmpcfg3::set_pmp(2, Range::NAPOT, Permission::NONE, false);
    }
    readback
}

pub fn readback() -> BoundaryReadback {
    BoundaryReadback {
        machine_private_lower: pmpaddr3::read(),
        machine_private_top: pmpaddr4::read(),
        shared_lower: pmpaddr6::read(),
        shared_top: pmpaddr7::read(),
        user_text_lower: pmpaddr9::read(),
        user_text_top: pmpaddr10::read(),
    }
}
