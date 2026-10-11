use core::arch::asm;

use esp_hal::riscv::register::{
    Permission, Range, pmpaddr3, pmpaddr4, pmpaddr5, pmpaddr6, pmpaddr14, pmpcfg0, pmpcfg1, pmpcfg3,
};
use manekey::boundary::riscv_pmp::{EcallIslandLayout, napot_csr_addr};

pub const CPU_APM_BASE: usize = 0x6009_a000;
pub const C5_PERIPHERAL_MMIO_BASE: usize = 0x6000_0000;
pub const C5_PERIPHERAL_MMIO_SIZE: usize = 1024 * 1024;
pub const C5_USER_FLASH_BASE: usize = 0x4200_0000;
pub const C5_USER_FLASH_SIZE: usize = 512 * 1024;

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

pub fn ecall_island_layout(
    layout: BoundaryLayout,
    user_stack: TorRegion,
) -> Option<EcallIslandLayout> {
    let common = EcallIslandLayout::new(
        layout.user_text.start,
        layout.user_text.end.checked_sub(layout.user_text.start)?,
        layout.shared.start,
        layout.shared.end.checked_sub(layout.shared.start)?,
        user_stack.start,
        user_stack.end.checked_sub(user_stack.start)?,
    );
    common.is_valid().then_some(common)
}

/// Broadens REE0 SRAM access; require exclusive CPU_APM ownership and install the narrow PMP policy before U-mode execution.
pub fn configure_ree0_sram_rw() -> bool {
    let attr = unsafe { ((CPU_APM_BASE + 0x0c) as *const u32).read_volatile() };
    unsafe {
        ((CPU_APM_BASE + 0x0c) as *mut u32).write_volatile(attr | 0x06);
        asm!("fence iorw, iorw");
        ((CPU_APM_BASE + 0xdc) as *mut u32).write_volatile(1);
    }
    unsafe { ((CPU_APM_BASE + 0x0c) as *const u32).read_volatile() == attr | 0x06 }
}

/// Install the BLE-less C5 policy; physical peripherals remain M-mode-owned.
///
/// # Safety
/// Own the selected unlocked PMP entries and supply valid aligned linker regions compatible with the boot table.
/// Reserve the whole U-data island exclusively; every U-mode object must fit the permitted island/stack.
/// Install a working private trap stack/vector and keep MPRV disabled.
pub unsafe fn install_product(layout: BoundaryLayout, user_stack: TorRegion) {
    let user_base = layout.shared.start & !65535;
    assert!(user_base.is_multiple_of(65536));
    assert_eq!(layout.shared.start, user_base + 4096);
    assert!(layout.shared.end <= user_stack.start && user_stack.end == user_base + 65536);
    assert!(layout.machine_private.start >= user_stack.end);
    assert!(layout.user_text.end <= C5_USER_FLASH_BASE + C5_USER_FLASH_SIZE);
    assert_eq!(
        pmpcfg0::read().bits & 0x8000_0000,
        0,
        "C5 PMP entry 3 locked"
    );
    assert_eq!(
        pmpcfg1::read().bits & 0x0080_8080,
        0,
        "C5 PMP entry 4/5/6 locked"
    );
    assert_eq!(
        pmpcfg3::read().bits & 0x0080_0000,
        0,
        "C5 PMP entry 14 locked"
    );
    unsafe {
        pmpcfg0::set_pmp(3, Range::OFF, Permission::NONE, false);
        pmpcfg1::set_pmp(0, Range::OFF, Permission::NONE, false);
        pmpcfg1::set_pmp(1, Range::OFF, Permission::NONE, false);
        pmpaddr3::write(napot_csr_addr(user_base, 4096));
        pmpcfg0::set_pmp(3, Range::NAPOT, Permission::R, false);
        pmpaddr4::write(napot_csr_addr(user_base, 65536));
        pmpcfg1::set_pmp(0, Range::NAPOT, Permission::RW, false);
        pmpaddr5::write(napot_csr_addr(0x4080_0000, 512 * 1024));
        pmpcfg1::set_pmp(1, Range::NAPOT, Permission::NONE, false);
        pmpaddr6::write(napot_csr_addr(C5_USER_FLASH_BASE, C5_USER_FLASH_SIZE));
        pmpcfg1::set_pmp(2, Range::NAPOT, Permission::RX, false);

        pmpaddr14::write(napot_csr_addr(
            C5_PERIPHERAL_MMIO_BASE,
            C5_PERIPHERAL_MMIO_SIZE,
        ));
        pmpcfg3::set_pmp(2, Range::NAPOT, Permission::NONE, false);
        asm!("fence iorw, iorw", "fence.i");
    }
    assert_eq!(pmpcfg0::read().bits >> 24, 0x19);
    assert_eq!(pmpcfg1::read().bits & 0x00ff_ffff, 0x001d_181b);
    assert_eq!((pmpcfg3::read().bits >> 16) & 0xff, 0x18);
    assert_eq!(pmpaddr3::read(), napot_csr_addr(user_base, 4096));
    assert_eq!(pmpaddr4::read(), napot_csr_addr(user_base, 65536));
    assert_eq!(pmpaddr5::read(), napot_csr_addr(0x4080_0000, 512 * 1024));
    assert_eq!(
        pmpaddr6::read(),
        napot_csr_addr(C5_USER_FLASH_BASE, C5_USER_FLASH_SIZE)
    );
    assert_eq!(
        pmpaddr14::read(),
        napot_csr_addr(C5_PERIPHERAL_MMIO_BASE, C5_PERIPHERAL_MMIO_SIZE)
    );
}
