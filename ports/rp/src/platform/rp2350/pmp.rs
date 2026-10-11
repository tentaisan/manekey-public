pub use manekey::boundary::riscv_pmp::{EcallIslandLayout, napot_csr_addr};
use manekey::{
    boundary::riscv_pmp::PermissionEncoding,
    security::policy::{self, Access, Asset, PmpRule},
};

pub const USBCTRL_REGS_BASE: usize = 0x5011_0000;
pub const USBCTRL_REGS_PMP_SIZE: usize = 4096;

pub const USB_DPRAM_BASE: usize = 0x5010_0000;
pub const USB_DPRAM_PMP_SIZE: usize = 4096;

pub const PIO0_BASE: usize = 0x5020_0000;
pub const PIO0_PMP_SIZE: usize = 4096;

pub const DMA_BASE: usize = 0x5000_0000;
pub const DMA_PMP_SIZE: usize = 4096;
pub const TIMER0_BASE: usize = 0x400b_0000;
pub const TIMER0_PMP_SIZE: usize = 4096;

pub const SIO_BASE: usize = 0xd000_0000;
pub const SIO_PMP_SIZE: usize = 4096;

pub const PMP_BLE_MONITOR_FLASH_BASE: usize = 0x1000_0000;
pub const PMP_BLE_MONITOR_FLASH_SIZE: usize = 1024 * 1024;
pub const PMP_BLE_USER_FLASH_BASE: usize = 0x1010_0000;
pub const PMP_BLE_USER_FLASH_SIZE: usize = 1024 * 1024;
pub const PMP_BLE_MONITOR_RAM_BASE: usize = 0x2000_0000;
#[cfg(feature = "riscv-pmp-ble-monitor-ml-dsa-layout")]
pub const PMP_BLE_MONITOR_RAM_SIZE: usize = 256 * 1024;
#[cfg(not(feature = "riscv-pmp-ble-monitor-ml-dsa-layout"))]
pub const PMP_BLE_MONITOR_RAM_SIZE: usize = 128 * 1024;
pub const PMP_BLE_USER_RAM_BASE: usize = 0x2004_0000;
pub const PMP_BLE_USER_RAM_SIZE: usize = 256 * 1024;
pub const PMP_BLE_SHARED_ABI_BASE: usize = PMP_BLE_USER_RAM_BASE;
pub const PMP_BLE_SHARED_ABI_SIZE: usize = 4 * 1024;
pub const PMP_BLE_USER_WRITABLE_RAM_BASE: usize = PMP_BLE_SHARED_ABI_BASE + PMP_BLE_SHARED_ABI_SIZE;
pub const PMP_BLE_USER_WRITABLE_RAM_END: usize = PMP_BLE_USER_RAM_BASE + PMP_BLE_USER_RAM_SIZE;
pub const PMP_BLE_USER_STACK_TOP: usize = PMP_BLE_USER_RAM_BASE + PMP_BLE_USER_RAM_SIZE;
pub const RP2350_FLASH_END: usize = 0x1040_0000;
pub const RP2350_STORAGE_START: usize = RP2350_FLASH_END - 16 * 1024;

pub const RP2350_HAZARD3_E6_PERMISSION_ENCODING: PermissionEncoding = PermissionEncoding {
    read: 0b100,
    write: 0b010,
    execute: 0b001,
    napot: 0b11 << 3,
};

pub const PMP_R: usize = RP2350_HAZARD3_E6_PERMISSION_ENCODING.read;
pub const PMP_W: usize = RP2350_HAZARD3_E6_PERMISSION_ENCODING.write;
pub const PMP_X: usize = RP2350_HAZARD3_E6_PERMISSION_ENCODING.execute;
pub const PMP_NAPOT: usize = RP2350_HAZARD3_E6_PERMISSION_ENCODING.napot;

pub const fn pmp_cfg_for_access(access: Access) -> usize {
    RP2350_HAZARD3_E6_PERMISSION_ENCODING.cfg_for_access(access)
}

pub fn pmp_cfg_for_policy_asset(asset: Asset) -> usize {
    match policy::find_policy_entry(asset).map(|entry| entry.pmp_rule) {
        Some(PmpRule::Allow(access)) => pmp_cfg_for_access(access),
        _ => 0,
    }
}

pub const fn napot_csr_readback_addr(csr_addr: usize) -> usize {
    csr_addr & !0x3
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Active-linker layout; require valid aligned non-overlapping NAPOT memory regions.
pub struct BleEcallIslandLayout {
    pub common: EcallIslandLayout,
    pub user_async_base: usize,
    pub user_async_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Hazard3 CPU PMP configuration; peripheral ACCESSCTRL and DMA-master protection are independent.
pub struct EcallIslandPmpConfig {
    pub pmpcfg0: usize,
    pub pmpcfg1: usize,
    pub pmpaddr0: usize,
    pub pmpaddr1: usize,
    pub pmpaddr2: usize,
    pub pmpaddr3: usize,
    pub pmpaddr4: usize,
    pub pmpaddr5: usize,
    pub pmpaddr6: usize,
}

impl EcallIslandPmpConfig {
    pub fn new(layout: EcallIslandLayout) -> Self {
        Self {
            pmpcfg0: pmp_cfg_for_policy_asset(Asset::UserText)
                | (pmp_cfg_for_policy_asset(Asset::SharedCallBuffer) << 8)
                | (pmp_cfg_for_policy_asset(Asset::UserStack) << 16)
                | (pmp_cfg_for_policy_asset(Asset::UsbController) << 24),
            pmpcfg1: pmp_cfg_for_policy_asset(Asset::UsbController)
                | (pmp_cfg_for_policy_asset(Asset::Timer) << 8)
                | (pmp_cfg_for_access(Access::READ_WRITE) << 16),
            pmpaddr0: napot_csr_addr(layout.user_text.base, layout.user_text.size),
            pmpaddr1: napot_csr_addr(layout.shared.base, layout.shared.size),
            pmpaddr2: napot_csr_addr(layout.user_stack.base, layout.user_stack.size),
            pmpaddr3: napot_csr_addr(USBCTRL_REGS_BASE, USBCTRL_REGS_PMP_SIZE),
            pmpaddr4: napot_csr_addr(USB_DPRAM_BASE, USB_DPRAM_PMP_SIZE),
            pmpaddr5: napot_csr_addr(TIMER0_BASE, TIMER0_PMP_SIZE),
            pmpaddr6: napot_csr_addr(SIO_BASE, SIO_PMP_SIZE),
        }
    }

    pub fn new_ble_mmio(layout: BleEcallIslandLayout) -> Self {
        let read_write = pmp_cfg_for_access(Access::READ_WRITE);
        Self {
            pmpcfg0: pmp_cfg_for_policy_asset(Asset::UserText)
                | (pmp_cfg_for_policy_asset(Asset::SharedCallBuffer) << 8)
                | (pmp_cfg_for_policy_asset(Asset::UserStack) << 16)
                | (pmp_cfg_for_policy_asset(Asset::UserAsyncState) << 24),

            pmpcfg1: read_write,
            pmpaddr0: napot_csr_addr(layout.common.user_text.base, layout.common.user_text.size),
            pmpaddr1: napot_csr_addr(layout.common.shared.base, layout.common.shared.size),
            pmpaddr2: napot_csr_addr(layout.common.user_stack.base, layout.common.user_stack.size),
            pmpaddr3: napot_csr_addr(layout.user_async_base, layout.user_async_size),
            pmpaddr4: napot_csr_addr(TIMER0_BASE, TIMER0_PMP_SIZE),
            pmpaddr5: 0,
            pmpaddr6: 0,
        }
    }

    /// Matching separate-image flash/RAM policy with higher-priority read-only shared ABI.
    pub fn new_ble_split() -> Self {
        let read_only = pmp_cfg_for_access(Access {
            read: true,
            write: false,
            execute: false,
        });
        Self {
            pmpcfg0: pmp_cfg_for_policy_asset(Asset::UserText)
                | (read_only << 8)
                | (pmp_cfg_for_policy_asset(Asset::UserAsyncState) << 16),
            pmpcfg1: 0,
            pmpaddr0: napot_csr_addr(PMP_BLE_USER_FLASH_BASE, PMP_BLE_USER_FLASH_SIZE),
            pmpaddr1: napot_csr_addr(PMP_BLE_SHARED_ABI_BASE, PMP_BLE_SHARED_ABI_SIZE),
            pmpaddr2: napot_csr_addr(PMP_BLE_USER_RAM_BASE, PMP_BLE_USER_RAM_SIZE),
            pmpaddr3: 0,
            pmpaddr4: 0,
            pmpaddr5: 0,
            pmpaddr6: 0,
        }
    }

    pub fn new_ble_split_multi_transport() -> Self {
        let mut config = Self::new_ble_split();
        let read_write = pmp_cfg_for_access(Access::READ_WRITE);
        config.pmpcfg0 |= read_write << 24;
        config.pmpcfg1 |= read_write;
        config.pmpaddr3 = napot_csr_addr(USBCTRL_REGS_BASE, USBCTRL_REGS_PMP_SIZE);
        config.pmpaddr4 = napot_csr_addr(USB_DPRAM_BASE, USB_DPRAM_PMP_SIZE);
        config
    }

    /// Add CPU access to DMA registers only with matching channel attribution and DMA MPU configuration.
    pub fn new_ble_split_dma() -> Self {
        let mut config = Self::new_ble_split();
        config.pmpcfg0 |= pmp_cfg_for_access(Access::READ_WRITE) << 24;
        config.pmpaddr3 = napot_csr_addr(DMA_BASE, DMA_PMP_SIZE);
        config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_readback(
        self,
        pmpcfg0: usize,
        pmpcfg1: usize,
        pmpaddr0: usize,
        pmpaddr1: usize,
        pmpaddr2: usize,
        pmpaddr3: usize,
        pmpaddr4: usize,
        pmpaddr5: usize,
        pmpaddr6: usize,
    ) -> bool {
        self.pmpcfg0 == pmpcfg0
            && self.pmpcfg1 == pmpcfg1
            && ((self.pmpcfg0 & 0xff) == 0 || napot_csr_readback_addr(self.pmpaddr0) == pmpaddr0)
            && (((self.pmpcfg0 >> 8) & 0xff) == 0
                || napot_csr_readback_addr(self.pmpaddr1) == pmpaddr1)
            && (((self.pmpcfg0 >> 16) & 0xff) == 0
                || napot_csr_readback_addr(self.pmpaddr2) == pmpaddr2)
            && (((self.pmpcfg0 >> 24) & 0xff) == 0
                || napot_csr_readback_addr(self.pmpaddr3) == pmpaddr3)
            && ((self.pmpcfg1 & 0xff) == 0 || napot_csr_readback_addr(self.pmpaddr4) == pmpaddr4)
            && (((self.pmpcfg1 >> 8) & 0xff) == 0
                || napot_csr_readback_addr(self.pmpaddr5) == pmpaddr5)
            && (((self.pmpcfg1 >> 16) & 0xff) == 0
                || napot_csr_readback_addr(self.pmpaddr6) == pmpaddr6)
    }
}
