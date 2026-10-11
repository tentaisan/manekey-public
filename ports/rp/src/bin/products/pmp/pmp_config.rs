use manekey_rp::platform::rp2350::pmp::{self as riscv_pmp, PMP_NAPOT, PMP_R, PMP_W, PMP_X};

use super::pmp_csr::write_ecall_island_config;

use super::pmp_led::blink_unexpected_trap;
use super::pmp_memory::{
    __pmp_shared_end, __pmp_shared_start, __pmp_user_async_end, __pmp_user_async_start,
    __pmp_user_stack_end, __pmp_user_stack_start, __pmp_user_text_end, __pmp_user_text_start,
};

use super::pmp_report;

/// # Safety
/// M-mode startup only, before user entry; replace the temporary permissive entry with final policy before mret.
pub unsafe fn pmp_config_write_readback_works() -> bool {
    let cfg = PMP_R | PMP_W | PMP_X | PMP_NAPOT;
    let readback: usize;
    unsafe {
        core::arch::asm!(
            "li t0, -1",
            "csrw pmpaddr0, t0",
            "csrw pmpcfg0, {cfg}",
            "csrr {readback}, pmpcfg0",
            cfg = in(reg) cfg,
            readback = lateout(reg) readback,
            options(nostack),
        );
    }
    readback & 0xff == cfg
}

/// # Safety
/// Install before user entry with exclusive PMP ownership and matching linker/peripheral delegation.
pub unsafe fn configure_ecall_island_pmp() {
    let expected = expected_ecall_island_pmp_readback();
    unsafe {
        write_ecall_island_config(expected);
    }
}

pub fn expected_ecall_island_pmp_readback() -> riscv_pmp::EcallIslandPmpConfig {
    if cfg!(feature = "riscv-pmp-ble-monitor-image") {
        if cfg!(feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental") {
            return riscv_pmp::EcallIslandPmpConfig::new_ble_split_multi_transport();
        }
        if cfg!(feature = "riscv-pmp-ble-monitor-dma-policy") {
            return riscv_pmp::EcallIslandPmpConfig::new_ble_split_dma();
        }
        return riscv_pmp::EcallIslandPmpConfig::new_ble_split();
    }
    let user_text_base = if cfg!(feature = "riscv-pmp-usb-frontend") {
        0x1000_0000
    } else {
        (&raw const __pmp_user_text_start) as usize
    };
    let user_text_size = if cfg!(feature = "riscv-pmp-usb-frontend") {
        512 * 1024
    } else {
        pmp_region_size(
            (&raw const __pmp_user_text_start) as usize,
            (&raw const __pmp_user_text_end) as usize,
        )
    };
    let layout = riscv_pmp::EcallIslandLayout::new(
        user_text_base,
        user_text_size,
        (&raw const __pmp_shared_start) as usize,
        pmp_region_size(
            (&raw const __pmp_shared_start) as usize,
            (&raw const __pmp_shared_end) as usize,
        ),
        (&raw const __pmp_user_stack_start) as usize,
        pmp_region_size(
            (&raw const __pmp_user_stack_start) as usize,
            (&raw const __pmp_user_stack_end) as usize,
        ),
    );
    if cfg!(feature = "riscv-pmp-ble-mmio-runtime") {
        riscv_pmp::EcallIslandPmpConfig::new_ble_mmio(riscv_pmp::BleEcallIslandLayout {
            common: layout,
            user_async_base: (&raw const __pmp_user_async_start) as usize,
            user_async_size: pmp_region_size(
                (&raw const __pmp_user_async_start) as usize,
                (&raw const __pmp_user_async_end) as usize,
            ),
        })
    } else {
        riscv_pmp::EcallIslandPmpConfig::new(layout)
    }
}

fn pmp_region_size(start: usize, end: usize) -> usize {
    let size = end.saturating_sub(start);
    if !pmp_report::is_napot_region(start, size) {
        blink_unexpected_trap();
    }
    size
}
