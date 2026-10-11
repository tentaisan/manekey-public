const ACCESSCTRL_BASE: usize = 0x4006_0000;
const ACCESSCTRL_PASSWORD: u32 = 0xacce_0000;
const ACCESSCTRL_ALLOW_ALL: u32 = ACCESSCTRL_PASSWORD | 0xff;
const GPIO_NSMASK0_OFFSET: usize = 0x0c;
const USBCTRL_OFFSET: usize = 0x48;
const DMA_OFFSET: usize = 0x44;
const PIO0_OFFSET: usize = 0x4c;
const TIMER0_OFFSET: usize = 0x98;
const TRNG_OFFSET: usize = 0xb4;
#[cfg(feature = "riscv-client-pin-sha256")]
const SHA256_OFFSET: usize = 0xb8;
#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
const CYW43_PIO_GPIO_NSMASK0: u32 = (1 << 24) | (1 << 29);
#[cfg(any(
    feature = "riscv-pmp-usb-frontend",
    feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental"
))]
/// M-mode startup delegation of USB/TIMER0; CPU PMP and DMA-master protection remain separate obligations.
pub fn configure_pmp_usb_accessctrl() {
    unsafe {
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + USBCTRL_OFFSET) as *mut u32,
            ACCESSCTRL_ALLOW_ALL,
        );
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + TIMER0_OFFSET) as *mut u32,
            ACCESSCTRL_ALLOW_ALL,
        );
    }
}

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
/// Delegate configured PIO0/TIMER0 before publishing GPIO ownership; execute under the exclusive monitor.
pub fn configure_pmp_ble_accessctrl() {
    unsafe {
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + PIO0_OFFSET) as *mut u32,
            ACCESSCTRL_ALLOW_ALL,
        );
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + TIMER0_OFFSET) as *mut u32,
            ACCESSCTRL_ALLOW_ALL,
        );
    }
}

#[cfg(feature = "riscv-pmp-ble-monitor-dma-policy")]
/// Delegate DMA and user SRAM banks only with the matching channel attribution and DMA MPU policy.
pub fn configure_pmp_ble_dma_accessctrl() {
    const SRAM0_OFFSET: usize = 0x1c;
    unsafe {
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + DMA_OFFSET) as *mut u32,
            ACCESSCTRL_ALLOW_ALL,
        );

        for bank in 4..8 {
            core::ptr::write_volatile(
                (ACCESSCTRL_BASE + SRAM0_OFFSET + bank * 4) as *mut u32,
                ACCESSCTRL_ALLOW_ALL,
            );
        }
    }
}

#[cfg(feature = "riscv-pmp-trusted-trng")]
pub fn configure_pmp_trusted_accessctrl() {
    unsafe {
        #[cfg(feature = "riscv-pmp-usb-internal-ccid")]
        {
            let access = &*rp235x_hal::pac::ACCESSCTRL::ptr();
            access.uart0().write(|w| {
                w.bits(
                    ACCESSCTRL_PASSWORD
                        | manekey::security::Rp2350AccessPermissions::SECURE_ONLY.bits(),
                )
            });
        }
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + TRNG_OFFSET) as *mut u32,
            ACCESSCTRL_PASSWORD | manekey::security::Rp2350AccessPermissions::SECURE_ONLY.bits(),
        );
        #[cfg(feature = "riscv-client-pin-sha256")]
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + SHA256_OFFSET) as *mut u32,
            ACCESSCTRL_PASSWORD | manekey::security::Rp2350AccessPermissions::SECURE_ONLY.bits(),
        );
    }
}

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
/// Publish only DIO/CLK after PIO delegation; power/CS remain monitor-owned.
pub fn publish_pmp_ble_gpio_ownership() {
    unsafe {
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + GPIO_NSMASK0_OFFSET) as *mut u32,
            CYW43_PIO_GPIO_NSMASK0,
        );
    }
}
