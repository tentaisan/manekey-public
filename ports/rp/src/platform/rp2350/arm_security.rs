use manekey::security::{NonsecureVector, Rp2350AccessPermissions, layout};

/// # Safety
/// Require the fixed Non-Secure vector region to be readable; validate the returned vector before handoff.
pub unsafe fn read_nonsecure_vector() -> NonsecureVector {
    let vectors = layout::NONSECURE_FLASH_START as *const u32;
    NonsecureVector {
        main_stack_pointer: unsafe { core::ptr::read_volatile(vectors) },
        reset_handler: unsafe { core::ptr::read_volatile(vectors.add(1)) },
    }
}

/// Secure startup only; exclusively own SAU with matching split-image linker regions before NS entry.
pub fn configure_arm_sau(sau: &mut cortex_m::peripheral::SAU) {
    use cortex_m::peripheral::sau::{SauRegion, SauRegionAttribute};

    assert!(sau.region_numbers() >= 3);
    sau.set_region(
        0,
        SauRegion {
            base_address: layout::NSC_FLASH_START,
            limit_address: layout::NSC_FLASH_END,
            attribute: SauRegionAttribute::NonSecureCallable,
        },
    )
    .expect("configure NSC flash SAU region");
    sau.set_region(
        1,
        SauRegion {
            base_address: layout::NONSECURE_FLASH_START,
            limit_address: layout::NONSECURE_FLASH_END,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .expect("configure Non-secure flash SAU region");
    sau.set_region(
        2,
        SauRegion {
            base_address: layout::NONSECURE_RAM_START,
            limit_address: layout::NONSECURE_RAM_END,
            attribute: SauRegionAttribute::NonSecure,
        },
    )
    .expect("configure Non-secure SRAM SAU region");
    sau.enable();
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "trustzone-handoff")]
/// Secure startup permission for NS hard-float code; context/state isolation remains the runtime's responsibility.
pub fn grant_arm_fpu_to_nonsecure() {
    const NSACR: *mut u32 = 0xe000_ed8c as *mut u32;
    const CP10_CP11: u32 = 0b11 << 10;
    unsafe {
        core::ptr::write_volatile(NSACR, core::ptr::read_volatile(NSACR) | CP10_CP11);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "trustzone-handoff")]
/// Secure startup attribution for matching split images; DMA master policy is a separate obligation.
pub fn configure_rp2350_memory_access() {
    const XIP_MAIN_OFFSET: usize = 0x18;
    const SRAM0_OFFSET: usize = 0x1c;
    const IO_BANK0_OFFSET: usize = 0x68;
    const PADS_BANK0_OFFSET: usize = 0x70;
    const TRNG_OFFSET: usize = 0xb4;
    const SHA256_OFFSET: usize = 0xb8;
    const RESETS_OFFSET: usize = 0x64;
    const CLOCKS_OFFSET: usize = 0xc0;
    const ROSC_OFFSET: usize = 0xc8;
    const PLL_SYS_OFFSET: usize = 0xcc;
    const PLL_USB_OFFSET: usize = 0xd0;
    const TICKS_OFFSET: usize = 0xd4;

    unsafe {
        write_rp2350_accessctrl(
            XIP_MAIN_OFFSET,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE,
        );
    }
    for bank in 0..4 {
        unsafe {
            write_rp2350_accessctrl(
                SRAM0_OFFSET + bank * 4,
                Rp2350AccessPermissions::SECURE_ONLY,
            );
        }
    }
    for bank in 4..10 {
        #[cfg(all(
            feature = "trustzone-usb-ble-secure-experimental",
            not(feature = "rp2350-cyw43-polling")
        ))]
        let permissions = Rp2350AccessPermissions::SECURE_AND_NONSECURE_DMA;
        #[cfg(any(
            not(feature = "trustzone-usb-ble-secure-experimental"),
            feature = "rp2350-cyw43-polling"
        ))]
        let permissions = Rp2350AccessPermissions::SECURE_AND_NONSECURE;
        unsafe {
            write_rp2350_accessctrl(SRAM0_OFFSET + bank * 4, permissions);
        }
    }
    unsafe {
        write_rp2350_accessctrl(IO_BANK0_OFFSET, Rp2350AccessPermissions::SECURE_ONLY);
        write_rp2350_accessctrl(PADS_BANK0_OFFSET, Rp2350AccessPermissions::SECURE_ONLY);
        write_rp2350_accessctrl(TRNG_OFFSET, Rp2350AccessPermissions::SECURE_ONLY);
        write_rp2350_accessctrl(SHA256_OFFSET, Rp2350AccessPermissions::SECURE_ONLY);

        for offset in [
            RESETS_OFFSET,
            CLOCKS_OFFSET,
            ROSC_OFFSET,
            PLL_SYS_OFFSET,
            PLL_USB_OFFSET,
            TICKS_OFFSET,
        ] {
            write_rp2350_accessctrl(offset, Rp2350AccessPermissions::SECURE_ONLY);
        }

        core::ptr::write_volatile(0x4006_000c as *mut u32, 0);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

/// Normal non-isolated startup only before HAL initialization; never call from the Secure split image.
pub fn configure_rp2350_normal_access() {
    const XIP_MAIN_OFFSET: usize = 0x18;
    const SRAM0_OFFSET: usize = 0x1c;
    const DMA_OFFSET: usize = 0x44;
    const PIO0_OFFSET: usize = 0x4c;
    const RESETS_OFFSET: usize = 0x64;
    const IO_BANK0_OFFSET: usize = 0x68;
    const PADS_BANK0_OFFSET: usize = 0x70;
    const USBCTRL_OFFSET: usize = 0x48;
    const TIMER0_OFFSET: usize = 0x98;
    const UART0_OFFSET: usize = 0xa0;
    const TRNG_OFFSET: usize = 0xb4;
    const CLOCKS_OFFSET: usize = 0xc0;
    const ROSC_OFFSET: usize = 0xc8;
    const PLL_SYS_OFFSET: usize = 0xcc;
    const PLL_USB_OFFSET: usize = 0xd0;
    const TICKS_OFFSET: usize = 0xd4;

    unsafe {
        write_rp2350_accessctrl(
            XIP_MAIN_OFFSET,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE_CORE0_CORE1_DMA,
        );
        for bank in 0..10 {
            write_rp2350_accessctrl(
                SRAM0_OFFSET + bank * 4,
                Rp2350AccessPermissions::SECURE_AND_NONSECURE_CORE0_CORE1_DMA,
            );
        }
        for offset in [
            DMA_OFFSET,
            PIO0_OFFSET,
            RESETS_OFFSET,
            IO_BANK0_OFFSET,
            PADS_BANK0_OFFSET,
            USBCTRL_OFFSET,
            TIMER0_OFFSET,
            UART0_OFFSET,
            TRNG_OFFSET,
            CLOCKS_OFFSET,
            ROSC_OFFSET,
            PLL_SYS_OFFSET,
            PLL_USB_OFFSET,
            TICKS_OFFSET,
        ] {
            write_rp2350_accessctrl(
                offset,
                Rp2350AccessPermissions::SECURE_AND_NONSECURE_CORE0_CORE1_DMA,
            );
        }
        core::ptr::write_volatile(0x4006_000c as *mut u32, u32::MAX);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "trustzone-handoff")]
/// Delegate initialized USB and its IRQ exclusively; Secure retains clock/reset ownership.
pub fn grant_rp2350_usb_to_nonsecure() {
    const USBCTRL_OFFSET: usize = 0x48;
    unsafe {
        write_rp2350_accessctrl(
            USBCTRL_OFFSET,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE,
        );
    }

    const NVIC_ICER0: *mut u32 = 0xe000_e180 as *mut u32;
    const NVIC_ICPR0: *mut u32 = 0xe000_e280 as *mut u32;
    const NVIC_ITNS0: *mut u32 = 0xe000_e380 as *mut u32;
    const USBCTRL_IRQ_MASK: u32 = 1 << 14;

    unsafe {
        core::ptr::write_volatile(NVIC_ICER0, USBCTRL_IRQ_MASK);
        core::ptr::write_volatile(NVIC_ICPR0, USBCTRL_IRQ_MASK);
        let targets = core::ptr::read_volatile(NVIC_ITNS0);
        core::ptr::write_volatile(NVIC_ITNS0, targets | USBCTRL_IRQ_MASK);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "trustzone-handoff")]
/// Delegate initialized TIMER0 and IRQ0; reserve alarm ownership against competing consumers.
pub fn grant_rp2350_timer0_alarm0_to_nonsecure() {
    const TIMER0_OFFSET: usize = 0x98;
    unsafe {
        write_rp2350_accessctrl(TIMER0_OFFSET, Rp2350AccessPermissions::SECURE_AND_NONSECURE);
    }

    const NVIC_ICER0: *mut u32 = 0xe000_e180 as *mut u32;
    const NVIC_ICPR0: *mut u32 = 0xe000_e280 as *mut u32;
    const NVIC_ITNS0: *mut u32 = 0xe000_e380 as *mut u32;
    const TIMER0_IRQ_0_MASK: u32 = 1;
    unsafe {
        core::ptr::write_volatile(NVIC_ICER0, TIMER0_IRQ_0_MASK);
        core::ptr::write_volatile(NVIC_ICPR0, TIMER0_IRQ_0_MASK);
        let targets = core::ptr::read_volatile(NVIC_ITNS0);
        core::ptr::write_volatile(NVIC_ITNS0, targets | TIMER0_IRQ_0_MASK);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "rp-internal-uart")]
/// Delegate UART0/GP0/GP1 for polling; IO bank delegation is not per-pin CTRL secrecy.
pub fn grant_rp2350_uart0_to_nonsecure() {
    unsafe {
        write_rp2350_accessctrl(0xa0, Rp2350AccessPermissions::SECURE_AND_NONSECURE);
        write_rp2350_accessctrl(0x68, Rp2350AccessPermissions::SECURE_AND_NONSECURE);

        for pin in [0, 1] {
            rp_pac::PADS_BANK0.gpio(pin).write(|w| {
                w.set_iso(false);
                w.set_ie(true);
                w.set_schmitt(true);
            });
        }
        let mask = core::ptr::read_volatile(0x4006_000c as *const u32);
        core::ptr::write_volatile(0x4006_000c as *mut u32, mask | 3);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(all(
    feature = "trustzone-usb-ble-secure-experimental",
    not(feature = "rp2350-cyw43-polling")
))]
/// Secure startup DMA/PIO delegation requiring idle exclusive channels, DMA MPU and matching NS buffers.
/// Pad/control bank delegation is broader than per-pin ownership.
pub fn grant_rp2350_cyw43_to_nonsecure() {
    const DMA_OFFSET: usize = 0x44;
    const PIO0_OFFSET: usize = 0x4c;
    const IO_BANK0_OFFSET: usize = 0x68;
    const PADS_BANK0_OFFSET: usize = 0x70;
    const DMA: usize = 0x5000_0000;
    unsafe {
        write_rp2350_accessctrl(
            PIO0_OFFSET,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE_DMA,
        );
        for offset in [DMA_OFFSET, IO_BANK0_OFFSET] {
            write_rp2350_accessctrl(offset, Rp2350AccessPermissions::SECURE_AND_NONSECURE);
        }

        for pin in [23, 25] {
            rp_pac::PADS_BANK0.gpio(pin).write(|w| {
                w.set_iso(false);
                w.set_ie(true);
            });
        }
        for pin in [24, 29] {
            rp_pac::PADS_BANK0.gpio(pin).write(|w| {
                w.set_iso(false);
                w.set_ie(true);
                w.set_schmitt(true);
                w.set_drive(rp_pac::pads::vals::Drive::_12mA);
                w.set_slewfast(true);
            });
        }

        write_rp2350_accessctrl(
            PADS_BANK0_OFFSET,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE_UNPRIVILEGED,
        );

        core::ptr::write_volatile(0x4006_000c as *mut u32, 0x2380_0000);

        core::ptr::write_volatile((DMA + 0x480) as *mut u32, 0x1);
        core::ptr::write_volatile((DMA + 0x484) as *mut u32, 0x1);
        core::ptr::write_volatile((DMA + 0x4c0) as *mut u32, 0x1);
        core::ptr::write_volatile((DMA + 0x500) as *mut u32, 0x6);
        core::ptr::write_volatile((DMA + 0x504) as *mut u32, 0x2004_0000);
        core::ptr::write_volatile((DMA + 0x508) as *mut u32, 0x2008_1fe3);
        core::ptr::write_volatile((DMA + 0x50c) as *mut u32, 0x5020_0000);
        core::ptr::write_volatile((DMA + 0x510) as *mut u32, 0x5020_3fe3);

        const NVIC_ICER0: *mut u32 = 0xe000_e180 as *mut u32;
        const NVIC_ICPR0: *mut u32 = 0xe000_e280 as *mut u32;
        const NVIC_ITNS0: *mut u32 = 0xe000_e380 as *mut u32;
        let mask = (1 << (rp_pac::Interrupt::PIO0_IRQ_0 as u32))
            | (1 << (rp_pac::Interrupt::DMA_IRQ_0 as u32));
        core::ptr::write_volatile(NVIC_ICER0, mask);
        core::ptr::write_volatile(NVIC_ICPR0, mask);
        let targets = core::ptr::read_volatile(NVIC_ITNS0);
        core::ptr::write_volatile(NVIC_ITNS0, targets | mask);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(all(
    feature = "trustzone-usb-ble-secure-experimental",
    feature = "rp2350-cyw43-polling"
))]
/// Secure startup polling delegation; reset and close DMA before NS entry, with exclusive PIO/pin ownership.
/// Bank-level pad/control delegation does not provide per-pin isolation.
pub fn grant_rp2350_cyw43_to_nonsecure() {
    unsafe {
        rp_pac::RESETS.reset().modify(|w| w.set_dma(true));
        write_rp2350_accessctrl(0x44, Rp2350AccessPermissions::SECURE_ONLY);
        rp_pac::RESETS.reset().modify(|w| w.set_dma(false));
        while !rp_pac::RESETS.reset_done().read().dma() {
            core::hint::spin_loop();
        }
        rp_pac::RESETS.reset().modify(|w| w.set_pio0(false));
        while !rp_pac::RESETS.reset_done().read().pio0() {
            core::hint::spin_loop();
        }
        write_rp2350_accessctrl(0x4c, Rp2350AccessPermissions::SECURE_AND_NONSECURE);
        write_rp2350_accessctrl(0x68, Rp2350AccessPermissions::SECURE_AND_NONSECURE);

        for pin in [23, 24, 25, 29] {
            rp_pac::PADS_BANK0.gpio(pin).write(|w| {
                w.set_iso(false);
                w.set_ie(true);
                w.set_schmitt(true);
                w.set_drive(rp_pac::pads::vals::Drive::_12mA);
                w.set_slewfast(true);
            });
        }
        write_rp2350_accessctrl(
            0x70,
            Rp2350AccessPermissions::SECURE_AND_NONSECURE_UNPRIVILEGED,
        );
        let mask = core::ptr::read_volatile(0x4006_000c as *const u32);
        core::ptr::write_volatile(0x4006_000c as *mut u32, mask | 0x2380_0000);
        let irq = 1 << (rp_pac::Interrupt::PIO0_IRQ_0 as u32);
        let dma_irqs = (1 << (rp_pac::Interrupt::DMA_IRQ_0 as u32))
            | (1 << (rp_pac::Interrupt::DMA_IRQ_1 as u32))
            | (1 << (rp_pac::Interrupt::DMA_IRQ_2 as u32))
            | (1 << (rp_pac::Interrupt::DMA_IRQ_3 as u32));
        core::ptr::write_volatile(0xe000_e180 as *mut u32, irq | dma_irqs);
        core::ptr::write_volatile(0xe000_e280 as *mut u32, irq | dma_irqs);
        let targets = core::ptr::read_volatile(0xe000_e380 as *const u32);
        core::ptr::write_volatile(0xe000_e380 as *mut u32, (targets & !dma_irqs) | irq);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

unsafe fn write_rp2350_accessctrl(offset: usize, permissions: Rp2350AccessPermissions) {
    const ACCESSCTRL_BASE: usize = 0x4006_0000;
    const ACCESSCTRL_PASSWORD: u32 = 0xacce_0000;
    unsafe {
        core::ptr::write_volatile(
            (ACCESSCTRL_BASE + offset) as *mut u32,
            ACCESSCTRL_PASSWORD | permissions.bits(),
        );
    }
}

#[cfg(feature = "trustzone-handoff")]
/// # Safety
/// Require validated matching NS image/vector and complete memory/peripheral/IRQ attribution before crossing domains.
pub unsafe fn handoff_arm_nonsecure(
    sau: &mut cortex_m::peripheral::SAU,
    vector: NonsecureVector,
) -> ! {
    let vector = vector.validate().expect("validate Non-secure reset vector");

    configure_arm_sau(sau);

    const VTOR_NS: *mut u32 = 0xe002_ed08 as *mut u32;
    unsafe {
        core::ptr::write_volatile(VTOR_NS, layout::NONSECURE_FLASH_START);
        cortex_m::register::msp::write_ns(vector.main_stack_pointer);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    unsafe {
        cortex_m::asm::bx_ns(vector.bxns_address());
    }

    loop {
        cortex_m::asm::wfi();
    }
}
