use manekey::security::SharedMemoryRegion;

pub const NS_FLASH_START: u32 = 0x0810_0000;
pub const NS_FLASH_END: u32 = 0x081f_6000;
pub const NS_RAM_START: u32 = 0x2004_0000;
pub const NS_RAM_END: u32 = 0x200b_e000;
pub const NSC_START: u32 = 0x0c0f_f000;
pub const NSC_END: u32 = 0x0c10_0000;
pub const NS_UART_START: u32 = 0x4001_3800;
pub const NS_UART_END: u32 = 0x4001_3c00;

pub const SHARED: SharedMemoryRegion = SharedMemoryRegion {
    start: NS_RAM_END,
    end: 0x200c_0000,
};

#[cfg(all(
    feature = "trustzone-nonsecure-image",
    feature = "trustzone-uart-runtime"
))]
/// NS polling ingress; requires Secure-configured clocks/attribution and exclusive UART ownership.
/// TX readiness waiting has no timeout and is not peer delivery acknowledgment.
pub fn run_uart(
    backend: manekey::boundary::arm_gateway::ArmSharedGatewayBackend<'static>,
    on_response: fn(),
) -> ! {
    use manekey::{
        ctaphid::trusted::TRUSTED_RESPONSE_MAX,
        frontend::{
            ingress::IngressArbiter,
            internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
        },
    };
    let uart = embassy_stm32::pac::USART1;
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut arbiter = IngressArbiter::new(backend);
    let mut output = [0; TRUSTED_RESPONSE_MAX + 32];
    loop {
        let _ = frontend.poll_cancel(&mut arbiter);
        let status = uart.isr().read();
        if status.ore() || status.fe() || status.ne() || status.pe() {
            uart.icr().write(|r| {
                r.set_ore(true);
                r.set_fe(true);
                r.set_ne(true);
                r.set_pe(true);
            });
            frontend.disconnect(&mut arbiter);
        }
        if !status.rxne() {
            core::hint::spin_loop();
            continue;
        }
        let byte = uart.rdr().read().dr() as u8;
        if let Ok(Some(InterconnectCtap2Outcome::Response { len })) =
            frontend.push_byte(&mut arbiter, byte, &mut output)
        {
            for byte in &output[..len] {
                while !uart.isr().read().txe() {
                    core::hint::spin_loop();
                }
                uart.tdr().write(|r| r.set_dr(*byte as u16));
            }
            on_response();
        }
    }
}

#[cfg(feature = "trustzone-secure-layout")]
/// Configure attribution after validating existing option-byte/layout state; does not program option bytes.
///
/// # Safety
/// Call once in Secure privileged startup with the required TZEN, bank/security watermarks and unlocked layout; NS must not be running.
/// Exclusively own SAU/MPCBB and coordinate peripheral/IRQ attribution separately.
pub unsafe fn configure_memory(sau: &mut cortex_m::peripheral::SAU) {
    use cortex_m::peripheral::sau::{SauRegion, SauRegionAttribute};
    use embassy_stm32::pac;

    let flash = unsafe { pac::flash::Flash::from_ptr(0x5002_2000 as *mut ()) };
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    let options = flash.optr().read();
    assert!(options.tzen(), "TrustZone must already be enabled");
    assert_eq!(options.rdp(), pac::flash::vals::Rdp::Level0);
    assert!(
        !options.swap_bank(),
        "Selected layout requires unswapped banks"
    );
    let boot = flash.secbootadd0r().read();
    assert!(!boot.boot_lock(), "Recovery selection must remain unlocked");
    assert_eq!(boot.secbootadd0() << 7, 0x0c00_0000);
    let watermark1 = flash.secwm1r1().read();
    let watermark2 = flash.secwm2r1().read();
    assert_eq!(
        (watermark1.secwm1_pstrt(), watermark1.secwm1_pend()),
        (0, 127)
    );
    assert_eq!(
        (watermark2.secwm2_pstrt(), watermark2.secwm2_pend()),
        (123, 127)
    );
    rcc.ahb1enr().modify(|r| r.set_gtzc1en(true));
    let _ = rcc.ahb1enr().read();

    for (controller, words, secure) in [
        (
            unsafe { pac::gtzc::Mpcbb::from_ptr(0x5003_2c00 as *mut ()) },
            12,
            true,
        ),
        (
            unsafe { pac::gtzc::Mpcbb::from_ptr(0x5003_3000 as *mut ()) },
            4,
            true,
        ),
        (
            unsafe { pac::gtzc::Mpcbb::from_ptr(0x5003_3400 as *mut ()) },
            32,
            false,
        ),
    ] {
        assert!(!controller.cr().read().glock());
        assert_eq!(controller.cfglock().read().splck(), 0);
        controller.cr().modify(|r| {
            r.set_invsecstate(false);
            r.set_srwiladis(true);
        });
        for index in 0..words {
            let value = if secure { u32::MAX } else { 0 };
            controller.seccfgr(index).write(|r| r.0 = value);
            assert_eq!(controller.seccfgr(index).read().0, value);
        }
    }
    let regions = [
        SauRegion {
            base_address: NSC_START,
            limit_address: NSC_END - 1,
            attribute: SauRegionAttribute::NonSecureCallable,
        },
        SauRegion {
            base_address: NS_FLASH_START,
            limit_address: NS_FLASH_END - 1,
            attribute: SauRegionAttribute::NonSecure,
        },
        SauRegion {
            base_address: NS_RAM_START,
            limit_address: SHARED.end - 1,
            attribute: SauRegionAttribute::NonSecure,
        },
        SauRegion {
            base_address: NS_UART_START,
            limit_address: NS_UART_END - 1,
            attribute: SauRegionAttribute::NonSecure,
        },
        SauRegion {
            base_address: 0x4204_0000,
            limit_address: 0x4204_ffff,
            attribute: SauRegionAttribute::NonSecure,
        },
    ];
    let count = if cfg!(feature = "trustzone-usb") {
        5
    } else if cfg!(feature = "trustzone-uart-runtime") {
        4
    } else {
        3
    };
    sau.init(&regions[..count]).expect("SAU layout");
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(all(
    feature = "trustzone-secure-layout",
    feature = "trustzone-uart-runtime"
))]
/// Prepare the NS UART using HSI16; readiness waits have no timeout.
///
/// # Safety
/// Secure startup exclusively owns RCC/GPIO/USART1 after memory attribution checks, before NS execution.
pub unsafe fn configure_uart_runtime() {
    use embassy_stm32::pac;
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    let gpio = unsafe { pac::gpio::Gpio::from_ptr(0x5202_0000 as *mut ()) };
    let uart = unsafe { pac::usart::Usart::from_ptr(0x5001_3800 as *mut ()) };
    let gtzc = unsafe { pac::gtzc::Gtzc1Tzsc::from_ptr(0x5003_2400 as *mut ()) };
    rcc.cr().modify(|r| r.set_hsion(true));
    while !rcc.cr().read().hsirdy() {
        core::hint::spin_loop();
    }
    rcc.cfgr1().modify(|r| r.set_sw(pac::rcc::vals::Sw::Hsi));
    while rcc.cfgr1().read().sws() != pac::rcc::vals::Sw::Hsi {
        core::hint::spin_loop();
    }
    rcc.cfgr2().modify(|r| {
        r.set_hpre(pac::rcc::vals::Hpre::Div1);
        r.set_ppre1(pac::rcc::vals::Ppre::Div1);
        r.set_ppre2(pac::rcc::vals::Ppre::Div1);
    });
    rcc.ahb2enr1().modify(|r| r.set_gpioaen(true));
    rcc.apb2enr().modify(|r| r.set_usart1en(true));
    let _ = rcc.apb2enr().read();
    for pin in [9, 10] {
        gpio.moder()
            .modify(|r| r.set_moder(pin, pac::gpio::vals::Moder::Alternate));
        gpio.afr(1).modify(|r| r.set_afr(pin - 8, 7));
        gpio.pupdr()
            .modify(|r| r.set_pupdr(pin, pac::gpio::vals::Pupdr::PullUp));
    }
    uart.cr1().write(|_| {});
    uart.cr2().write(|_| {});
    uart.cr3().write(|_| {});
    uart.brr().write(|r| r.0 = 139);
    uart.cr1().write(|r| {
        r.set_re(true);
        r.set_te(true);
        r.set_ue(true);
    });
    while !uart.isr().read().reack() || !uart.isr().read().teack() {
        core::hint::spin_loop();
    }
    gtzc.seccfgr2().modify(|r| r.set_usart1sec(false));
    assert!(!gtzc.seccfgr2().read().usart1sec());
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[cfg(feature = "trustzone-secure-layout")]
/// Validate the NS vector and hand off to the configured image.
///
/// # Safety
/// Complete matching memory/peripheral/IRQ and service initialization first; load a trusted NS image at NS_FLASH_START.
/// Preserve exclusive core ownership and valid NS stack/code regions through handoff.
pub unsafe fn handoff(core: cortex_m::Peripherals) -> ! {
    let vector = manekey::security::NonsecureVector {
        main_stack_pointer: unsafe { core::ptr::read_volatile(NS_FLASH_START as *const u32) },
        reset_handler: unsafe { core::ptr::read_volatile((NS_FLASH_START + 4) as *const u32) },
    };
    vector
        .validate_in(NS_RAM_START, NS_RAM_END, NS_FLASH_START, NS_FLASH_END)
        .expect("NS vector");
    unsafe {
        core::arch::asm!("msr MSPLIM_NS, {limit}", limit = in(reg) NS_RAM_START,
                         options(nostack, preserves_flags));
        cortex_m::asm::bootload_ns(NS_FLASH_START as *const u32, core.SCBNS)
    }
}
