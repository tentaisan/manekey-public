// Portions derived from embassy-stm32/src/rng.rs at
// b12a6d9efcd2711037abca1b63a661a9ef726444 (Embassy).
// Copyright (c) Embassy project contributors
// Upstream portions used under Apache-2.0; original integration retains its port license.
// Modified: adapted RNG conditioning for Secure aliases, owned clocks and bounded waits.
use core::sync::atomic::{AtomicU32, Ordering};
use embassy_stm32::pac;
use embassy_stm32::pac::interrupt;
use manekey::ctaphid::{
    entropy::{EntropyError, EntropySource},
    pin_uv_auth::PinUvAuthTokenClock,
};
#[cfg(feature = "hardware-sha256")]
#[path = "secure_hash.rs"]
mod secure_hash;
#[cfg(feature = "hardware-sha256")]
pub use secure_hash::SecureSha256;

const FLASH_ALIAS: u32 = 0x0c00_0000;
fn flash() -> pac::flash::Flash {
    unsafe { pac::flash::Flash::from_ptr(0x5002_2000 as *mut ()) }
}
fn timer() -> pac::timer::TimGp32 {
    unsafe { pac::timer::TimGp32::from_ptr(0x5000_0000 as *mut ()) }
}
fn rng() -> pac::rng::Rng {
    unsafe { pac::rng::Rng::from_ptr(0x520c_0800 as *mut ()) }
}

#[unsafe(no_mangle)]
pub static TZ_CLOCK_WRAPS: AtomicU32 = AtomicU32::new(0);

#[embassy_stm32::pac::interrupt]
fn TIM2() {
    if timer().sr().read().uif() {
        timer().sr().modify(|r| r.set_uif(false));
        TZ_CLOCK_WRAPS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Initialize Secure service resources before NS handoff; no DMA driver is enabled.
///
/// # Safety
/// Call once after memory attribution and HSI16 UART setup; exclusively own timer, RNG, HASH, GPIO, clocks and FP/IRQ policy.
pub unsafe fn initialize() {
    unsafe {
        let nsacr = 0xe000_ed8c as *mut u32;
        core::ptr::write_volatile(nsacr, core::ptr::read_volatile(nsacr) | (3 << 10));
        let fpccr = 0xe000_ef34 as *mut u32;
        core::ptr::write_volatile(
            fpccr,
            (core::ptr::read_volatile(fpccr)
                | (1 << 31)
                | (1 << 29)
                | (1 << 28)
                | (1 << 27)
                | (1 << 26))
                & !(1 << 30),
        );
    }
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    let gtzc = unsafe { pac::gtzc::Gtzc1Tzsc::from_ptr(0x5003_2400 as *mut ()) };
    gtzc.seccfgr1().modify(|r| r.set_tim2sec(true));
    gtzc.seccfgr3().modify(|r| r.set_rngsec(true));
    assert!(gtzc.seccfgr1().read().tim2sec());
    assert!(gtzc.seccfgr3().read().rngsec());
    #[cfg(feature = "hardware-sha256")]
    unsafe {
        secure_hash::initialize();
    }

    rcc.apb1enr1().modify(|r| r.set_tim2en(true));
    let _ = rcc.apb1enr1().read();
    timer().cr1().write(|_| {});
    timer().psc().write_value(15_999);
    timer().arr().write_value(u32::MAX);
    timer().egr().write(|r| r.set_ug(true));
    timer().sr().modify(|r| r.set_uif(false));
    timer().dier().modify(|r| r.set_uie(true));
    let irq = pac::Interrupt::TIM2 as u32;
    let itns = (0xe000_e380 + 4 * (irq / 32)) as *mut u32;
    unsafe {
        core::ptr::write_volatile(itns, core::ptr::read_volatile(itns) & !(1 << (irq % 32)));
    }
    cortex_m::peripheral::NVIC::unpend(pac::Interrupt::TIM2);
    unsafe {
        cortex_m::peripheral::NVIC::unmask(pac::Interrupt::TIM2);
    }
    timer().cr1().write(|r| r.set_cen(true));
    rcc.cr().modify(|r| r.set_hsi48on(true));
    assert!(wait(|| rcc.cr().read().hsi48rdy()));
    rcc.ccipr2()
        .modify(|r| r.set_rngsel(pac::rcc::vals::Rngsel::Hsi48));
    rcc.ahb2enr1().modify(|r| r.set_rngen(true));
    rcc.ahb2rstr1().modify(|r| r.set_rngrst(true));
    rcc.ahb2rstr1().modify(|r| r.set_rngrst(false));
    let _ = rcc.ahb2enr1().read();

    rng().cr().write(|r| {
        r.set_condrst(true);
        r.set_nistc(pac::rng::vals::Nistc::Custom);
        r.set_rng_config1(pac::rng::vals::RngConfig1::ConfigA);
        r.set_rng_config2(pac::rng::vals::RngConfig2::ConfigAB);
        r.set_rng_config3(pac::rng::vals::RngConfig3::ConfigA);
        r.set_clkdiv(pac::rng::vals::Clkdiv::NoDiv);
        r.set_ced(false);
        r.set_ardis(false);
        r.set_rngen(true);
    });
    assert!(wait(|| rng().cr().read().condrst()));
    rng()
        .htcr()
        .write(|r| r.set_htcfg(pac::rng::vals::Htcfg::Magic));
    rng()
        .htcr()
        .write(|r| r.set_htcfg(pac::rng::vals::Htcfg::Recommended));
    rng().cr().modify(|r| r.set_condrst(false));
    rng().sr().modify(|r| r.set_seis(false));
    SecureEntropy.word().expect("Secure RNG conditioning");
    rcc.ahb2enr1().modify(|r| r.set_gpiocen(true));
    let _ = rcc.ahb2enr1().read();
    let gpio = unsafe { pac::gpio::Gpio::from_ptr(0x5202_0800 as *mut ()) };
    gpio.moder().modify(|r| {
        r.set_moder(7, pac::gpio::vals::Moder::Output);
        r.set_moder(13, pac::gpio::vals::Moder::Input);
    });
    gpio.pupdr()
        .modify(|r| r.set_pupdr(13, pac::gpio::vals::Pupdr::PullDown));
    led_off();
    #[cfg(feature = "trustzone-usb")]
    unsafe {
        prepare_usb()
    };
}

#[cfg(feature = "trustzone-usb")]
/// Prepare NS transport attribution.
///
/// # Safety
/// Secure startup exclusively owns clock, power, GPIO and transport IRQ policy; NS must not be running.
unsafe fn prepare_usb() {
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    let pwr = unsafe { pac::pwr::Pwr::from_ptr(0x5602_0800 as *mut ()) };
    let gpio = unsafe { pac::gpio::Gpio::from_ptr(0x5202_0000 as *mut ()) };
    let gtzc = unsafe { pac::gtzc::Gtzc1Tzsc::from_ptr(0x5003_2400 as *mut ()) };
    rcc.ccipr1()
        .modify(|r| r.set_iclksel(pac::rcc::vals::Iclksel::Hsi48));
    rcc.ahb3enr().modify(|r| r.set_pwren(true));
    let _ = rcc.ahb3enr().read();
    pwr.svmcr().modify(|r| {
        r.set_usv(true);
        r.set_uvmen(true);
    });
    assert!(wait(|| pwr.svmsr().read().vddusbrdy()));
    for pin in [11, 12] {
        gpio.moder()
            .modify(|r| r.set_moder(pin, pac::gpio::vals::Moder::Alternate));
        gpio.afr(1).modify(|r| r.set_afr(pin - 8, 10));
        gpio.ospeedr()
            .modify(|r| r.set_ospeedr(pin, pac::gpio::vals::Ospeedr::VeryHighSpeed));
        gpio.pupdr()
            .modify(|r| r.set_pupdr(pin, pac::gpio::vals::Pupdr::Floating));
    }
    rcc.ahb2enr1().modify(|r| r.set_usb_otg_fsen(true));
    rcc.ahb2rstr1().modify(|r| r.set_usb_otg_fsrst(true));
    rcc.ahb2rstr1().modify(|r| r.set_usb_otg_fsrst(false));
    gtzc.seccfgr2().modify(|r| r.set_usbsec(false));
    assert!(!gtzc.seccfgr2().read().usbsec());

    let target = (0xe000_e380u32 + 4 * (73 / 32)) as *mut u32;
    unsafe {
        core::ptr::write_volatile(target, core::ptr::read_volatile(target) | (1 << (73 % 32)));
    }
    let uart_target = (0xe000_e380u32 + 4 * (61 / 32)) as *mut u32;
    unsafe {
        core::ptr::write_volatile(
            uart_target,
            core::ptr::read_volatile(uart_target) | (1 << (61 % 32)),
        );
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

fn wait(mut ready: impl FnMut() -> bool) -> bool {
    let start = timer().cnt().read();
    while !ready() {
        if timer().cnt().read().wrapping_sub(start) >= 5000 {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Requires initialized Secure TIM2 and exclusive overflow/IRQ ownership; time units are milliseconds.
pub struct SecureClock;
impl SecureClock {
    pub fn new() -> Self {
        Self
    }
}
impl PinUvAuthTokenClock for SecureClock {
    fn now_ms(&self) -> u64 {
        critical_section::with(|_| {
            let mut wraps = TZ_CLOCK_WRAPS.load(Ordering::Relaxed);
            let mut ticks = timer().cnt().read();

            if timer().sr().read().uif() {
                timer().sr().modify(|r| r.set_uif(false));
                wraps = wraps.wrapping_add(1);
                TZ_CLOCK_WRAPS.store(wraps, Ordering::Relaxed);
                ticks = timer().cnt().read();
            }
            (u64::from(wraps) << 32) | u64::from(ticks)
        })
    }
}
impl manekey::user_interface::UiClock for SecureClock {
    fn now(&mut self) -> u64 {
        self.now_ms()
    }
}
pub struct SecureButton;
impl manekey::user_interface::ButtonInput for SecureButton {
    fn is_pressed(&mut self) -> bool {
        let gpio = unsafe { pac::gpio::Gpio::from_ptr(0x5202_0800 as *mut ()) };
        gpio.idr().read().idr(13) == pac::gpio::vals::Idr::High
    }
}
pub type PhysicalPresence = manekey::user_interface::TimedButtonPresence<SecureButton, SecureClock>;
pub fn physical_presence() -> PhysicalPresence {
    PhysicalPresence::new(SecureButton, SecureClock::new(), crate::ui::PRESENCE_CONFIG)
}
pub fn led_on() {
    unsafe { pac::gpio::Gpio::from_ptr(0x5202_0800 as *mut ()) }
        .bsrr()
        .write(|r| r.set_bs(7, true));
}
pub fn led_off() {
    unsafe { pac::gpio::Gpio::from_ptr(0x5202_0800 as *mut ()) }
        .bsrr()
        .write(|r| r.set_br(7, true));
}

/// Requires initialized Secure RNG and active clocks; hardware error flags fail without software fallback.
pub struct SecureEntropy;
impl SecureEntropy {
    fn word(&mut self) -> Result<u32, EntropyError> {
        if !wait(|| {
            let status = rng().sr().read();
            status.drdy() || status.seis() || status.ceis()
        }) {
            return Err(EntropyError::Unavailable);
        }
        let status = rng().sr().read();
        if status.seis() || status.ceis() || status.secs() || status.cecs() {
            return Err(EntropyError::HealthCheckFailed);
        }
        Ok(rng().dr().read())
    }
}
impl EntropySource for SecureEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in output.chunks_mut(4) {
            chunk.copy_from_slice(&self.word()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// Secure-alias media adapter; caller reserves declared pages and excludes concurrent Flash/DMA owners.
/// No option bytes are programmed; plaintext media provides no rollback or physical secure-erasure guarantee.
pub struct PrivateFlash;
impl PrivateFlash {
    fn range(address: u32, len: usize) -> Result<u32, ()> {
        if !crate::flash_layout::private_range(address, len, cfg!(feature = "flash-managed-keys")) {
            return Err(());
        }
        Ok(FLASH_ALIAS + address)
    }
    pub fn blocking_read(&mut self, address: u32, bytes: &mut [u8]) -> Result<(), ()> {
        let pointer = Self::range(address, bytes.len())?;
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = unsafe { core::ptr::read_volatile((pointer + index as u32) as *const u8) };
        }
        Ok(())
    }
    fn unlock() -> Result<(), ()> {
        if flash().seccr().read().lock() {
            flash().seckeyr().write_value(0x4567_0123);
            flash().seckeyr().write_value(0xcdef_89ab);
        }
        if flash().seccr().read().lock() {
            return Err(());
        }

        flash().secsr().write(|r| {
            r.set_eop(true);
            r.set_operr(true);
            r.set_progerr(true);
            r.set_wrperr(true);
            r.set_pgaerr(true);
            r.set_sizerr(true);
            r.set_pgserr(true);
        });
        Ok(())
    }
    fn ready() -> Result<(), ()> {
        if !wait(|| {
            let r = flash().secsr().read();
            !r.wdw() && !r.bsy()
        }) {
            return Err(());
        }
        let r = flash().secsr().read();
        if r.operr() || r.progerr() || r.wrperr() || r.pgaerr() || r.sizerr() || r.pgserr() {
            Err(())
        } else {
            Ok(())
        }
    }
    pub fn blocking_erase(&mut self, from: u32, to: u32) -> Result<(), ()> {
        Self::range(from, to.checked_sub(from).ok_or(())? as usize)?;
        if from % 8192 != 0 || to % 8192 != 0 {
            return Err(());
        }
        Self::unlock()?;
        let result = (|| {
            for address in (from..to).step_by(8192) {
                Self::ready()?;
                let (bank2, page) = crate::flash_layout::erase_bank_page(address).ok_or(())?;
                flash().seccr().write(|r| {
                    r.set_per(true);
                    r.set_bker(bank2);
                    r.set_pnb(page);
                    r.set_strt(true);
                });
                Self::ready()?;
            }
            Ok(())
        })();
        flash().seccr().write(|r| r.set_lock(true));
        result
    }
    pub fn blocking_write(&mut self, address: u32, bytes: &[u8]) -> Result<(), ()> {
        let pointer = Self::range(address, bytes.len())?;
        if address % 16 != 0 || bytes.len() % 16 != 0 {
            return Err(());
        }
        Self::unlock()?;
        let result = (|| {
            for (index, quadword) in bytes.chunks_exact(16).enumerate() {
                Self::ready()?;
                flash().seccr().write(|r| r.set_pg(true));
                for (word, bytes) in quadword.chunks_exact(4).enumerate() {
                    unsafe {
                        core::ptr::write_volatile(
                            (pointer + (index * 16 + word * 4) as u32) as *mut u32,
                            u32::from_le_bytes(bytes.try_into().unwrap()),
                        );
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                }
                Self::ready()?;
                flash().seccr().write(|r| r.set_pg(false));
            }
            Ok(())
        })();
        flash().seccr().write(|r| r.set_lock(true));
        result
    }
}
