use ra_hal::write_protect::ProtectedModify;
use ra_hal::{Peri, pac, peripherals};

// SCI2 has no FIFO: the HAL's current UART implementation only accepts SCI0/1.
pub struct Sci2;

#[cfg(feature = "mpu-usb-ccid")]
mod buffered {
    use super::*;
    use core::cell::RefCell;
    use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
    use ra_hal::event_link::{IcuInterrupt, InterruptEvent};
    use ra_hal::interrupt;
    struct Receive {
        bytes: heapless::Deque<u8, 512>,
        lost: bool,
    }
    static RX: Mutex<CriticalSectionRawMutex, RefCell<Receive>> =
        Mutex::new(RefCell::new(Receive {
            bytes: heapless::Deque::new(),
            lost: false,
        }));
    pub fn start() {
        cortex_m::interrupt::free(|_| unsafe {
            let irq = ra_hal::interrupt::IEL3;
            irq.icu_disable();
            irq.icu_unpend();
            cortex_m::peripheral::NVIC::unpend(irq);
            irq.icu_enable(InterruptEvent::Sci2Rxi);
            let mut core = cortex_m::Peripherals::steal();
            core.NVIC.set_priority(irq, 0x20);
            pac::SCI2.scr().modify(|v| v.set_rie(true));
            cortex_m::peripheral::NVIC::unmask(irq);
        });
    }
    pub fn read_event() -> u32 {
        RX.lock(|rx| {
            let mut rx = rx.borrow_mut();
            if rx.lost {
                rx.lost = false;
                rx.bytes.clear();
                return u32::MAX - 1;
            }
            rx.bytes.pop_front().map(u32::from).unwrap_or(u32::MAX)
        })
    }
    #[ra_hal::interrupt]
    fn IEL3() {
        let status = pac::SCI2.ssr().read();
        let bad = status.orer() || status.fer() || status.per();
        let byte = if status.rdrf() {
            Some(pac::SCI2.rdr().read())
        } else {
            None
        };
        pac::SCI2.ssr().modify(|r| {
            r.set_orer(false);
            r.set_fer(false);
            r.set_per(false);
            r.set_rdrf(false);
        });
        RX.lock(|rx| {
            let mut rx = rx.borrow_mut();
            if bad || (!rx.lost && byte.is_some_and(|b| rx.bytes.push_back(b).is_err())) {
                rx.bytes.clear();
                rx.lost = true;
            }
        });
        ra_hal::interrupt::IEL3.icu_unpend();
    }
}

impl Sci2 {
    #[cfg(feature = "mpu-usb-ccid")]
    pub fn start_buffered(&mut self) {
        buffered::start();
    }
    #[cfg(feature = "mpu-usb-ccid")]
    pub fn read_event(&mut self) -> u32 {
        buffered::read_event()
    }
    pub fn new(
        _sci: Peri<'_, peripherals::SCI2>,
        _tx: Peri<'_, peripherals::P302>,
        _rx: Peri<'_, peripherals::P301>,
    ) -> Self {
        // The consumed HAL tokens give this adapter exclusive peripheral ownership.
        unsafe { Self::init_registers() }
    }

    pub unsafe fn init_registers() -> Self {
        pac::MSTP.mstpcrb().modify(|r| r.set_mstpb29(false));
        pac::SCI2.scr().write_value(pac::sci::regs::Scr(0));
        for pin in [3 * 16 + 1, 3 * 16 + 2] {
            pac::PFS.pin(pin).protected_modify(|r| {
                r.set_pmr(pac::pfs::vals::PortMode::Gpio);
                r.set_asel(false);
                r.set_pdr(if pin == 3 * 16 + 2 {
                    pac::pfs::vals::PortDirection::Output
                } else {
                    pac::pfs::vals::PortDirection::Input
                });
                r.set_psel(pac::pfs::vals::PortFunction::Sci0);
                r.set_pmr(pac::pfs::vals::PortMode::Peripheral);
            });
        }
        pac::SCI2.smr().write_value(pac::sci::regs::Smr(0));
        pac::SCI2.scmr().write_value(pac::sci::regs::Scmr(0xf2));
        pac::SCI2.semr().write(|r| {
            r.set_abcs(true);
            r.set_bgdm(true);
        });
        let hoco_hz = match pac::SYSTEM.hococr2().read().hcfrqw() {
            pac::system::vals::Hcfrq1::_32mhz => 32_000_000,
            pac::system::vals::Hcfrq1::_48mhz => 48_000_000,
            pac::system::vals::Hcfrq1::_64mhz => 64_000_000,
            _ => panic!("unsupported HOCO"),
        };
        // RA4M1 SCI uses PCLKA, unlike RA2's PCLKB clock selection.
        let pclka = hoco_hz >> pac::SYSTEM.sckdivcr().read().pcka().to_bits();
        let divisor = (pclka + 4 * 115_200) / (8 * 115_200);
        assert!((1..=256).contains(&divisor));
        pac::SCI2.brr().write_value((divisor - 1) as u8);
        cortex_m::asm::delay(48_000);
        pac::SCI2.scr().write(|r| {
            r.set_te(true);
            r.set_re(true);
        });
        Self
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            while !pac::SCI2.ssr().read().tdre() {}
            pac::SCI2.tdr().write_value(byte);
            pac::SCI2.ssr().modify(|r| r.set_tdre(false));
        }
    }

    pub fn read(&mut self) -> Option<u8> {
        let status = pac::SCI2.ssr().read();
        if status.orer() || status.fer() || status.per() {
            pac::SCI2.ssr().modify(|r| {
                r.set_orer(false);
                r.set_fer(false);
                r.set_per(false);
            });
            return None;
        }
        if !status.rdrf() {
            return None;
        }
        let byte = pac::SCI2.rdr().read();
        pac::SCI2.ssr().modify(|r| r.set_rdrf(false));
        Some(byte)
    }
}

impl core::fmt::Write for Sci2 {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        self.write(text.as_bytes());
        Ok(())
    }
}
