use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};
use critical_section::Mutex;
use embassy_stm32::pac;
use manekey::ctaphid::hash::{Sha256Backend, Sha256Error};

static OWNED: AtomicBool = AtomicBool::new(false);
static LOCK: Mutex<RefCell<()>> = Mutex::new(RefCell::new(()));

fn registers() -> pac::hash::Hash {
    unsafe { pac::hash::Hash::from_ptr(0x520c_0400 as *mut ()) }
}
fn reset() {
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    rcc.ahb2rstr1().modify(|r| r.set_hashrst(true));
    rcc.ahb2rstr1().modify(|r| r.set_hashrst(false));
}

/// Initialize the Secure HASH owner.
///
/// # Safety
/// Call once in Secure startup before NS handoff; exclusively own HASH/clock/attribution state and exclude other IRQ/DMA drivers.
pub unsafe fn initialize() {
    assert!(!OWNED.swap(true, Ordering::SeqCst));
    let gtzc = unsafe { pac::gtzc::Gtzc1Tzsc::from_ptr(0x5003_2400 as *mut ()) };
    gtzc.seccfgr3().modify(|r| r.set_hashsec(true));
    assert!(gtzc.seccfgr3().read().hashsec());
    let rcc = unsafe { pac::rcc::Rcc::from_ptr(0x5602_0c00 as *mut ()) };
    rcc.ahb2enr1().modify(|r| r.set_hashen(true));
    let _ = rcc.ahb2enr1().read();
    reset();
    cortex_m::peripheral::NVIC::mask(pac::Interrupt::HASH);
    cortex_m::peripheral::NVIC::unpend(pac::Interrupt::HASH);
}

fn wait(mut ready: impl FnMut() -> bool) -> Result<(), Sha256Error> {
    for _ in 0..100_000 {
        if ready() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Sha256Error::HardwareUnavailable)
}

#[derive(Clone, Copy)]
/// Secure polling HASH; no DMA/context export or software fallback.
/// Poll bounds are iterations, not wall-clock deadlines; platform preserves exclusive initialization and attribution.
pub struct SecureSha256;
impl Sha256Backend for SecureSha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_parts(&[data])
    }
    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        if !OWNED.load(Ordering::SeqCst) {
            return Err(Sha256Error::HardwareUnavailable);
        }
        critical_section::with(|cs| {
            let _owner = LOCK
                .borrow(cs)
                .try_borrow_mut()
                .map_err(|_| Sha256Error::HardwareUnavailable)?;
            reset();
            let result = digest(parts);

            reset();
            result
        })
    }
}

fn digest(parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
    let regs = registers();
    regs.imr().write(|_| {});
    regs.cr().write(|r| {
        r.set_datatype(2);
        r.set_algo(3);
        r.set_init(true);
    });
    let mut word = [0; 4];
    let mut used = 0;
    let mut words = 0usize;
    let mut feed = |word: [u8; 4]| -> Result<(), Sha256Error> {
        if words == 0 || (words >= 17 && (words - 17) % 16 == 0) {
            wait(|| regs.sr().read().dinis())?;
        }
        regs.din().write_value(u32::from_le_bytes(word));
        words += 1;
        Ok(())
    };
    for part in parts {
        for byte in *part {
            word[used] = *byte;
            used += 1;
            if used == 4 {
                feed(word)?;
                word = [0; 4];
                used = 0;
            }
        }
    }
    if used != 0 {
        feed(word)?;
    }
    regs.str().modify(|r| r.set_nblw((used * 8) as u8));
    wait(|| !regs.sr().read().busy())?;
    regs.str().modify(|r| r.set_dcal(true));
    wait(|| regs.sr().read().dcis())?;
    let mut output = [0; 32];
    for (index, chunk) in output.chunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&regs.hr(index).read().to_be_bytes());
    }
    Ok(output)
}
