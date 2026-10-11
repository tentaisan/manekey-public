use core::sync::atomic::{AtomicBool, Ordering};

use manekey::boundary::mailbox::{
    MailboxClientTransport, MailboxEndpoint, MailboxError, MailboxState,
};
use manekey::presence::{
    PresenceInputInfo, PresenceStatus, TimedPresenceState, UserPresence, UserPresenceInput,
};
use rp235x_hal as hal;

use crate::platform::rp::user_interface::RP2350_RISCV_GPIO15_PRESENCE_CONFIG;

const CORE1_XIP_PAUSE_SPINS: u32 = 1_000_000;
const MSTATUS_MIE: usize = 1 << 3;

static CORE1_XIP_PAUSE_REQUESTED: AtomicBool = AtomicBool::new(false);
static CORE1_XIP_PAUSED: AtomicBool = AtomicBool::new(false);
static CORE1_XIP_PAUSE_OWNED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "riscv-dual-core-bootsel")]
static CORE0_XIP_PAUSE_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "riscv-dual-core-bootsel")]
static CORE0_XIP_PAUSED: AtomicBool = AtomicBool::new(false);

/// Exclusive pause lease; drop releases the request and the next acquisition waits for acknowledgement withdrawal.
pub struct Core1XipPauseGuard {
    _exclusive: (),
}

impl Drop for Core1XipPauseGuard {
    fn drop(&mut self) {
        CORE1_XIP_PAUSE_REQUESTED.store(false, Ordering::Release);
        hal::arch::sev();
        CORE1_XIP_PAUSE_OWNED.store(false, Ordering::Release);
    }
}

/// Reject overlapping leases and wait for the previous acknowledgement to clear before requesting a new pause.
/// Acknowledgement covers core1 only; exclude DMA/debugger XIP access separately.
pub fn request_core1_xip_pause() -> Option<Core1XipPauseGuard> {
    CORE1_XIP_PAUSE_OWNED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()?;
    let guard = Core1XipPauseGuard { _exclusive: () };

    if !wait_for_pause_state(&CORE1_XIP_PAUSED, false) {
        return None;
    }
    CORE1_XIP_PAUSE_REQUESTED.store(true, Ordering::Release);
    hal::arch::sev();
    if !wait_for_pause_state(&CORE1_XIP_PAUSED, true) {
        return None;
    }
    Some(guard)
}

fn wait_for_pause_state(paused: &AtomicBool, expected: bool) -> bool {
    let mut spins = CORE1_XIP_PAUSE_SPINS;
    while paused.load(Ordering::Acquire) != expected {
        if spins == 0 {
            return false;
        }
        hal::arch::nop();
        spins -= 1;
    }
    true
}

#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
/// Core1-only RAM parking loop; retain RAM placement and matching single-owner requester.
pub fn core1_park_for_xip_if_requested() {
    if !CORE1_XIP_PAUSE_REQUESTED.load(Ordering::Acquire) {
        return;
    }

    let previous_mstatus: usize;
    unsafe {
        core::arch::asm!(
            "csrrc {previous}, mstatus, {mie}",
            previous = out(reg) previous_mstatus,
            mie = in(reg) MSTATUS_MIE,
            options(nomem, nostack)
        );
    }
    CORE1_XIP_PAUSED.store(true, Ordering::Release);
    while CORE1_XIP_PAUSE_REQUESTED.load(Ordering::Acquire) {
        unsafe {
            core::arch::asm!("slt x0, x0, x0", options(nomem, nostack));
        }
    }
    CORE1_XIP_PAUSED.store(false, Ordering::Release);
    if previous_mstatus & MSTATUS_MIE != 0 {
        unsafe {
            core::arch::asm!(
                "csrs mstatus, {mie}",
                mie = in(reg) MSTATUS_MIE,
                options(nomem, nostack)
            );
        }
    }
}

#[cfg(feature = "riscv-dual-core-bootsel")]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
/// Core0-only RAM parking loop; retain RAM placement and exclude other XIP masters separately.
pub fn core0_park_for_bootsel_if_requested() {
    if !CORE0_XIP_PAUSE_REQUESTED.load(Ordering::Acquire) {
        return;
    }
    let previous_mstatus: usize;
    unsafe {
        core::arch::asm!(
            "csrrc {previous}, mstatus, {mie}",
            previous = out(reg) previous_mstatus,
            mie = in(reg) MSTATUS_MIE,
            options(nomem, nostack)
        );
    }
    CORE0_XIP_PAUSED.store(true, Ordering::Release);
    while CORE0_XIP_PAUSE_REQUESTED.load(Ordering::Acquire) {
        unsafe { core::arch::asm!("slt x0, x0, x0", options(nomem, nostack)) };
    }
    CORE0_XIP_PAUSED.store(false, Ordering::Release);
    if previous_mstatus & MSTATUS_MIE != 0 {
        unsafe {
            core::arch::asm!("csrs mstatus, {mie}", mie = in(reg) MSTATUS_MIE, options(nomem, nostack));
        }
    }
}

#[cfg(feature = "riscv-dual-core-bootsel")]
/// Single core1 sampler requiring the core0 parking loop and exclusive XIP ownership.
pub struct DualCoreBootselPresence {
    state: TimedPresenceState,
}

#[cfg(feature = "riscv-dual-core-bootsel")]
impl DualCoreBootselPresence {
    pub const fn new() -> Self {
        Self {
            state: crate::platform::rp::user_interface::RP2350_RISCV_BOOTSEL_PRESENCE_CONFIG
                .state(),
        }
    }

    fn now_us() -> u64 {
        RawGpio15UserPresence::now_us()
    }

    fn button_pressed() -> bool {
        if !wait_for_pause_state(&CORE0_XIP_PAUSED, false) {
            return false;
        }
        CORE0_XIP_PAUSE_REQUESTED.store(true, Ordering::Release);
        hal::arch::sev();
        if !wait_for_pause_state(&CORE0_XIP_PAUSED, true) {
            CORE0_XIP_PAUSE_REQUESTED.store(false, Ordering::Release);
            hal::arch::sev();
            return false;
        }
        let pressed = crate::platform::rp::user_interface::riscv_bootsel_pressed_single_hart();
        CORE0_XIP_PAUSE_REQUESTED.store(false, Ordering::Release);
        hal::arch::sev();
        pressed
    }
}

#[cfg(feature = "riscv-dual-core-bootsel")]
impl UserPresence for DualCoreBootselPresence {
    fn is_present(&mut self) -> bool {
        Self::button_pressed()
    }
    fn begin_wait(&mut self) {
        self.state.begin_wait(Self::now_us());
    }
    fn poll(&mut self) -> PresenceStatus {
        self.state.poll(Self::now_us(), Self::button_pressed())
    }
    fn cancel(&mut self) {
        self.state.cancel();
    }
    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || Self::button_pressed()
    }
}

#[cfg(feature = "riscv-dual-core-bootsel")]
impl UserPresenceInput for DualCoreBootselPresence {
    fn input_info(&self) -> PresenceInputInfo {
        crate::platform::rp::user_interface::RP2350_RISCV_BOOTSEL_PRESENCE_CONFIG.input_info
    }
}

/// Single serialized mailbox client; sharing an endpoint does not provide client arbitration.
pub struct RiscvPollingTransport<'a, const REQUEST: usize, const RESPONSE: usize> {
    endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>,
}

impl<'a, const REQUEST: usize, const RESPONSE: usize> RiscvPollingTransport<'a, REQUEST, RESPONSE> {
    pub const fn new(endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>) -> Self {
        Self { endpoint }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxClientTransport
    for RiscvPollingTransport<'_, REQUEST, RESPONSE>
{
    fn submit_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.endpoint.submit_operation(operation_code, request)?;
        hal::arch::sev();
        Ok(())
    }

    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError> {
        if self.endpoint.state()? == MailboxState::ResponseReady {
            self.endpoint.take_status_response(response).map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Low-active GPIO15 presence requiring initialized TIMER0 and pull-up input; timing uses microseconds.
pub struct RawGpio15UserPresence {
    state: TimedPresenceState,
}

impl RawGpio15UserPresence {
    pub const fn new() -> Self {
        Self {
            state: RP2350_RISCV_GPIO15_PRESENCE_CONFIG.state(),
        }
    }

    fn now_us() -> u64 {
        let timer = unsafe { &*hal::pac::TIMER0::ptr() };
        let mut high = timer.timerawh().read().bits();
        loop {
            let low = timer.timerawl().read().bits();
            let next_high = timer.timerawh().read().bits();
            if high == next_high {
                return (u64::from(high) << 32) | u64::from(low);
            }
            high = next_high;
        }
    }

    fn button_pressed() -> bool {
        let sio = unsafe { &*hal::pac::SIO::ptr() };
        (sio.gpio_in().read().bits() & (1 << 15)) == 0
    }
}

impl UserPresence for RawGpio15UserPresence {
    fn is_present(&mut self) -> bool {
        Self::button_pressed()
    }

    fn begin_wait(&mut self) {
        self.state.begin_wait(Self::now_us());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state.poll(Self::now_us(), Self::button_pressed())
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || Self::button_pressed()
    }
}

impl UserPresenceInput for RawGpio15UserPresence {
    fn input_info(&self) -> PresenceInputInfo {
        RP2350_RISCV_GPIO15_PRESENCE_CONFIG.input_info
    }
}

fn read_mtvec_base() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("csrr {value}, mtvec", value = out(reg) value);
    }
    value & !0b11
}

fn fifo_read_timeout(fifo: &mut hal::sio::SioFifo, mut spins: u32) -> Option<u32> {
    while spins > 0 {
        if let Some(value) = fifo.read() {
            return Some(value);
        }
        hal::arch::nop();
        spins -= 1;
    }
    None
}

/// # Safety
/// Exclusively own core1 reset/FIFO and valid aligned firmware-lifetime stack RAM; entry must not return.
/// Use a valid shared trap vector. Only receive waits are bounded; failure does not prove core1 stopped.
pub unsafe fn spawn_riscv_core1(
    psm: &mut hal::pac::PSM,
    fifo: &mut hal::sio::SioFifo,
    stack_start: *mut usize,
    stack_words: usize,
    entry: extern "C" fn() -> !,
) -> Result<(), ()> {
    if stack_start.is_null() || stack_words == 0 {
        return Err(());
    }

    psm.frce_off().modify(|_, w| w.proc1().set_bit());
    while !psm.frce_off().read().proc1().bit_is_set() {
        hal::arch::nop();
    }
    psm.frce_off().modify(|_, w| w.proc1().clear_bit());

    let stack_end = unsafe { stack_start.add(stack_words) };
    let stack_ptr = ((stack_end as usize) & !0x7) as u32;
    let cmd_seq = [
        0,
        0,
        1,
        read_mtvec_base() as u32,
        stack_ptr,
        entry as *const () as usize as u32,
    ];

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

    let mut seq = 0;
    let mut failures = 0;
    while seq < cmd_seq.len() {
        let cmd = cmd_seq[seq];
        if cmd == 0 {
            fifo.drain();
            hal::arch::sev();
        }
        fifo.write_blocking(cmd);
        match fifo_read_timeout(fifo, 1_000_000) {
            Some(response) if response == cmd => seq += 1,
            Some(_) | None => {
                seq = 0;
                failures += 1;
                if failures > 16 {
                    return Err(());
                }
            }
        }
    }

    fifo_read_timeout(fifo, 10_000_000)
        .filter(|response| *response == 1)
        .map(|_| ())
        .ok_or(())
}
