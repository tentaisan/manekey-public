use core::mem::{ManuallyDrop, align_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering, compiler_fence};

use manekey::boundary::mailbox::{
    MailboxClientTransport, MailboxEndpoint, MailboxError, MailboxOperationService, MailboxService,
    MailboxState, Notification,
};

static IS_POLLING_CORE1_INIT: AtomicBool = AtomicBool::new(false);

/// Exclusive notification FIFO owner; do not share tokens with a Flash pause/resume IRQ consumer.
pub struct SioFifo;

/// FIFO notifications accompany endpoint transitions; notification failure does not roll back state.
pub struct SioMailboxTransport<'a, const REQUEST: usize, const RESPONSE: usize> {
    fifo: SioFifo,
    endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>,
}

/// Single endpoint client using shared state and wake hints; not hardware isolation.
pub struct PollingMailboxTransport<'a, const REQUEST: usize, const RESPONSE: usize> {
    endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>,
}

impl<'a, const REQUEST: usize, const RESPONSE: usize>
    PollingMailboxTransport<'a, REQUEST, RESPONSE>
{
    pub const fn new(endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>) -> Self {
        Self { endpoint }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxClientTransport
    for PollingMailboxTransport<'_, REQUEST, RESPONSE>
{
    fn submit_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.endpoint.submit_operation(operation_code, request)?;
        cortex_m::asm::sev();
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

impl<'a, const REQUEST: usize, const RESPONSE: usize> SioMailboxTransport<'a, REQUEST, RESPONSE> {
    pub const fn new(endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>) -> Self {
        Self {
            fifo: SioFifo::new(),
            endpoint,
        }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxClientTransport
    for SioMailboxTransport<'_, REQUEST, RESPONSE>
{
    fn submit_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.fifo
            .submit_operation(self.endpoint, operation_code, request)
    }

    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError> {
        while let Some(notification) = self.fifo.try_receive() {
            if notification.state == MailboxState::ResponseReady {
                return self.endpoint.take_status_response(response).map(Some);
            }
        }
        Ok(None)
    }
}

impl SioFifo {
    pub const fn new() -> Self {
        Self
    }

    pub fn try_notify_tx(&self, notification: Notification) -> bool {
        let sio = &rp_pac::SIO;
        if !sio.fifo().st().read().rdy() {
            return false;
        }
        sio.fifo().wr().write_value(notification.encode());
        true
    }

    pub fn try_receive(&self) -> Option<Notification> {
        let sio = &rp_pac::SIO;
        if !sio.fifo().st().read().vld() {
            return None;
        }
        Notification::decode(sio.fifo().rd().read())
    }

    pub fn submit<const REQUEST: usize, const RESPONSE: usize>(
        &self,
        endpoint: &MailboxEndpoint<REQUEST, RESPONSE>,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        endpoint.submit(request)?;
        if self.try_notify_tx(Notification::new(0, MailboxState::RequestReady)) {
            Ok(())
        } else {
            Err(MailboxError::InvalidTransition)
        }
    }

    pub fn submit_operation<const REQUEST: usize, const RESPONSE: usize>(
        &self,
        endpoint: &MailboxEndpoint<REQUEST, RESPONSE>,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        endpoint.submit_operation(operation_code, request)?;
        if self.try_notify_tx(Notification::new(0, MailboxState::RequestReady)) {
            Ok(())
        } else {
            Err(MailboxError::InvalidTransition)
        }
    }

    pub fn pump<const REQUEST: usize, const RESPONSE: usize, S: MailboxService>(
        &self,
        endpoint: &MailboxEndpoint<REQUEST, RESPONSE>,
        service: &mut S,
        request: &mut [u8; REQUEST],
        response: &mut [u8; RESPONSE],
    ) -> Result<bool, MailboxError> {
        let Some(notification) = self.try_receive() else {
            return Ok(false);
        };
        if notification.state != MailboxState::RequestReady {
            return Ok(false);
        }
        let processed = endpoint.pump_once(service, request, response)?;
        if processed
            && !self.try_notify_tx(Notification::new(
                notification.worker,
                MailboxState::ResponseReady,
            ))
        {
            return Err(MailboxError::InvalidTransition);
        }
        Ok(processed)
    }

    pub fn pump_operation<
        const REQUEST: usize,
        const RESPONSE: usize,
        S: MailboxOperationService,
    >(
        &self,
        endpoint: &MailboxEndpoint<REQUEST, RESPONSE>,
        service: &mut S,
        request: &mut [u8; REQUEST],
        response: &mut [u8; RESPONSE],
    ) -> Result<bool, MailboxError> {
        let Some(notification) = self.try_receive() else {
            return Ok(false);
        };
        if notification.state != MailboxState::RequestReady {
            return Ok(false);
        }
        let processed = endpoint.pump_operation_once(service, request, response)?;
        if processed
            && !self.try_notify_tx(Notification::new(
                notification.worker,
                MailboxState::ResponseReady,
            ))
        {
            return Err(MailboxError::InvalidTransition);
        }
        Ok(processed)
    }
}

/// Start once with exclusive core1/FIFO/stack ownership; captured closure and frame must fit aligned stack.
/// ROM handshake and FIFO waits have no wall-clock timeout.
pub fn spawn_core1_polling<F, const SIZE: usize>(
    _core1: embassy_rp::Peri<'static, embassy_rp::peripherals::CORE1>,
    stack: &'static mut embassy_rp::multicore::Stack<SIZE>,
    entry: F,
) where
    F: FnOnce() -> bad::Never + Send + 'static,
{
    extern "C" fn core1_startup<F: FnOnce() -> bad::Never>(
        _: u64,
        _: u64,
        entry: *mut ManuallyDrop<F>,
        stack_bottom: *mut usize,
    ) -> ! {
        unsafe { core1_polling_setup(stack_bottom) };

        let entry = unsafe { ManuallyDrop::take(&mut *entry) };
        compiler_fence(Ordering::SeqCst);

        fifo_write_blocking(1);
        IS_POLLING_CORE1_INIT.store(true, Ordering::Release);

        #[cfg(all(feature = "chip-rp235xa", has_fpu))]
        unsafe {
            let p = cortex_m::Peripherals::steal();
            p.SCB.cpacr.modify(|cpacr| cpacr | (3 << 20) | (3 << 22));
        }

        entry()
    }

    reset_core1();

    let stack_words = stack.mem.len() / 8 * 2;
    let mem = unsafe {
        core::slice::from_raw_parts_mut(stack.mem.as_mut_ptr() as *mut usize, stack_words)
    };
    let mut stack_ptr = unsafe { mem.as_mut_ptr().add(mem.len()) };

    unsafe {
        let entry_size = size_of::<ManuallyDrop<F>>();
        if entry_size + 16 > stack.mem.len() {
            panic!("CORE1 stack too small for entry");
        }
        let entry_align = align_of::<ManuallyDrop<F>>();
        let entry_addr = ((stack_ptr as usize).wrapping_sub(entry_size)) & !(entry_align - 1);
        let frame_bottom = (entry_addr & !7usize)
            .checked_sub(2 * size_of::<usize>())
            .expect("CORE1 stack frame underflow");
        assert!(
            frame_bottom >= mem.as_ptr() as usize
                && entry_addr
                    .checked_add(entry_size)
                    .is_some_and(|end| end <= stack_ptr as usize),
            "CORE1 stack too small for aligned entry"
        );
        let entry_ptr = entry_addr as *mut ManuallyDrop<F>;
        entry_ptr.write(ManuallyDrop::new(entry));
        stack_ptr = entry_ptr.cast::<usize>();
        stack_ptr = ((stack_ptr as usize) & !7usize) as *mut usize;

        stack_ptr = stack_ptr.sub(1);
        stack_ptr.cast::<*mut usize>().write(mem.as_mut_ptr());
        stack_ptr = stack_ptr.sub(1);
        stack_ptr.cast::<*mut ManuallyDrop<F>>().write(entry_ptr);
    }

    compiler_fence(Ordering::Release);

    let vector_table = unsafe { cortex_m::Peripherals::steal().SCB.vtor.read() };
    let cmd_seq = [
        0,
        0,
        1,
        vector_table as usize,
        stack_ptr as usize,
        core1_startup::<F> as *const () as usize,
    ];

    let mut seq = 0;
    let mut fails = 0;
    loop {
        let cmd = cmd_seq[seq] as u32;
        if cmd == 0 {
            fifo_drain();
            cortex_m::asm::sev();
        }
        fifo_write_blocking(cmd);

        if fifo_read_blocking() == cmd {
            seq += 1;
        } else {
            seq = 0;
            fails += 1;
            if fails > 16 {
                panic!("CORE1 not responding");
            }
        }
        if seq >= cmd_seq.len() {
            break;
        }
    }

    let _ = fifo_read_blocking();
}

pub fn is_polling_core1_init() -> bool {
    IS_POLLING_CORE1_INIT.load(Ordering::Acquire)
}

/// # Safety
/// Called only on core1 before user entry with an exclusively owned valid stack and protection state.
unsafe fn core1_polling_setup(stack_bottom: *mut usize) {
    let _ = stack_bottom;
    #[cfg(feature = "chip-rp2040")]
    unsafe {
        let mpu = &*cortex_m::peripheral::MPU::PTR;
        assert_eq!(mpu.ctrl.read(), 0);
        let (base, rasr) =
            manekey::boundary::arm_m_mpu::stack_guard_region(stack_bottom as u32).unwrap();
        mpu.rnr.write(0);
        mpu.rbar.write(base);
        mpu.rasr.write(rasr);
        mpu.ctrl.write(5);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
    #[cfg(feature = "chip-rp235xa")]
    unsafe {
        cortex_m::register::msplim::write(stack_bottom.addr() as u32);
        (&*cortex_m::peripheral::ICB::PTR)
            .actlr
            .modify(|w| w | (1 << 29));
    }
}

fn reset_core1() {
    let psm = rp_pac::PSM;
    psm.frce_off().modify(|w| w.set_proc1(true));
    while !psm.frce_off().read().proc1() {
        cortex_m::asm::nop();
    }
    psm.frce_off().modify(|w| w.set_proc1(false));
}

fn fifo_write_blocking(value: u32) {
    let sio = &rp_pac::SIO;
    while !sio.fifo().st().read().rdy() {
        cortex_m::asm::nop();
    }
    sio.fifo().wr().write_value(value);
    cortex_m::asm::sev();
}

fn fifo_read_blocking() -> u32 {
    let sio = &rp_pac::SIO;
    while !sio.fifo().st().read().vld() {
        cortex_m::asm::nop();
    }
    sio.fifo().rd().read()
}

fn fifo_drain() {
    let sio = &rp_pac::SIO;
    while sio.fifo().st().read().vld() {
        let _ = sio.fifo().rd().read();
    }
}

// Never helper derived from bad-rs; Copyright (c) 2019 Nikolai Vazquez.
// Source: https://github.com/nvzqz/bad-rs/blob/fdc623548d1a30c44feebfde745da929186201f9/src/never.rs
// Original helper: Unlicense OR MIT; retained MIT terms are in ports/rp/NOTICE.
mod bad {
    pub(crate) type Never = <F as HasOutput>::Output;

    pub trait HasOutput {
        type Output;
    }

    impl<O> HasOutput for fn() -> O {
        type Output = O;
    }

    type F = fn() -> !;
}
