use core::sync::atomic::{AtomicU32, Ordering};

use esp_hal::system::{AppCoreGuard, Cpu, CpuControl, Error, Stack};
use manekey::{
    boundary::mailbox::{LocalMailboxWorker, MailboxEndpoint},
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedBackend},
};

/// Software worker ownership, not RAM isolation; retain the returned AppCoreGuard while using its endpoint.
pub struct AppCoreTrustedWorker<const STACK_SIZE: usize> {
    stack: &'static mut Stack<STACK_SIZE>,
    endpoint: &'static MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    marker: &'static AtomicU32,
}

impl<const STACK_SIZE: usize> AppCoreTrustedWorker<STACK_SIZE> {
    pub const fn new(
        stack: &'static mut Stack<STACK_SIZE>,
        endpoint: &'static MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
        marker: &'static AtomicU32,
    ) -> Self {
        Self {
            stack,
            endpoint,
            marker,
        }
    }

    pub fn start<T: TrustedBackend + Send + 'static>(
        self,
        cpu_control: &mut CpuControl<'static>,
        dispatcher: T,
        marker_threshold: u32,
    ) -> Result<(AppCoreGuard<'static>, u32), Error> {
        let guard = cpu_control.start_app_core(self.stack, move || {
            run_trusted_worker(dispatcher, self.endpoint, self.marker)
        })?;
        let marker = wait_for_trusted_worker_marker(self.marker, marker_threshold);
        Ok((guard, marker))
    }
}

/// Spins without timeout until the startup marker reaches threshold.
pub fn wait_for_trusted_worker_marker(marker: &AtomicU32, threshold: u32) -> u32 {
    loop {
        let value = marker.load(Ordering::Acquire);
        if value >= threshold {
            return value;
        }
        core::hint::spin_loop();
    }
}

pub fn run_trusted_worker<T: TrustedBackend>(
    dispatcher: T,
    endpoint: &'static MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    marker: &'static AtomicU32,
) -> ! {
    let mut worker = LocalMailboxWorker::new(dispatcher);
    let mut marker_value = Cpu::current() as u32;

    loop {
        marker_value = marker_value.wrapping_add(1);
        marker.store(marker_value, Ordering::Release);
        let _ = worker.pump_once(endpoint);
        core::hint::spin_loop();
    }
}
