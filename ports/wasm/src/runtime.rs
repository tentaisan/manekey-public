// SPDX-License-Identifier: AGPL-3.0-only

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::backend::{HostClock, HostCredentialStorage, HostEntropy, HostPinStorage};
use manekey::ctaphid::{
    key_store::FlashPrivateKeyStore,
    pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthStateStorage, StoredPinUvAuthProvider},
    storage::{FLASH_SECTOR_SIZE, STORAGE_PAGE_COUNT, Storage, StorageBackend},
    trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedDispatcher, TrustedResult},
    user_verification::UnavailableUserVerification,
};
use manekey::presence::{ManualPresenceState, PresenceStatus, UserPresence};

#[cfg(target_feature = "atomics")]
compile_error!("manekey-wasm requires an isolated single-thread no-std instance");

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

/// Single-thread instance protected by Entry; host callbacks and buffer access must not race Rust.
struct SingleInstance<T>(UnsafeCell<T>);

unsafe impl<T> Sync for SingleInstance<T> {}

static ENTERED: AtomicBool = AtomicBool::new(false);
static PRESENCE: SingleInstance<ManualPresenceState> =
    SingleInstance(UnsafeCell::new(ManualPresenceState::new(30_000)));

struct Entry;
impl Entry {
    fn enter() -> Option<Self> {
        ENTERED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self)
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        ENTERED.store(false, Ordering::Release);
    }
}

struct ExplicitPresence;
impl UserPresence for ExplicitPresence {
    fn is_present(&mut self) -> bool {
        self.poll() == PresenceStatus::Confirmed
    }
    fn begin_wait(&mut self) {
        unsafe {
            let state = &mut *PRESENCE.0.get();
            if let Some(now) = HostClock::checked_now_ms() {
                let _ = state.begin_wait(now);
            } else {
                state.cancel();
            }
        }
    }
    fn poll(&mut self) -> PresenceStatus {
        unsafe {
            let state = &mut *PRESENCE.0.get();
            match HostClock::checked_now_ms() {
                Some(now) => state.poll(now),
                None => {
                    state.cancel();
                    PresenceStatus::TimedOut
                }
            }
        }
    }
    fn cancel(&mut self) {
        unsafe {
            (*PRESENCE.0.get()).cancel();
        }
    }
}

type Dispatcher = TrustedDispatcher<
    HostCredentialStorage,
    ExplicitPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<HostPinStorage>,
        manekey::ctaphid::crypto::SoftwareClientPinCrypto,
        HostClock,
    >,
    FlashPrivateKeyStore,
    HostEntropy,
>;

struct Runtime {
    dispatcher: Option<Dispatcher>,
    input: [u8; TRUSTED_REQUEST_MAX],
    output: [u8; TRUSTED_RESPONSE_MAX],
    output_len: usize,
    last_clock: Option<u64>,
}
static RUNTIME: SingleInstance<Runtime> = SingleInstance(UnsafeCell::new(Runtime {
    dispatcher: None,
    input: [0; TRUSTED_REQUEST_MAX],
    output: [0; TRUSTED_RESPONSE_MAX],
    output_len: 0,
    last_clock: None,
}));

fn clock_valid(runtime: &mut Runtime) -> bool {
    let now = HostClock::checked_now_ms();
    if now.is_none() || now.is_some_and(|now| runtime.last_clock.is_some_and(|last| now < last)) {
        if let Some(dispatcher) = runtime.dispatcher.as_mut() {
            let _ = dispatcher.cancel();
        }

        unsafe {
            (*PRESENCE.0.get()).cancel();
        }
        runtime.output_len = 0;
        return false;
    }
    runtime.last_clock = now;
    true
}

fn response(result: Option<TrustedResult<'_>>, output: &mut [u8], length: &mut usize) -> u32 {
    match result {
        Some(TrustedResult::Response(data)) if data.len() <= output.len() => {
            output[..data.len()].copy_from_slice(data);
            *length = data.len();
        }
        None => *length = 0,
        other => {
            output[0] = match other {
                Some(TrustedResult::UserPresencePending) => 0x2e,
                Some(TrustedResult::Busy) => 0x21,
                Some(TrustedResult::InvalidRequest) => 0x03,
                _ => 0x7f,
            };
            *length = 1;
        }
    }
    *length as u32
}

#[unsafe(no_mangle)]
/// Initializes once. Host callbacks are synchronous and non-reentrant.
/// Persistence and power-loss guarantees belong to the host, not readback.
pub extern "C" fn manekey_product_init() -> u32 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    let runtime = unsafe { &mut *RUNTIME.0.get() };
    if runtime.dispatcher.is_some() || !clock_valid(runtime) {
        return 0;
    }
    let mut credentials = HostCredentialStorage;
    let mut page = [0; FLASH_SECTOR_SIZE];
    for index in 0..STORAGE_PAGE_COUNT {
        if credentials.read_page(index, &mut page).is_err() {
            return 0;
        }
    }
    let mut pin = JournaledPinUvAuthStorage::new(HostPinStorage);
    if pin.load_pin_state().is_err() {
        return 0;
    }
    page.fill(0);
    runtime.dispatcher = Some(TrustedDispatcher::new_with_transports(
        Storage::new(credentials),
        ExplicitPresence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_clock(pin, HostClock),
        FlashPrivateKeyStore,
        HostEntropy,
        manekey::transport::USB_TRANSPORTS,
    ));
    1
}

#[unsafe(no_mangle)]
/// Request buffer pointer; host must not modify it during an operation or callback.
pub extern "C" fn manekey_product_input_ptr() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*RUNTIME.0.get()).input).cast() }
}
#[unsafe(no_mangle)]
pub extern "C" fn manekey_product_input_capacity() -> u32 {
    TRUSTED_REQUEST_MAX as u32
}
#[unsafe(no_mangle)]
/// Response pointer; read only while idle and only the returned response length.
pub extern "C" fn manekey_product_response_ptr() -> *const u8 {
    unsafe { core::ptr::addr_of!((*RUNTIME.0.get()).output).cast() }
}

#[unsafe(no_mangle)]
pub extern "C" fn manekey_product_submit(length: u32) -> u32 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    let runtime = unsafe { &mut *RUNTIME.0.get() };
    if !clock_valid(runtime) || length == 0 || length as usize > TRUSTED_REQUEST_MAX {
        runtime.output[0] = 0x03;
        runtime.output_len = 1;
        return 1;
    }
    let Some(dispatcher) = runtime.dispatcher.as_mut() else {
        return 0;
    };
    let result = dispatcher.submit_cbor(&runtime.input[..length as usize]);
    response(Some(result), &mut runtime.output, &mut runtime.output_len)
}

#[unsafe(no_mangle)]
pub extern "C" fn manekey_product_poll() -> u32 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    let runtime = unsafe { &mut *RUNTIME.0.get() };
    if !clock_valid(runtime) {
        return 0;
    }
    let Some(dispatcher) = runtime.dispatcher.as_mut() else {
        return 0;
    };
    response(
        dispatcher.poll(),
        &mut runtime.output,
        &mut runtime.output_len,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn manekey_product_cancel() -> u32 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    let runtime = unsafe { &mut *RUNTIME.0.get() };
    runtime
        .dispatcher
        .as_mut()
        .is_some_and(|dispatcher| dispatcher.cancel()) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn manekey_product_pending_request() -> u64 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    unsafe {
        if !clock_valid(&mut *RUNTIME.0.get()) {
            return 0;
        }
        (*PRESENCE.0.get())
            .pending_request(HostClock::checked_now_ms().unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

#[unsafe(no_mangle)]
/// Confirms the current request; the host owns UI authentication and physical-action policy.
pub extern "C" fn manekey_product_confirm(request: u64) -> u32 {
    let Some(_entry) = Entry::enter() else {
        return 0;
    };

    unsafe {
        if !clock_valid(&mut *RUNTIME.0.get()) {
            return 0;
        }
        (*PRESENCE.0.get()).confirm(request, HostClock::checked_now_ms().unwrap_or(u64::MAX)) as u32
    }
}
