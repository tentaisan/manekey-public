#![no_std]
#![no_main]

use manekey::boundary::{
    mailbox::{LocalMailboxTransport, LocalMailboxWorker, MailboxEndpoint},
    mailbox_backend::MailboxTrustedBackend,
};
#[cfg(all(
    not(feature = "riscv-flash-managed-keys"),
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(not(feature = "riscv-flash-managed-keys"))]
use manekey::ctaphid::key_store::FlashPrivateKeyStore;
use manekey::ctaphid::{
    entropy::HmacDrbgEntropy,
    pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
    storage::Storage,
    trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedDispatcher},
    user_verification::UnavailableUserVerification,
};
use manekey_rp::platform::rp::storage::{RiscvFlashStorage, RiscvPinUvAuthFlashStorage};
#[cfg(all(
    feature = "riscv-pico-2-w-ble-bootsel",
    not(feature = "up-always-present")
))]
use manekey_rp::platform::rp::user_interface::RiscvBootselPresence;
#[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
use manekey_rp::platform::rp::user_interface::RiscvGpioUserPresence;
use manekey_rp::platform::rp2350::{entropy::RiscvTrng, riscv_token_clock::Rp2350RiscvTokenClock};

const BACKEND_TASK_SPAWN_FAILED: u32 = 0xffff_fffe;

#[cfg(all(
    feature = "riscv-pico-2-w-ble-bootsel",
    not(feature = "up-always-present")
))]
type SelectedPresence = RiscvBootselPresence;
#[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
type SelectedPresence = RiscvGpioUserPresence<ButtonPin>;

#[cfg(feature = "up-always-present")]
type SelectedPresence = manekey::presence::AlwaysPresent;

#[cfg(feature = "riscv-flash-managed-keys")]
type SelectedPrivateKeyStore = manekey_rp::platform::rp2350::key_store::Keys<
    manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
>;
#[cfg(all(
    not(feature = "riscv-flash-managed-keys"),
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
))]
type SelectedPrivateKeyStore = AdditionalSignaturePrivateKeyStore<
    FlashPrivateKeyStore,
    manekey_rp::platform::rp2350::riscv_crypto::MlDsa,
>;
#[cfg(not(any(
    feature = "riscv-flash-managed-keys",
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
)))]
type SelectedPrivateKeyStore = FlashPrivateKeyStore;

type SelectedDispatcher = TrustedDispatcher<
    RiscvFlashStorage,
    SelectedPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<RiscvPinUvAuthFlashStorage>,
        manekey_rp::platform::rp2350::riscv_crypto::ClientPinCrypto,
        Rp2350RiscvTokenClock,
    >,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<RiscvTrng>,
    manekey_rp::platform::rp2350::riscv_ui::PresenceObserver,
>;

type SelectedBleBackend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;
type SelectedBleRuntime = ();
const SELECTED_BLE_RUNTIME_TICK_MS: u64 = 100;

static MAILBOX_ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
static DISPATCHER: static_cell::StaticCell<SelectedDispatcher> = static_cell::StaticCell::new();

#[allow(unused_variables)]
/// Initialize one worker/client before radio startup with exclusive TRNG/SHA/Flash ownership.
/// Local mailbox task separation is not hardware isolation; BOOTSEL requires XIP-master exclusion.
fn selected_ble_backend(
    spawner: embassy_executor::Spawner,
    timer: rp235x_hal::timer::Timer<rp235x_hal::timer::CopyableTimer0>,
    button: ButtonPin,
    trng: rp235x_hal::pac::TRNG,
    _psm: &mut rp235x_hal::pac::PSM,
    _fifo: &mut rp235x_hal::sio::SioFifo,
) -> Result<(SelectedBleBackend, SelectedBleRuntime), u32> {
    #[allow(unused_mut)]
    let mut entropy = HmacDrbgEntropy::new(RiscvTrng::new(trng))
        .map_err(|_| manekey_rp::platform::rp2350::entropy::riscv_entropy_error())?;
    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(all(
        feature = "riscv-pico-2-w-ble-bootsel",
        not(feature = "up-always-present")
    ))]
    let presence = RiscvBootselPresence::new();
    #[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
    let presence = RiscvGpioUserPresence::new(button, timer);
    #[allow(unused_mut)]
    let mut records = Storage::new(RiscvFlashStorage::new());
    #[cfg(feature = "riscv-flash-managed-keys")]
    let private_key_store = unsafe {
        manekey_rp::platform::rp2350::key_store::open(
            manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
            &mut records,
            &mut entropy,
        )
    }
    .map_err(|_| 0xffff_fff9_u32)?;
    #[cfg(all(
        not(feature = "riscv-flash-managed-keys"),
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
    ))]
    let private_key_store = AdditionalSignaturePrivateKeyStore::new(
        FlashPrivateKeyStore,
        manekey_rp::platform::rp2350::riscv_crypto::ml_dsa(),
    );
    #[cfg(not(any(
        feature = "riscv-flash-managed-keys",
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
    )))]
    let private_key_store = FlashPrivateKeyStore;
    let dispatcher = DISPATCHER.init(
        TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            presence,
            UnavailableUserVerification,
            StoredPinUvAuthProvider::new_with_crypto_and_clock(
                JournaledPinUvAuthStorage::new(RiscvPinUvAuthFlashStorage::new()),
                unsafe { manekey_rp::platform::rp2350::riscv_crypto::client_pin_crypto() },
                Rp2350RiscvTokenClock,
            ),
            private_key_store,
            entropy,
            selected_transport_ids(),
            manekey_rp::platform::rp2350::riscv_ui::presence_observer(),
        ),
    );
    let token = trusted_task(dispatcher).map_err(|_| BACKEND_TASK_SPAWN_FAILED)?;
    spawner.spawn(token);
    Ok((
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX_ENDPOINT)),
        (),
    ))
}

fn selected_ble_runtime_tick(_runtime: &mut SelectedBleRuntime) {}

fn selected_ble_runtime_should_poll_status(_runtime: &mut SelectedBleRuntime) -> bool {
    true
}

#[embassy_executor::task]
/// Sole dispatcher worker for the fixed endpoint; callers must serialize their mailbox operations.
async fn trusted_task(dispatcher: &'static mut SelectedDispatcher) {
    let mut worker = LocalMailboxWorker::from_ref(dispatcher);

    loop {
        match worker.pump_once(&MAILBOX_ENDPOINT) {
            Ok(true) => {}
            Ok(false) | Err(_) => embassy_futures::yield_now().await,
        }
    }
}

include!("ble/riscv_pico_2_w_ble_common.rs");
