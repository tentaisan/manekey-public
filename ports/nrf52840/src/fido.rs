#[cfg(feature = "client-pin-volatile")]
use crate::crypto::{Cc310Sha256, SharedCc310Peripheral, SharedCc310Sha256};
#[cfg(not(feature = "client-pin-volatile"))]
use crate::key_store::selected_private_key_store;
#[cfg(feature = "client-pin-volatile")]
use crate::key_store::wrap_private_key_store;
#[cfg(feature = "experimental-p256-accelerator")]
use crate::p256::Cc310P256;
#[cfg(feature = "client-pin-flash-storage")]
use crate::storage::{NrfPinUvAuthFlashStorage, NrfSoftdevicePinUvAuthFlashStorage};
#[cfg(feature = "client-pin-volatile")]
use crate::token_clock::NrfRtc1TokenClock;
use crate::{
    entropy::{NrfRngEntropy, SoftdeviceEntropy},
    key_store::SelectedPrivateKeyStore,
    storage::{SelectedSoftdeviceStorage, SelectedStorage},
};
#[cfg(feature = "client-pin-volatile")]
use core::cell::RefCell;
#[cfg(feature = "experimental-p256-accelerator")]
use manekey::ctaphid::crypto::SoftwareAes256Block;
#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "nrf-flash-managed-keys")
))]
use manekey::ctaphid::key_store::DerivedPrivateKeyStore;
#[cfg(feature = "client-pin-flash-storage")]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(not(feature = "client-pin-volatile"))]
use manekey::ctaphid::pin_uv_auth::UnconfiguredPinUvAuth;
#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "client-pin-flash-storage")
))]
use manekey::ctaphid::pin_uv_auth::VolatilePinUvAuthStorage;
use manekey::ctaphid::{
    CtaphidFrontend, entropy::HmacDrbgEntropy, trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
#[cfg(feature = "client-pin-volatile")]
use manekey::ctaphid::{
    crypto::Sha256ClientPinCrypto,
    hash::Sha256Backend,
    pin_uv_auth::{PinUvAuthStateStorage, StoredPinUvAuthProvider},
};
use manekey::ctaphid::{
    entropy::EntropySource,
    storage::{Storage, StorageBackend},
};
use manekey::presence::NoPresenceObserver;
#[cfg(feature = "nrf-dual-task")]
use manekey::{
    boundary::{
        mailbox::{LocalMailboxTransport, LocalMailboxWorker, MailboxEndpoint},
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
};
use nrf52840_pac::{FICR, RTC1};
#[cfg(feature = "client-pin-volatile")]
use static_cell::StaticCell;

#[cfg(not(feature = "client-pin-volatile"))]
pub type SelectedPinUvAuth = UnconfiguredPinUvAuth;
#[cfg(not(feature = "client-pin-volatile"))]
pub type SelectedSoftdevicePinUvAuth = UnconfiguredPinUvAuth;
#[cfg(feature = "client-pin-volatile")]
#[cfg(not(feature = "experimental-p256-accelerator"))]
type SelectedClientPinCrypto = Sha256ClientPinCrypto<SharedCc310Sha256>;
#[cfg(feature = "experimental-p256-accelerator")]
type SelectedClientPinCrypto =
    Sha256ClientPinCrypto<SharedCc310Sha256, SoftwareAes256Block, Cc310P256>;

#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "client-pin-flash-storage")
))]
type SelectedUsbPinStorage = VolatilePinUvAuthStorage;
#[cfg(feature = "client-pin-flash-storage")]
type SelectedUsbPinStorage = JournaledPinUvAuthStorage<NrfPinUvAuthFlashStorage>;
#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "client-pin-flash-storage")
))]
type SelectedBlePinStorage = VolatilePinUvAuthStorage;
#[cfg(feature = "client-pin-flash-storage")]
type SelectedBlePinStorage = JournaledPinUvAuthStorage<NrfSoftdevicePinUvAuthFlashStorage>;

#[cfg(feature = "client-pin-volatile")]
pub type SelectedPinUvAuth =
    StoredPinUvAuthProvider<SelectedUsbPinStorage, SelectedClientPinCrypto, NrfRtc1TokenClock>;
#[cfg(feature = "client-pin-volatile")]
pub type SelectedSoftdevicePinUvAuth =
    StoredPinUvAuthProvider<SelectedBlePinStorage, SelectedClientPinCrypto, NrfRtc1TokenClock>;

#[cfg(feature = "client-pin-volatile")]
static SHARED_CC310: StaticCell<SharedCc310Peripheral> = StaticCell::new();

#[cfg(not(feature = "client-pin-volatile"))]
pub fn selected_crypto_backends<R: StorageBackend, E: EntropySource>(
    ficr: FICR,
    _rtc1: RTC1,
    log: fn(&str),
    _records: &mut Storage<R>,
    _entropy: &mut E,
) -> (SelectedPrivateKeyStore, SelectedPinUvAuth) {
    (
        selected_private_key_store(ficr, log),
        UnconfiguredPinUvAuth::new(),
    )
}

#[cfg(not(feature = "client-pin-volatile"))]
pub fn selected_softdevice_crypto_backends<R: StorageBackend, E: EntropySource>(
    ficr: FICR,
    rtc1: RTC1,
    log: fn(&str),
    records: &mut Storage<R>,
    entropy: &mut E,
) -> (SelectedPrivateKeyStore, SelectedSoftdevicePinUvAuth) {
    selected_crypto_backends(ficr, rtc1, log, records, entropy)
}

#[cfg(feature = "client-pin-volatile")]
pub fn selected_crypto_backends<R: StorageBackend, E: EntropySource>(
    ficr: FICR,
    rtc1: RTC1,
    log: fn(&str),
    records: &mut Storage<R>,
    entropy: &mut E,
) -> (SelectedPrivateKeyStore, SelectedPinUvAuth) {
    #[cfg(feature = "client-pin-flash-storage")]
    let pin_storage = JournaledPinUvAuthStorage::new(NrfPinUvAuthFlashStorage::new());
    #[cfg(not(feature = "client-pin-flash-storage"))]
    let pin_storage = VolatilePinUvAuthStorage::new();
    build_crypto_backends(ficr, rtc1, log, pin_storage, records, entropy, false)
}

#[cfg(feature = "client-pin-volatile")]
pub fn selected_softdevice_crypto_backends<R: StorageBackend, E: EntropySource>(
    ficr: FICR,
    rtc1: RTC1,
    log: fn(&str),
    records: &mut Storage<R>,
    entropy: &mut E,
) -> (SelectedPrivateKeyStore, SelectedSoftdevicePinUvAuth) {
    #[cfg(feature = "client-pin-flash-storage")]
    let pin_storage = JournaledPinUvAuthStorage::new(NrfSoftdevicePinUvAuthFlashStorage::new());
    #[cfg(not(feature = "client-pin-flash-storage"))]
    let pin_storage = VolatilePinUvAuthStorage::new();
    build_crypto_backends(ficr, rtc1, log, pin_storage, records, entropy, true)
}

#[cfg(feature = "client-pin-volatile")]
/// Initialize static crypto once with exclusive CryptoCell/RTC1 ownership and matching storage mode.
fn build_crypto_backends<S: PinUvAuthStateStorage, R: StorageBackend, E: EntropySource>(
    _ficr: FICR,
    rtc1: RTC1,
    log: fn(&str),
    pin_storage: S,
    _records: &mut Storage<R>,
    _entropy: &mut E,
    _softdevice: bool,
) -> (
    SelectedPrivateKeyStore,
    StoredPinUvAuthProvider<S, SelectedClientPinCrypto, NrfRtc1TokenClock>,
) {
    let shared = &*SHARED_CC310.init(critical_section::Mutex::new(RefCell::new(unsafe {
        Cc310Sha256::new_unchecked()
    })));
    let mut key_store_hash = SharedCc310Sha256::new(shared);
    let kat_input = [b'a', b'b', b'c'];
    assert_eq!(
        key_store_hash.digest(&kat_input).ok(),
        Some([
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ])
    );
    #[cfg(feature = "client-pin-flash-storage")]
    log("client-pin=nrf-cryptocell-sha256-flash\r\n");
    #[cfg(not(feature = "client-pin-flash-storage"))]
    log("client-pin=nrf-cryptocell-sha256-volatile\r\n");
    #[cfg(not(feature = "nrf-flash-managed-keys"))]
    let key_store = wrap_private_key_store(
        DerivedPrivateKeyStore::from_device_id_with_hash(
            &crate::key_store::nrf_device_id(&_ficr),
            key_store_hash,
        )
        .expect("derive nRF52840 device key with shared CryptoCell SHA-256"),
    );
    #[cfg(feature = "nrf-flash-managed-keys")]
    let key_store = {
        let keys =
            crate::key_store::open_managed(_softdevice, _records, _entropy, key_store_hash, log)
                .unwrap_or_else(|error| {
                    use manekey::ctaphid::managed_key_store::ManagedKeyError;
                    log(match error {
                        ManagedKeyError::Hardware => "managed error: hardware\r\n",
                        ManagedKeyError::CorruptStorage => "managed error: corrupt-storage\r\n",
                        ManagedKeyError::ForeignAsset => "managed error: foreign-asset\r\n",
                        ManagedKeyError::MissingAsset => "managed error: missing-asset\r\n",
                        ManagedKeyError::InvalidHandle => "managed error: invalid-handle\r\n",
                        ManagedKeyError::Entropy => "managed error: entropy\r\n",
                        _ => "managed error: other\r\n",
                    });

                    panic!("managed factory failed closed")
                });
        log("key-store=nrf-flash-managed\r\n");
        wrap_private_key_store(keys)
    };
    #[cfg(not(feature = "experimental-p256-accelerator"))]
    let client_pin_crypto = Sha256ClientPinCrypto::new(SharedCc310Sha256::new(shared));
    #[cfg(feature = "experimental-p256-accelerator")]
    let client_pin_crypto = {
        let mut p256 = Cc310P256::new().expect("initialize experimental CC310 P-256 backend");
        p256.self_test()
            .expect("experimental CC310 P-256 startup self-test");
        log("client-pin-p256=experimental-nrf-cc310\r\n");
        Sha256ClientPinCrypto::new_with_backends(
            SharedCc310Sha256::new(shared),
            SoftwareAes256Block,
            p256,
        )
    };
    let pin_uv_auth = StoredPinUvAuthProvider::new_with_crypto_and_clock(
        pin_storage,
        client_pin_crypto,
        NrfRtc1TokenClock::start(rtc1),
    );
    (key_store, pin_uv_auth)
}

/// Direct dispatcher composition; hardware isolation requires a separate boundary runtime.
pub type NrfDispatcher<UserPresence, Observer = NoPresenceObserver> = TrustedDispatcher<
    SelectedStorage,
    UserPresence,
    UnavailableUserVerification,
    SelectedPinUvAuth,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<NrfRngEntropy>,
    Observer,
>;

/// Requires active SoftDevice entropy/storage ownership and reserved private media.
pub type NrfSoftdeviceDispatcher<UserPresence, Observer = NoPresenceObserver> = TrustedDispatcher<
    SelectedSoftdeviceStorage,
    UserPresence,
    UnavailableUserVerification,
    SelectedSoftdevicePinUvAuth,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<SoftdeviceEntropy>,
    Observer,
>;

#[cfg(not(feature = "nrf-dual-task"))]
pub type NrfCtaphid<UserPresence, Observer = NoPresenceObserver> =
    CtaphidFrontend<NrfDispatcher<UserPresence, Observer>>;

#[cfg(feature = "nrf-dual-task")]
pub type NrfCtaphid = CtaphidFrontend<NrfLocalMailboxBackend>;

#[cfg(feature = "nrf-dual-task")]
type NrfMailboxEndpoint = MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

#[cfg(feature = "nrf-dual-task")]
pub static NRF_MAILBOX: NrfMailboxEndpoint = NrfMailboxEndpoint::new();

#[cfg(feature = "nrf-dual-task")]
/// Single-core cooperative mailbox, not hardware isolation; reserve one frontend/worker owner.
pub type NrfLocalMailboxBackend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;

#[cfg(feature = "nrf-dual-task")]
pub fn local_mailbox_backend() -> NrfLocalMailboxBackend {
    MailboxTrustedBackend::new(LocalMailboxTransport::new(&NRF_MAILBOX))
}

#[cfg(feature = "nrf-dual-task")]

pub type NrfLocalTrustedWorker<D> =
    LocalMailboxWorker<D, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;
