#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
use crate::fips204_scratch_workspace::init_backend as init_fips204_scratch_backend;
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(feature = "experimental-ml-dsa-fips204")]
use manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
use manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;

use manekey::{
    ctaphid::{
        entropy::HmacDrbgEntropy,
        pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
        storage::Storage,
        trusted::TrustedDispatcher,
        user_verification::UnavailableUserVerification,
    },
    frontend::ingress::IngressArbiter,
    presence::{NoPresenceObserver, UserPresence},
    transport::{BLE_TRANSPORTS, USB_BLE_TRANSPORTS, USB_TRANSPORTS},
    user_interface::{AtomicUiStatus, UiPresenceObserver},
};

use crate::{
    entropy::Nrf54EntropySource,
    presence::UserKeyPresence,
    storage::{Nrf54RramCredentialStorage, Nrf54RramPinStorage, Nrf54SharedRram},
};

#[cfg(not(any(feature = "kmu-key-store", feature = "flash-managed-keys")))]
type BaseRramKeyStore = crate::crypto_config::DerivedKeys;
#[cfg(feature = "kmu-key-store")]
type BaseRramKeyStore = crate::kmu_key_store::KmuKeyStore;
#[cfg(feature = "flash-managed-keys")]
type BaseRramKeyStore = crate::flash_key_store::FlashKeys;

#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
type SelectedRramKeyStore = BaseRramKeyStore;
#[cfg(feature = "experimental-ml-dsa-fips204")]
type SelectedRramKeyStore = AdditionalSignaturePrivateKeyStore<BaseRramKeyStore, Fips204MlDsa44>;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
type SelectedRramKeyStore = AdditionalSignaturePrivateKeyStore<
    BaseRramKeyStore,
    crate::fips204_scratch_workspace::ScratchBackend,
>;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
type SelectedRramKeyStore =
    AdditionalSignaturePrivateKeyStore<BaseRramKeyStore, MldsaNativeMlDsa44>;

fn selected_rram_key_store(
    rram: &'static Nrf54SharedRram,
    storage: &mut Storage<Nrf54RramCredentialStorage>,
    entropy: &mut HmacDrbgEntropy<Nrf54EntropySource>,
) -> SelectedRramKeyStore {
    #[cfg(any(feature = "kmu-key-store", feature = "flash-managed-keys"))]
    let fallback = {
        let mut empty = true;
        for index in 0..manekey::ctaphid::storage::MAX_RECORDS {
            if storage
                .load_record_checked(index)
                .expect("managed credential journal integrity")
                .is_some()
            {
                empty = false;
            }
        }
        #[cfg(feature = "kmu-key-store")]
        let mut store = crate::kmu_key_store::open(rram, entropy, empty).expect("KMU device root");
        #[cfg(feature = "flash-managed-keys")]
        let mut store =
            crate::flash_key_store::open(rram, entropy, empty).expect("RRAM device root");
        store
            .reconcile(storage)
            .expect("managed credential journal reconciliation");
        store
    };
    #[cfg(feature = "experimental-ml-dsa-fips204")]
    {
        AdditionalSignaturePrivateKeyStore::new(fallback, Fips204MlDsa44)
    }
    #[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
    {
        AdditionalSignaturePrivateKeyStore::new(fallback, init_fips204_scratch_backend())
    }
    #[cfg(feature = "experimental-ml-dsa-mldsa-native")]
    {
        AdditionalSignaturePrivateKeyStore::new(fallback, MldsaNativeMlDsa44)
    }
    #[cfg(not(any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )))]
    {
        fallback
    }
}

/// Requires reserved RRAM journals, selected managed keys and initialized Secure crypto/entropy owners.
pub type RramDispatcher<'d, P = UserKeyPresence<'d>> = TrustedDispatcher<
    Nrf54RramCredentialStorage,
    P,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<Nrf54RramPinStorage>,
        crate::crypto_config::ClientPinCrypto,
    >,
    SelectedRramKeyStore,
    HmacDrbgEntropy<Nrf54EntropySource>,
    UiPresenceObserver<NoPresenceObserver, &'static AtomicUiStatus>,
>;

pub type RramIngressArbiter<'d, P = UserKeyPresence<'d>> = IngressArbiter<RramDispatcher<'d, P>>;

pub fn build_rram_dispatcher<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
) -> RramDispatcher<'d, P> {
    build_rram_dispatcher_with_transports(presence, entropy, rram, ui_status, BLE_TRANSPORTS)
}

/// Construct once per owner; transport declarations do not prove physical USB bridge availability.
pub fn build_rram_dispatcher_with_transports<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
    transports: &'static [&'static [u8]],
) -> RramDispatcher<'d, P> {
    let mut entropy = entropy;
    let mut storage = Storage::new(Nrf54RramCredentialStorage::new(rram));
    let key_store = selected_rram_key_store(rram, &mut storage, &mut entropy);
    TrustedDispatcher::new_with_transports_and_presence_observer(
        storage,
        presence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_crypto(
            JournaledPinUvAuthStorage::new(Nrf54RramPinStorage::new(rram)),
            crate::crypto_config::client_pin_crypto(),
        ),
        key_store,
        entropy,
        transports,
        UiPresenceObserver::new(NoPresenceObserver, ui_status),
    )
}

pub fn build_rram_virtual_hid_dispatcher<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
) -> RramDispatcher<'d, P> {
    build_rram_dispatcher_with_transports(presence, entropy, rram, ui_status, USB_TRANSPORTS)
}

pub fn build_rram_virtual_hid_arbiter<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
) -> RramIngressArbiter<'d, P> {
    IngressArbiter::new(build_rram_virtual_hid_dispatcher(
        presence, entropy, rram, ui_status,
    ))
}

pub fn build_rram_ble_arbiter<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
) -> RramIngressArbiter<'d, P> {
    IngressArbiter::new(build_rram_dispatcher(presence, entropy, rram, ui_status))
}

pub fn build_rram_ble_virtual_hid_arbiter<'d, P: UserPresence>(
    presence: P,
    entropy: HmacDrbgEntropy<Nrf54EntropySource>,
    rram: &'static Nrf54SharedRram,
    ui_status: &'static AtomicUiStatus,
) -> RramIngressArbiter<'d, P> {
    IngressArbiter::new(build_rram_dispatcher_with_transports(
        presence,
        entropy,
        rram,
        ui_status,
        USB_BLE_TRANSPORTS,
    ))
}
