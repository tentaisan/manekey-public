use core::cell::RefCell;

use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use esp_hal::{
    efuse,
    peripherals::{AES, SHA},
    time::Instant,
};
use esp_println::println;
use manekey::ctaphid::{
    crypto::Sha256ClientPinCrypto,
    hash::{Sha256Backend, Sha256Error},
    key_store::DerivedPrivateKeyStore,
    pin_uv_auth::{PinUvAuthStateStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
};
use static_cell::StaticCell;

use crate::crypto::{
    EspAes256, EspSha256, build_derived_key_store, verify_aes256_accelerator,
    verify_sha256_accelerator,
};

/// Critical-section shared SHA state; platform must provide cross-core exclusion and protected placement.
pub type SharedEspShaPeripheral = Mutex<CriticalSectionRawMutex, RefCell<EspSha256<'static>>>;
static SHARED_SHA: StaticCell<SharedEspShaPeripheral> = StaticCell::new();

pub fn init_shared_hash(sha: SHA<'static>) -> SharedEspSha256 {
    shared_hash_from_peripheral(&*SHARED_SHA.init(new_shared_sha_peripheral(sha)))
}

pub fn shared_hash_from_peripheral(shared: &'static SharedEspShaPeripheral) -> SharedEspSha256 {
    let mut hash = SharedEspSha256 { shared };
    verify_sha256_accelerator(&mut hash);
    println!("ESP SHA-256 accelerator shared by key store and ClientPIN");
    hash
}

#[derive(Clone, Copy)]
pub struct SharedEspSha256 {
    shared: &'static SharedEspShaPeripheral,
}

impl Sha256Backend for SharedEspSha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.shared.lock(|sha| sha.borrow_mut().digest(data))
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        self.shared.lock(|sha| sha.borrow_mut().digest_parts(parts))
    }
}

#[derive(Clone, Copy)]
pub struct EspTokenClock;

impl PinUvAuthTokenClock for EspTokenClock {
    fn now_ms(&self) -> u64 {
        Instant::now().duration_since_epoch().as_millis()
    }
}

pub type EspSoftwarePinCrypto = Sha256ClientPinCrypto<SharedEspSha256, EspAes256<'static>>;
pub type EspSoftwarePinProvider<S> =
    StoredPinUvAuthProvider<S, EspSoftwarePinCrypto, EspTokenClock>;

pub fn init_shared_sha(
    sha: SHA<'static>,
) -> (DerivedPrivateKeyStore<SharedEspSha256>, SharedEspSha256) {
    init_shared_sha_in(&SHARED_SHA, sha)
}

/// Initialize the slot once per peripheral lifetime; reuse or hardware-check failure may panic.
pub fn init_shared_sha_in(
    slot: &'static StaticCell<SharedEspShaPeripheral>,
    sha: SHA<'static>,
) -> (DerivedPrivateKeyStore<SharedEspSha256>, SharedEspSha256) {
    let shared = &*slot.init(new_shared_sha_peripheral(sha));
    init_shared_sha_from_peripheral(shared)
}

pub fn new_shared_sha_peripheral(sha: SHA<'static>) -> SharedEspShaPeripheral {
    Mutex::new(RefCell::new(EspSha256::new(sha)))
}

/// Derived key material uses the public MAC, not a secret device root.
pub fn init_shared_sha_from_peripheral(
    shared: &'static SharedEspShaPeripheral,
) -> (DerivedPrivateKeyStore<SharedEspSha256>, SharedEspSha256) {
    let hash = shared_hash_from_peripheral(shared);
    let device_mac = efuse::base_mac_address();
    (build_derived_key_store(device_mac.as_bytes(), hash), hash)
}

pub fn checked_aes(aes: AES<'static>) -> EspAes256<'static> {
    let mut aes = EspAes256::new(aes);
    verify_aes256_accelerator(&mut aes);
    println!("ESP AES-256 accelerator enabled for ClientPIN CBC");
    aes
}

pub fn build_software_pin_backends<S: PinUvAuthStateStorage>(
    sha: SHA<'static>,
    aes: AES<'static>,
    storage: S,
) -> (
    DerivedPrivateKeyStore<SharedEspSha256>,
    EspSoftwarePinProvider<S>,
) {
    build_software_pin_backends_in(&SHARED_SHA, sha, aes, storage)
}

pub fn build_software_pin_backends_in<S: PinUvAuthStateStorage>(
    sha_slot: &'static StaticCell<SharedEspShaPeripheral>,
    sha: SHA<'static>,
    aes: AES<'static>,
    storage: S,
) -> (
    DerivedPrivateKeyStore<SharedEspSha256>,
    EspSoftwarePinProvider<S>,
) {
    let (key_store, hash) = init_shared_sha_in(sha_slot, sha);
    build_software_pin_backends_from_hash(key_store, hash, aes, storage)
}

pub fn build_software_pin_backends_from_shared<S: PinUvAuthStateStorage>(
    shared: &'static SharedEspShaPeripheral,
    aes: AES<'static>,
    storage: S,
) -> (
    DerivedPrivateKeyStore<SharedEspSha256>,
    EspSoftwarePinProvider<S>,
) {
    let (key_store, hash) = init_shared_sha_from_peripheral(shared);
    build_software_pin_backends_from_hash(key_store, hash, aes, storage)
}

fn build_software_pin_backends_from_hash<S: PinUvAuthStateStorage>(
    key_store: DerivedPrivateKeyStore<SharedEspSha256>,
    hash: SharedEspSha256,
    aes: AES<'static>,
    storage: S,
) -> (
    DerivedPrivateKeyStore<SharedEspSha256>,
    EspSoftwarePinProvider<S>,
) {
    (key_store, pin_from_hash(hash, aes, storage))
}

/// Uses hardware SHA/AES, software P-256 and caller-owned PIN persistence.
pub fn pin_from_hash<S: PinUvAuthStateStorage>(
    hash: SharedEspSha256,
    aes: AES<'static>,
    storage: S,
) -> EspSoftwarePinProvider<S> {
    let crypto = Sha256ClientPinCrypto::new_with_aes(hash, checked_aes(aes));
    StoredPinUvAuthProvider::new_with_crypto_and_clock(storage, crypto, EspTokenClock)
}
