use manekey::ctaphid::{
    crypto::SoftwareEs256,
    entropy::EntropySource,
    flash_key_storage::FlashKeyStorage,
    managed_key_store::{ManagedKeyError, ManagedPrivateKeyStore},
    storage::{Storage, StorageBackend},
};

pub type ClassicalKeys<B> =
    ManagedPrivateKeyStore<FlashKeyStorage<B>, SoftwareEs256, super::crypto::Hash>;
#[cfg(any(
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental",
    feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
    feature = "riscv-single-core-ml-dsa-fips204-experimental",
    feature = "riscv-dual-core-ml-dsa-fips204-experimental"
))]
pub type Keys<B> = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<
    ClassicalKeys<B>,
    super::crypto::MlDsa,
>;
#[cfg(not(any(
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental",
    feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
    feature = "riscv-single-core-ml-dsa-fips204-experimental",
    feature = "riscv-dual-core-ml-dsa-fips204-experimental"
)))]
pub type Keys<B> = ClassicalKeys<B>;

/// # Safety
/// Caller is the sole trusted hash/Flash owner; delegated media must park the requesting hart.
pub unsafe fn open_classical<B: StorageBackend, R: StorageBackend, E: EntropySource>(
    backend: B,
    records: &mut Storage<R>,
    entropy: &mut E,
) -> Result<ClassicalKeys<B>, ManagedKeyError> {
    crate::platform::rp::key_store::open_classical(
        backend,
        records,
        entropy,
        unsafe { super::crypto::hash_backend() },
        cfg!(any(
            feature = "riscv-flash-managed-key-setup",
            feature = "rp2350-flash-managed-key-setup"
        )),
    )
}

/// # Safety
/// Maintain exclusive hash/Flash ownership; initialize private ML-DSA scratch once when selected.
pub unsafe fn open<B: StorageBackend, R: StorageBackend, E: EntropySource>(
    backend: B,
    records: &mut Storage<R>,
    entropy: &mut E,
) -> Result<Keys<B>, ManagedKeyError> {
    let base = unsafe { open_classical(backend, records, entropy) }?;
    #[cfg(any(
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental",
        feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
        feature = "riscv-single-core-ml-dsa-fips204-experimental",
        feature = "riscv-dual-core-ml-dsa-fips204-experimental"
    ))]
    return Ok(Keys::new(base, super::crypto::ml_dsa()));
    #[cfg(not(any(
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental",
        feature = "riscv-pmp-trusted-ml-dsa-fips204-experimental",
        feature = "riscv-single-core-ml-dsa-fips204-experimental",
        feature = "riscv-dual-core-ml-dsa-fips204-experimental"
    )))]
    Ok(base)
}
