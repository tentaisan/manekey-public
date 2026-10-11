// SPDX-License-Identifier: AGPL-3.0-only
#![no_std]

#[cfg(all(
    feature = "runtime",
    not(any(feature = "flash-managed-keys", feature = "kmu-key-store", any()))
))]
compile_error!("product runtime requires a persistent managed key store");

#[cfg(all(feature = "flash-managed-keys", feature = "kmu-key-store"))]
compile_error!("select one persistent managed key backend");

#[cfg(all(
    feature = "cracen-sha256",
    any(
        feature = "trustzone-nonsecure-image",
        feature = "trustzone-nonsecure-shared-image",
        any()
    )
))]
compile_error!("CRACEN product adapters are Secure-owned; initialize them in a Secure entrypoint");

#[cfg(any(
    all(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-fips204-scratch"
    ),
    all(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-mldsa-native"
    ),
    all(
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )
))]
compile_error!("select exactly one nRF54L15 experimental ML-DSA backend");

#[cfg(any(feature = "ble", any()))]
pub mod ble_ingress;
pub mod board;
#[cfg(feature = "cracen-sha256")]
pub mod crypto;
#[cfg(feature = "runtime")]
pub mod crypto_config;
#[cfg(feature = "runtime")]
pub mod entropy;
#[cfg(feature = "runtime")]
pub mod fido;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
pub mod fips204_scratch_workspace;
#[cfg(feature = "flash-managed-keys")]
pub mod flash_key_store;
pub mod interconnect;
#[cfg(feature = "kmu-key-store")]
pub mod kmu;
#[cfg(feature = "kmu-key-store")]
pub mod kmu_key_store;

#[cfg(feature = "nrf54l15-dual-task")]
pub mod mailbox;
#[cfg(feature = "runtime")]
pub mod presence;
#[cfg(feature = "ble")]
pub mod samd11_virtual_hid;

#[cfg(feature = "runtime")]
pub mod storage;
#[cfg(feature = "trustzone-secure-layout")]
pub mod trustzone;
#[cfg(feature = "runtime")]
pub mod ui;
