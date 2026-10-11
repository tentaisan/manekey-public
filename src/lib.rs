// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Learning/experimental authentication core; not a certified production authenticator.
// Security depends on the selected entropy, storage, attestation, PIN/UV and hardware boundary.
// Build and representative tests do not establish full conformance or production security.




























#[cfg(all(
    feature = "ctaphid-small-message-buffers",
    feature = "experimental-large-message-buffers"
))]
compile_error!("small and experimental large CTAPHID message buffers are mutually exclusive");


pub mod ctaphid;


pub mod security;


pub mod presence;


pub mod boundary;


pub mod transport;


pub mod frontend;


pub mod nfc {
    pub use crate::frontend::fido_apdu::{
        FidoApduFrontend, NfcApduFrontend, NfcApduOutcome, NfcApduReply,
    };
    pub use crate::frontend::nfc_iso_dep::{
        FIDO_ATS, FIDO_INF_MAX, IsoDepCommandAssembler, IsoDepError, IsoDepFrame,
        IsoDepResponseFragmenter, NfcIsoDepAction, NfcIsoDepFrontend, parse_frame,
    };
}


pub mod user_interface;

pub mod paired_journal;

pub mod storage_region;









