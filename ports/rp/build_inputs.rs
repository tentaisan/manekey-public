use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const NVRAM_SHA256: [u8; 32] = [
    0x49, 0x04, 0xbd, 0xbb, 0x0c, 0x93, 0x7b, 0xd0, 0xac, 0x2e, 0xb2, 0xa1, 0xd6, 0x2f, 0x2d, 0xa4,
    0xdd, 0x90, 0xe3, 0x20, 0x82, 0x38, 0x4e, 0x02, 0x87, 0x4e, 0x8d, 0x67, 0x1b, 0x0f, 0x33, 0x0d,
];


pub fn configure_nvram() {
    println!("cargo:rerun-if-env-changed=MANEKEY_CYW43_NVRAM_FILE");
    let Some(input) = env::var_os("MANEKEY_CYW43_NVRAM_FILE") else {
        return;
    };
    let input = PathBuf::from(input)
        .canonicalize()
        .expect("MANEKEY_CYW43_NVRAM_FILE must name a readable file");
    assert!(input.is_file(), "NVRAM input must be a regular file");
    println!("cargo:rerun-if-changed={}", input.display());
    let bytes = fs::read(&input).expect("read external NVRAM input");
    assert!(valid_nvram(&bytes), "NVRAM length or SHA-256 mismatch");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("cyw43-nvram.bin");
    fs::write(&output, bytes).expect("write verified NVRAM build input");
    println!(
        "cargo:rustc-env=MANEKEY_CYW43_NVRAM_VERIFIED={}",
        output.display()
    );
}

fn valid_nvram(bytes: &[u8]) -> bool {
    bytes.len() == 742 && Sha256::digest(bytes).as_slice() == NVRAM_SHA256
}












