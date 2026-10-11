use aes::Aes256;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    FieldBytes, PublicKey, Sec1Point, SecretKey,
    ecdh::diffie_hellman,
    ecdsa::{Signature, SigningKey, signature::Signer},
};

use sha2::Sha256;
use subtle::{ConstantTimeEq, ConstantTimeLess};

use crate::ctaphid::{
    entropy::EntropySource,
    hash::{Sha256Backend, sha256_digest},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aes256Error {
    HardwareUnavailable,
}

/// Raw AES blocks; adapters own exclusion and callers discard modified output after errors.
pub trait Aes256BlockBackend {
    fn encrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error>;

    fn decrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareAes256Block;

impl Aes256BlockBackend for SoftwareAes256Block {
    fn encrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        cbc::Encryptor::<Aes256>::new_from_slices(key, &[0; 16])
            .map_err(|_| Aes256Error::HardwareUnavailable)?
            .encrypt_padded::<NoPadding>(block, 16)
            .map_err(|_| Aes256Error::HardwareUnavailable)?;
        Ok(())
    }

    fn decrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        cbc::Decryptor::<Aes256>::new_from_slices(key, &[0; 16])
            .map_err(|_| Aes256Error::HardwareUnavailable)?
            .decrypt_padded::<NoPadding>(block)
            .map_err(|_| Aes256Error::HardwareUnavailable)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256EcdhError {
    InvalidKey,
    HardwareUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Contains an exported private scalar; Copy/Debug can expose it and drop does not erase it.
pub struct P256KeyPair {
    pub private_key: [u8; 32],
    pub public_x: [u8; 32],
    pub public_y: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256KeyAgreement {
    Exported(P256KeyPair),
    BackendOwned {
        public_x: [u8; 32],
        public_y: [u8; 32],
    },
}

impl P256KeyAgreement {
    pub const fn public_xy(&self) -> (&[u8; 32], &[u8; 32]) {
        match self {
            Self::Exported(key_pair) => (&key_pair.public_x, &key_pair.public_y),
            Self::BackendOwned { public_x, public_y } => (public_x, public_y),
        }
    }
}

pub const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
pub const P256_GENERATOR_X: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
pub const P256_GENERATOR_Y: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256EcdhKatError {
    PublicKey(P256EcdhError),
    PublicKeyMismatch,
    SharedSecret(P256EcdhError),
    SharedSecretMismatch,
    InvalidPrivateKeyAccepted,
    InvalidPeerPointAccepted,
}

/// Backend-owned agreement requires overrides; the default exports private-key material.
pub trait P256EcdhBackend {
    fn generate_key_pair(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Result<P256KeyPair, P256EcdhError> {
        let private_key =
            generate_private_key(entropy).ok_or(P256EcdhError::HardwareUnavailable)?;
        let (public_x, public_y) = self.public_key_xy(&private_key)?;
        Ok(P256KeyPair {
            private_key,
            public_x,
            public_y,
        })
    }

    fn generate_key_agreement(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Result<P256KeyAgreement, P256EcdhError> {
        self.generate_key_pair(entropy)
            .map(P256KeyAgreement::Exported)
    }

    fn public_key_xy(
        &mut self,
        private_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), P256EcdhError>;

    fn ecdh(
        &mut self,
        private_key: &[u8; 32],
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError>;

    fn ecdh_current(
        &mut self,
        _peer_x: &[u8; 32],
        _peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        Err(P256EcdhError::HardwareUnavailable)
    }
}

pub fn p256_private_scalar_is_valid(private_key: &[u8; 32]) -> bool {
    let mut nonzero = 0u8;
    let mut less = subtle::Choice::from(0);
    let mut greater = subtle::Choice::from(0);
    for (candidate, order) in private_key.iter().zip(P256_ORDER) {
        nonzero |= *candidate;
        let undecided = !(less | greater);
        less |= undecided & candidate.ct_lt(&order);
        greater |= undecided & order.ct_lt(candidate);
    }

    bool::from(!nonzero.ct_eq(&0) & less)
}

pub fn verify_p256_ecdh_backend<B: P256EcdhBackend>(
    backend: &mut B,
) -> Result<(), P256EcdhKatError> {
    const PRIVATE_TWO: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ];
    const TWO_G_X: [u8; 32] = [
        0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
        0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66,
        0x99, 0x78,
    ];
    const TWO_G_Y: [u8; 32] = [
        0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30,
        0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78,
        0x73, 0xd1,
    ];

    let public = backend
        .public_key_xy(&PRIVATE_TWO)
        .map_err(P256EcdhKatError::PublicKey)?;
    if public != (TWO_G_X, TWO_G_Y) {
        return Err(P256EcdhKatError::PublicKeyMismatch);
    }

    let shared = backend
        .ecdh(&PRIVATE_TWO, &P256_GENERATOR_X, &P256_GENERATOR_Y)
        .map_err(P256EcdhKatError::SharedSecret)?;
    if shared != TWO_G_X {
        return Err(P256EcdhKatError::SharedSecretMismatch);
    }

    if backend.public_key_xy(&[0; 32]) != Err(P256EcdhError::InvalidKey) {
        return Err(P256EcdhKatError::InvalidPrivateKeyAccepted);
    }
    if backend.ecdh(&PRIVATE_TWO, &[0; 32], &[0; 32]) != Err(P256EcdhError::InvalidKey) {
        return Err(P256EcdhKatError::InvalidPeerPointAccepted);
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareP256Ecdh;

impl P256EcdhBackend for SoftwareP256Ecdh {
    fn public_key_xy(
        &mut self,
        private_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), P256EcdhError> {
        let signing_key = signing_key_from_bytes(private_key).ok_or(P256EcdhError::InvalidKey)?;
        public_key_xy(&signing_key).ok_or(P256EcdhError::InvalidKey)
    }

    fn ecdh(
        &mut self,
        private_key: &[u8; 32],
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        ecdh_shared_secret(private_key, peer_x, peer_y).ok_or(P256EcdhError::InvalidKey)
    }
}

/// PIN protocol primitives; in-place output may be modified on failure.
pub trait ClientPinCrypto {
    fn ecdh(&mut self, private_key: &[u8; 32], x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]>;

    fn ecdh_current(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]>;

    fn generate_key_agreement(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Option<P256KeyAgreement>;

    fn pin_hash(&mut self, pin: &[u8]) -> Option<[u8; 16]>;

    fn verify_token_auth_param(
        &mut self,
        protocol: u8,
        token: &[u8; 32],
        message: &[u8],
        param: &[u8],
    ) -> bool;

    fn hmac_sha256(&mut self, key: &[u8], parts: &[&[u8]]) -> Option<[u8; 32]>;

    fn protocol_one_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 32]>;

    fn protocol_two_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 64]>;

    fn verify_protocol_one_auth_param(
        &mut self,
        shared_secret: &[u8; 32],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool;

    fn decrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]>;

    fn encrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        plaintext: &'a mut [u8],
    ) -> Option<&'a [u8]>;

    fn verify_protocol_two_auth_param(
        &mut self,
        shared_secret: &[u8; 64],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool;

    fn decrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]>;

    fn encrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        iv: &[u8; 16],
        plaintext: &[u8],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareClientPinCrypto;

/// Composes hash/AES/P-256 backends; constructors use software AES/P-256 unless overridden.
pub struct Sha256ClientPinCrypto<H, A = SoftwareAes256Block, P = SoftwareP256Ecdh> {
    hash: H,
    aes: A,
    p256: P,
}

impl<H> Sha256ClientPinCrypto<H, SoftwareAes256Block, SoftwareP256Ecdh> {
    pub const fn new(hash: H) -> Self {
        Self {
            hash,
            aes: SoftwareAes256Block,
            p256: SoftwareP256Ecdh,
        }
    }
}

impl<H, A> Sha256ClientPinCrypto<H, A, SoftwareP256Ecdh> {
    pub const fn new_with_aes(hash: H, aes: A) -> Self {
        Self {
            hash,
            aes,
            p256: SoftwareP256Ecdh,
        }
    }
}

impl<H, A, P> Sha256ClientPinCrypto<H, A, P> {
    pub const fn new_with_backends(hash: H, aes: A, p256: P) -> Self {
        Self { hash, aes, p256 }
    }

    pub fn hash_mut(&mut self) -> &mut H {
        &mut self.hash
    }

    pub fn aes_mut(&mut self) -> &mut A {
        &mut self.aes
    }

    pub fn p256_mut(&mut self) -> &mut P {
        &mut self.p256
    }
}

const MAX_CLIENT_PIN_HMAC_PARTS: usize = 4;

/// Returns None on backend failure or more than four message parts.
pub fn hmac_sha256_with_hash<H: Sha256Backend>(
    hash: &mut H,
    key: &[u8],
    parts: &[&[u8]],
) -> Option<[u8; 32]> {
    if parts.len() > MAX_CLIENT_PIN_HMAC_PARTS {
        return None;
    }

    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..32].copy_from_slice(&hash.digest(key).ok()?);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for ((inner, outer), key) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(key_block)
    {
        *inner ^= key;
        *outer ^= key;
    }

    let mut inner_parts: [&[u8]; MAX_CLIENT_PIN_HMAC_PARTS + 1] = [&[]; 5];
    inner_parts[0] = &inner_pad;
    inner_parts[1..parts.len() + 1].copy_from_slice(parts);
    let inner = hash.digest_parts(&inner_parts[..parts.len() + 1]).ok()?;
    hash.digest_parts(&[&outer_pad, &inner]).ok()
}

fn client_pin_protocol_two_shared_secret_with_hash<H: Sha256Backend>(
    ecdh_secret: &[u8; 32],
    hash: &mut H,
) -> Option<[u8; 64]> {
    let salt = [0u8; 32];
    let counter = [1u8];
    let prk = hmac_sha256_with_hash(hash, &salt, &[ecdh_secret])?;
    let hmac_key = hmac_sha256_with_hash(hash, &prk, &[b"CTAP2 HMAC key", &counter])?;
    let aes_key = hmac_sha256_with_hash(hash, &prk, &[b"CTAP2 AES key", &counter])?;
    let mut shared_secret = [0u8; 64];
    shared_secret[..32].copy_from_slice(&hmac_key);
    shared_secret[32..].copy_from_slice(&aes_key);
    Some(shared_secret)
}

fn aes256_cbc_encrypt_in_place<A: Aes256BlockBackend>(
    aes: &mut A,
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &mut [u8],
) -> Option<()> {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return None;
    }

    let mut previous = *iv;
    for chunk in plaintext.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().ok()?;
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        aes.encrypt_block(key, block).ok()?;
        previous = *block;
    }
    Some(())
}

fn aes256_cbc_decrypt_in_place<A: Aes256BlockBackend>(
    aes: &mut A,
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &mut [u8],
) -> Option<()> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return None;
    }

    let mut previous = *iv;
    for chunk in ciphertext.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().ok()?;
        let current = *block;
        aes.decrypt_block(key, block).ok()?;
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        previous = current;
    }
    Some(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Es256Error {
    HardwareUnavailable,

    InvalidPrivateKey,

    BufferTooSmall,
}

/// Signs with caller-provided private material; hardware isolation belongs to the adapter.
pub trait Es256Backend {
    fn public_key_xy(&mut self, private_key: &[u8; 32])
    -> Result<([u8; 32], [u8; 32]), Es256Error>;

    fn sign_der<'a>(
        &mut self,
        private_key: &[u8; 32],
        message: &[u8],
        signature_buf: &'a mut [u8],
    ) -> Result<&'a [u8], Es256Error>;

    fn sign_webauthn_der<'a>(
        &mut self,
        private_key: &[u8; 32],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Result<&'a [u8], Es256Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareEs256;

impl SoftwareEs256 {
    fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey, Es256Error> {
        signing_key_from_bytes(private_key).ok_or(Es256Error::InvalidPrivateKey)
    }
}

impl Es256Backend for SoftwareEs256 {
    fn public_key_xy(
        &mut self,
        private_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), Es256Error> {
        public_key_xy(&Self::signing_key(private_key)?).ok_or(Es256Error::InvalidPrivateKey)
    }

    fn sign_der<'a>(
        &mut self,
        private_key: &[u8; 32],
        message: &[u8],
        signature_buf: &'a mut [u8],
    ) -> Result<&'a [u8], Es256Error> {
        let signing_key = Self::signing_key(private_key)?;
        let signature: Signature = signing_key.sign(message);
        let der = signature.to_der();
        let der_bytes = der.as_bytes();

        if signature_buf.len() < der_bytes.len() {
            return Err(Es256Error::BufferTooSmall);
        }

        signature_buf[..der_bytes.len()].copy_from_slice(der_bytes);
        Ok(&signature_buf[..der_bytes.len()])
    }

    fn sign_webauthn_der<'a>(
        &mut self,
        private_key: &[u8; 32],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Result<&'a [u8], Es256Error> {
        let signed_len = auth_data.len() + client_data_hash.len();

        if signature_buf.len() < signed_len {
            return Err(Es256Error::BufferTooSmall);
        }

        signature_buf[..auth_data.len()].copy_from_slice(auth_data);
        signature_buf[auth_data.len()..signed_len].copy_from_slice(client_data_hash);

        let signing_key = Self::signing_key(private_key)?;
        let signature: Signature = signing_key.sign(&signature_buf[..signed_len]);
        let der = signature.to_der();
        let der_bytes = der.as_bytes();

        if signature_buf.len() < der_bytes.len() {
            return Err(Es256Error::BufferTooSmall);
        }

        signature_buf[..der_bytes.len()].copy_from_slice(der_bytes);
        Ok(&signature_buf[..der_bytes.len()])
    }
}

pub fn signing_key_from_bytes(private_key: &[u8; 32]) -> Option<SigningKey> {
    SigningKey::from_slice(private_key).ok()
}

pub fn public_key_xy(signing_key: &SigningKey) -> Option<([u8; 32], [u8; 32])> {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_sec1_point(false);

    let public_key = encoded.as_bytes();

    if public_key.len() != 65 || public_key[0] != 0x04 {
        return None;
    }

    let public_key_x: [u8; 32] = public_key[1..33].try_into().ok()?;
    let public_key_y: [u8; 32] = public_key[33..65].try_into().ok()?;

    Some((public_key_x, public_key_y))
}

pub fn ecdh_shared_secret(
    private_key: &[u8; 32],
    peer_x: &[u8; 32],
    peer_y: &[u8; 32],
) -> Option<[u8; 32]> {
    let secret_key = SecretKey::from_slice(private_key).ok()?;
    let peer_x = FieldBytes::from(*peer_x);
    let peer_y = FieldBytes::from(*peer_y);
    let encoded_point = Sec1Point::from_affine_coordinates(&peer_x, &peer_y, false);
    let public_key = PublicKey::from_sec1_bytes(encoded_point.as_bytes()).ok()?;
    let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());

    Some((*shared_secret.raw_secret_bytes()).into())
}

pub fn client_pin_protocol_one_shared_secret(ecdh_secret: &[u8; 32]) -> [u8; 32] {
    sha256_digest(ecdh_secret)
}

pub fn client_pin_protocol_one_shared_secret_with_hash<H: Sha256Backend>(
    ecdh_secret: &[u8; 32],
    hash: &mut H,
) -> Option<[u8; 32]> {
    hash.digest(ecdh_secret).ok()
}

pub fn client_pin_protocol_two_shared_secret(ecdh_secret: &[u8; 32]) -> [u8; 64] {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0; 32]), ecdh_secret);
    let mut shared_secret = [0u8; 64];
    hkdf.expand(b"CTAP2 HMAC key", &mut shared_secret[..32])
        .expect("fixed HKDF output length");
    hkdf.expand(b"CTAP2 AES key", &mut shared_secret[32..])
        .expect("fixed HKDF output length");
    shared_secret
}

pub fn client_pin_hash(pin: &[u8]) -> [u8; 16] {
    let digest = sha256_digest(pin);
    digest[..16]
        .try_into()
        .expect("SHA-256 digest has 32 bytes")
}

pub fn client_pin_hash_with_hash<H: Sha256Backend>(pin: &[u8], hash: &mut H) -> Option<[u8; 16]> {
    let digest = hash.digest(pin).ok()?;
    Some(
        digest[..16]
            .try_into()
            .expect("SHA-256 digest has 32 bytes"),
    )
}

pub fn verify_client_pin_auth_param(
    shared_secret: &[u8; 32],
    message: &[u8],
    pin_uv_auth_param: &[u8],
) -> bool {
    verify_client_pin_auth_param_parts(shared_secret, &[message], pin_uv_auth_param)
}

pub fn verify_client_pin_token_auth_param(
    protocol: u8,
    token: &[u8; 32],
    message: &[u8],
    param: &[u8],
) -> bool {
    let length = match protocol {
        1 => 16,
        2 => 32,
        _ => return false,
    };
    if param.len() != length {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(token).expect("fixed HMAC key");
    mac.update(message);
    mac.finalize().into_bytes()[..length].ct_eq(param).into()
}

pub fn verify_client_pin_auth_param_parts(
    shared_secret: &[u8; 32],
    parts: &[&[u8]],
    pin_uv_auth_param: &[u8],
) -> bool {
    if pin_uv_auth_param.len() != 16 {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(shared_secret).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let expected = mac.finalize().into_bytes();

    expected[..16].ct_eq(pin_uv_auth_param).into()
}

pub fn decrypt_client_pin_protocol_one<'a>(
    shared_secret: &[u8; 32],
    encrypted: &'a mut [u8],
) -> Option<&'a [u8]> {
    if encrypted.is_empty() || encrypted.len() % 16 != 0 {
        return None;
    }

    let cipher = cbc::Decryptor::<Aes256>::new_from_slices(shared_secret, &[0; 16]).ok()?;
    cipher.decrypt_padded::<NoPadding>(encrypted).ok()
}

pub fn encrypt_client_pin_protocol_one<'a>(
    shared_secret: &[u8; 32],
    plaintext: &'a mut [u8],
) -> Option<&'a [u8]> {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return None;
    }

    let len = plaintext.len();
    let cipher = cbc::Encryptor::<Aes256>::new_from_slices(shared_secret, &[0; 16]).ok()?;
    cipher.encrypt_padded::<NoPadding>(plaintext, len).ok()
}

impl ClientPinCrypto for SoftwareClientPinCrypto {
    fn ecdh(&mut self, private_key: &[u8; 32], x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]> {
        ecdh_shared_secret(private_key, x, y)
    }

    fn ecdh_current(&mut self, _x: &[u8; 32], _y: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }

    fn generate_key_agreement(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Option<P256KeyAgreement> {
        SoftwareP256Ecdh.generate_key_agreement(entropy).ok()
    }

    fn pin_hash(&mut self, pin: &[u8]) -> Option<[u8; 16]> {
        Some(client_pin_hash(pin))
    }

    fn verify_token_auth_param(
        &mut self,
        protocol: u8,
        token: &[u8; 32],
        message: &[u8],
        param: &[u8],
    ) -> bool {
        verify_client_pin_token_auth_param(protocol, token, message, param)
    }

    fn hmac_sha256(&mut self, key: &[u8], parts: &[&[u8]]) -> Option<[u8; 32]> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
        for part in parts {
            mac.update(part);
        }
        Some(mac.finalize().into_bytes().into())
    }

    fn protocol_one_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 32]> {
        Some(client_pin_protocol_one_shared_secret(ecdh_secret))
    }

    fn protocol_two_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 64]> {
        Some(client_pin_protocol_two_shared_secret(ecdh_secret))
    }

    fn verify_protocol_one_auth_param(
        &mut self,
        shared_secret: &[u8; 32],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool {
        verify_client_pin_auth_param_parts(shared_secret, parts, pin_uv_auth_param)
    }

    fn decrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        decrypt_client_pin_protocol_one(shared_secret, encrypted)
    }

    fn encrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        plaintext: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        encrypt_client_pin_protocol_one(shared_secret, plaintext)
    }

    fn verify_protocol_two_auth_param(
        &mut self,
        shared_secret: &[u8; 64],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool {
        if pin_uv_auth_param.len() != 32 {
            return false;
        }
        let mut mac = HmacSha256::new_from_slice(&shared_secret[..32])
            .expect("HMAC accepts fixed key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize()
            .into_bytes()
            .as_slice()
            .ct_eq(pin_uv_auth_param)
            .into()
    }

    fn decrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if encrypted.len() <= 16 || (encrypted.len() - 16) % 16 != 0 {
            return None;
        }
        let (iv, ciphertext) = encrypted.split_at_mut(16);
        let cipher = cbc::Decryptor::<Aes256>::new_from_slices(&shared_secret[32..], iv).ok()?;
        cipher.decrypt_padded::<NoPadding>(ciphertext).ok()
    }

    fn encrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        iv: &[u8; 16],
        plaintext: &[u8],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if plaintext.is_empty() || plaintext.len() % 16 != 0 || output.len() < plaintext.len() + 16
        {
            return None;
        }
        output[..16].copy_from_slice(iv);
        output[16..16 + plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = &mut output[16..16 + plaintext.len()];
        let cipher = cbc::Encryptor::<Aes256>::new_from_slices(&shared_secret[32..], iv).ok()?;
        cipher
            .encrypt_padded::<NoPadding>(ciphertext, plaintext.len())
            .ok()?;
        Some(&output[..16 + plaintext.len()])
    }
}

impl<H: Sha256Backend, A: Aes256BlockBackend, P: P256EcdhBackend> ClientPinCrypto
    for Sha256ClientPinCrypto<H, A, P>
{
    fn ecdh(&mut self, private_key: &[u8; 32], x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]> {
        self.p256.ecdh(private_key, x, y).ok()
    }

    fn ecdh_current(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Option<[u8; 32]> {
        self.p256.ecdh_current(x, y).ok()
    }

    fn generate_key_agreement(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Option<P256KeyAgreement> {
        self.p256.generate_key_agreement(entropy).ok()
    }

    fn pin_hash(&mut self, pin: &[u8]) -> Option<[u8; 16]> {
        client_pin_hash_with_hash(pin, &mut self.hash)
    }

    fn verify_token_auth_param(
        &mut self,
        protocol: u8,
        token: &[u8; 32],
        message: &[u8],
        param: &[u8],
    ) -> bool {
        let length = match protocol {
            1 => 16,
            2 => 32,
            _ => return false,
        };
        if param.len() != length {
            return false;
        }
        hmac_sha256_with_hash(&mut self.hash, token, &[message])
            .is_some_and(|expected| expected[..length].ct_eq(param).into())
    }

    fn hmac_sha256(&mut self, key: &[u8], parts: &[&[u8]]) -> Option<[u8; 32]> {
        hmac_sha256_with_hash(&mut self.hash, key, parts)
    }

    fn protocol_one_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 32]> {
        client_pin_protocol_one_shared_secret_with_hash(ecdh_secret, &mut self.hash)
    }

    fn protocol_two_shared_secret(&mut self, ecdh_secret: &[u8; 32]) -> Option<[u8; 64]> {
        client_pin_protocol_two_shared_secret_with_hash(ecdh_secret, &mut self.hash)
    }

    fn verify_protocol_one_auth_param(
        &mut self,
        shared_secret: &[u8; 32],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool {
        pin_uv_auth_param.len() == 16
            && hmac_sha256_with_hash(&mut self.hash, shared_secret, parts)
                .is_some_and(|expected| expected[..16].ct_eq(pin_uv_auth_param).into())
    }

    fn decrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        aes256_cbc_decrypt_in_place(&mut self.aes, shared_secret, &[0; 16], encrypted)?;
        Some(encrypted)
    }

    fn encrypt_protocol_one<'a>(
        &mut self,
        shared_secret: &[u8; 32],
        plaintext: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        aes256_cbc_encrypt_in_place(&mut self.aes, shared_secret, &[0; 16], plaintext)?;
        Some(plaintext)
    }

    fn verify_protocol_two_auth_param(
        &mut self,
        shared_secret: &[u8; 64],
        parts: &[&[u8]],
        pin_uv_auth_param: &[u8],
    ) -> bool {
        pin_uv_auth_param.len() == 32
            && hmac_sha256_with_hash(&mut self.hash, &shared_secret[..32], parts)
                .is_some_and(|expected| expected.ct_eq(pin_uv_auth_param).into())
    }

    fn decrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if encrypted.len() <= 16 || (encrypted.len() - 16) % 16 != 0 {
            return None;
        }
        let (iv, ciphertext) = encrypted.split_at_mut(16);
        let iv: [u8; 16] = (&*iv).try_into().ok()?;
        aes256_cbc_decrypt_in_place(
            &mut self.aes,
            shared_secret[32..].try_into().ok()?,
            &iv,
            ciphertext,
        )?;
        Some(ciphertext)
    }

    fn encrypt_protocol_two<'a>(
        &mut self,
        shared_secret: &[u8; 64],
        iv: &[u8; 16],
        plaintext: &[u8],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if plaintext.is_empty() || plaintext.len() % 16 != 0 || output.len() < plaintext.len() + 16
        {
            return None;
        }
        output[..16].copy_from_slice(iv);
        output[16..16 + plaintext.len()].copy_from_slice(plaintext);
        aes256_cbc_encrypt_in_place(
            &mut self.aes,
            shared_secret[32..].try_into().ok()?,
            iv,
            &mut output[16..16 + plaintext.len()],
        )?;
        Some(&output[..16 + plaintext.len()])
    }
}

pub fn sign_attestation<'a>(
    signing_key: &SigningKey,
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
    buf: &'a mut [u8],
) -> Option<&'a [u8]> {
    let signed_len = auth_data.len() + client_data_hash.len();

    if buf.len() < signed_len {
        return None;
    }

    buf[..auth_data.len()].copy_from_slice(auth_data);
    buf[auth_data.len()..signed_len].copy_from_slice(client_data_hash);

    let signature: Signature = signing_key.sign(&buf[..signed_len]);
    let der = signature.to_der();
    let der_bytes = der.as_bytes();

    if buf.len() < der_bytes.len() {
        return None;
    }

    buf[..der_bytes.len()].copy_from_slice(der_bytes);
    Some(&buf[..der_bytes.len()])
}

pub fn generate_random_bytes<E: EntropySource, const N: usize>(entropy: &mut E) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    entropy.fill_entropy(&mut bytes).ok()?;
    Some(bytes)
}

pub fn sign_assertion<'a>(
    signing_key: &SigningKey,
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
    sig_buf: &'a mut [u8],
) -> Option<&'a [u8]> {
    let signed_len = auth_data.len() + client_data_hash.len();

    if sig_buf.len() < signed_len {
        return None;
    }

    sig_buf[..auth_data.len()].copy_from_slice(auth_data);
    sig_buf[auth_data.len()..signed_len].copy_from_slice(client_data_hash);

    let signature: Signature = signing_key.sign(&sig_buf[..signed_len]);
    let der = signature.to_der();

    let der_bytes = der.as_bytes();

    if sig_buf.len() < der_bytes.len() {
        return None;
    }

    sig_buf[..der_bytes.len()].copy_from_slice(der_bytes);

    Some(&sig_buf[..der_bytes.len()])
}

pub fn generate_private_key<E: EntropySource + ?Sized>(entropy: &mut E) -> Option<[u8; 32]> {
    for _ in 0..16 {
        let mut private_key = [0u8; 32];
        entropy.fill_entropy(&mut private_key).ok()?;

        if signing_key_from_bytes(&private_key).is_some() {
            return Some(private_key);
        }
    }

    None
}
