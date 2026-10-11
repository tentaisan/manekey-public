


pub const HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
const MAGIC: [u8; 4] = *b"MKK1";

pub fn bind_managed_key<H: super::hash::Sha256Backend>(
    hash: &mut H,
    root: &[u8; 32],
    domain: &'static [u8],
    header: ManagedKeyHeader,
    nonce: &[u8; 16],
) -> Option<[u8; 32]> {
    let mac = super::crypto::hmac_sha256_with_hash(hash, root, &[domain, &header.encode(), nonce])?;
    Some(header.bind(mac[..16].try_into().ok()?))
}

pub fn authenticate_managed_key<H: super::hash::Sha256Backend>(
    hash: &mut H,
    root: &[u8; 32],
    domain: &'static [u8],
    material: &[u8; 32],
    nonce: &[u8; 16],
    resources: usize,
) -> Option<ManagedKeyHeader> {
    let header = ManagedKeyHeader::decode(&material[..16])?;
    if usize::from(header.resource) >= resources
        || header.generation != u64::from_le_bytes(nonce[..8].try_into().ok()?)
    {
        return None;
    }
    let expected = bind_managed_key(hash, root, domain, header, nonce)?;
    let mut difference = 0u8;
    for (a, b) in expected[16..].iter().zip(&material[16..]) {
        difference |= a ^ b;
    }
    (difference == 0).then_some(header)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedKeyHeader {
    pub resource: u16,
    pub generation: u64,
}

impl ManagedKeyHeader {
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = 1; // format
        bytes[5] = 1; // ES256
        bytes[6..8].copy_from_slice(&self.resource.to_le_bytes());
        bytes[8..].copy_from_slice(&self.generation.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HEADER_LEN || bytes[..4] != MAGIC || bytes[4] != 1 || bytes[5] != 1 {
            return None;
        }
        Some(Self {
            resource: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
            generation: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
        })
    }

    pub fn bind(self, tag: [u8; TAG_LEN]) -> [u8; 32] {
        let mut handle = [0; 32];
        handle[..HEADER_LEN].copy_from_slice(&self.encode());
        handle[HEADER_LEN..].copy_from_slice(&tag);
        handle
    }
}




































































