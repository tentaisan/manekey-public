pub const BLE_BOND_RECORD_LEN: usize = 64;
const BLE_BOND_RECORD_MAGIC: &[u8; 4] = b"MKB1";
const BLE_BOND_RECORD_VERSION_V1: u8 = 1;
const BLE_BOND_RECORD_VERSION_V2: u8 = 2;
const BLE_BOND_RECORD_CHECKSUM_OFFSET: usize = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Plain bond material; caller owns confidentiality and persistence.
pub struct StoredBleBondRecord {
    pub master_id_ediv: u16,
    pub master_id_rand: [u8; 8],
    pub ltk: [u8; 16],
    pub ltk_flags: u8,
    pub peer_addr_flags: u8,
    pub peer_addr: [u8; 6],
    pub peer_irk: [u8; 16],
}

pub fn encode(record: StoredBleBondRecord) -> [u8; BLE_BOND_RECORD_LEN] {
    let mut out = [0xffu8; BLE_BOND_RECORD_LEN];
    out[0..4].copy_from_slice(BLE_BOND_RECORD_MAGIC);
    out[4] = BLE_BOND_RECORD_VERSION_V2;
    out[8..10].copy_from_slice(&record.master_id_ediv.to_le_bytes());
    out[10..18].copy_from_slice(&record.master_id_rand);
    out[18..34].copy_from_slice(&record.ltk);
    out[34] = record.ltk_flags;
    out[35] = record.peer_addr_flags;
    out[36..42].copy_from_slice(&record.peer_addr);
    out[42..58].copy_from_slice(&record.peer_irk);
    let checksum = checksum(&out[..BLE_BOND_RECORD_CHECKSUM_OFFSET]).to_le_bytes();
    out[BLE_BOND_RECORD_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
    out
}

/// V2 checks corruption, not authenticity; legacy V1 has no checksum validation.
pub fn decode(data: &[u8; BLE_BOND_RECORD_LEN]) -> Option<StoredBleBondRecord> {
    if &data[0..4] != BLE_BOND_RECORD_MAGIC {
        return None;
    }
    match data[4] {
        BLE_BOND_RECORD_VERSION_V1 => {}
        BLE_BOND_RECORD_VERSION_V2 => {
            let stored_checksum = u32::from_le_bytes(
                data[BLE_BOND_RECORD_CHECKSUM_OFFSET..]
                    .try_into()
                    .expect("fixed bond checksum range"),
            );
            if stored_checksum != checksum(&data[..BLE_BOND_RECORD_CHECKSUM_OFFSET]) {
                return None;
            }
        }
        _ => return None,
    }

    Some(StoredBleBondRecord {
        master_id_ediv: u16::from_le_bytes([data[8], data[9]]),
        master_id_rand: data[10..18].try_into().expect("fixed bond rand range"),
        ltk: data[18..34].try_into().expect("fixed bond LTK range"),
        ltk_flags: data[34],
        peer_addr_flags: data[35],
        peer_addr: data[36..42]
            .try_into()
            .expect("fixed bond peer address range"),
        peer_irk: data[42..58].try_into().expect("fixed bond IRK range"),
    })
}

fn checksum(data: &[u8]) -> u32 {
    data.iter().fold(0x811c_9dc5u32, |hash, byte| {
        hash.wrapping_mul(0x0100_0193) ^ u32::from(*byte)
    })
}
