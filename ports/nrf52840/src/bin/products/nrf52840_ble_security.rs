use core::cell::RefCell;

use manekey::transport::ble::BleBondAdmission;
use nrf_softdevice::ble::{
    Connection, EncryptionInfo, IdentityKey, MasterId, SecurityMode,
    security::{IoCapabilities, SecurityHandler},
};
#[cfg(feature = "nrf-flash-storage")]
use nrf_softdevice::raw;
#[cfg(feature = "nrf-flash-storage")]
use nrf52840::bond_record::{
    BLE_BOND_RECORD_LEN, StoredBleBondRecord, decode as decode_stored_bond_record,
    encode as encode_stored_bond_record,
};
#[cfg(feature = "nrf-flash-storage")]
use nrf52840::storage::{read_ble_bond_record, write_ble_bond_record};

use super::{log, log_word};

pub(super) static BLE_SECURITY_HANDLER: NrfBleSecurityHandler = NrfBleSecurityHandler;
pub(super) static BLE_BOND_CACHE: NrfVolatileBondCache = NrfVolatileBondCache::new();

/// Bond admission without MITM-capable local I/O; transport security is not user verification.
pub(super) struct NrfBleSecurityHandler;

#[derive(Clone, Copy)]
struct NrfBleBondRecord {
    master_id: MasterId,
    key: EncryptionInfo,
    peer_id: IdentityKey,
}

/// Single peer's plaintext bond material; caller owns memory and persistence protection.
pub(super) struct NrfVolatileBondCache {
    record: critical_section::Mutex<RefCell<Option<NrfBleBondRecord>>>,
    #[cfg(feature = "nrf-flash-storage")]
    flash_persist_pending: critical_section::Mutex<RefCell<bool>>,
}

impl NrfVolatileBondCache {
    const fn new() -> Self {
        Self {
            record: critical_section::Mutex::new(RefCell::new(None)),
            #[cfg(feature = "nrf-flash-storage")]
            flash_persist_pending: critical_section::Mutex::new(RefCell::new(false)),
        }
    }

    fn store(&self, record: NrfBleBondRecord) {
        critical_section::with(|cs| {
            self.record.borrow_ref_mut(cs).replace(record);
        });
    }

    #[cfg(feature = "nrf-flash-storage")]
    fn store_bonded(&self, record: NrfBleBondRecord) {
        critical_section::with(|cs| {
            self.record.borrow_ref_mut(cs).replace(record);
            *self.flash_persist_pending.borrow_ref_mut(cs) = true;
        });
    }

    #[cfg(feature = "nrf-flash-storage")]
    fn take_pending_flash_record(&self) -> Option<NrfBleBondRecord> {
        critical_section::with(|cs| {
            if !core::mem::take(&mut *self.flash_persist_pending.borrow_ref_mut(cs)) {
                return None;
            }
            *self.record.borrow_ref(cs)
        })
    }

    #[cfg(feature = "ble-bonded-only")]
    fn load_record(&self) -> Option<NrfBleBondRecord> {
        critical_section::with(|cs| *self.record.borrow_ref(cs))
    }

    fn load_key(&self, master_id: MasterId) -> Option<EncryptionInfo> {
        critical_section::with(|cs| {
            self.record
                .borrow_ref(cs)
                .as_ref()
                .filter(|record| record.master_id == master_id)
                .map(|record| record.key)
        })
    }

    pub(super) fn cached_peer_addr_flags(&self) -> Option<u8> {
        critical_section::with(|cs| {
            self.record
                .borrow_ref(cs)
                .as_ref()
                .map(|record| record.peer_id.addr.flags)
        })
    }
}

#[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
fn encode_bond_record(record: NrfBleBondRecord) -> [u8; BLE_BOND_RECORD_LEN] {
    encode_stored_bond_record(StoredBleBondRecord {
        master_id_ediv: record.master_id.ediv,
        master_id_rand: record.master_id.rand,
        ltk: record.key.ltk,
        ltk_flags: record.key.flags,
        peer_addr_flags: record.peer_id.addr.flags,
        peer_addr: record.peer_id.addr.bytes,
        peer_irk: record.peer_id.as_raw().id_info.irk,
    })
}

#[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
fn decode_bond_record(data: &[u8; BLE_BOND_RECORD_LEN]) -> Option<NrfBleBondRecord> {
    let record = decode_stored_bond_record(data)?;

    let peer_id = IdentityKey::from_raw(raw::ble_gap_id_key_t {
        id_info: raw::ble_gap_irk_t {
            irk: record.peer_irk,
        },
        id_addr_info: raw::ble_gap_addr_t {
            _bitfield_1: raw::ble_gap_addr_t::new_bitfield_1(
                record.peer_addr_flags & 1,
                record.peer_addr_flags >> 1,
            ),
            addr: record.peer_addr,
        },
    });

    Some(NrfBleBondRecord {
        master_id: MasterId {
            ediv: record.master_id_ediv,
            rand: record.master_id_rand,
        },
        key: EncryptionInfo {
            ltk: record.ltk,
            flags: record.ltk_flags,
        },
        peer_id,
    })
}

#[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
fn load_flash_bond_record() -> Option<NrfBleBondRecord> {
    let mut data = [0xffu8; BLE_BOND_RECORD_LEN];
    if read_ble_bond_record(&mut data).is_err() {
        log("ble bond flash read failed");
        return None;
    }
    let record = decode_bond_record(&data);
    if record.is_some() {
        log("ble bond flash hit");
    } else {
        log("ble bond flash empty");
    }
    record
}

#[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
fn store_flash_bond_record(record: NrfBleBondRecord) -> bool {
    let data = encode_bond_record(record);
    if write_ble_bond_record(&data).is_ok() {
        log("ble bond flash stored");
        true
    } else {
        log("ble bond flash store failed");
        false
    }
}

#[cfg(all(feature = "ble-security", feature = "nrf-flash-storage"))]
/// Call after connection closure under exclusive Flash/event ownership, outside security callbacks.
pub(super) fn persist_pending_bond_record() {
    let Some(record) = BLE_BOND_CACHE.take_pending_flash_record() else {
        return;
    };

    if !store_flash_bond_record(record) {
        BLE_BOND_CACHE.store_bonded(record);
    }
}

#[cfg(feature = "ble-bonded-only")]
fn load_cached_or_flash_bond_record() -> Option<NrfBleBondRecord> {
    if let Some(record) = BLE_BOND_CACHE.load_record() {
        log("ble bond allowlist hit volatile");
        return Some(record);
    }

    #[cfg(feature = "nrf-flash-storage")]
    if let Some(record) = load_flash_bond_record() {
        log("ble bond allowlist hit flash");
        BLE_BOND_CACHE.store(record);
        return Some(record);
    }

    log("ble bond allowlist empty");
    None
}

#[cfg(feature = "ble-bonded-only")]
pub(super) fn is_allowed_bonded_peer(conn: &Connection) -> bool {
    let peer_addr = conn.peer_address();
    if let Some(record) = load_cached_or_flash_bond_record() {
        log_word("ble bonded-only peer flags", peer_addr.flags as u32);
        log_word(
            "ble bonded-only stored flags",
            record.peer_id.addr.flags as u32,
        );
        if BleBondAdmission::BondedOnly.permits_peer(record.peer_id.is_match(peer_addr)) {
            log("ble bonded-only peer accepted");
            true
        } else {
            log("ble bonded-only peer rejected");
            false
        }
    } else {
        log("ble bonded-only missing bond");
        false
    }
}

impl SecurityHandler for NrfBleSecurityHandler {
    fn io_capabilities(&self) -> IoCapabilities {
        IoCapabilities::None
    }

    fn can_bond(&self, _conn: &Connection) -> bool {
        let admission = BleBondAdmission::from_bonded_only(cfg!(feature = "ble-bonded-only"));
        if !admission.permits_new_bond() {
            log("ble bonded-only rejects new bond");
        }
        admission.permits_new_bond()
    }

    fn on_security_update(&self, _conn: &Connection, security_mode: SecurityMode) {
        log("ble security update");
        log_security_mode(security_mode);
    }

    fn on_bonded(
        &self,
        _conn: &Connection,
        master_id: MasterId,
        key: EncryptionInfo,
        peer_id: IdentityKey,
    ) {
        log("ble bonded");
        log_word("ble bonded ediv", master_id.ediv as u32);
        log_word("ble bonded ltk_flags", key.flags as u32);
        log_word("ble bonded addr_flags", peer_id.addr.flags as u32);
        let record = NrfBleBondRecord {
            master_id,
            key,
            peer_id,
        };
        #[cfg(feature = "nrf-flash-storage")]
        BLE_BOND_CACHE.store_bonded(record);
        #[cfg(not(feature = "nrf-flash-storage"))]
        BLE_BOND_CACHE.store(record);
        log("ble bond cached volatile");
        #[cfg(feature = "nrf-flash-storage")]
        log("ble bond flash persist deferred");
    }

    fn get_key(&self, _conn: &Connection, master_id: MasterId) -> Option<EncryptionInfo> {
        if let Some(key) = BLE_BOND_CACHE.load_key(master_id) {
            log("ble bond key hit volatile");
            return Some(key);
        }
        log("ble bond key miss volatile");

        #[cfg(feature = "nrf-flash-storage")]
        if let Some(record) = load_flash_bond_record() {
            if record.master_id == master_id {
                log("ble bond key hit flash");
                BLE_BOND_CACHE.store(record);
                return Some(record.key);
            }
            log("ble bond key flash master mismatch");
        }

        None
    }
}

pub(super) fn log_security_mode(mode: SecurityMode) {
    let label = match mode {
        SecurityMode::NoAccess => "ble sec=noaccess",
        SecurityMode::Open => "ble sec=open",
        SecurityMode::JustWorks => "ble sec=justworks",
        SecurityMode::Mitm => "ble sec=mitm",
        SecurityMode::LescMitm => "ble sec=lesc-mitm",
        SecurityMode::Signed => "ble sec=signed",
        SecurityMode::SignedMitm => "ble sec=signed-mitm",
    };
    log(label);
}
