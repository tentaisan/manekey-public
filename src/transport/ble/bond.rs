pub const BLE_BOND_RECORD_LEN: usize = 47;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleBondAdmission {
    Pairable,
    BondedOnly,
}

impl BleBondAdmission {
    pub const fn from_bonded_only(enabled: bool) -> Self {
        if enabled {
            Self::BondedOnly
        } else {
            Self::Pairable
        }
    }

    pub const fn permits_peer(self, has_saved_bond: bool) -> bool {
        matches!(self, Self::Pairable) || has_saved_bond
    }

    pub const fn permits_new_bond(self) -> bool {
        matches!(self, Self::Pairable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StoredBleSecurityLevel {
    NoEncryption = 0,
    Encrypted = 1,
    EncryptedAuthenticated = 2,
}

impl StoredBleSecurityLevel {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoEncryption),
            1 => Some(Self::Encrypted),
            2 => Some(Self::EncryptedAuthenticated),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]

/// Plaintext bond keys: Debug exposes keys and Copy duplicates them.
/// Drop does not erase keys. Callers must prevent logging and protect key lifetimes.
pub struct StoredBleBond {
    pub ltk: [u8; 16],
    pub bd_addr: [u8; 6],
    pub bd_addr_kind: u8,
    pub irk: Option<[u8; 16]>,
    pub is_bonded: bool,
    pub security_level: StoredBleSecurityLevel,
}

impl StoredBleBond {
    const FORMAT_VERSION: u8 = 2;
    const MAGIC: [u8; 4] = *b"MBND";

    pub fn encode(self) -> [u8; BLE_BOND_RECORD_LEN] {
        let mut out = [0xff; BLE_BOND_RECORD_LEN];
        out[0..4].copy_from_slice(&Self::MAGIC);
        out[4] = Self::FORMAT_VERSION;
        out[5] = self.security_level as u8;
        out[6] = u8::from(self.is_bonded);
        out[7] = u8::from(self.irk.is_some());
        out[8..24].copy_from_slice(&self.ltk);
        out[24..30].copy_from_slice(&self.bd_addr);
        out[30] = self.bd_addr_kind;
        if let Some(irk) = self.irk {
            out[31..47].copy_from_slice(&irk);
        }
        out
    }

    pub fn decode(input: &[u8; BLE_BOND_RECORD_LEN]) -> Option<Self> {
        if input[0..4] != Self::MAGIC || input[4] != Self::FORMAT_VERSION {
            return None;
        }
        let security_level = StoredBleSecurityLevel::from_u8(input[5])?;
        let is_bonded = match input[6] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let has_irk = match input[7] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let mut ltk = [0; 16];
        ltk.copy_from_slice(&input[8..24]);
        let mut bd_addr = [0; 6];
        bd_addr.copy_from_slice(&input[24..30]);
        let bd_addr_kind = input[30];
        let irk = if has_irk {
            let mut irk = [0; 16];
            irk.copy_from_slice(&input[31..47]);
            Some(irk)
        } else {
            None
        };
        Some(Self {
            ltk,
            bd_addr,
            bd_addr_kind,
            irk,
            is_bonded,
            security_level,
        })
    }
}

/// Bond persistence interface; confidentiality, integrity and isolation are not guaranteed.
pub trait BleBondStore {
    fn load_bonds<F>(&mut self, visit: F)
    where
        F: FnMut(StoredBleBond);

    fn store_bond(&mut self, bond: StoredBleBond) -> bool;

    fn clear_bonds(&mut self) -> bool;
}

impl BleBondStore for () {
    fn load_bonds<F>(&mut self, _visit: F)
    where
        F: FnMut(StoredBleBond),
    {
    }

    fn store_bond(&mut self, _bond: StoredBleBond) -> bool {
        false
    }

    fn clear_bonds(&mut self) -> bool {
        true
    }
}
