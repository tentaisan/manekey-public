pub const ERASE: u32 = 8192;
pub const BANK: u32 = 1024 * 1024;
pub const END: u32 = 2 * BANK;
pub const PRIVATE_START: u32 = END - 5 * ERASE;
pub const MANAGED_START: u32 = BANK - 4 * ERASE;
pub const MANAGED_END: u32 = MANAGED_START + 2 * ERASE;

/// Checks declared media bounds only; does not configure or prove Flash security attribution.
pub fn private_range(address: u32, len: usize, managed: bool) -> bool {
    let Some(end) = u32::try_from(len)
        .ok()
        .and_then(|len| address.checked_add(len))
    else {
        return false;
    };
    (address >= PRIVATE_START && end <= END)
        || (managed && address >= MANAGED_START && end <= MANAGED_END)
}

pub fn erase_bank_page(address: u32) -> Option<(bool, u8)> {
    if address >= END || address % ERASE != 0 {
        return None;
    }
    Some((address >= BANK, ((address % BANK) / ERASE) as u8))
}
