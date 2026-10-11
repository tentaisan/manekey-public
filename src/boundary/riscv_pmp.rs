use crate::security::policy::Access;

pub const TRUSTED_CALL_ECALL_ID: u32 = 0x504d_ec10;

pub const USER_EVENT_RETURN_ECALL_ID: u32 = 0x504d_ec22;

pub const BYTE_IO_ECALL_ID: u32 = 0x504d_ec23;
pub const BYTE_IO_READ: u32 = 0;
pub const BYTE_IO_WRITE: u32 = 1;
pub const BYTE_IO_EMPTY: u32 = 256;
pub const BYTE_IO_WOULD_BLOCK: u32 = 257;
pub const BYTE_IO_DENIED: u32 = 258;
pub const BYTE_IO_RECEIVE_ERROR: u32 = 259;

pub const fn byte_io_request_is_valid(operation: u32, value: u32) -> bool {
    match operation {
        BYTE_IO_READ => value == 0,
        BYTE_IO_WRITE => value <= u8::MAX as u32,
        _ => false,
    }
}

pub const PRESENCE_PENDING_ECALL_ID: u32 = 0x504d_ec24;

pub const BLE_BOND_ECALL_ID: u32 = 0x504d_ec21;
pub const BLE_BOND_OP_LOAD: u32 = 0;
pub const BLE_BOND_OP_STORE: u32 = 1;
pub const BLE_BOND_OP_CLEAR: u32 = 2;
pub const BLE_BOND_STATUS_OK: u32 = 0;
pub const BLE_BOND_STATUS_NOT_FOUND: u32 = 1;
pub const BLE_BOND_STATUS_INVALID: u32 = 2;
pub const BLE_BOND_STATUS_FAILED: u32 = 3;
pub const BLE_BOND_STATUS_DENIED: u32 = 4;

pub const CYW43_GPIO_ECALL_ID: u32 = 0x504d_ec1b;
pub const CYW43_GPIO_STATUS_OK: u32 = 0;
pub const CYW43_GPIO_STATUS_DENIED: u32 = 1;

pub const TIMER_ARM_ECALL_ID: u32 = 0x504d_ec1d;

pub const TIMER_REARM_ECALL_ID: u32 = 0x504d_ec1f;

pub const TIMER_STATUS_ECALL_ID: u32 = 0x504d_ec1c;

pub const DMA_IRQ_STATUS_ECALL_ID: u32 = 0x504d_ec20;
pub const TIMER_STATUS_OK: u32 = 0;
pub const TIMER_STATUS_DENIED: u32 = 1;

pub const BLE_SPLIT_ENTRY_ECALL_ID: u32 = 0x504d_ec1e;
pub const BLE_SPLIT_ENTRY_EXPECTED_MASK: u32 = 0x0000_007f;
pub const BLE_SPLIT_RUNNER_EXPECTED_MASK: u32 = 0x0000_00ff;
pub const BLE_SPLIT_HCI_EXPECTED_MASK: u32 = 0x0000_01ff;

pub const TIMER_MAX_DELAY_US: u32 = 10_000_000;

pub const fn timer_delay_is_valid(delay_us: u32) -> bool {
    delay_us != 0 && delay_us <= TIMER_MAX_DELAY_US
}

/// Address arithmetic only; does not establish mapping, permissions, ownership or caller authentication.
pub const fn fixed_buffer_is_in_region(
    pointer: u32,
    length: usize,
    region_start: usize,
    region_end: usize,
) -> bool {
    let start = pointer as usize;
    match start.checked_add(length) {
        Some(end) => start >= region_start && end <= region_end,
        None => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcallIslandRegion {
    pub base: usize,
    pub size: usize,
}

impl EcallIslandRegion {
    pub const fn end(self) -> Option<usize> {
        self.base.checked_add(self.size)
    }

    pub const fn is_nonempty(self) -> bool {
        self.size != 0 && self.end().is_some()
    }

    pub const fn overlaps(self, other: Self) -> bool {
        match (self.end(), other.end()) {
            (Some(end), Some(other_end)) => self.base < other_end && other.base < end,
            _ => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Generic user text/shared/stack layout; ports configure PMP and deny private trap-stack access.
pub struct EcallIslandLayout {
    pub user_text: EcallIslandRegion,
    pub shared: EcallIslandRegion,
    pub user_stack: EcallIslandRegion,
}

impl EcallIslandLayout {
    pub const fn new(
        user_text_base: usize,
        user_text_size: usize,
        shared_base: usize,
        shared_size: usize,
        user_stack_base: usize,
        user_stack_size: usize,
    ) -> Self {
        Self {
            user_text: EcallIslandRegion {
                base: user_text_base,
                size: user_text_size,
            },
            shared: EcallIslandRegion {
                base: shared_base,
                size: shared_size,
            },
            user_stack: EcallIslandRegion {
                base: user_stack_base,
                size: user_stack_size,
            },
        }
    }

    /// Checks nonempty disjoint ranges only, not hardware encoding, permissions or bootloader conflicts.
    pub const fn is_valid(self) -> bool {
        self.user_text.is_nonempty()
            && self.shared.is_nonempty()
            && self.user_stack.is_nonempty()
            && !self.user_text.overlaps(self.shared)
            && !self.user_text.overlaps(self.user_stack)
            && !self.shared.overlaps(self.user_stack)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Cyw43GpioCommand {
    PowerLow = 0,
    PowerHigh = 1,
    ChipSelectLow = 2,
    ChipSelectHigh = 3,
}

impl Cyw43GpioCommand {
    pub const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::PowerLow),
            1 => Some(Self::PowerHigh),
            2 => Some(Self::ChipSelectLow),
            3 => Some(Self::ChipSelectHigh),
            _ => None,
        }
    }

    pub const fn pin_and_level(self) -> (u8, bool) {
        match self {
            Self::PowerLow => (23, false),
            Self::PowerHigh => (23, true),
            Self::ChipSelectLow => (25, false),
            Self::ChipSelectHigh => (25, true),
        }
    }
}

#[cfg(feature = "experimental-large-message-buffers")]
pub const SHARED_CALL_REGION_SOFT_LIMIT: usize = 8192;
#[cfg(not(feature = "experimental-large-message-buffers"))]
pub const SHARED_CALL_REGION_SOFT_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionEncoding {
    pub read: usize,
    pub write: usize,
    pub execute: usize,
    pub napot: usize,
}

impl PermissionEncoding {
    pub const fn cfg_for_access(self, access: Access) -> usize {
        (if access.read { self.read } else { 0 })
            | (if access.write { self.write } else { 0 })
            | (if access.execute { self.execute } else { 0 })
            | self.napot
    }
}

pub const STANDARD_PERMISSION_ENCODING: PermissionEncoding = PermissionEncoding {
    read: 0b001,
    write: 0b010,
    execute: 0b100,
    napot: 0b11 << 3,
};

/// Caller supplies aligned base and power-of-two size at least eight bytes.
/// This unchecked encoding does not validate or install PMP permissions.
pub const fn napot_csr_addr(base: usize, size: usize) -> usize {
    (base | ((size - 1) >> 1)) >> 2
}

pub const fn pmp_entry_cfg(cfg: &[u32; 4], entry: usize) -> Option<u8> {
    if entry >= 16 {
        return None;
    }
    Some((cfg[entry / 4] >> ((entry % 4) * 8)) as u8)
}

pub const fn pmp_unlocked_mask(cfg: &[u32; 4]) -> u16 {
    let mut mask = 0u16;
    let mut entry = 0;
    while entry < 16 {
        if let Some(value) = pmp_entry_cfg(cfg, entry) {
            if value & 0x80 == 0 {
                mask |= 1 << entry;
            }
        }
        entry += 1;
    }
    mask
}

pub const fn pmp_addr_writable(cfg: &[u32; 4], entry: usize) -> bool {
    let Some(value) = pmp_entry_cfg(cfg, entry) else {
        return false;
    };
    if value & 0x80 != 0 {
        return false;
    }
    if let Some(next) = pmp_entry_cfg(cfg, entry + 1) {
        if next & 0x80 != 0 && (next >> 3) & 0x3 == 1 {
            return false;
        }
    }
    true
}
