pub mod layout {
    pub const FLASH_BASE: u32 = 0x1000_0000;
    pub const SECURE_FLASH_START: u32 = 0x1000_0000;
    pub const SECURE_FLASH_END: u32 = 0x100f_efff;
    pub const NSC_FLASH_START: u32 = 0x100f_f000;
    pub const NSC_FLASH_END: u32 = 0x100f_ffff;
    pub const NONSECURE_FLASH_START: u32 = 0x1010_0000;
    #[cfg(not(feature = "rp2350-managed-flash-layout"))]
    pub const NONSECURE_FLASH_END: u32 = 0x103f_afff;
    #[cfg(feature = "rp2350-managed-flash-layout")]
    pub const NONSECURE_FLASH_END: u32 = 0x103f_8fff;
    pub const SECURE_MANAGED_KEYS_START: u32 = 0x103f_9000;
    pub const SECURE_BLE_BOND_START: u32 = 0x103f_b000;
    pub const SECURE_STORAGE_START: u32 = 0x103f_c000;
    pub const FLASH_END: u32 = 0x103f_ffff;
    pub const FLASH_SIZE: usize = (FLASH_END - FLASH_BASE + 1) as usize;
    pub const SECURE_STORAGE_OFFSET: usize = (SECURE_STORAGE_START - FLASH_BASE) as usize;

    pub const SECURE_RAM_START: u32 = 0x2000_0000;
    pub const SECURE_RAM_END: u32 = 0x2003_ffff;
    pub const NONSECURE_RAM_START: u32 = 0x2004_0000;
    pub const NONSECURE_RAM_END: u32 = 0x2008_1fff;
    pub const PRESENCE_UI_HINT_ADDRESS: u32 = NONSECURE_RAM_END - 3;
    pub const NONSECURE_MARKER_ADDRESS: u32 = 0x2008_1ff0;
    pub const NONSECURE_MARKER_VALUE: u32 = 0x4e53_5f4f;
    pub const GATEWAY_MARKER_ADDRESS: u32 = NONSECURE_MARKER_ADDRESS + 4;
    pub const GATEWAY_MARKER_VALUE: u32 = 0x5347_5f4f;
    pub const SECURE_GATEWAY_ADDRESS: u32 = NSC_FLASH_START + 1;
    pub const BLE_BOND_GATEWAY_ADDRESS: u32 = NSC_FLASH_START + 0x21;

    pub const fn is_sau_region(base: u32, limit: u32) -> bool {
        base <= limit && base & 0x1f == 0 && limit & 0x1f == 0x1f
    }

    const _: () = assert!(is_sau_region(NSC_FLASH_START, NSC_FLASH_END));
    const _: () = assert!(is_sau_region(NONSECURE_FLASH_START, NONSECURE_FLASH_END));
    const _: () = assert!(is_sau_region(NONSECURE_RAM_START, NONSECURE_RAM_END));
    const _: () = assert!(SECURE_FLASH_END + 1 == NSC_FLASH_START);
    const _: () = assert!(NSC_FLASH_END + 1 == NONSECURE_FLASH_START);
    const _: () = assert!(
        NONSECURE_FLASH_END + 1
            == if cfg!(feature = "rp2350-managed-flash-layout") {
                SECURE_MANAGED_KEYS_START
            } else {
                SECURE_BLE_BOND_START
            }
    );
    const _: () = assert!(SECURE_MANAGED_KEYS_START + 0x2000 == SECURE_BLE_BOND_START);
    const _: () = assert!(SECURE_BLE_BOND_START + 0x1000 == SECURE_STORAGE_START);
    const _: () = assert!(NONSECURE_MARKER_ADDRESS >= NONSECURE_RAM_START);
    const _: () = assert!(NONSECURE_MARKER_ADDRESS + 4 <= NONSECURE_RAM_END + 1);
    const _: () = assert!(GATEWAY_MARKER_ADDRESS + 4 <= NONSECURE_RAM_END + 1);
    const _: () = assert!(PRESENCE_UI_HINT_ADDRESS & 3 == 0);
    const _: () = assert!(PRESENCE_UI_HINT_ADDRESS >= NONSECURE_RAM_START);
    const _: () = assert!(PRESENCE_UI_HINT_ADDRESS + 4 <= NONSECURE_RAM_END + 1);
}

pub use trusted_boundary::{
    SharedMemoryRegion, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedCallDescriptor,
    TrustedCallError, ValidatedTrustedCall, operation as trusted_operation,
    status as trusted_status,
};

pub const NONSECURE_SHARED_MEMORY: trusted_boundary::SharedMemoryRegion =
    trusted_boundary::SharedMemoryRegion {
        start: layout::NONSECURE_RAM_START,
        end: layout::NONSECURE_RAM_END + 1,
    };

pub mod policy {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Asset {
        UserText,
        UserStack,
        UserAsyncState,
        SharedCallBuffer,
        MachineText,
        MachineData,
        MachineTrapStack,
        Trng,
        QmiFlashControl,
        XipCtrl,
        UsbController,
        Timer,
        BootRomFlashRoutines,
        Dma,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Owner {
        TrustedMonitor,
        UserTransport,
        SharedBoundary,
        Unused,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Access {
        pub read: bool,
        pub write: bool,
        pub execute: bool,
    }

    impl Access {
        pub const NONE: Self = Self {
            read: false,
            write: false,
            execute: false,
        };
        pub const READ_WRITE: Self = Self {
            read: true,
            write: true,
            execute: false,
        };
        pub const READ_EXECUTE: Self = Self {
            read: true,
            write: false,
            execute: true,
        };

        pub const fn allows_data_access(self) -> bool {
            self.read || self.write
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PmpRule {
        Allow(Access),
        DenyByDefault,
        NotCpuVisible,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AccessCtrlRule {
        TrustedOnly,
        UserAllowedLater,
        NotApplicable,
        DmaMpuRequired,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SecurityPolicyEntry {
        pub asset: Asset,
        pub owner: Owner,
        pub user_access: Access,
        pub pmp_rule: PmpRule,
        pub accessctrl_rule: AccessCtrlRule,
    }

    impl SecurityPolicyEntry {
        pub const fn is_user_visible(self) -> bool {
            self.user_access.read || self.user_access.write || self.user_access.execute
        }

        pub const fn is_default_denied_to_user(self) -> bool {
            matches!(self.pmp_rule, PmpRule::DenyByDefault) && !self.is_user_visible()
        }
    }

    pub const RP2350_RISCV_PMP_MINIMAL_POLICY: &[SecurityPolicyEntry] = &[
        SecurityPolicyEntry {
            asset: Asset::UserText,
            owner: Owner::UserTransport,
            user_access: Access::READ_EXECUTE,
            pmp_rule: PmpRule::Allow(Access::READ_EXECUTE),
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::UserStack,
            owner: Owner::UserTransport,
            user_access: Access::READ_WRITE,
            pmp_rule: PmpRule::Allow(Access::READ_WRITE),
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::UserAsyncState,
            owner: Owner::UserTransport,
            user_access: Access::READ_WRITE,
            pmp_rule: PmpRule::Allow(Access::READ_WRITE),
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::SharedCallBuffer,
            owner: Owner::SharedBoundary,
            user_access: Access::READ_WRITE,
            pmp_rule: PmpRule::Allow(Access::READ_WRITE),
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::MachineText,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::MachineData,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::MachineTrapStack,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::NotApplicable,
        },
        SecurityPolicyEntry {
            asset: Asset::Trng,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::TrustedOnly,
        },
        SecurityPolicyEntry {
            asset: Asset::QmiFlashControl,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::TrustedOnly,
        },
        SecurityPolicyEntry {
            asset: Asset::XipCtrl,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::TrustedOnly,
        },
        SecurityPolicyEntry {
            asset: Asset::UsbController,
            owner: Owner::UserTransport,
            user_access: Access::READ_WRITE,
            pmp_rule: PmpRule::Allow(Access::READ_WRITE),
            accessctrl_rule: AccessCtrlRule::UserAllowedLater,
        },
        SecurityPolicyEntry {
            asset: Asset::Timer,
            owner: Owner::UserTransport,
            user_access: Access::READ_WRITE,
            pmp_rule: PmpRule::Allow(Access::READ_WRITE),
            accessctrl_rule: AccessCtrlRule::UserAllowedLater,
        },
        SecurityPolicyEntry {
            asset: Asset::BootRomFlashRoutines,
            owner: Owner::TrustedMonitor,
            user_access: Access::NONE,
            pmp_rule: PmpRule::DenyByDefault,
            accessctrl_rule: AccessCtrlRule::TrustedOnly,
        },
        SecurityPolicyEntry {
            asset: Asset::Dma,
            owner: Owner::Unused,
            user_access: Access::NONE,
            pmp_rule: PmpRule::NotCpuVisible,
            accessctrl_rule: AccessCtrlRule::DmaMpuRequired,
        },
    ];

    pub const fn find_policy_entry(asset: Asset) -> Option<SecurityPolicyEntry> {
        let mut index = 0;
        while index < RP2350_RISCV_PMP_MINIMAL_POLICY.len() {
            let entry = RP2350_RISCV_PMP_MINIMAL_POLICY[index];
            if entry.asset as u8 == asset as u8 {
                return Some(entry);
            }
            index += 1;
        }
        None
    }
}

/// Validates descriptor arithmetic against the default RP2350 window, not hardware attribution.
pub const fn validate_trusted_call(
    descriptor_ptr: u32,
    descriptor: TrustedCallDescriptor,
) -> Result<ValidatedTrustedCall, TrustedCallError> {
    trusted_boundary::validate_trusted_call(NONSECURE_SHARED_MEMORY, descriptor_ptr, descriptor)
}

pub const fn trusted_call_error_status(error: TrustedCallError) -> u32 {
    match error {
        TrustedCallError::InvalidDescriptor => trusted_status::INVALID_DESCRIPTOR,
        TrustedCallError::InvalidOperation => trusted_status::INVALID_OPERATION,
        TrustedCallError::InvalidRequest => trusted_status::INVALID_REQUEST,
        TrustedCallError::InvalidResponse | TrustedCallError::OverlappingRanges => {
            trusted_status::INVALID_RESPONSE
        }
    }
}

pub const fn descriptor_pointer_is_in_shared(
    shared_memory: trusted_boundary::SharedMemoryRegion,
    descriptor_ptr: u32,
) -> bool {
    let descriptor_size = core::mem::size_of::<TrustedCallDescriptor>() as u32;
    descriptor_ptr & 3 == 0
        && descriptor_ptr >= shared_memory.start
        && match descriptor_ptr.checked_add(descriptor_size) {
            Some(end) => end <= shared_memory.end,
            None => false,
        }
}

/// # Safety
/// Supply a mapped stable shared window with valid volatile descriptor/payload access.
/// Exclude backend reentry, DMA/other concurrent mutation and invalid aliases throughout dispatch.
pub unsafe fn dispatch_trusted_call_from_shared<T: crate::ctaphid::trusted::TrustedBackend>(
    shared_memory: trusted_boundary::SharedMemoryRegion,
    descriptor_ptr: u32,
    trusted: &mut T,
) -> u32 {
    if !descriptor_pointer_is_in_shared(shared_memory, descriptor_ptr) {
        return trusted_status::INVALID_DESCRIPTOR;
    }
    let descriptor =
        unsafe { core::ptr::read_volatile(descriptor_ptr as *const TrustedCallDescriptor) };
    let validated =
        match trusted_boundary::validate_trusted_call(shared_memory, descriptor_ptr, descriptor) {
            Ok(validated) => validated,
            Err(error) => return trusted_call_error_status(error),
        };
    unsafe { dispatch_validated_trusted_call(descriptor_ptr, validated.descriptor, trusted) }
}

/// # Safety
/// Validate operation, lengths, alignment, bounds and nonoverlap equivalent to validate_trusted_call first.
/// Provide valid stable volatile access and exclusive backend ownership throughout dispatch.
pub unsafe fn dispatch_validated_trusted_call<T: crate::ctaphid::trusted::TrustedBackend>(
    descriptor_ptr: u32,
    descriptor: TrustedCallDescriptor,
    trusted: &mut T,
) -> u32 {
    let descriptor_out = descriptor_ptr as *mut TrustedCallDescriptor;
    let mut request = [0u8; TRUSTED_REQUEST_MAX as usize];
    for (index, byte) in request[..descriptor.request_len as usize]
        .iter_mut()
        .enumerate()
    {
        *byte =
            unsafe { core::ptr::read_volatile((descriptor.request_ptr as *const u8).add(index)) };
    }
    let mut response = [0u8; TRUSTED_RESPONSE_MAX as usize];
    let result = crate::boundary::gateway::dispatch(
        trusted,
        descriptor.status,
        &request[..descriptor.request_len as usize],
        &mut response[..descriptor.response_capacity as usize],
    );
    request[..descriptor.request_len as usize].fill(0);

    for (index, byte) in response[..result.response_len as usize].iter().enumerate() {
        unsafe {
            core::ptr::write_volatile((descriptor.response_ptr as *mut u8).add(index), *byte);
        }
    }
    response[..result.response_len as usize].fill(0);
    unsafe {
        core::ptr::addr_of_mut!((*descriptor_out).response_len).write_volatile(result.response_len);
        core::ptr::addr_of_mut!((*descriptor_out).status).write_volatile(result.status);
    }
    result.status
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Address/alignment validation only; caller authenticates the image and configures attribution.
pub struct NonsecureVector {
    pub main_stack_pointer: u32,
    pub reset_handler: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonsecureVectorError {
    StackOutOfRange,
    StackMisaligned,
    ResetNotThumb,
    ResetOutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// RP2350 register encoding; bits() always includes DEBUG and CORE0 access.
/// This does not configure hardware or establish debug/physical access protection.
pub struct Rp2350AccessPermissions {
    pub secure_privileged: bool,
    pub nonsecure_privileged: bool,
    pub nonsecure_unprivileged: bool,
    pub core1: bool,
    pub dma: bool,
}

impl Rp2350AccessPermissions {
    const DEBUG: u32 = 1 << 7;
    const DMA: u32 = 1 << 6;
    const CORE1: u32 = 1 << 5;
    const CORE0: u32 = 1 << 4;
    const SECURE_PRIVILEGED: u32 = 1 << 3;
    const NONSECURE_PRIVILEGED: u32 = 1 << 1;
    const NONSECURE_UNPRIVILEGED: u32 = 1 << 0;

    pub const SECURE_ONLY: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: false,
        nonsecure_unprivileged: false,
        core1: false,
        dma: false,
    };

    pub const SECURE_AND_NONSECURE: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: true,
        nonsecure_unprivileged: false,
        core1: false,
        dma: false,
    };

    pub const SECURE_AND_NONSECURE_UNPRIVILEGED: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: true,
        nonsecure_unprivileged: true,
        core1: false,
        dma: false,
    };

    pub const SECURE_AND_NONSECURE_DMA: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: true,
        nonsecure_unprivileged: false,
        core1: false,
        dma: true,
    };

    pub const SECURE_AND_NONSECURE_CORE0_CORE1: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: true,
        nonsecure_unprivileged: false,
        core1: true,
        dma: false,
    };

    pub const SECURE_AND_NONSECURE_CORE0_CORE1_DMA: Self = Self {
        secure_privileged: true,
        nonsecure_privileged: true,
        nonsecure_unprivileged: false,
        core1: true,
        dma: true,
    };

    pub const fn bits(self) -> u32 {
        Self::DEBUG
            | if self.dma { Self::DMA } else { 0 }
            | Self::CORE0
            | if self.core1 { Self::CORE1 } else { 0 }
            | if self.secure_privileged {
                Self::SECURE_PRIVILEGED
            } else {
                0
            }
            | if self.nonsecure_privileged {
                Self::NONSECURE_PRIVILEGED
            } else {
                0
            }
            | if self.nonsecure_unprivileged {
                Self::NONSECURE_UNPRIVILEGED
            } else {
                0
            }
    }
}

impl NonsecureVector {
    pub const fn validate(self) -> Result<Self, NonsecureVectorError> {
        self.validate_in(
            layout::NONSECURE_RAM_START,
            layout::NONSECURE_RAM_END + 1,
            layout::NONSECURE_FLASH_START,
            layout::NONSECURE_FLASH_END + 1,
        )
    }

    pub const fn validate_in(
        self,
        ram_start: u32,
        ram_end: u32,
        flash_start: u32,
        flash_end: u32,
    ) -> Result<Self, NonsecureVectorError> {
        if ram_start >= ram_end
            || self.main_stack_pointer <= ram_start
            || self.main_stack_pointer > ram_end
        {
            return Err(NonsecureVectorError::StackOutOfRange);
        }
        if self.main_stack_pointer & 0x7 != 0 {
            return Err(NonsecureVectorError::StackMisaligned);
        }
        if self.reset_handler & 1 == 0 {
            return Err(NonsecureVectorError::ResetNotThumb);
        }
        let reset_address = self.reset_handler & !1;
        if flash_start >= flash_end || reset_address < flash_start || reset_address >= flash_end {
            return Err(NonsecureVectorError::ResetOutOfRange);
        }
        Ok(self)
    }

    pub const fn bxns_address(self) -> u32 {
        self.reset_handler & !1
    }
}
