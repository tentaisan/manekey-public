// SPDX-License-Identifier: Apache-2.0
#![no_std]





#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedCallDescriptor {
    pub request_ptr: u32,
    pub request_len: u32,
    pub response_ptr: u32,
    pub response_capacity: u32,
    pub response_len: u32,
    pub status: u32,
}

pub const TRUSTED_REQUEST_MAX: u32 = 1024;
#[cfg(not(feature = "large-response"))]
pub const TRUSTED_RESPONSE_MAX: u32 = 1024;
#[cfg(feature = "large-response")]
pub const TRUSTED_RESPONSE_MAX: u32 = 4096;



pub mod operation {
    // These codes do not authorize a service; each gateway must explicitly permit it.
    // SECURE_ECB framing and exact block sizes are gateway-specific, not checked here.
    pub const SUBMIT_CBOR: u32 = 0;
    pub const POLL: u32 = 1;
    pub const CANCEL: u32 = 2;

    pub const SUBMIT_U2F: u32 = 3;


    pub const SECURE_RANDOM: u32 = 4;




    pub const SECURE_ECB: u32 = 5;
}

pub mod status {
    pub const OK: u32 = 0;
    pub const INVALID_DESCRIPTOR: u32 = 1;
    pub const INVALID_REQUEST: u32 = 2;
    pub const INVALID_RESPONSE: u32 = 3;
    pub const OUTPUT_TOO_SMALL: u32 = 4;
    pub const USER_PRESENCE_PENDING: u32 = 5;
    pub const BUSY: u32 = 6;
    pub const INVALID_OPERATION: u32 = 7;
}

const _: () = assert!(core::mem::size_of::<TrustedCallDescriptor>() == 24);
const _: () = assert!(core::mem::align_of::<TrustedCallDescriptor>() == 4);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedTrustedCall {
    pub descriptor: TrustedCallDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedCallError {
    InvalidDescriptor,
    InvalidOperation,
    InvalidRequest,
    InvalidResponse,
    OverlappingRanges,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryRegion {
    pub start: u32,
    pub end: u32,
}

impl SharedMemoryRegion {
    pub const fn new(start: u32, end: u32) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    const fn contains(self, range: AddressRange) -> bool {
        range.start >= self.start && range.end <= self.end
    }
}

#[derive(Clone, Copy)]
struct AddressRange {
    start: u32,
    end: u32,
}

impl AddressRange {
    const fn new(start: u32, len: u32) -> Option<Self> {
        if len == 0 {
            return None;
        }
        match start.checked_add(len) {
            Some(end) => Some(Self { start, end }),
            None => None,
        }
    }

    const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}


// Validates scalar ranges only; no pointer is dereferenced and no hardware isolation is configured.
// The gateway must enforce ownership, stable request data and service-specific formats before use.
pub const fn validate_trusted_call(
    shared_memory: SharedMemoryRegion,
    descriptor_ptr: u32,
    descriptor: TrustedCallDescriptor,
) -> Result<ValidatedTrustedCall, TrustedCallError> {
    if descriptor_ptr & 3 != 0 {
        return Err(TrustedCallError::InvalidDescriptor);
    }
    let descriptor_range = match AddressRange::new(
        descriptor_ptr,
        core::mem::size_of::<TrustedCallDescriptor>() as u32,
    ) {
        Some(range) if shared_memory.contains(range) => range,
        _ => return Err(TrustedCallError::InvalidDescriptor),
    };
    let request_range = match descriptor.status {
        operation::SUBMIT_CBOR | operation::SUBMIT_U2F => {
            if descriptor.request_len > TRUSTED_REQUEST_MAX {
                return Err(TrustedCallError::InvalidRequest);
            }
            match AddressRange::new(descriptor.request_ptr, descriptor.request_len) {
                Some(range) if shared_memory.contains(range) => Some(range),
                _ => return Err(TrustedCallError::InvalidRequest),
            }
        }
        operation::POLL | operation::CANCEL | operation::SECURE_RANDOM => {
            if descriptor.request_len != 0 {
                return Err(TrustedCallError::InvalidRequest);
            }
            None
        }
        operation::SECURE_ECB => {
            if descriptor.request_len > TRUSTED_REQUEST_MAX {
                return Err(TrustedCallError::InvalidRequest);
            }
            match AddressRange::new(descriptor.request_ptr, descriptor.request_len) {
                Some(range) if shared_memory.contains(range) => Some(range),
                _ => return Err(TrustedCallError::InvalidRequest),
            }
        }
        _ => return Err(TrustedCallError::InvalidOperation),
    };
    if descriptor.response_capacity > TRUSTED_RESPONSE_MAX {
        return Err(TrustedCallError::InvalidResponse);
    }
    let response_range =
        match AddressRange::new(descriptor.response_ptr, descriptor.response_capacity) {
            Some(range) if shared_memory.contains(range) => range,
            _ => return Err(TrustedCallError::InvalidResponse),
        };
    let request_overlaps = match request_range {
        Some(request_range) => {
            descriptor_range.overlaps(request_range) || request_range.overlaps(response_range)
        }
        None => false,
    };
    if request_overlaps || descriptor_range.overlaps(response_range) {
        return Err(TrustedCallError::OverlappingRanges);
    }
    Ok(ValidatedTrustedCall { descriptor })
}



































































































































































































