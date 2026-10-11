

pub const OP_LOAD: u32 = 0;
pub const OP_STORE: u32 = 1;
pub const OP_CLEAR: u32 = 2;
pub const STATUS_OK: u32 = 0;
pub const STATUS_NOT_FOUND: u32 = 1;
pub const STATUS_INVALID: u32 = 2;
pub const STATUS_FAILED: u32 = 3;
pub const STATUS_DENIED: u32 = 4;

#[cfg(all(target_arch = "arm", target_os = "none"))]
pub struct ArmBleBondGatewayStore {
    gateway_address: u32,
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
impl ArmBleBondGatewayStore {



    // Safety: gateway_address must be a valid Thumb entry in an NSC region.
    // The entry must implement this synchronous r0/r1 bond-record ABI
    // and preserve the Arm calling convention. The secure gateway must validate
    // operation, buffer range and access permissions before reading or writing
    // BLE_BOND_RECORD_LEN bytes; OP_CLEAR receives a null buffer. It must not
    // retain the temporary buffer pointer after returning.
    pub const unsafe fn new(gateway_address: u32) -> Self {
        Self { gateway_address }
    }

    fn invoke(&self, operation: u32, buffer: *mut u8) -> u32 {
        let result: u32;
        unsafe {
            core::arch::asm!(
                "blx r4",
                in("r4") self.gateway_address,
                inout("r0") operation => result,
                in("r1") buffer as u32,
                out("r2") _,
                out("r3") _,
                out("r12") _,
                out("lr") _,
            );
        }
        result
    }
}

#[cfg(all(target_arch = "arm", target_os = "none"))]
impl crate::transport::ble::BleBondStore for ArmBleBondGatewayStore {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(crate::transport::ble::StoredBleBond),
    {
        // Bond records include key material in caller RAM. This adapter does
        // not zero temporary copies or provide storage confidentiality itself.
        let mut encoded = [0xff; crate::transport::ble::BLE_BOND_RECORD_LEN];
        if self.invoke(OP_LOAD, encoded.as_mut_ptr()) == STATUS_OK
            && let Some(bond) = crate::transport::ble::StoredBleBond::decode(&encoded)
        {
            visit(bond);
        }
    }

    fn store_bond(&mut self, bond: crate::transport::ble::StoredBleBond) -> bool {
        let mut encoded = bond.encode();
        self.invoke(OP_STORE, encoded.as_mut_ptr()) == STATUS_OK
    }

    fn clear_bonds(&mut self) -> bool {
        self.invoke(OP_CLEAR, core::ptr::null_mut()) == STATUS_OK
    }
}
