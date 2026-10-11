use super::BleFidoError;

pub const FIDO_SERVICE_UUID_16: u16 = 0xfffd;

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";

pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";

pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";

pub const FIDO_SERVICE_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

pub const FIDO_SERVICE_REVISION_UUID_16: u16 = 0x2a28;

pub const FIDO2_SERVICE_REVISION_BIT: u8 = 0x20;

pub const FIDO_SERVICE_REVISION: &str = "FIDO_2_0";

pub const LE_GENERAL_DISCOVERABLE_BR_EDR_NOT_SUPPORTED: u8 = 0x06;

pub const CONTROL_POINT_LENGTH_MIN: usize = 20;

pub const CONTROL_POINT_LENGTH_MAX: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FidoBleProfile {
    pub address: [u8; 6],
    pub device_name: &'static [u8],
}

struct BleAdWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> BleAdWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn write(&mut self, ty: u8, data: &[u8]) -> Result<(), BleFidoError> {
        if data.len() > u8::MAX as usize - 1 {
            return Err(BleFidoError::AdvDataTooLong);
        }
        let needed = 2 + data.len();
        if self.out.len().saturating_sub(self.len) < needed {
            return Err(BleFidoError::AdvDataTooLong);
        }
        self.out[self.len] = (data.len() + 1) as u8;
        self.out[self.len + 1] = ty;
        self.out[self.len + 2..self.len + needed].copy_from_slice(data);
        self.len += needed;
        Ok(())
    }
}

impl FidoBleProfile {
    /// Uses a shared development address; assign distinct addresses per device.
    pub const fn manekey() -> Self {
        Self {
            address: [0xc1, 0x7a, 0xf1, 0xd0, 0x02, 0xc2],
            device_name: b"ManeKey FIDO BLE",
        }
    }

    pub const fn service_uuid_le(self) -> [u8; 2] {
        FIDO_SERVICE_UUID_16.to_le_bytes()
    }

    pub const fn service_revision(self) -> &'static str {
        FIDO_SERVICE_REVISION
    }

    pub const fn service_revision_bitfield(self) -> u8 {
        FIDO2_SERVICE_REVISION_BIT
    }

    pub const fn display_address(self) -> [u8; 6] {
        [
            self.address[5],
            self.address[4],
            self.address[3],
            self.address[2],
            self.address[1],
            self.address[0],
        ]
    }

    pub const fn is_static_random_address(self) -> bool {
        self.display_address()[0] & 0xc0 == 0xc0
    }

    pub fn encode_legacy_advertising_data(self, out: &mut [u8]) -> Result<usize, BleFidoError> {
        let mut writer = BleAdWriter::new(out);
        writer.write(0x01, &[LE_GENERAL_DISCOVERABLE_BR_EDR_NOT_SUPPORTED])?;
        writer.write(0x03, &self.service_uuid_le())?;
        Ok(writer.len())
    }

    pub fn encode_legacy_scan_response(self, out: &mut [u8]) -> Result<usize, BleFidoError> {
        let mut writer = BleAdWriter::new(out);
        writer.write(0x09, self.device_name)?;
        Ok(writer.len())
    }
}
