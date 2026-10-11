pub const DEFAULT_USB_VID: u16 = 0xCAFE;

pub const DEFAULT_USB_PID: u16 = 0x4011;

pub const DEFAULT_USB_MANUFACTURER: &str = "ManeKey";

pub const REPORT_SIZE: usize = 64;

pub const REPORT_SIZE_U16: u16 = REPORT_SIZE as u16;

pub const REPORT_SIZE_U8: u8 = REPORT_SIZE as u8;

pub const POLL_MS: u8 = 5;

pub const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// USB metadata with development defaults; configure authorized IDs for distribution.
pub struct CtaphidUsbDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: &'static str,
    pub product: &'static str,
    pub serial_number: Option<&'static str>,
    pub poll_ms: u8,
    pub report_size: usize,
}

impl CtaphidUsbDeviceInfo {
    pub const fn new(product: &'static str, serial_number: &'static str) -> Self {
        Self {
            vendor_id: DEFAULT_USB_VID,
            product_id: DEFAULT_USB_PID,
            manufacturer: DEFAULT_USB_MANUFACTURER,
            product,
            serial_number: Some(serial_number),
            poll_ms: POLL_MS,
            report_size: REPORT_SIZE,
        }
    }

    pub const fn without_serial(product: &'static str) -> Self {
        Self {
            vendor_id: DEFAULT_USB_VID,
            product_id: DEFAULT_USB_PID,
            manufacturer: DEFAULT_USB_MANUFACTURER,
            product,
            serial_number: None,
            poll_ms: POLL_MS,
            report_size: REPORT_SIZE,
        }
    }

    pub const fn with_manufacturer(mut self, manufacturer: &'static str) -> Self {
        self.manufacturer = manufacturer;
        self
    }

    pub const fn with_vid_pid(mut self, vendor_id: u16, product_id: u16) -> Self {
        self.vendor_id = vendor_id;
        self.product_id = product_id;
        self
    }

    pub const fn with_poll_ms(mut self, poll_ms: u8) -> Self {
        self.poll_ms = poll_ms;
        self
    }
}
