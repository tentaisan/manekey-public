

pub mod ccid_bulk;
pub mod ccid_control;

#[cfg(all(feature = "embassy-usb-transport", any(target_os = "none", test)))]
pub mod embassy;
#[cfg(feature = "usb-device-transport")]
pub mod polling_ccid;
