#![no_std]
#![no_main]

#[cfg(not(any(
    feature = "riscv-pmp-usb-frontend",
    feature = "riscv-pmp-ble-monitor-image"
)))]
compile_error!("PMP product entry requires a USB frontend or split BLE monitor");

include!("pmp_entrypoint.rs");
