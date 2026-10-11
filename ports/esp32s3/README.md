# ESP32-S3

## Scope

ESP32-S3 boards matching this port's GPIO and flash layout.

USB HID, optional CCID, BLE and Internal UART; ES256, experimental ML-DSA, managed keys, task and core separation. PMS product isolation remains pending.

## External inputs

Cargo obtains the locked HAL, runtime and selected wireless driver libraries.
No separately installed ESP-IDF tree is required by the examples in this port.
The Rust target/toolchain must support this chip. Xtensa builds require the
Espressif toolchain; build-std configurations require rust-src.

Native ML-DSA additionally requires Clang for RISC-V targets or the chip-specific
Xtensa GCC toolchain for Xtensa targets. Its C source snapshot is included in
this repository, not downloaded by the crypto build script.
Wireless libraries retain their original terms. Building locally does not
establish permission to redistribute every linked vendor binary.

## Boundaries

Direct, dual-task and dual-core products use shared trusted-service interfaces.
Tasks and cores alone do not enforce access protection.
PMS product isolation remains pending; the build below is not a protected
frontend/trusted-service split. DMA and IRQ protection must not be inferred
from core separation.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install the Espressif Rust toolchain with Xtensa support and the rust-src component.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +esp build --release --locked --no-default-features \
  --target xtensa-esp32s3-none-elf --bin esp32s3_usb_ble_fido \
  --features internal-uart,usb-ble-multi,board-ui,log-jtag-serial,usb-ccid-experimental,flash-managed-keys
```

The ELF is written to `target/xtensa-esp32s3-none-elf/release/esp32s3_usb_ble_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use BOOT (GPIO0) for presence. RGB indication depends on the board revision; do not assume identical LED behavior across boards.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
