# ESP32-S2

## Scope

ESP32-S2 boards matching this port's GPIO and flash layout.

USB HID, optional CCID and Internal UART; ES256, experimental ML-DSA, managed keys and task separation. This chip has no BLE. PMS product isolation remains pending.

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

Direct and dual-task products use shared protocol/key/storage interfaces.
Task separation does not provide memory protection.
A PMS-isolated product is not included; its runtime integration remains pending.
USB/UART support does not imply DMA or interrupt isolation.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install the Espressif Rust toolchain with Xtensa support and the rust-src component.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +esp build --release --locked --no-default-features \
  --target xtensa-esp32s2-none-elf --bin esp32s2_usb_fido \
  --features usb-hid,internal-uart,flash-managed-keys,client-pin-flash,log-uart
```

The ELF is written to `target/xtensa-esp32s2-none-elf/release/esp32s2_usb_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use BOOT for presence when the USER LED lights. EN/RESET does not confirm presence.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
