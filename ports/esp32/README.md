# ESP32 / NodeMCU-32S

## Scope

NodeMCU-32S (including the single-core revision-1 configuration).

BLE and Internal UART; ES256, persistent PIN and managed keys. Experimental ML-DSA backends and task separation are available. MPU product isolation remains pending; there is no native USB device transport.

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

Direct and dual-task products connect UART/BLE frontends to shared trusted
protocol/key/storage interfaces. Separate tasks do not prevent memory access.
A hardware MPU-isolated product is not provided by this port; isolation
integration remains pending. The build below is not hardware-isolated.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install the Espressif Rust toolchain with Xtensa support and the rust-src component.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +esp build --release --locked --no-default-features \
  --target xtensa-esp32-none-elf --bin esp32_ble_internal_uart_fido \
  --features managed-internal-uart
```

The ELF is written to `target/xtensa-esp32-none-elf/release/esp32_ble_internal_uart_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use B/BOOT (IO0) for presence when the blue USER LED lights. Do not press EN/RESET.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
