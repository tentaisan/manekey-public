# ESP32-C6

## Scope

Seeed Studio XIAO ESP32-C6.

BLE and Internal UART; ES256, experimental ML-DSA, managed keys and task separation. BLE-less PMP products are available. PMP and BLE are not combined in the bare-metal product configuration.

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

Direct and dual-task configurations provide shared execution or mailbox
separation; separate tasks alone do not protect memory.

The BLE-less `esp32c6_pmp_internal_uart_fido` product separates the UART frontend
from the trusted protocol/key/storage service through PMP.
Select `pmp-internal-uart-fido` without BLE/RTOS features.
This is the native PMP product, not an ESP-TEE deployment. CPU protection is
not a general guarantee of DMA, IRQ or peripheral isolation.
The BLE build example below is not a PMP build.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target riscv32imac-unknown-none-elf --bin esp32c6_ble_internal_uart_fido \
  --features ble,internal-uart,log-jtag-serial,shared-flash,client-pin-flash,flash-managed-keys,up-always-present
```

The ELF is written to `target/riscv32imac-unknown-none-elf/release/esp32c6_ble_internal_uart_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

This example uses automatic presence for development only. It does not require
physical user consent and must not be treated as a production presence policy.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
