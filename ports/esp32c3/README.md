# ESP32-C3

## Scope

Seeed Studio XIAO ESP32-C3.

BLE and Internal UART; ES256, persistent PIN, managed keys and task separation. ML-DSA is a BLE-less UART option; BLE plus ML-DSA is not supported by the current product build. PMP product isolation is not included.

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

Direct and task-separated UART/BLE products use the common trusted-service
interface. A separate task does not enforce memory protection.
No PMP-isolated product is included in this port. The BLE-less ML-DSA option
changes resource usage, not the security boundary.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target riscv32imc-unknown-none-elf --bin esp32c3_internal_uart_fido \
  --features internal-uart,log-jtag-serial,shared-flash,client-pin-flash,flash-managed-keys,up-always-present
```

The ELF is written to `target/riscv32imc-unknown-none-elf/release/esp32c3_internal_uart_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

This example uses automatic presence for development only. It does not require
physical user consent and must not be treated as a production presence policy.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
