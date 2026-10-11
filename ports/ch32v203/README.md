# CH32V203

## Scope

CH32V203 with a matching flash geometry and USB/UART connections.

USB HID, optional CCID and Internal UART; ES256, persistent PIN, managed keys and task separation. ADC entropy is experimental. ML-DSA and hardware isolation products are not included.

## Boundaries

Direct and task-separated products use shared protocol/key/storage interfaces.
There is no hardware-isolated frontend/trusted-service product in this port.
Task separation and managed storage are not substitutes for memory protection.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target riscv32imc-unknown-none-elf --bin ch32v203_multi_fido \
  --features fido-p256,experimental-adc-entropy,internal-uart,flash-storage,storage-small,client-pin-flash,flash-managed-keys
```

The ELF is written to `target/riscv32imc-unknown-none-elf/release/ch32v203_multi_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
