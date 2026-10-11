# STM32U575

## Scope

ST NUCLEO-U575ZI-Q.

USB HID, CCID and Internal UART; ES256, experimental ML-DSA, managed keys, task separation and paired TrustZone images. Hardware SHA-256 is optional. The ordinary build below does not configure device security options.

## Boundaries

The ordinary product supports Direct and dual-task execution without a
Secure/Non-Secure split. Separate tasks alone do not protect memory.

The TrustZone product pairs `stm32u575_tz_secure_fido` and
`stm32u575_tz_nonsecure_fido`. Secure services handle protocol/key/storage
operations; Non-Secure frontends provide UART, USB HID and CCID.
Hardware hashing belongs to the selected trusted configuration.

Matching image layouts and device security configuration are required.
Peripheral/DMA/IRQ ownership is port-specific; TrustZone is not a blanket
whole-system isolation guarantee. Do not change device security options
without a verified recovery procedure. The build below is the non-TZ product.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv8m.main-none-eabihf --bin stm32u575_usb_fido \
  --features usb-ccid,internal-uart,hal-time,hardware-sha256,flash-managed-keys,physical-up
```

The ELF is written to `target/thumbv8m.main-none-eabihf/release/stm32u575_usb_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use USER when the green LED lights. Do not press RESET.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
