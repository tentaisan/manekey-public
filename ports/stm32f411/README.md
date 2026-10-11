# STM32F411

## Scope

ST NUCLEO-F411RE.

USB HID, CCID and Internal UART; ES256, experimental ML-DSA, managed keys, task separation and MPU products. ADC/LSI entropy is experimental, not a certified random-number source.

## Boundaries

The ordinary product supports Direct and dual-task execution.
The `stm32f411_mpu_internal` product separates UART/USB frontends from
privileged protocol/key/storage services through the common MPU interface.

Select `mpu-layout`, adding `mpu-usb-hid` and `mpu-usb-ccid` for USB.
ML-DSA backends are selectable subject to the protected layout's memory budget.
CPU MPU protection is not a general DMA or interrupt isolation guarantee.
The ordinary build below uses `product-layout`, not `mpu-layout`.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv7em-none-eabihf --bin stm32f411_usb_fido \
  --features product-layout,experimental-adc-lsi-entropy,usb-ccid,flash-managed-keys,physical-up
```

The ELF is written to `target/thumbv7em-none-eabihf/release/stm32f411_usb_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use USER (B1) when the green LD2 LED lights. Do not press RESET.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
