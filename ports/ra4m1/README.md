# RA4M1

## Scope

Seeed Studio XIAO RA4M1 and Arduino Nano R4.

USB HID, CCID and Internal UART; ES256, persistent PIN, managed keys, task separation and MPU products. SCE5 AES and hardware-wrapped key integration are optional. ML-DSA product integration is not supported within the current memory budget.

## External inputs

Cargo obtains the locked HAL and Rust dependencies. The selected Renesas SCE5
source subset is included under `vendor/renesas-sce5`; a separate full FSP SDK
download is not required by this build.

Enabling `sce5-runtime`, `sce5-aes` or hardware-wrapped key features requires
`arm-none-eabi-gcc` and the compiler's accompanying binutils on PATH.
See Cargo.toml for the feature dependencies and vendor licenses for the included
source. The firmware ELF does not include a replacement board bootloader.

## Boundaries

The ordinary product supports Direct or dual-task execution.
Separate tasks are not memory-protection boundaries.

The `ra4m1_mpu_internal` product uses MPU-restricted frontends and privileged
protocol/key/storage services. Select `mpu-internal`, with `mpu-usb-hid` and
`mpu-usb-ccid` for the corresponding USB frontends; UART is also supported.
The configured CPU MPU regions do not establish general DMA/IRQ isolation.
The ordinary build below is not an MPU build.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv7em-none-eabihf --bin ra4m1_usb_fido \
  --features board-xiao,small-message-buffers,fido-product,internal-uart,flash-managed-keys,physical-up
```

The ELF is written to `target/thumbv7em-none-eabihf/release/ra4m1_usb_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

For Nano R4, replace `board-xiao` with `board-nano-r4`; select exactly one board.

On XIAO, use BOOT when the USER LED lights. Nano R4 instead uses its GPIO presence input.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
