# nRF52840

## Scope

Seeed Studio XIAO nRF52840.

USB HID, CCID, BLE and Internal UART; ES256, experimental ML-DSA, managed keys, task separation and MPU products. CryptoCell SHA-256/P-256 providers are optional. NFC is not included in this source release.

## External inputs and device images

Cargo downloads the locked Rust dependencies and SoftDevice bindings; bindings
are not the SoftDevice firmware image.

BLE products require Nordic S140 **7.3.0** on the device. Obtain
`s140_nrf52_7.3.0_softdevice.hex` from the
[Nordic S140 downloads](https://www.nordicsemi.com/Products/Development-software/s140/download?lang=en).
The expected SHA-256 is
`5f460d35efcb4ab0f280e83cd15f804e979172a3646c5b66e86af6b7b2975ba6`.
For a downloaded file in the current directory, verify it with:

```sh
printf '%s  %s\n' \
  5f460d35efcb4ab0f280e83cd15f804e979172a3646c5b66e86af6b7b2975ba6 \
  s140_nrf52_7.3.0_softdevice.hex | sha256sum --check
```

An application-only ELF does not include S140 or the XIAO bootloader.
The default layout starts the application at `0x27000`; use a bootloader and
controller image compatible with that layout. Do not mass-erase an existing
bootloader or flash a combined image without a verified recovery method.
Compiling a USB-only application does not itself require downloading S140,
but its selected layout and boot path must still match the device.

The optional `nrf-cryptocell-p256` feature additionally requires
[nRF5 SDK 17.1.0](https://www.nordicsemi.com/Products/Development-software/nrf5-sdk/download)
and GNU Arm Embedded tools (`arm-none-eabi-gcc` and `arm-none-eabi-ar`).
Extract the SDK and set:

```sh
export NRF5_SDK_ROOT=/absolute/path/to/nRF5_SDK_17.1.0_ddde560
```

The build expects `external/nrf_cc310/include/crys_ecpki_kg.h` and
`external/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a`.
Add `nrf-cryptocell-p256` to the chosen build's feature list.
This SDK is not required by the software P-256 example above. It is also not a
substitute for separately selecting the required S140 version.
The SDK and controller retain Nordic's original license conditions.

## Boundaries

Direct and dual-task configurations share memory unless MPU protection is
selected. The `nrf52840_mpu_internal` product separates transport frontends
from privileged protocol/key/storage services using the shared MPU interface.

Select `nrf-mpu-product`; `nrf-ble-mpu-product` adds the BLE integration.
MPU products support UART, USB HID, CCID and BLE configurations.
SoftDevice/controller services remain part of the privileged integration;
the radio controller is not an independently isolated untrusted process.
CPU MPU permissions do not imply complete DMA or interrupt isolation.
The build example below selects the ordinary, non-MPU product.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv7em-none-eabihf --bin nrf52840_internal_usb_fido \
  --features nrf-internal-uart,client-pin-flash-storage,nrf-flash-storage,nrf-flash-managed-keys,up-always-present
```

The ELF is written to `target/thumbv7em-none-eabihf/release/nrf52840_internal_usb_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

This example uses automatic presence for development only. It does not require
physical user consent and must not be treated as a production presence policy.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
