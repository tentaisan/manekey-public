# nRF54L15

## Scope

Seeed Studio XIAO nRF54L15.

BLE and Internal UART; ES256, experimental ML-DSA, managed keys and task separation. CRACEN providers and KMU integration are optional. TrustZone products use BLE-less UART; BLE security-domain isolation remains limited by the controller integration. SAMD11 USB bridge firmware is not provided here.

## External inputs

Cargo obtains the locked MPSL/SDC bindings and controller libraries from their
declared dependencies. This port does not require a separate S140 image or
`NRF5_SDK_ROOT`; those belong to the nRF52840 integration.

CRACEN and controller binding builds require host Clang/libclang and an Arm C
compiler. Select host libclang rather than an unrelated cross-toolchain LLVM.
The `flash-managed-keys` feature also enables the CRACEN P-256 integration.

The optional `cracen-p256-experimental` feature compiles
`src/cracen_microcode.c` with the included
`vendor/nordic-cracen/microcode_binary.h`. It requires a compatible Arm C
compiler. No additional manual microcode download is required.
Vendor libraries and microcode retain their Nordic conditions; see NOTICE and
the designated-component linking exception.

Native ML-DSA uses the included C snapshot and requires an Arm C compiler.
TrustZone configurations require both matching Secure and Non-Secure images.
The onboard SAMD11 firmware is separate and is not built or replaced by these
commands.

## Boundaries

The BLE product supports Direct and dual-task execution. Task separation is not
hardware memory isolation.

The BLE-less TrustZone product pairs `nrf54l15_tz_uart_secure_product` with
`nrf54l15_tz_uart_nonsecure_product`: the UART frontend runs Non-Secure while
protocol/key/storage and selected cryptographic services run Secure.
Both images must use compatible layouts and gateway configuration.

This does not provide a Non-Secure BLE frontend with fully Secure MPSL/SDC and
radio cryptography; that controller integration remains unsupported.
Peripheral/DMA/IRQ protection is specific to the selected TrustZone layout.
The BLE build example below is not the TrustZone product.

## Build

Run from this directory so Cargo reads its local linker configuration.
Install Rust 1.98.1 and the target shown below. Builds using build-std require rust-src and a compatible nightly toolchain.
Native C-backed crypto features additionally require a compatible C compiler.

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv8m.main-none-eabihf --bin nrf54l15_ble_fido \
  --features runtime,ble,ble-security,ble-notify-pacing,standalone-critical-section,flash-managed-keys
```

The ELF is written to `target/thumbv8m.main-none-eabihf/release/nrf54l15_ble_fido`,
or the corresponding directory under `CARGO_TARGET_DIR`.

Use B/User Key for presence when the green USER LED lights. Do not press RESET.

Managed-key initialization is a separate, explicit provisioning operation.
Do not enable setup features on a device whose stored state must be preserved.
Available features are listed in `Cargo.toml`; not every combination fits memory
or establishes an isolation boundary. See local LICENSE and NOTICE files.
