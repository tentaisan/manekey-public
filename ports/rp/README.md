# Raspberry Pi RP

## Scope

Targets: Pico and Pico W (RP2040 Arm), Pico 2 and Pico 2 W
(RP2350 Arm or RISC-V). Wireless transports apply only to W boards.

USB HID, CCID, Internal UART and BLE share the common protocol.
ES256, managed keys, persistent PIN and experimental ML-DSA backends are available.
Task/core configurations, RP2040 MPU, RP2350 PMP and paired Arm TrustZone images
have distinct feature and memory requirements. TrustZone core1 splitting is not
provided by the current integration.

## Boundary configurations

| Target | Model | Frontend transports |
| --- | --- | --- |
| RP2040 | Direct, task/core separation | USB HID, CCID, UART; BLE on Pico W |
| RP2040 | MPU | USB HID, CCID, UART; BLE on Pico W |
| RP2350 RISC-V | Direct, task/core separation | USB HID, CCID, UART; BLE on Pico 2 W |
| RP2350 RISC-V | PMP | USB HID, CCID, UART; a separate radio frontend on Pico 2 W |
| RP2350 Arm | Direct, task/core separation | USB HID, CCID, UART; BLE on Pico 2 W |
| RP2350 Arm | TrustZone | Non-Secure USB HID, CCID and UART; BLE on Pico 2 W |

In protected configurations, frontends exchange requests with the trusted
protocol/key/storage service. Peripheral services and ownership remain
port-specific; the table is not a guarantee of arbitrary DMA or IRQ isolation.
Task/core separation alone does not prevent memory access between components.

MPU uses `rp2040-mpu-product` (optionally `rp2040-mpu-ble`).
The PMP example below selects a protected service plus UART/USB frontends.
Arm TrustZone uses separate `tz-secure` and Non-Secure binaries with matching
layouts. TrustZone core1 splitting is not included.
The ordinary USB/BLE examples below are not MPU or TrustZone builds.

## GitHub builds and trial images

The product workflow builds ordinary, non-wireless Pico and Pico 2 Arm firmware
with ES256, managed keys, BOOTSEL presence and the green LED.
Linux UHID and WASM have build-only checks. Other build-only jobs cover selected
RA4M1, STM32, CH32, Nordic, ESP and wireless RP configurations, including selected
MPU products. Their images are not uploaded or added to Releases.
It does not build every boundary or ML-DSA variant.

- Pushes to main and pull requests perform build checks.
- Manual runs can also build separate initialization images.
- Version tags such as `v0.1.0` or `v0.1.0-rc.1` can create a Draft Release
  after all build jobs succeed. RC tags are marked as pre-releases.
- Artifact and Release upload remain disabled until the repository variable
  per-board `MANEKEY_PICO_BINARY_RELEASE_APPROVED` or
  `MANEKEY_PICO2_BINARY_RELEASE_APPROVED` is set to `true` following distribution review.
  That variable is an operator gate, not a license grant or automated audit.

Packages contain UF2, checksums, build selectors, usage notes and project license
files, original dependency legal notices and matching project/dependency source
archives. Packaging retrieves missing upstream license texts from fixed revisions
and verifies their SHA-256; it requires Python 3.11 or newer and network access.
Use a clean committed source tree so the source archive matches the build.
The Pico-only gate `MANEKEY_PICO_BINARY_RELEASE_APPROVED` does not authorize other
boards or host products. A manual run with both `include_initialization` and
`pico_draft` can create a separate `pico-v0.1.0-rc.1` draft prerelease.
For Pico 2 Arm, use `pico2_draft` instead and its per-board gate. Do not request
both board drafts in the same manual run.
Publishing a Draft Release remains a manual action; existing tags/assets are
not automatically overwritten.

For a compatible, already provisioned board:

1. Download the package for the exact board (Pico is not Pico 2 or a W board).
2. Verify the archive checksum and the UF2 checksum inside the package.
3. Hold BOOTSEL while connecting USB, then copy the UF2 to the mounted boot drive.
4. After restart, use a FIDO2/WebAuthn client over USB HID. Press BOOTSEL when the
   green LED indicates a pending presence request. Use only disposable test credentials.

A runtime image refuses to initialize a missing managed root. An explicit
`initialize` image is for deliberately provisioning empty credential storage
and generates the root on the device, not in CI. Once initialized, install the
`runtime` image. This is not a factory-reset image and does not bypass corrupt
or incompatible storage. Do not erase keys to make an incompatible image boot.

To build the same packages locally, install the toolchain, `flip-link` 0.1.11
and the pinned converter used in the workflow, then run from the project root:

```sh
cargo +1.98.1 install elf2uf2-rs --git https://github.com/JoNil/elf2uf2-rs.git --rev f14bf2d981772cd9fbe5bac33b685719caac1add --locked
bash scripts/build-rp-release.sh pico runtime
bash scripts/build-rp-release.sh pico2 runtime
# Explicit empty-device provisioning only:
bash scripts/build-rp-release.sh pico initialize
```

Packages are written to `dist/`. These examples do not flash a connected board
or change OTP/security configuration.

## Experimental ML-DSA-44 images

Non-wireless Pico and Pico 2 Arm have separate USB HID trial images with ES256 and
ML-DSA-44 using the vendored mldsa-native backend. It uses BOOTSEL and the green
LED, not automatic presence. Install GNU Arm GCC in addition to the tools above.

```sh
bash scripts/build-rp-release.sh pico runtime-mldsa44
# Explicit empty-device provisioning only:
bash scripts/build-rp-release.sh pico initialize-mldsa44
bash scripts/build-rp-release.sh pico2 runtime-mldsa44
bash scripts/build-rp-release.sh pico2 initialize-mldsa44
```

The runtime image is
`dist/manekey-pico-runtime-mldsa44/manekey-pico-runtime-mldsa44.uf2`.
For Pico 2 Arm, replace `pico` with `pico2` in that path.
It uses the same managed-key storage layout; changing firmware is not a reset.
These variants target non-wireless Pico and Pico 2 Arm. CI builds them, but uploads remain
subject to the distribution gate. This is an experimental algorithm option,
not a claim of certified FIDO or general browser compatibility.

On a WebAuthn test site that offers ML-DSA-44, select only that algorithm when
registering a disposable test account so ES256 cannot be selected instead.
Confirm the registered algorithm is ML-DSA-44 (COSE -48), then test login.
Use the browser's USB security-key option and press BOOTSEL when the LED lights.
If the browser or server rejects the algorithm, keep that compatibility
limitation separate from the firmware's raw CTAP tests.

## Build

Install Rust 1.98.1, the selected target and `flip-link` for Arm builds.
Native ML-DSA requires a compatible C compiler. Run from this directory.

Example: Pico 2 RISC-V PMP, UART/HID/CCID and native ML-DSA:

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target riscv32imac-unknown-none-elf --bin riscv-pmp-fido \
  --features riscv-pmp-usb-internal-ccid,riscv-flash-managed-keys,experimental-ml-dsa-mldsa-native,riscv-pmp-board-ui-experimental
```

Example: Pico Arm USB HID with managed keys:

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv6m-none-eabi --bin manekey \
  --features chip-rp2040,key-storage-flash,pin-storage-flash,rp-flash-managed-keys,up-bootsel-experimental,board-ui-experimental
```

ELFs are written to `target/<target>/release/<binary>`, unless
`CARGO_TARGET_DIR` is set. Arm RP2350 uses `thumbv8m.main-none-eabihf`.
TrustZone requires matching Secure and Non-Secure images, not just one ELF.

## Pico W and Pico 2 W: USB + BLE

Obtain the fixed upstream NVRAM file explicitly, then export its absolute path.
Run these commands from this directory:

```sh
curl --fail --location \
  https://raw.githubusercontent.com/embassy-rs/embassy/0af1937a5ac77f52fea943b677088c38ef9e91c6/cyw43-firmware/nvram_rp2040.bin \
  --output /tmp/manekey-cyw43-nvram.bin
printf '%s  %s\n' \
  4904bdbb0c937bd0ac2eb2a1d62f2da4dd90e32082384e02874e8d671b0f330d \
  /tmp/manekey-cyw43-nvram.bin | sha256sum --check
export MANEKEY_CYW43_NVRAM_FILE=/tmp/manekey-cyw43-nvram.bin
```

The build also verifies the 742-byte file and its checksum before including it.
Cargo does not fetch this NVRAM file automatically.

Pico W (RP2040 Arm), USB HID + BLE, persistent PIN and managed keys:

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv6m-none-eabi --bin pico-w-multi-transport-fido \
  --features pico-w-multi-transport-board-ui-security-fido,rp-flash-managed-keys
```

Pico 2 W (RP2350 Arm), USB HID + BLE with the same presence policy:

```sh
cargo +1.98.1 build --release --locked --no-default-features \
  --target thumbv8m.main-none-eabihf --bin pico-2-w-multi-transport-fido \
  --features pico-2-w-multi-transport-board-ui-fido,pico-ble-bond-flash,rp2350-flash-managed-keys
```

Both examples use BOOTSEL and the green onboard LED, not automatic presence.
The generated ELF follows the output path described above. Building does not
flash the board or provision its managed-key root.

These commands describe local builds. Permission to distribute a generated
image containing CYW43 firmware, CLM and NVRAM must be assessed separately under
the applicable vendor terms. See NOTICE; the source license is not a substitute
for those terms.

Wireless builds require an explicitly supplied `MANEKEY_CYW43_NVRAM_FILE`.
See NOTICE for the fixed upstream URL and checksum; Cargo does not download it.
Vendor firmware redistribution conditions remain separate.

These examples use BOOTSEL for presence and the green onboard LED as the
pending-request indicator. Press BOOTSEL when indicated and release it after
confirmation. Automatic presence is not enabled.
Managed-key setup is an explicit provisioning operation. Do not enable setup
features on devices whose state must be retained. See Cargo.toml for selectors
and local LICENSE/NOTICE files for licensing.
