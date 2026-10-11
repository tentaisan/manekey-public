# ManeKey

ManeKey is an experimental Rust authentication and cryptography foundation.
FIDO is its first application. A shared protocol implementation is composed with
platform-specific transports, cryptographic providers, storage and security boundaries.

ManeKey is an experimental implementation for learning about and evaluating
authentication, cryptography, and isolation mechanisms, including their
limitations and failure modes. It does not guarantee security and is not
intended to protect production credentials. It is not a certified authenticator.
Available features depend on the selected board, backend and memory layout.
Long-duration, high-load and power-loss qualification is not implied.

## Security boundaries

Transport-facing frontends handle communication; trusted services handle
authentication state, key operations, cryptography and persistent storage.
The selected port determines how these roles are connected and protected.

Direct calls, separate tasks and separate cores are composition models, not
memory-protection guarantees. Selected ports also provide experimental
MPU, PMP or TrustZone configurations. Their transport support and protection
scope differ; consult the port README.

A CPU memory boundary does not automatically isolate DMA, interrupts, radio
controllers or other peripherals. Presence checks and key-storage policies
remain separate requirements. These implementations are for evaluation, not
a claim of complete system isolation.

## Layout

- [src](src/README.md): shared protocol, transport, frontend and boundary code.
- `crates/`: reusable boundary, interconnect, peripheral and cryptographic components.
- `ports/`: board integration, hardware access and firmware memory layouts.

## Implementations

| Port | Target |
| --- | --- |
| [RP](ports/rp/README.md) | Pico, Pico W, Pico 2 and Pico 2 W |
| [ESP32](ports/esp32/README.md) | NodeMCU-32S |
| [ESP32-C3](ports/esp32c3/README.md) | XIAO ESP32-C3 |
| [ESP32-C5](ports/esp32c5/README.md) | ESP32-C5 |
| [ESP32-C6](ports/esp32c6/README.md) | XIAO ESP32-C6 |
| [ESP32-S2](ports/esp32s2/README.md) | ESP32-S2 |
| [ESP32-S3](ports/esp32s3/README.md) | ESP32-S3 |
| [nRF52840](ports/nrf52840/README.md) | XIAO nRF52840 |
| [nRF54L15](ports/nrf54l15/README.md) | XIAO nRF54L15 |
| [RA4M1](ports/ra4m1/README.md) | XIAO RA4M1 and Arduino Nano R4 |
| [STM32F411](ports/stm32f411/README.md) | NUCLEO-F411RE |
| [STM32U575](ports/stm32u575/README.md) | NUCLEO-U575ZI-Q |
| [CH32V203](ports/ch32v203/README.md) | CH32V203 |
| [Linux UHID](ports/linux-uhid/README.md) | Linux |
| [WASM](ports/wasm/README.md) | WebAssembly |

`ports/esp-common`, `ports/stm32-common`, `ports/rp2040` and `ports/rp2350`
provide shared integration or linker inputs; they are not standalone products.

## GitHub builds

The product workflow checks selected ordinary and boundary configurations.
Build-only jobs cover RA4M1 (XIAO/Nano R4), STM32F411/U575, CH32V203,
nRF52840/nRF54L15, RP wireless boards and the ESP32/C3/C5/C6/S2/S3 ports.
Selected MPU/PMP variants are included; this is not an exhaustive feature matrix.
Distributed binary packages are limited to non-wireless Pico and Pico 2 Arm.
Other product sources and their build checks remain available; their binaries
are not uploaded or attached to Releases.
Other configured boards are build-only checks, not downloadable release images.
Uploads require explicit distribution approval; version tags create Draft
Releases for manual review rather than publishing automatically.
See [RP trial images](ports/rp/README.md#github-builds-and-trial-images) and the
host port READMEs for usage and limitations.

## Licensing

Original shared code uses Apache-2.0; original port code uses AGPL-3.0-only.
See the applicable Cargo manifests, LICENSE files and NOTICE files.
Third-party code retains its own terms. The Nordic linking exception is limited
to its specified materials. Source availability does not grant unrestricted
redistribution of vendor firmware or generated binaries.
