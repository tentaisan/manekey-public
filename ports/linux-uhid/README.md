# Linux UHID

A Linux userspace FIDO implementation using the kernel UHID interface.
The product provides ES256, OS entropy, persistent storage and explicit presence
handling. Kernel device access and application presence policy must be configured
by the operator; this is not a hardware-isolated authenticator.

## Boundaries

Transport and authentication services run inside one userspace process.
Linux process protection does not isolate those components from each other.
File permissions and explicit presence policy are host responsibilities;
this port does not create an MPU/PMP/TrustZone boundary.

## Local package

GitHub checks this product build but does not upload its binary or include it
in Releases. Binary distribution is limited to Pico and Pico 2 firmware.
From the project root, run:

```sh
bash scripts/build-host-release.sh linux-uhid
```

The package is `dist/manekey-linux-uhid.tar.gz` and contains the product artifact,
checksums, usage notes and project license files. Before distributing a local
package, satisfy all applicable dependency license/source obligations.

## Build

Install Rust 1.98.1. Run from this directory:

```sh
cargo +1.98.1 build --release --locked --target x86_64-unknown-linux-gnu --bin uhid-fido
```

Output: `target/x86_64-unknown-linux-gnu/release/uhid-fido`, or the corresponding
`CARGO_TARGET_DIR` path. Run `uhid-fido STORAGE_DIRECTORY [UHID_PATH]`;
the default device is `/dev/uhid`.
Access to `/dev/uhid` is required. See local LICENSE and NOTICE files.
