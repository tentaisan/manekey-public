# WebAssembly

A browser-oriented FIDO backend compiled to WebAssembly.
The JavaScript runtime adapter in `src/browser.mjs` supplies Web Crypto entropy,
storage integration and explicit presence callbacks. It is not a USB device
or a replacement for a browser's native WebAuthn authenticator integration.

## Boundaries

The WebAssembly runtime boundary separates the module from its host, but does
not isolate transport, protocol and key services within ManeKey.
Entropy, persistence and presence callbacks are supplied by the host
application. A browser sandbox does not make a compromised host trustworthy.

## Local package

GitHub checks this product build but does not upload its binary or include it
in Releases. Binary distribution is limited to Pico and Pico 2 firmware.
From the project root, run:

```sh
bash scripts/build-host-release.sh wasm
```

The package is `dist/manekey-wasm.tar.gz` and contains the product artifact,
checksums, usage notes and project license files. Before distributing a local
package, satisfy all applicable dependency license/source obligations.

## Build

Install Rust 1.98.1 and the WebAssembly target. Run from this directory:

```sh
rustup target add wasm32-unknown-unknown --toolchain 1.98.1
cargo +1.98.1 build --release --locked --target wasm32-unknown-unknown
```

Output: `target/wasm32-unknown-unknown/release/manekey_wasm.wasm`, or the
corresponding `CARGO_TARGET_DIR` path. Load it with `src/browser.mjs` and provide
the storage and presence callbacks required by that adapter.
Storage durability and consent depend on the hosting application.
See local LICENSE and NOTICE files.
