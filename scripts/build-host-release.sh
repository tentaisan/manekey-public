#!/usr/bin/env bash
set -euo pipefail

product="${1:?usage: build-host-release.sh linux-uhid|wasm}"
case "$product" in
  linux-uhid) target=x86_64-unknown-linux-gnu; artifact=uhid-fido ;;
  wasm) target=wasm32-unknown-unknown; artifact=manekey_wasm.wasm ;;
  *) echo "Unsupported product: $product" >&2; exit 2 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/release-products}"
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=."
cargo "+${MANEKEY_RUST_TOOLCHAIN:-1.98.1}" build \
  --manifest-path "$root/ports/$product/Cargo.toml" --release --locked --target "$target"
package="$root/dist/manekey-$product"
mkdir -p "$package"
cp "$CARGO_TARGET_DIR/$target/release/$artifact" "$package/"
if [[ "$product" == wasm ]]; then
  cp "$root/ports/wasm/src/browser.mjs" "$package/"
fi
cp "$root/ports/$product/LICENSE-AGPL-3.0" "$package/"
if [[ -f "$root/ports/$product/NOTICE" ]]; then
  cp "$root/ports/$product/NOTICE" "$package/NOTICE-PORT"
fi
cp "$root/LICENSE-APACHE-2.0" "$root/LICENSE-MIT" "$root/NOTICE" "$package/"
printf 'product=%s\ntarget=%s\nrust=%s\n' "$product" "$target" \
  "${MANEKEY_RUST_TOOLCHAIN:-1.98.1}" > "$package/BUILD"
printf '%s\n' \
  'Experimental software; no security guarantee. Use only disposable credentials.' \
  'Linux: x86_64 GNU/Linux build. CI uses Ubuntu 24.04; check libc compatibility.' \
  'Run uhid-fido STORAGE_DIRECTORY [UHID_PATH]; default /dev/uhid.' \
  'WASM: load the module through browser.mjs and supply explicit presence/storage callbacks.' \
  'Neither package contains provisioned credentials or a device root.' \
  'See the matching product README and applicable licenses.' > "$package/USAGE"
(cd "$package" && sha256sum "./$artifact" > SHA256SUMS)
if [[ "$product" == wasm ]]; then
  (cd "$package" && sha256sum ./browser.mjs >> SHA256SUMS)
fi
tar -C "$root/dist" -czf "$root/dist/manekey-$product.tar.gz" "manekey-$product"
