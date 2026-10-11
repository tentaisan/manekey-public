#!/usr/bin/env bash
set -euo pipefail

board="${1:?usage: build-rp-release.sh pico|pico2 runtime|initialize|runtime-mldsa44|initialize-mldsa44}"
variant="${2:-runtime}"
case "$board" in
  pico)
    target=thumbv6m-none-eabi
    family=rp2040
    chip=chip-rp2040
    managed=rp-flash-managed-keys
    setup=rp2040-flash-managed-key-setup
    ;;
  pico2)
    target=thumbv8m.main-none-eabihf
    family=rp2350-arm-s
    chip=chip-rp235xa
    managed=rp2350-flash-managed-keys
    setup=rp2350-flash-managed-key-setup
    ;;
  *) echo "Unsupported board: $board" >&2; exit 2 ;;
esac
algorithm=es256
backend=software
crypto_features=
case "$variant" in
  runtime) ;;
  initialize) managed="$managed,$setup" ;;
  runtime-mldsa44|initialize-mldsa44)
    algorithm=es256+mldsa44
    backend=mldsa-native
    if [[ "$board" == pico ]]; then
      crypto_features=,rp2040-ml-dsa-fips204-experimental,experimental-ml-dsa-mldsa-native
    else
      crypto_features=,rp2350-ml-dsa-fips204-experimental,experimental-ml-dsa-mldsa-native
    fi
    if [[ "$variant" == initialize-mldsa44 ]]; then managed="$managed,$setup"; fi
    ;;
  *) echo "Unsupported variant: $variant" >&2; exit 2 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
features="$chip,key-storage-flash,pin-storage-flash,$managed,up-bootsel-experimental,board-ui-experimental$crypto_features"
toolchain="${MANEKEY_RUST_TOOLCHAIN:-1.98.1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/release-products}"
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$(cd "$CARGO_TARGET_DIR" && pwd)"
cd "$root/ports/rp"
cargo "+$toolchain" build --release --locked --no-default-features \
  --target "$target" --bin manekey --features "$features"
package="$root/dist/manekey-$board-$variant"
mkdir -p "$package"
elf2uf2-rs convert --family "$family" \
  "$CARGO_TARGET_DIR/$target/release/manekey" "$package/manekey-$board-$variant.uf2"
cp "$root/ports/rp/LICENSE-AGPL-3.0" "$package/"
cp "$root/ports/rp/LICENSE-LEGACY-APACHE-2.0" "$package/"
cp "$root/ports/rp/LICENSE-LEGACY-MIT" "$package/"
cp "$root/ports/rp/NOTICE" "$package/NOTICE-RP"
cp "$root/LICENSE-APACHE-2.0" "$root/LICENSE-MIT" "$root/NOTICE" "$package/"
if [[ "$backend" == mldsa-native ]]; then
  cp "$root/crates/crypto/mldsa-native/NOTICE" "$package/NOTICE-MLDSA-NATIVE"
  cp "$root/crates/crypto/mldsa-native/upstream/LICENSE" "$package/LICENSE-MLDSA-NATIVE"
fi
printf 'board=%s\nvariant=%s\ntarget=%s\ntoolchain=%s\nfeatures=%s\nalgorithms=%s\nbackend=%s\n' \
  "$board" "$variant" "$target" "$toolchain" "$features" "$algorithm" "$backend" > "$package/BUILD"
printf '%s\n' \
  'Experimental firmware; no security guarantee.' \
  'Use only on the named non-wireless board. BOOTSEL confirms presence; the green LED indicates a request.' \
  'Runtime images require an existing compatible managed root.' \
  'Initialization images are only for deliberately provisioning empty credential storage.' \
  'No keys, PIN or device root are embedded in this package.' \
  'Never mass-erase a device merely to run this firmware.' \
  'See the source release RP README and applicable licenses.' > "$package/USAGE"
python3 "$root/scripts/package-rp-source.py" "$package" "$target" "$features" "$toolchain"
(cd "$package" && sha256sum ./*.uf2 ./*source.tar.gz > SHA256SUMS)
tar -C "$root/dist" -czf "$root/dist/manekey-$board-$variant.tar.gz" "manekey-$board-$variant"
