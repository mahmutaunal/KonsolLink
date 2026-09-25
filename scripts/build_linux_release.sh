#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly ROOT
readonly ARCH=${ARCH:-$(uname -m)}
readonly OUT="$ROOT/target/release-packages/linux"
readonly GATEWAY=${GATEWAY_BIN:-$ROOT/target/m4/linux/$ARCH/go-pcap2socks}
readonly TPWS=${TPWS_BIN:-$ROOT/target/m4/linux/$ARCH/tpws}

rm -rf "$OUT"
mkdir -p "$OUT"
npm --prefix "$ROOT/apps/desktop" ci
npm --prefix "$ROOT/apps/desktop" run tauri build -- --bundles deb --ci -- --locked
ARCH="$ARCH" GATEWAY_BIN="$GATEWAY" TPWS_BIN="$TPWS" \
  GATEWAY_SOURCE="${GATEWAY_SOURCE:-$ROOT/target/m4/go-pcap2socks}" \
  ZAPRET_SOURCE="${ZAPRET_SOURCE:-$ROOT/target/m4/zapret}" \
  "$ROOT/scripts/build_linux_package.sh"

deb=$(find "$ROOT/target/release/bundle/deb" -maxdepth 1 -type f -name '*.deb' -print -quit)
[[ -n $deb ]] || { echo 'Tauri .deb package was not produced.' >&2; exit 1; }
install -m 0644 "$deb" "$OUT/KonsolLink-1.0.0-linux-$ARCH.deb"
install -m 0644 "$ROOT/target/m4/KonsolLink-1.0.0-linux-$ARCH.tar.gz" "$OUT/KonsolLink-1.0.0-linux-$ARCH-runtime.tar.gz"
install -m 0644 "$ROOT/target/release-metadata/konsollink-1.0.0.cdx.json" "$OUT/konsollink-1.0.0.cdx.json"
install -m 0644 "$ROOT/target/release-metadata/LICENSES.md" "$OUT/LICENSES.md"
install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$OUT/THIRD_PARTY_NOTICES.md"
python3 "$ROOT/scripts/make_release_checksums.py" create "$OUT"
python3 "$ROOT/scripts/make_release_checksums.py" verify "$OUT"
