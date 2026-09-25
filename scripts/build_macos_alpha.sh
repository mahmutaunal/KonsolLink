#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin
export PATH
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
OUT="$ROOT/target/alpha"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="KonsolLink-1.0.0-rc-macos-arm64-$STAMP"
mkdir -p "$OUT"
STAGE="$(mktemp -d "$OUT/stage.XXXXXX")"
PACKAGE="$STAGE/$NAME"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

cd "$ROOT"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p konsollink-helper
python3 scripts/verify_gateway_policy.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
npm --prefix apps/desktop run build
npm --prefix apps/desktop run tauri build -- --debug --bundles app
/usr/bin/codesign --force --deep --sign - "$ROOT/target/debug/bundle/macos/KonsolLink.app"
/usr/bin/codesign --verify --deep --strict "$ROOT/target/debug/bundle/macos/KonsolLink.app"

mkdir -p "$PACKAGE/target/debug/bundle/macos" "$PACKAGE/target/m2" \
  "$PACKAGE/scripts" "$PACKAGE/engines" "$PACKAGE/docs"
/usr/bin/ditto "$ROOT/target/debug/bundle/macos/KonsolLink.app" \
  "$PACKAGE/target/debug/bundle/macos/KonsolLink.app"
install -m 0755 "$ROOT/target/debug/konsollink-helper" "$PACKAGE/target/debug/konsollink-helper"
install -m 0555 "$ROOT/target/m2/tpws-v72.13" "$PACKAGE/target/m2/tpws-v72.13"
install -m 0555 "$ROOT/target/m2/go-pcap2socks-ec407738-konsollink" \
  "$PACKAGE/target/m2/go-pcap2socks-ec407738-konsollink"
install -m 0755 "$ROOT/scripts/m0-service.sh" "$PACKAGE/scripts/m0-service.sh"
install -m 0755 "$ROOT/scripts/m3_benchmark.py" "$PACKAGE/scripts/m3_benchmark.py"
install -m 0755 "$ROOT/scripts/package_manifest.py" "$PACKAGE/scripts/package_manifest.py"
install -m 0755 "$ROOT/scripts/verify_gateway_policy.py" "$PACKAGE/scripts/verify_gateway_policy.py"
install -m 0644 "$ROOT/engines/gateway-macos.json" "$PACKAGE/engines/gateway-macos.json"
install -m 0644 "$ROOT/engines/go-pcap2socks-LICENSE" "$PACKAGE/engines/go-pcap2socks-LICENSE"
install -m 0644 "$ROOT/engines/go-pcap2socks-ec407738-konsollink.patch" \
  "$PACKAGE/engines/go-pcap2socks-ec407738-konsollink.patch"
install -m 0644 "$ROOT/engines/zapret-tpws-v72.13.toml" "$PACKAGE/engines/zapret-tpws-v72.13.toml"
install -m 0644 "$ROOT/LICENSE" "$PACKAGE/LICENSE"
install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$PACKAGE/THIRD_PARTY_NOTICES.md"
install -m 0644 "$ROOT/docs/M2_ACCEPTANCE_TEST.md" "$PACKAGE/docs/M2_ACCEPTANCE_TEST.md"
install -m 0644 "$ROOT/docs/M3_PERFORMANCE_ALPHA.md" "$PACKAGE/docs/M3_PERFORMANCE_ALPHA.md"
install -m 0755 "$ROOT/KonsolLink M2 Kabul Testi.command" "$PACKAGE/KonsolLink M2 Kabul Testi.command"
install -m 0755 "$ROOT/KonsolLink M3 Performans Testi.command" "$PACKAGE/KonsolLink M3 Performans Testi.command"

python3 "$ROOT/scripts/package_manifest.py" create "$PACKAGE"
python3 "$ROOT/scripts/package_manifest.py" verify "$PACKAGE"
ARCHIVE="$OUT/$NAME.zip"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$PACKAGE" "$ARCHIVE"
printf 'Alpha package: %s\nSHA-256: ' "$ARCHIVE"
/usr/bin/shasum -a 256 "$ARCHIVE" | /usr/bin/awk '{print $1}'
