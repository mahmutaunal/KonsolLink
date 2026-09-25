#!/usr/bin/env bash
set -euo pipefail
umask 022

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly ROOT
readonly ARCH=${ARCH:-${1:-$(uname -m)}}
readonly GATEWAY=${GATEWAY_BIN:-$ROOT/target/m4/linux/$ARCH/go-pcap2socks}
readonly TPWS=${TPWS_BIN:-$ROOT/target/m4/linux/$ARCH/tpws}
readonly GATEWAY_SOURCE=${GATEWAY_SOURCE:-$ROOT/target/m4/go-pcap2socks}
readonly ZAPRET_SOURCE=${ZAPRET_SOURCE:-$ROOT/target/m4/zapret}
readonly OUT="$ROOT/target/m4/KonsolLink-1.0.0-linux-$ARCH"

[[ -f $GATEWAY && -x $GATEWAY ]] || { echo "Missing executable gateway: $GATEWAY" >&2; exit 1; }
[[ -f $TPWS && -x $TPWS ]] || { echo "Missing executable tpws: $TPWS" >&2; exit 1; }
[[ -d $GATEWAY_SOURCE/.git ]] || { echo "Missing pinned gateway source: $GATEWAY_SOURCE" >&2; exit 1; }
[[ $(git -C "$GATEWAY_SOURCE" rev-parse HEAD) == ec40773869e835bd09cb134e638e4e3333d89e0c ]] || { echo 'Gateway source commit mismatch.' >&2; exit 1; }
[[ -f $ZAPRET_SOURCE/docs/LICENSE.txt ]] || { echo "Missing zapret license: $ZAPRET_SOURCE" >&2; exit 1; }
rm -rf "$OUT"
install -d "$OUT"
install -m 0555 "$GATEWAY" "$OUT/go-pcap2socks"
install -m 0555 "$TPWS" "$OUT/tpws"
install -m 0555 "$ROOT/platform/linux/konsollink-runtime.sh" "$OUT/konsollink-runtime"
install -m 0555 "$ROOT/platform/linux/install.sh" "$OUT/install.sh"
install -m 0444 "$ROOT/platform/linux/konsollink.service" "$OUT/konsollink.service"
install -m 0444 "$ROOT/platform/linux/49-konsollink.rules" "$OUT/49-konsollink.rules"
install -m 0444 "$ROOT/services/discord/hosts.txt" "$OUT/discord-hosts.txt"
install -m 0444 "$ROOT/engines/gateway.json" "$OUT/gateway.json"
install -m 0444 "$ROOT/engines/go-pcap2socks-ec407738-konsollink.patch" "$OUT/go-pcap2socks-ec407738-konsollink.patch"
install -m 0444 "$ROOT/engines/go-pcap2socks-LICENSE" "$OUT/go-pcap2socks-LICENSE"
install -m 0444 "$ZAPRET_SOURCE/docs/LICENSE.txt" "$OUT/zapret-LICENSE"
install -m 0444 "$ROOT/THIRD_PARTY_NOTICES.md" "$OUT/THIRD_PARTY_NOTICES.md"
git -C "$GATEWAY_SOURCE" archive --format=tar.gz --output="$OUT/go-pcap2socks-ec407738-source.tar.gz" HEAD
(cd "$OUT" && sha256sum discord-hosts.txt gateway.json go-pcap2socks tpws > runtime.sha256)
tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")"
shasum -a 256 "$OUT.tar.gz"
