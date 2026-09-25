#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ACTION=${1:-install}
readonly PACKAGE=${2:-$(cd -- "$(dirname -- "$0")" && pwd -P)}
readonly ROOT=/opt/konsollink
[[ $EUID -eq 0 ]] || { echo 'Installer must run as root.' >&2; exit 1; }

if [[ $ACTION == uninstall ]]; then
  systemctl stop konsollink.service 2>/dev/null || true
  systemctl disable konsollink.service 2>/dev/null || true
  rm -f /etc/systemd/system/konsollink.service /etc/polkit-1/rules.d/49-konsollink.rules
  rm -rf "$ROOT"
  systemctl daemon-reload
  exit 0
fi
[[ $ACTION == install ]] || { echo 'Usage: install.sh [install|uninstall] [package-root]' >&2; exit 2; }

for file in runtime.sha256 discord-hosts.txt gateway.json go-pcap2socks tpws konsollink-runtime konsollink.service 49-konsollink.rules; do
  [[ -f $PACKAGE/$file && ! -L $PACKAGE/$file ]] || { echo "Missing package file: $file" >&2; exit 1; }
done
(cd "$PACKAGE" && sha256sum --strict --check runtime.sha256)
systemctl stop konsollink.service 2>/dev/null || true
install -d -o root -g root -m 0755 "$ROOT"
install -o root -g root -m 0555 "$PACKAGE/konsollink-runtime" "$ROOT/konsollink-runtime"
install -o root -g root -m 0555 "$PACKAGE/go-pcap2socks" "$ROOT/go-pcap2socks"
install -o root -g root -m 0555 "$PACKAGE/tpws" "$ROOT/tpws"
install -o root -g root -m 0444 "$PACKAGE/discord-hosts.txt" "$ROOT/discord-hosts.txt"
install -o root -g root -m 0444 "$PACKAGE/gateway.json" "$ROOT/gateway.json"
install -o root -g root -m 0444 "$PACKAGE/runtime.sha256" "$ROOT/runtime.sha256"
install -o root -g root -m 0644 "$PACKAGE/konsollink.service" /etc/systemd/system/konsollink.service
install -o root -g root -m 0644 "$PACKAGE/49-konsollink.rules" /etc/polkit-1/rules.d/49-konsollink.rules
systemctl daemon-reload
systemctl disable konsollink.service >/dev/null 2>&1 || true
echo 'KonsolLink installed as an on-demand systemd service.'
