#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
grep -Fq 'KillMode=control-group' "$ROOT/platform/linux/konsollink.service"
grep -Fq 'Restart=no' "$ROOT/platform/linux/konsollink.service"
grep -Fq 'subject.local && subject.active' "$ROOT/platform/linux/49-konsollink.rules"
grep -Fq 'wait -n' "$ROOT/platform/linux/konsollink-runtime.sh"
grep -Fq 'sha256sum --strict --check' "$ROOT/platform/linux/konsollink-runtime.sh"
if grep -Eq 'iptables|nft|sysctl|ip_forward|masquerade' "$ROOT/platform/linux/konsollink-runtime.sh"; then
  echo 'Linux runtime unexpectedly mutates kernel routing/firewall state.' >&2
  exit 1
fi
echo 'Linux M4 runtime policy: OK'
