#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT=/opt/konsollink
readonly MANIFEST="$ROOT/runtime.sha256"
readonly HOSTS="$ROOT/discord-hosts.txt"
readonly CONFIG="$ROOT/gateway.json"
readonly TPWS="$ROOT/tpws"
readonly GATEWAY="$ROOT/go-pcap2socks"

die() { printf 'KonsolLink: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'runtime must be started by systemd as root'
[[ -d $ROOT && ! -L $ROOT ]] || die 'unsafe install root'
[[ -f $MANIFEST && ! -L $MANIFEST ]] || die 'runtime manifest missing'

expected=(discord-hosts.txt gateway.json go-pcap2socks tpws)
mapfile -t declared < <(awk 'NF == 2 { sub(/^\*/, "", $2); print $2 }' "$MANIFEST" | LC_ALL=C sort)
[[ ${#declared[@]} -eq ${#expected[@]} ]] || die 'unexpected runtime manifest size'
for index in "${!expected[@]}"; do
  [[ ${declared[$index]} == "${expected[$index]}" ]] || die 'unexpected runtime manifest entry'
done
(cd "$ROOT" && /usr/bin/sha256sum --strict --check runtime.sha256) >/dev/null || die 'runtime hash mismatch'

for file in "$HOSTS" "$CONFIG" "$TPWS" "$GATEWAY"; do
  [[ -f $file && ! -L $file ]] || die "unsafe runtime file: $file"
  [[ $(stat -c '%u:%g' "$file") == 0:0 ]] || die "runtime file is not root-owned: $file"
  mode=$(stat -c '%a' "$file")
  [[ $mode == 444 || $mode == 555 ]] || die "runtime file has unsafe mode: $file"
done

domains=$(paste -sd, "$HOSTS")
[[ -n $domains && $domains != *[!a-z0-9.,-]* ]] || die 'invalid Discord host list'

children=()
# shellcheck disable=SC2329 # invoked by TERM/INT/EXIT traps
stop_children() {
  trap - TERM INT EXIT
  for pid in "${children[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${children[@]:-}"; do wait "$pid" 2>/dev/null || true; done
}
trap stop_children TERM INT EXIT

"$TPWS" --bind-addr=127.0.0.1 --socks --port=19081 --maxconn=256 \
  --uid=nobody --filter-tcp=80 --methodeol --hostlist-domains="$domains" \
  --new --filter-tcp=443 --split-pos=1,midsld --disorder --hostlist-domains="$domains" --debug=0 &
children+=("$!")
"$GATEWAY" "$CONFIG" &
children+=("$!")

# Either child stopping invalidates the whole runtime. systemd KillMode closes
# the service cgroup even if the supervisor itself is terminated unexpectedly.
wait -n "${children[@]}"
die 'a required runtime process stopped'
