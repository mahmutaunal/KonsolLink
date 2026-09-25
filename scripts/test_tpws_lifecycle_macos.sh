#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

if [[ $(uname -s) != Darwin || $# != 1 || "$1" != /* || ! -f "$1" || -L "$1" ]]; then
  echo 'Usage: scripts/test_tpws_lifecycle_macos.sh /absolute/path/zapret-v72.13.tar.gz' >&2
  exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/konsollink-tpws-lifecycle.XXXXXX")
artifact="$work_dir/tpws"
log="$work_dir/tpws.log"
pid=

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

if nc -z 127.0.0.1 19081 >/dev/null 2>&1; then
  echo 'Loopback test port 19081 is already in use.' >&2
  exit 1
fi

"$script_dir/build_tpws_macos.sh" "$1" "$artifact" >/dev/null
"$artifact" \
  --bind-addr=127.0.0.1 \
  --port=19081 \
  --socks \
  --filter-tcp=80 --methodeol \
  --hostlist-domains=discord.com,discord.gg,discordapp.com,discordapp.net,discord.net,discord.media,discordcdn.com \
  --new --filter-tcp=443 --split-pos=1,midsld --disorder \
  --hostlist-domains=discord.com,discord.gg,discordapp.com,discordapp.net,discord.net,discord.media,discordcdn.com \
  --debug=0 >"$log" 2>&1 &
pid=$!

ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo 'tpws exited before becoming ready.' >&2
    sed -n '1,40p' "$log" >&2
    exit 1
  fi
  if nc -z 127.0.0.1 19081 >/dev/null 2>&1; then ready=true; break; fi
  sleep 0.05
done
if [[ "$ready" != true ]]; then echo 'tpws loopback listener did not become ready.' >&2; exit 1; fi

kill -TERM "$pid"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.05
done
if kill -0 "$pid" 2>/dev/null; then echo 'tpws did not stop after SIGTERM.' >&2; exit 1; fi
wait "$pid" || status=$?
status=${status:-0}
if [[ "$status" != 0 && "$status" != 143 ]]; then echo "Unexpected tpws exit status: $status" >&2; exit 1; fi
pid=

if nc -z 127.0.0.1 19081 >/dev/null 2>&1; then
  echo 'tpws listener remained open after stop.' >&2
  exit 1
fi
echo 'tpws loopback lifecycle: OK'
