#!/bin/bash
# Developer test installer; the signed SMAppService package remains a release gate.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LABEL=tr.konsollink.m0
DIR=/Library/PrivilegedHelperTools/tr.konsollink.m0
BIN="$DIR/konsollink-helper"
ENGINE_DIR="$DIR/engines"
ENGINE_BIN="$ENGINE_DIR/tpws-v72.13"
GATEWAY_BIN="$ENGINE_DIR/go-pcap2socks-ec407738-konsollink"
GATEWAY_CONFIG="$ENGINE_DIR/gateway-macos.json"
LEGACY_GATEWAY_CONFIG="$ENGINE_DIR/gateway.json"
ENGINE_SHA256=f2749747f9fee28d92bbf149211b21492308c0c9bc6c818a829adc08dd722225
GATEWAY_SHA256=0345531054e54fbcb4f66d065a700b3f847b4b4c8ec9a8884f383619d6d046ed
GATEWAY_CONFIG_SHA256=33491fa98e3cf6a64244c5052aa9b14e5d1dd47aa8e8d69e7fd536254b4af66e
PLIST=/Library/LaunchDaemons/tr.konsollink.m0.plist
IPC_DIR=/private/var/db/konsollink-ipc
if [[ $(id -u) != 0 ]]; then
  echo 'Run with sudo. See docs/M0_DEVICE_TEST.md.' >&2; exit 1
fi
for parent in /Library /Library/PrivilegedHelperTools /Library/LaunchDaemons; do
  if [[ ! -d "$parent" || -L "$parent" || $(stat -f %u "$parent") != 0 ]]; then
    echo "Unsafe/missing system directory: $parent" >&2; exit 1
  fi
  mode=$(stat -f %Lp "$parent")
  if (( (8#$mode & 0022) != 0 )); then echo "Writable system directory: $parent" >&2; exit 1; fi
done
case "${1:-}" in
  install|install-with-engine)
    mode=$1
    if [[ "$mode" == install ]]; then
      if [[ $# != 3 ]]; then
        echo 'Usage: sudo scripts/m0-service.sh install /absolute/path/to/konsollink-helper CLIENT_UID' >&2; exit 1
      fi
      helper_source=$2
      client_uid=$3
      engine_source=
    else
      if [[ $# != 6 ]]; then
        echo 'Usage: sudo scripts/m0-service.sh install-with-engine HELPER TPWS PCAP2SOCKS CONFIG CLIENT_UID' >&2; exit 1
      fi
      helper_source=$2
      engine_source=$3
      gateway_source=$4
      gateway_config_source=$5
      client_uid=$6
    fi
    if [[ ! "$client_uid" =~ ^[1-9][0-9]*$ || "$client_uid" -gt 4294967294 ]]; then
      echo 'CLIENT_UID must identify an unprivileged account.' >&2; exit 1
    fi
    if [[ "$helper_source" != /* || ! -f "$helper_source" || -L "$helper_source" ]]; then echo 'Expected a regular built helper at an absolute path.' >&2; exit 1; fi
    if [[ -n "$engine_source" ]]; then
      if [[ "$engine_source" != /* || ! -f "$engine_source" || -L "$engine_source" ]]; then
        echo 'Expected a regular tpws artifact at an absolute path.' >&2; exit 1
      fi
      source_hash=$(shasum -a 256 "$engine_source" | awk '{print $1}')
      if [[ "$source_hash" != "$ENGINE_SHA256" ]]; then echo 'tpws SHA-256 mismatch.' >&2; exit 1; fi
      if [[ "$gateway_source" != /* || ! -f "$gateway_source" || -L "$gateway_source" ]]; then
        echo 'Expected a regular go-pcap2socks artifact at an absolute path.' >&2; exit 1
      fi
      gateway_hash=$(shasum -a 256 "$gateway_source" | awk '{print $1}')
      if [[ "$gateway_hash" != "$GATEWAY_SHA256" ]]; then echo 'go-pcap2socks SHA-256 mismatch.' >&2; exit 1; fi
      if [[ "$gateway_config_source" != /* || ! -f "$gateway_config_source" || -L "$gateway_config_source" ]]; then
        echo 'Expected a regular gateway config at an absolute path.' >&2; exit 1
      fi
      config_hash=$(shasum -a 256 "$gateway_config_source" | awk '{print $1}')
      if [[ "$config_hash" != "$GATEWAY_CONFIG_SHA256" ]]; then echo 'Gateway config SHA-256 mismatch.' >&2; exit 1; fi
    fi
    if [[ -e "$DIR" || -L "$DIR" || -e "$PLIST" || -L "$PLIST" ]]; then
      echo 'Existing installation: uninstall it first; recovery evidence will be preserved.' >&2; exit 1
    fi
    cleanup_partial() {
      rm -f "$PLIST" "$GATEWAY_CONFIG" "$LEGACY_GATEWAY_CONFIG" "$GATEWAY_BIN" "$ENGINE_BIN" "$BIN"
      rmdir "$ENGINE_DIR" 2>/dev/null || true
      rmdir "$DIR" 2>/dev/null || true
    }
    installation_complete=false
    cleanup_partial_on_exit() {
      status=$?
      if [[ "$installation_complete" != true ]]; then cleanup_partial; fi
      return "$status"
    }
    trap cleanup_partial_on_exit EXIT
    install -d -o root -g wheel -m 755 "$DIR"
    install -o root -g wheel -m 755 "$helper_source" "$BIN"
    if [[ -n "$engine_source" ]]; then
      install -d -o root -g wheel -m 755 "$ENGINE_DIR"
      install -o root -g wheel -m 0555 "$engine_source" "$ENGINE_BIN"
      install -o root -g wheel -m 0555 "$gateway_source" "$GATEWAY_BIN"
      install -o root -g wheel -m 0444 "$gateway_config_source" "$GATEWAY_CONFIG"
      if [[ -L "$ENGINE_BIN" || ! -f "$ENGINE_BIN" || $(stat -f %u "$ENGINE_BIN") != 0 || $(stat -f %Lp "$ENGINE_BIN") != 555 || $(stat -f %l "$ENGINE_BIN") != 1 ]]; then
        echo 'Installed tpws ownership, mode or link count is unsafe.' >&2; exit 1
      fi
      installed_hash=$(shasum -a 256 "$ENGINE_BIN" | awk '{print $1}')
      if [[ "$installed_hash" != "$ENGINE_SHA256" ]]; then echo 'Installed tpws SHA-256 mismatch.' >&2; exit 1; fi
      installed_gateway_hash=$(shasum -a 256 "$GATEWAY_BIN" | awk '{print $1}')
      if [[ "$installed_gateway_hash" != "$GATEWAY_SHA256" ]]; then echo 'Installed go-pcap2socks SHA-256 mismatch.' >&2; exit 1; fi
      installed_config_hash=$(shasum -a 256 "$GATEWAY_CONFIG" | awk '{print $1}')
      if [[ "$installed_config_hash" != "$GATEWAY_CONFIG_SHA256" ]]; then echo 'Installed gateway config SHA-256 mismatch.' >&2; exit 1; fi
      "$ENGINE_BIN" --version >/dev/null
      "$ENGINE_BIN" --dry-run --bind-addr=127.0.0.1 --port=19081 --maxconn=256 --user=root \
        --filter-tcp=80 --hostspell=hoSt \
        --hostlist-domains=discord.com,discord.gg,discordapp.com,discordapp.net,discord.net,discord.media,discordcdn.com \
        --new --filter-tcp=443 --split-pos=2 --oob \
        --hostlist-domains=discord.com,discord.gg,discordapp.com,discordapp.net,discord.net,discord.media,discordcdn.com \
        --debug=0 >/dev/null
    fi
    "$BIN" recover
    umask 077
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>$BIN</string><string>serve</string><string>--uid</string><string>$client_uid</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>ExitTimeOut</key><integer>60</integer>
<key>ProcessType</key><string>Interactive</string>
<key>Umask</key><integer>63</integer>
</dict></plist>
PLIST
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    plutil -lint "$PLIST"
    launchctl bootstrap system "$PLIST"
    installation_complete=true
    trap - EXIT
    if [[ -n "$engine_source" ]]; then
      echo 'M2 developer helper and verified engine installed. No gateway or bypass has been enabled.'
    else
      echo 'M0 helper installed. No gateway has been enabled.'
    fi
    ;;
  uninstall)
    if [[ $# != 1 || ! -f "$BIN" || -L "$BIN" || -L "$DIR" || -L "$PLIST" || $(stat -f %u "$BIN") != 0 ]]; then
      echo 'Unsafe/missing installation; preserve journal and inspect manually.' >&2; exit 1
    fi
    if launchctl print "system/$LABEL" >/dev/null 2>&1; then
      # A failed/crash-looping service may not have a socket to receive stop.
      # bootout still has to run before the fixed installed binary recovers.
      "$BIN" stop >/dev/null 2>&1 || true
      if ! launchctl bootout "system/$LABEL"; then
        echo 'Could not unload the helper service; installation retained.' >&2; exit 1
      fi
    fi
    # Wait for the supervisor's old process to release its lifetime lock.
    recovered=false
    for _ in 1 2 3 4 5; do
      if "$BIN" recover; then recovered=true; break; fi
      sleep 1
    done
    if [[ "$recovered" != true ]]; then echo 'Recovery failed. Installation and journal retained.' >&2; exit 1; fi
    if [[ -e "$ENGINE_DIR" || -L "$ENGINE_DIR" ]]; then
      if [[ -L "$ENGINE_DIR" || ! -d "$ENGINE_DIR" || $(stat -f %u "$ENGINE_DIR") != 0 || \
            -L "$ENGINE_BIN" || ! -f "$ENGINE_BIN" || $(stat -f %u "$ENGINE_BIN") != 0 ]]; then
        echo 'Unsafe engine installation; preserve files and inspect manually.' >&2; exit 1
      fi
      rm -f "$GATEWAY_CONFIG" "$LEGACY_GATEWAY_CONFIG" "$GATEWAY_BIN" "$ENGINE_BIN"
      rmdir "$ENGINE_DIR"
    fi
    rm -f "$PLIST" "$BIN"
    rmdir "$DIR"
    rmdir "$IPC_DIR" 2>/dev/null || true
    echo 'Service removed. Root-owned journal is retained as recovery evidence.'
    ;;
  *) echo 'Usage: m0-service.sh install HELPER UID | install-with-engine HELPER TPWS PCAP2SOCKS CONFIG UID | uninstall' >&2; exit 1 ;;
esac
