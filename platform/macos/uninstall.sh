#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
[[ $(id -u) == 0 ]] || { echo 'Kaldırıcı sudo ile çalıştırılmalıdır.' >&2; exit 1; }
readonly LABEL=tr.konsollink.m0
readonly ROOT=/Library/PrivilegedHelperTools/tr.konsollink.m0
readonly HELPER="$ROOT/konsollink-helper"
readonly PLIST=/Library/LaunchDaemons/tr.konsollink.m0.plist

if [[ -e "$ROOT" || -L "$ROOT" ]]; then
  [[ -d "$ROOT" && ! -L "$ROOT" && -f "$HELPER" && ! -L "$HELPER" && $(stat -f %u "$HELPER") == 0 ]] || {
    echo 'Kurulum yolu güvenli değil; otomatik silme yapılmadı.' >&2; exit 1
  }
  "$HELPER" stop >/dev/null 2>&1 || true
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  recovered=false
  for _ in 1 2 3 4 5; do
    if "$HELPER" recover; then recovered=true; break; fi
    sleep 1
  done
  [[ $recovered == true ]] || { echo 'Ağ recovery başarısız; dosyalar korundu.' >&2; exit 1; }
  rm -rf "$ROOT"
fi
rm -f "$PLIST"
rm -rf /Applications/KonsolLink.app
rmdir /private/var/db/konsollink-ipc 2>/dev/null || true
echo 'KonsolLink kaldırıldı. Konsol IP ayarını Otomatik yapın.'
