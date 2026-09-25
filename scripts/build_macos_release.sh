#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin
if [[ -n ${KONSOLLINK_RUST_BIN:-} ]]; then PATH="$KONSOLLINK_RUST_BIN:$PATH"; fi
export PATH
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly ROOT
readonly VERSION=1.0.0
ARCH=$(uname -m)
readonly ARCH
readonly OUT="$ROOT/target/release-packages/macos"
readonly APP_IDENTITY=${APPLE_APPLICATION_IDENTITY:-}
readonly INSTALLER_IDENTITY=${APPLE_INSTALLER_IDENTITY:-}
readonly UNSIGNED=${ALLOW_UNSIGNED_RC:-0}
readonly TPWS="$ROOT/target/m2/tpws-v72.13"
readonly GATEWAY="$ROOT/target/m2/go-pcap2socks-ec407738-konsollink"
readonly GATEWAY_SOURCE=${GATEWAY_SOURCE:-$ROOT/target/release-sources/go-pcap2socks}

run_pkgbuild() {
  local stderr_file status
  stderr_file=$(mktemp "$OUT/pkgbuild.stderr.XXXXXX")
  set +e
  COPYFILE_DISABLE=1 pkgbuild "$@" 2>"$stderr_file"
  status=$?
  set -e
  grep -v '^write: Permission denied$' "$stderr_file" >&2 || true
  rm -f "$stderr_file"
  return "$status"
}

[[ -x $TPWS && -x $GATEWAY ]] || { echo 'Pinned macOS engines must be built first.' >&2; exit 1; }
[[ -d $GATEWAY_SOURCE/.git ]] || { echo 'Pinned go-pcap2socks source checkout is required.' >&2; exit 1; }
[[ $(git -C "$GATEWAY_SOURCE" rev-parse HEAD) == ec40773869e835bd09cb134e638e4e3333d89e0c ]] || { echo 'Gateway source commit mismatch.' >&2; exit 1; }
git -C "$GATEWAY_SOURCE" apply --check "$ROOT/engines/go-pcap2socks-ec407738-konsollink.patch"
if [[ -z $APP_IDENTITY || -z $INSTALLER_IDENTITY ]]; then
  [[ $UNSIGNED == 1 ]] || { echo 'Developer ID Application and Installer identities are required for a stable package.' >&2; exit 1; }
  suffix=-rc3-unsigned
  volume_name='KonsolLink 1.0 RC3'
else
  suffix=
  volume_name='KonsolLink 1.0'
fi
readonly volume_name
readonly NAME="KonsolLink-$VERSION$suffix-macos-$ARCH"
rm -rf "$OUT"
mkdir -p "$OUT"
STAGE=$(mktemp -d "$OUT/stage.XXXXXX")
readonly STAGE
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/root/Applications" "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines"

cd "$ROOT"
cp "$TPWS" "$STAGE/tpws-v72.13"
cp "$GATEWAY" "$STAGE/go-pcap2socks-ec407738-konsollink"
if [[ -n $APP_IDENTITY ]]; then
  codesign --force --options runtime --timestamp --sign "$APP_IDENTITY" "$STAGE/tpws-v72.13"
  codesign --force --options runtime --timestamp --sign "$APP_IDENTITY" "$STAGE/go-pcap2socks-ec407738-konsollink"
else
  codesign --force --sign - "$STAGE/tpws-v72.13"
  codesign --force --sign - "$STAGE/go-pcap2socks-ec407738-konsollink"
fi
export KONSOLLINK_TPWS_SHA256
export KONSOLLINK_PCAP2SOCKS_SHA256
KONSOLLINK_TPWS_SHA256=$(shasum -a 256 "$STAGE/tpws-v72.13" | awk '{print $1}')
KONSOLLINK_PCAP2SOCKS_SHA256=$(shasum -a 256 "$STAGE/go-pcap2socks-ec407738-konsollink" | awk '{print $1}')
cargo build --release --locked -p konsollink-helper
npm --prefix apps/desktop run tauri build -- --bundles app --ci -- --locked
app="$ROOT/target/release/bundle/macos/KonsolLink.app"
helper="$ROOT/target/release/konsollink-helper"
if [[ -n $APP_IDENTITY ]]; then
  codesign --force --options runtime --timestamp --sign "$APP_IDENTITY" "$helper"
  codesign --force --deep --options runtime --timestamp --sign "$APP_IDENTITY" "$app"
  codesign --verify --deep --strict --verbose=2 "$app"
else
  codesign --force --sign - "$helper"
  codesign --force --deep --sign - "$app"
fi

ditto "$app" "$STAGE/root/Applications/KonsolLink.app"
install -m 0755 "$helper" "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/konsollink-helper"
install -m 0555 "$STAGE/tpws-v72.13" "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/tpws-v72.13"
install -m 0555 "$STAGE/go-pcap2socks-ec407738-konsollink" "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/go-pcap2socks-ec407738-konsollink"
install -m 0444 "$ROOT/engines/gateway-macos.json" "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/gateway-macos.json"
cp -R "$ROOT/platform/macos/pkg-scripts" "$STAGE/scripts"
chmod 0555 "$STAGE/scripts/preinstall" "$STAGE/scripts/postinstall"

# pkgbuild strips non-package metadata while archiving. macOS attaches a
# provenance xattr to locally produced files, and read-only payload files make
# that cleanup fail. Keep the staged files owner-writable; postinstall applies
# the final root-owned 0555/0444 runtime modes before launchd starts the helper.
chmod u+w "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/konsollink-helper" \
  "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/tpws-v72.13" \
  "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/go-pcap2socks-ec407738-konsollink" \
  "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/gateway-macos.json"
xattr -cr "$STAGE/root"
chmod 0755 "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/konsollink-helper"
chmod 0755 "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/tpws-v72.13" \
  "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/go-pcap2socks-ec407738-konsollink"
chmod 0644 "$STAGE/root/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/gateway-macos.json"

pkg_args=(--root "$STAGE/root" --scripts "$STAGE/scripts" --identifier tr.konsollink.pkg --version "$VERSION" --install-location /)
if [[ -n $INSTALLER_IDENTITY ]]; then pkg_args+=(--sign "$INSTALLER_IDENTITY" --timestamp); fi
run_pkgbuild "${pkg_args[@]}" "$OUT/$NAME.pkg"
if [[ -n $INSTALLER_IDENTITY ]]; then
  pkgutil --check-signature "$OUT/$NAME.pkg"
  if [[ -n ${APPLE_NOTARY_PROFILE:-} ]]; then
    xcrun notarytool submit "$OUT/$NAME.pkg" --keychain-profile "$APPLE_NOTARY_PROFILE" --wait
    xcrun stapler staple "$OUT/$NAME.pkg"
    xcrun stapler validate "$OUT/$NAME.pkg"
  else
    echo 'APPLE_NOTARY_PROFILE is required before stable publication.' >&2
    exit 1
  fi
fi
install -m 0555 "$ROOT/platform/macos/uninstall.sh" "$OUT/KonsolLink-$VERSION-macos-uninstall.sh"
install -m 0444 "$ROOT/target/release-metadata/konsollink-1.0.0.cdx.json" "$OUT/konsollink-1.0.0.cdx.json"
install -m 0444 "$ROOT/target/release-metadata/LICENSES.md" "$OUT/LICENSES.md"
install -m 0444 "$ROOT/THIRD_PARTY_NOTICES.md" "$OUT/THIRD_PARTY_NOTICES.md"
install -m 0444 "$ROOT/engines/go-pcap2socks-LICENSE" "$OUT/go-pcap2socks-LICENSE"
install -m 0444 "$ROOT/engines/go-pcap2socks-ec407738-konsollink.patch" "$OUT/go-pcap2socks-ec407738-konsollink.patch"
git -C "$GATEWAY_SOURCE" archive --format=tar.gz --output="$OUT/go-pcap2socks-ec407738-source.tar.gz" HEAD
install -m 0444 "$ROOT/target/m2/zapret-v72.13.tar.gz" "$OUT/zapret-v72.13-source.tar.gz"

dmg_stage=$(mktemp -d "$OUT/dmg.XXXXXX")
cp "$OUT/$NAME.pkg" "$dmg_stage/"
cp "$ROOT/platform/macos/DMG-KURULUM.txt" "$dmg_stage/KURULUM.txt"
cp "$ROOT/platform/macos/uninstall.sh" "$dmg_stage/KonsolLink'i Kaldır.command"
chmod 0555 "$dmg_stage/KonsolLink'i Kaldır.command"
hdiutil create -quiet -fs HFS+ -format UDZO -volname "$volume_name" \
  -srcfolder "$dmg_stage" "$OUT/$NAME.dmg"
rm -rf "$dmg_stage"

python3 "$ROOT/scripts/make_release_checksums.py" create "$OUT"
python3 "$ROOT/scripts/make_release_checksums.py" verify "$OUT"
shasum -a 256 "$OUT/$NAME.pkg"
shasum -a 256 "$OUT/$NAME.dmg"
