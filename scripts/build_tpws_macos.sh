#!/bin/sh
set -eu

archive_sha256="25c74e6c5f48963fa244c2955e76694a07c39447245a0457e2efdc74b3317e68"
license_sha256="dcf5abd3e5d876c1065982871c0cec7368c0e61fc795c541798729516bb6b54f"
output_sha256="f2749747f9fee28d92bbf149211b21492308c0c9bc6c818a829adc08dd722225"
source_date_epoch="1784614671"

usage() {
  echo "Kullanım: $0 /tam/yol/zapret-v72.13.tar.gz [çıktı-yolu]" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
archive=$1
[ -f "$archive" ] || { echo "Arşiv bulunamadı: $archive" >&2; exit 1; }

output=${2:-"${TMPDIR:-/tmp}/konsollink-tpws-v72.13-macos-universal"}

for command_name in python3 shasum tar make clang lipo otool codesign; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Gerekli araç bulunamadı: $command_name" >&2
    exit 1
  }
done

actual_archive_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
[ "$actual_archive_sha256" = "$archive_sha256" ] || {
  echo "Arşiv SHA-256 doğrulaması başarısız." >&2
  exit 1
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/konsollink-tpws.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

python3 - "$archive" <<'PY'
import os
import sys
import tarfile

archive = sys.argv[1]
prefix = "zapret-v72.13/"
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("Arşiv boş.")
    for member in members:
        name = member.name
        normalized = os.path.normpath(name)
        if name == "zapret-v72.13":
            if not member.isdir():
                raise SystemExit("Geçersiz kök üye.")
            continue
        if not name.startswith(prefix):
            raise SystemExit(f"Beklenmeyen kök yol: {name}")
        if os.path.isabs(name) or normalized == ".." or normalized.startswith("../"):
            raise SystemExit(f"Güvenli olmayan yol: {name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"Desteklenmeyen arşiv üyesi: {name}")
PY

tar -xzf "$archive" -C "$work_dir"
source_root="$work_dir/zapret-v72.13"
actual_license_sha256=$(shasum -a 256 "$source_root/docs/LICENSE.txt" | awk '{print $1}')
[ "$actual_license_sha256" = "$license_sha256" ] || {
  echo "MIT lisans metni doğrulaması başarısız." >&2
  exit 1
}

# Release arşivindeki hazır binaries/ ağacı hiçbir aşamada kullanılmaz.
rm -rf "$source_root/binaries"
export SOURCE_DATE_EPOCH="$source_date_epoch"
make -C "$source_root/tpws" clean >/dev/null
make -C "$source_root/tpws" mac CC=clang

built="$source_root/tpws/tpws"
actual_output_sha256=$(shasum -a 256 "$built" | awk '{print $1}')
[ "$actual_output_sha256" = "$output_sha256" ] || {
  echo "Derleme hash'i nitelendirilmiş araç zinciriyle eşleşmiyor." >&2
  echo "Beklenen: $output_sha256" >&2
  echo "Oluşan:   $actual_output_sha256" >&2
  exit 1
}

[ "$(lipo -archs "$built")" = "x86_64 arm64" ] || {
  echo "Binary beklenen x86_64 + arm64 mimarilerini içermiyor." >&2
  exit 1
}
actual_libraries=$(otool -L "$built" | awk '/^\t/{print $1}' | sort -u)
expected_libraries='/usr/lib/libSystem.B.dylib
/usr/lib/libz.1.dylib'
[ "$actual_libraries" = "$expected_libraries" ] || {
  echo "Beklenmeyen dinamik kitaplık bağımlılığı." >&2
  echo "$actual_libraries" >&2
  exit 1
}

# Apple Silicon dilimi linker ad-hoc imzası taşır. Universal çıktı dağıtım
# imzası değildir; x86_64 dilimi upstream hedefinde imzasızdır.
codesign --verify --strict --arch arm64 "$built"
"$built" --version
"$built" --dry-run \
  --bind-addr=127.0.0.1 \
  --port=19081 \
  --socks \
  --hostlist-domains=discord.com,discord.gg \
  --split-pos=2 --oob \
  --debug=0

if "$built" --dry-run --bind-addr=127.0.0.1 --port=19081 --socks --split-pos=invalid >/dev/null 2>&1; then
  echo "Geçersiz ayar beklenmedik biçimde kabul edildi." >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output")"
cp "$built" "$output"
chmod 0755 "$output"
echo "Doğrulanmış kaynak derlemesi hazır: $output"
echo "SHA-256: $actual_output_sha256"
