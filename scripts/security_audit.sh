#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly ROOT
readonly OUT="$ROOT/target/release-metadata"
mkdir -p "$OUT"
command -v cargo-audit >/dev/null || { echo 'cargo-audit 0.22.2 is required.' >&2; exit 1; }
[[ $(cargo-audit --version) == 'cargo-audit 0.22.2' ]] || { echo 'Unexpected cargo-audit version.' >&2; exit 1; }

set +e
cargo-audit audit --json > "$OUT/cargo-audit.json"
cargo_status=$?
npm --prefix "$ROOT/apps/desktop" audit --json > "$OUT/npm-audit.json"
npm_status=$?
set -e

python3 - "$OUT/cargo-audit.json" "$OUT/npm-audit.json" <<'PY'
import json, sys
cargo = json.load(open(sys.argv[1], encoding="utf-8"))
npm = json.load(open(sys.argv[2], encoding="utf-8"))
vulnerabilities = cargo.get("vulnerabilities", {}).get("list", [])
if vulnerabilities:
    raise SystemExit(f"RustSec vulnerabilities found: {len(vulnerabilities)}")
actual = {
    item["advisory"]["id"]
    for category in cargo.get("warnings", {}).values()
    for item in category
}
# Target-specific Tauri GTK build dependencies. None is used by KonsolLink's
# policy/runtime code. Any change to this reviewed set fails the release gate.
reviewed = {
    "RUSTSEC-2024-0370", "RUSTSEC-2024-0429", "RUSTSEC-2025-0075",
    "RUSTSEC-2025-0080", "RUSTSEC-2025-0081", "RUSTSEC-2025-0098",
    "RUSTSEC-2025-0100",
}
if actual != reviewed:
    raise SystemExit(f"RustSec warning set changed: actual={sorted(actual)}")
counts = npm.get("metadata", {}).get("vulnerabilities", {})
if counts.get("total", 0) != 0:
    raise SystemExit(f"npm vulnerabilities found: {counts}")
print(f"Security audit: 0 known vulnerabilities; {len(actual)} reviewed RustSec warnings; npm clean.")
PY

[[ $cargo_status -eq 0 ]] || { echo "cargo-audit failed with $cargo_status" >&2; exit "$cargo_status"; }
[[ $npm_status -eq 0 ]] || { echo "npm audit failed with $npm_status" >&2; exit "$npm_status"; }
