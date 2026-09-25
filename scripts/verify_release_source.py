#!/usr/bin/env python3
"""Static 1.0 release-contract checks that do not require signing credentials."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"

for path in [
    "crates/konsollink-core/Cargo.toml", "crates/konsollink-platform/Cargo.toml",
    "helper/Cargo.toml", "apps/desktop/src-tauri/Cargo.toml",
]:
    data = tomllib.loads((ROOT / path).read_text(encoding="utf-8"))
    if data["package"]["version"] != VERSION:
        raise SystemExit(f"release version drift: {path}")
for path in ["apps/desktop/package.json", "apps/desktop/src-tauri/tauri.conf.json"]:
    if json.loads((ROOT / path).read_text(encoding="utf-8"))["version"] != VERSION:
        raise SystemExit(f"release version drift: {path}")
lock = json.loads((ROOT / "apps/desktop/package-lock.json").read_text(encoding="utf-8"))
if lock["version"] != VERSION or lock["packages"][""]["version"] != VERSION:
    raise SystemExit("npm lockfile version drift")

workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
for token in [
    "verify_release_qualification.py", "security_audit.sh", "generate_release_metadata.py",
    "APPLE_APPLICATION_IDENTITY", "WINDOWS_CERTIFICATE_PFX", "notarytool", "actions/attest@v4",
    "gh release create v1.0.0", "--verify-tag",
]:
    if token not in workflow:
        raise SystemExit(f"release workflow gate missing: {token}")

for path in ["scripts/build_macos_release.sh", "scripts/build_windows_package.ps1", "scripts/build_linux_package.sh"]:
    text = (ROOT / path).read_text(encoding="utf-8")
    if re.search(r"KonsolLink-0\.[0-9]", text):
        raise SystemExit(f"pre-1.0 package name remains: {path}")

mac_release = (ROOT / "scripts/build_macos_release.sh").read_text(encoding="utf-8")
windows_release = (ROOT / "scripts/build_windows_release.ps1").read_text(encoding="utf-8")
windows_runtime = (ROOT / "scripts/build_windows_package.ps1").read_text(encoding="utf-8")
for label, text, tokens in [
    ("macOS", mac_release, ["-rc3-unsigned", "APPLE_NOTARY_PROFILE", "stapler validate"]),
    ("Windows installer", windows_release, ["-rc-unsigned", "NsisCandidates.Count -ne 1", "signtool"]),
    ("Windows runtime", windows_runtime, ["-rc-unsigned", "ALLOW_UNSIGNED_RC", "Authenticode"]),
]:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise SystemExit(f"{label} release gate missing: {', '.join(missing)}")

qualification = json.loads((ROOT / "release/qualification.json").read_text(encoding="utf-8"))
if qualification.get("version") != VERSION or qualification.get("status") not in {"pending", "passed"}:
    raise SystemExit("invalid release qualification state")
if "GitHub Private Vulnerability Reporting" not in (ROOT / "docs/SECURITY.md").read_text(encoding="utf-8"):
    raise SystemExit("private security reporting channel missing")
print("KonsolLink 1.0 source release contract: OK")
