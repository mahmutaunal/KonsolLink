#!/usr/bin/env python3
"""Create and verify a closed SHA-256 inventory for final release assets."""

import hashlib
import json
import sys
from pathlib import Path

ALLOWED_SUFFIXES = {".pkg", ".dmg", ".zip", ".exe", ".deb", ".rpm", ".AppImage", ".gz", ".json", ".md", ".sh", ".patch", ".txt"}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def create(directory: Path) -> None:
    assets = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.name in {"SHA256SUMS", "release-manifest.json"} or not path.is_file():
            continue
        if not any(path.name.endswith(suffix) for suffix in ALLOWED_SUFFIXES) and not path.name.endswith("LICENSE"):
            raise SystemExit(f"unexpected release asset: {path.name}")
        assets.append({"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)})
    if not assets:
        raise SystemExit("release directory contains no assets")
    (directory / "SHA256SUMS").write_text("".join(f"{item['sha256']}  {item['name']}\n" for item in assets), encoding="ascii")
    manifest = {"schema": 1, "product": "KonsolLink", "version": "1.0.0", "assets": assets}
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def verify(directory: Path) -> None:
    manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    if set(manifest) != {"schema", "product", "version", "assets"} or manifest["schema"] != 1 or manifest["version"] != "1.0.0":
        raise SystemExit("invalid release manifest")
    expected = {item["name"]: item for item in manifest["assets"]}
    actual = {path.name for path in directory.iterdir() if path.is_file()} - {"SHA256SUMS", "release-manifest.json"}
    if actual != set(expected):
        raise SystemExit("release asset set differs from manifest")
    for name, item in expected.items():
        path = directory / name
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise SystemExit(f"release asset mismatch: {name}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"create", "verify"}:
        raise SystemExit("usage: make_release_checksums.py create|verify DIRECTORY")
    folder = Path(sys.argv[2]).resolve()
    if not folder.is_dir() or folder.is_symlink():
        raise SystemExit("release directory must be a real directory")
    (create if sys.argv[1] == "create" else verify)(folder)
