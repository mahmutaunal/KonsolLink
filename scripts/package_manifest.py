#!/usr/bin/env python3
"""Create or verify a bounded SHA-256 manifest for a KonsolLink package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

MAX_FILES = 10_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MANIFEST = "MANIFEST.sha256.json"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > MAX_FILE_BYTES:
                raise ValueError(f"oversized package file: {path}")
            hasher.update(block)
    return hasher.hexdigest()


def inventory(root: Path) -> list[dict[str, object]]:
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST or path.is_dir():
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if target.startswith("/") or ".." in Path(target).parts:
                raise ValueError(f"unsafe package symlink: {relative}")
            entries.append({"path": relative, "type": "symlink", "target": target})
        elif stat.S_ISREG(mode):
            entries.append({
                "path": relative, "type": "file", "bytes": path.stat().st_size,
                "sha256": digest(path),
            })
        else:
            raise ValueError(f"unsupported package entry: {relative}")
        if len(entries) > MAX_FILES:
            raise ValueError("package file count limit exceeded")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("root must be a directory")
    manifest = root / MANIFEST
    if args.mode == "create":
        data = {
            "schema": 1,
            "product": "KonsolLink macOS alpha",
            "go_pcap2socks_commit": "ec40773869e835bd09cb134e638e4e3333d89e0c",
            "files": inventory(root),
        }
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return 0
    try:
        expected = json.loads(manifest.read_text(encoding="utf-8"))
        if set(expected) != {"schema", "product", "go_pcap2socks_commit", "files"}:
            raise ValueError("invalid manifest schema")
        actual = inventory(root)
        if expected["schema"] != 1 or expected["files"] != actual:
            raise ValueError("package manifest mismatch")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"Verified {len(actual)} package entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
