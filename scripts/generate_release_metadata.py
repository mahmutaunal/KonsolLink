#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM and license inventory from lockfiles."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "target" / "release-metadata"
PRODUCT = "KonsolLink"
VERSION = "1.0.0"


def cargo_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if not result.stdout:
        raise RuntimeError("cargo metadata returned no JSON output")
    metadata = json.loads(result.stdout)
    if not isinstance(metadata, dict):
        raise ValueError("cargo metadata returned a non-object JSON document")
    return metadata


def license_objects(expression: str | None) -> list[dict]:
    if not expression:
        return [{"license": {"name": "NOASSERTION"}}]
    return [{"expression": expression}]


def cargo_components(metadata: dict) -> tuple[list[dict], dict[str, list[str]], list[dict]]:
    workspace = set(metadata["workspace_members"])
    components: list[dict] = []
    licenses: list[dict] = []
    refs: dict[str, str] = {}
    for package in metadata["packages"]:
        purl = f"pkg:cargo/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}"
        refs[package["id"]] = purl
        expression = package.get("license")
        components.append({
            "type": "application" if package["id"] in workspace else "library",
            "bom-ref": purl,
            "name": package["name"],
            "version": package["version"],
            "purl": purl,
            "licenses": license_objects(expression),
            "properties": [{"name": "konsollink:ecosystem", "value": "cargo"}],
        })
        licenses.append({
            "ecosystem": "cargo",
            "name": package["name"],
            "version": package["version"],
            "license": expression or "NOASSERTION",
            "source": package.get("source") or "workspace",
        })
    dependencies: dict[str, list[str]] = {}
    for node in metadata.get("resolve", {}).get("nodes", []):
        ref = refs.get(node["id"])
        if ref:
            dependencies[ref] = sorted(refs[item] for item in node.get("dependencies", []) if item in refs)
    return components, dependencies, licenses


def npm_components() -> tuple[list[dict], dict[str, list[str]], list[dict]]:
    lock = json.loads((ROOT / "apps/desktop/package-lock.json").read_text(encoding="utf-8"))
    components: list[dict] = []
    licenses: list[dict] = []
    path_refs: dict[str, str] = {}
    for path, package in sorted(lock.get("packages", {}).items()):
        if not path or "version" not in package:
            continue
        name = package.get("name") or path.rsplit("node_modules/", 1)[-1]
        version = package["version"]
        purl = f"pkg:npm/{quote(name, safe='@/')}@{quote(version, safe='')}"
        path_refs[path] = purl
        expression = package.get("license")
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "licenses": license_objects(expression),
            "properties": [{"name": "konsollink:ecosystem", "value": "npm"}],
        }
        integrity = package.get("integrity", "")
        if integrity.startswith("sha512-"):
            try:
                component["hashes"] = [{
                    "alg": "SHA-512",
                    "content": base64.b64decode(integrity[7:]).hex(),
                }]
            except ValueError:
                raise SystemExit(f"invalid npm integrity for {name}@{version}")
        components.append(component)
        licenses.append({
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "license": expression or "NOASSERTION",
            "source": package.get("resolved", "package-lock"),
        })
    # npm lockfile dependency paths are resolution-dependent. Component
    # inventory remains complete; the root relationship is explicit.
    root_ref = f"pkg:generic/konsollink-desktop@{VERSION}"
    dependencies = {root_ref: sorted(set(path_refs.values()))}
    return components, dependencies, licenses


def engine_components() -> tuple[list[dict], list[dict]]:
    platform = tomllib.loads((ROOT / "engines/platforms.toml").read_text(encoding="utf-8"))
    items = [
        ("go-pcap2socks", "ec40773869e835bd09cb134e638e4e3333d89e0c", "GPL-3.0-only", None),
        ("zapret-tpws", "72.13", "MIT", "25c74e6c5f48963fa244c2955e76694a07c39447245a0457e2efdc74b3317e68"),
        ("GoodbyeDPI", platform["windows"]["goodbyedpi"]["release"], "Apache-2.0", platform["windows"]["goodbyedpi"]["archive_sha256"]),
        ("WinDivert", "bundled-with-goodbyedpi-0.2.2", "LGPL-3.0-or-later OR GPL-2.0-or-later", platform["windows"]["goodbyedpi"]["windivert_driver_sha256"]),
    ]
    components, licenses = [], []
    for name, version, expression, digest in items:
        purl = f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}"
        component = {
            "type": "application",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "licenses": [{"expression": expression}],
            "properties": [{"name": "konsollink:ecosystem", "value": "native-engine"}],
        }
        if digest:
            component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        components.append(component)
        licenses.append({"ecosystem": "native-engine", "name": name, "version": version, "license": expression, "source": "engines/platforms.toml"})
    return components, licenses


def timestamp() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", str(int(time.time()))))
    return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cargo, cargo_deps, cargo_licenses = cargo_components(cargo_metadata())
    npm, npm_deps, npm_licenses = npm_components()
    engines, engine_licenses = engine_components()
    root_ref = f"pkg:generic/KonsolLink@{VERSION}"
    components = sorted(cargo + npm + engines, key=lambda c: c["bom-ref"])
    dependencies = {**cargo_deps, **npm_deps, root_ref: sorted(c["bom-ref"] for c in components if c["type"] == "application")}
    identity = "\n".join(c["bom-ref"] for c in components)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp(),
            "tools": {"components": [{"type": "application", "name": "KonsolLink release metadata generator", "version": VERSION}]},
            "component": {"type": "application", "bom-ref": root_ref, "name": PRODUCT, "version": VERSION},
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": items} for ref, items in sorted(dependencies.items())],
    }
    (OUT / "konsollink-1.0.0.cdx.json").write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    licenses = sorted(cargo_licenses + npm_licenses + engine_licenses, key=lambda x: (x["ecosystem"], x["name"], x["version"]))
    unknown = [item for item in licenses if item["license"] == "NOASSERTION"]
    report = {"schema": 1, "product": PRODUCT, "version": VERSION, "components": licenses, "unknown_licenses": unknown}
    (OUT / "licenses.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = ["# KonsolLink 1.0.0 dependency licenses", "", f"Components: {len(licenses)}", "", "| Ecosystem | Package | Version | License |", "|---|---|---|---|"]
    for item in licenses:
        lines.append(f"| {item['ecosystem']} | {item['name']} | {item['version']} | {item['license']} |")
    (OUT / "LICENSES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if unknown:
        print("Dependencies with unknown license metadata:", file=sys.stderr)
        for item in unknown:
            print(f"- {item['ecosystem']}:{item['name']}@{item['version']}", file=sys.stderr)
        return 1
    print(f"CycloneDX SBOM: {len(components)} components; license inventory complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
