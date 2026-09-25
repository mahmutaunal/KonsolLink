#!/usr/bin/env python3
"""Compile reviewed M5 evidence files into the stable release gate document."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_release_qualification import verify  # noqa: E402


def main() -> int:
    evidence_root = ROOT / "release" / "evidence"
    runs = []
    for path in sorted(evidence_root.glob("*.json")) if evidence_root.is_dir() else []:
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("schema") != 1 or report.get("version") != "1.0.0":
            raise ValueError(f"invalid evidence schema: {path.name}")
        runs.append({
            "evidence": path.relative_to(ROOT).as_posix(),
            "device": report.get("device"),
            "host_os": report.get("host_os"),
            "isp": report.get("isp"),
            "ip_mode": report.get("ip_mode"),
            "passed": report.get("passed") is True,
            "performance_passed": report.get("performance", {}).get("passed") is True,
        })
    document = {"schema": 1, "product": "KonsolLink", "version": "1.0.0", "status": "passed", "runs": runs}
    try:
        verify(document)
    except ValueError as error:
        document["status"] = "pending"
        (ROOT / "release/qualification.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(f"Qualification remains pending: {error}", file=sys.stderr)
        return 1
    (ROOT / "release/qualification.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Qualification passed with {len(runs)} reviewed runs.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Could not compile qualification: {error}", file=sys.stderr)
        raise SystemExit(2)
