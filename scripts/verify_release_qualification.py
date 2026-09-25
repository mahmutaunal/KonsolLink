#!/usr/bin/env python3
"""Fail closed until the declared 1.0 physical support matrix is evidenced."""

import json
import sys
from pathlib import Path

REQUIRED_DEVICES = {"ps5", "xbox-one", "xbox-series"}
REQUIRED_HOSTS = {"macos-arm64", "windows-x64", "linux-x64"}
REQUIRED_ISPS = {"turk-telekom", "turknet", "superonline", "vodafone"}
REQUIRED_IP_MODES = {"ipv4", "cgnat", "dual-stack"}


def verify(document: dict) -> None:
    if set(document) != {"schema", "product", "version", "status", "runs"}:
        raise ValueError("qualification document has unknown or missing fields")
    if document["schema"] != 1 or document["product"] != "KonsolLink" or document["version"] != "1.0.0" or document["status"] != "passed":
        raise ValueError("qualification status is not passed for 1.0.0")
    runs = document["runs"]
    if not isinstance(runs, list) or not runs:
        raise ValueError("qualification has no physical runs")
    required_run_fields = {"evidence", "device", "host_os", "isp", "ip_mode", "passed", "performance_passed"}
    for run in runs:
        if set(run) != required_run_fields or run["passed"] is not True or run["performance_passed"] is not True:
            raise ValueError("qualification contains a failed or malformed run")
        evidence = Path(run["evidence"])
        if evidence.is_absolute() or ".." in evidence.parts or evidence.suffix != ".json":
            raise ValueError("qualification evidence path is unsafe")
    for field, required in [
        ("device", REQUIRED_DEVICES), ("host_os", REQUIRED_HOSTS),
        ("isp", REQUIRED_ISPS), ("ip_mode", REQUIRED_IP_MODES),
    ]:
        actual = {run[field] for run in runs}
        missing = required - actual
        if missing:
            raise ValueError(f"qualification is missing {field}: {sorted(missing)}")


if __name__ == "__main__":
    path = Path(sys.argv[1] if len(sys.argv) == 2 else "release/qualification.json")
    try:
        verify(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Release qualification blocked: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("KonsolLink 1.0 physical qualification matrix: passed")
