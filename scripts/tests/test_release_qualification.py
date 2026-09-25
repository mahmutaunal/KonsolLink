import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("qualification", ROOT / "scripts/verify_release_qualification.py")
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(module)


def run(device, host, isp, ip_mode, number):
    return {"evidence": f"release/evidence/{number}.json", "device": device, "host_os": host, "isp": isp, "ip_mode": ip_mode, "passed": True, "performance_passed": True}


class QualificationTests(unittest.TestCase):
    def complete(self):
        return {
            "schema": 1, "product": "KonsolLink", "version": "1.0.0", "status": "passed",
            "runs": [
                run("ps5", "macos-arm64", "turk-telekom", "ipv4", 1),
                run("xbox-one", "windows-x64", "turknet", "cgnat", 2),
                run("xbox-series", "linux-x64", "superonline", "dual-stack", 3),
                run("ps5", "macos-arm64", "vodafone", "ipv4", 4),
            ],
        }

    def test_complete_matrix_passes(self):
        module.verify(self.complete())

    def test_pending_failed_or_missing_scope_is_rejected(self):
        for mutate in (
            lambda d: d.update(status="pending"),
            lambda d: d["runs"][0].update(passed=False),
            lambda d: d.update(runs=d["runs"][:-1]),
            lambda d: d["runs"][0].update(evidence="../escape.json"),
        ):
            document = self.complete()
            mutate(document)
            with self.assertRaises(ValueError):
                module.verify(document)


if __name__ == "__main__":
    unittest.main()
