import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "m3_benchmark.py"
SPEC = importlib.util.spec_from_file_location("m3_benchmark", SCRIPT)
M3 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(M3)


class EvaluationTests(unittest.TestCase):
    def write(self, baseline=(100.0, 5.0), enabled=(99.2, 5.8), integrity=True):
        handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        with handle:
            for phase, values in (("baseline", baseline), ("enabled", enabled)):
                for _ in range(M3.ROUNDS):
                    handle.write(json.dumps({
                        "schema": M3.SCHEMA,
                        "phase": phase,
                        "latency_ms": values[1],
                        "throughput_mbps": values[0],
                        "integrity": integrity,
                        "engine_cpu_percent": 2.0 if phase == "enabled" else 0.0,
                        "engine_rss_mib": 42.0 if phase == "enabled" else 0.0,
                    }) + "\n")
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_accepts_exact_m3_thresholds_and_reports_resources(self):
        report = M3.evaluate(self.write())
        self.assertTrue(report["passed"])
        self.assertEqual(report["delta"]["throughput_loss_percent"], 0.8)
        self.assertEqual(report["enabled"]["median_engine_rss_mib"], 42.0)

    def test_rejects_latency_throughput_integrity_and_too_few_samples(self):
        self.assertFalse(M3.evaluate(self.write(enabled=(98.9, 5.2)))["passed"])
        self.assertFalse(M3.evaluate(self.write(enabled=(100.0, 6.0)))["passed"])
        with self.assertRaisesRegex(ValueError, "integrity"):
            M3.evaluate(self.write(integrity=False))
        path = self.write()
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "at least"):
            M3.evaluate(path)

    def test_rejects_unknown_fields_and_non_finite_values(self):
        path = self.write()
        item = json.loads(path.read_text().splitlines()[0])
        item["extra"] = True
        path.write_text(json.dumps(item) + "\n")
        with self.assertRaisesRegex(ValueError, "schema"):
            M3.evaluate(path)

    def test_server_stops_after_both_complete_phases(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            output = Path(handle.name)
        self.addCleanup(output.unlink)
        server = M3.ThreadingHTTPServer(("127.0.0.1", 0), M3.BenchmarkHandler)
        server.token = "test-token"
        server.output = output
        server.counts = {phase: 0 for phase in M3.PHASES}
        server.count_lock = threading.Lock()
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        self.addCleanup(server.server_close)
        port = server.server_address[1]
        for phase in M3.PHASES:
            for _ in range(M3.ROUNDS):
                body = json.dumps({
                    "phase": phase, "latency_ms": 5.0,
                    "throughput_mbps": 100.0, "integrity": True,
                }).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/result?token=test-token",
                    data=body, headers={"content-type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.read(), b"ok")
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(M3.evaluate(output)["passed"])


if __name__ == "__main__":
    unittest.main()
