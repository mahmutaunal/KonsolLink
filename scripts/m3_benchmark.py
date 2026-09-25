#!/usr/bin/env python3
"""Controlled LAN benchmark and strict M3 result evaluator (stdlib only)."""

from __future__ import annotations

import argparse
import json
import math
import secrets
import socket
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCHEMA = 1
ROUNDS = 9
PORT = 18777
PAYLOAD = bytes(range(256)) * (8 * 1024 * 1024 // 256)
PHASES = ("baseline", "enabled")


def finite(value: object, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("measurement is not numeric")
    number = float(value)
    if not math.isfinite(number) or not low <= number <= high:
        raise ValueError("measurement is outside the accepted range")
    return number


def read_samples(path: Path) -> dict[str, list[dict[str, object]]]:
    phases = {phase: [] for phase in PHASES}
    if not path.is_file():
        raise ValueError("measurement file does not exist")
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        if set(item) != {
            "schema", "phase", "latency_ms", "throughput_mbps", "integrity",
            "engine_cpu_percent", "engine_rss_mib",
        } or item["schema"] != SCHEMA or item["phase"] not in phases:
            raise ValueError(f"invalid measurement schema on line {number}")
        finite(item["latency_ms"], 0, 60_000)
        finite(item["throughput_mbps"], 0.001, 100_000)
        finite(item["engine_cpu_percent"], 0, 10_000)
        finite(item["engine_rss_mib"], 0, 1_048_576)
        if not isinstance(item["integrity"], bool):
            raise ValueError(f"invalid integrity value on line {number}")
        phases[item["phase"]].append(item)
    return phases


def evaluate(path: Path) -> dict[str, object]:
    phases = read_samples(path)
    for phase, samples in phases.items():
        if len(samples) < ROUNDS:
            raise ValueError(f"{phase} needs at least {ROUNDS} samples")
        if not all(sample["integrity"] for sample in samples):
            raise ValueError(f"{phase} contains a payload integrity failure")

    def median(phase: str, key: str) -> float:
        return statistics.median(float(sample[key]) for sample in phases[phase])

    base_rate = median("baseline", "throughput_mbps")
    enabled_rate = median("enabled", "throughput_mbps")
    base_latency = median("baseline", "latency_ms")
    enabled_latency = median("enabled", "latency_ms")
    throughput_loss = max(0.0, (base_rate - enabled_rate) / base_rate * 100.0)
    latency_delta = enabled_latency - base_latency
    checks = {
        "payload_integrity": True,
        "throughput_loss_at_most_1_percent": throughput_loss <= 1.0,
        "median_added_latency_below_1_ms": latency_delta < 1.0,
    }
    return {
        "schema": SCHEMA,
        "passed": all(checks.values()),
        "checks": checks,
        "samples_per_phase": {phase: len(items) for phase, items in phases.items()},
        "baseline": {
            "median_latency_ms": round(base_latency, 3),
            "median_throughput_mbps": round(base_rate, 3),
        },
        "enabled": {
            "median_latency_ms": round(enabled_latency, 3),
            "median_throughput_mbps": round(enabled_rate, 3),
            "median_engine_cpu_percent": round(median("enabled", "engine_cpu_percent"), 3),
            "median_engine_rss_mib": round(median("enabled", "engine_rss_mib"), 3),
        },
        "delta": {
            "throughput_loss_percent": round(throughput_loss, 3),
            "added_latency_ms": round(latency_delta, 3),
        },
    }


def resource_snapshot() -> tuple[float, float]:
    """Return aggregate CPU percent and RSS MiB for only fixed KonsolLink images."""
    try:
        output = subprocess.run(
            ["/bin/ps", "-axo", "rss=,%cpu=,command="],
            check=True, capture_output=True, text=True, timeout=2,
        ).stdout[:1_000_000]
    except (OSError, subprocess.SubprocessError):
        return (0.0, 0.0)
    rss_kib = 0
    cpu = 0.0
    markers = (
        "/tr.konsollink.m0/engines/tpws-v72.13",
        "/tr.konsollink.m0/engines/go-pcap2socks-ec407738-konsollink",
        "/tr.konsollink.m0/konsollink-helper __engine-child gateway",
    )
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3 or not any(marker in fields[2] for marker in markers):
            continue
        try:
            rss_kib += int(fields[0])
            cpu += float(fields[1].replace(",", "."))
        except ValueError:
            continue
    return (round(cpu, 3), round(rss_kib / 1024.0, 3))


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 53))
        return str(sock.getsockname()[0])
    finally:
        sock.close()


def page(token: str, phase: str) -> bytes:
    escaped_token = json.dumps(token)
    escaped_phase = json.dumps(phase)
    return f"""<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>
<title>KonsolLink M3</title><style>body{{font:20px system-ui;max-width:720px;margin:40px auto;padding:20px;background:#111;color:#eee}}button{{font-size:22px;padding:14px}}pre{{white-space:pre-wrap}}</style>
<h1>KonsolLink M3 — {phase}</h1><p>Bu sayfa dokuz yerel bütünlük, gecikme ve hız ölçümü yapar.</p>
<button id=b>Ölçümü başlat</button><pre id=o>Hazır</pre><script>
const token={escaped_token}, phase={escaped_phase}, rounds={ROUNDS};
const out=document.querySelector('#o'), button=document.querySelector('#b');
function intact(buffer){{let b=new Uint8Array(buffer);if(b.length!==8*1024*1024)return false;for(let i=0;i<b.length;i++)if(b[i]!==i%256)return false;return true}}
button.onclick=async()=>{{button.disabled=true;try{{for(let i=0;i<rounds;i++){{
 let t=performance.now();await fetch('/ping?token='+token+'&n='+i,{{cache:'no-store'}});let latency=performance.now()-t;
 t=performance.now();let buffer=await (await fetch('/payload?token='+token+'&n='+i,{{cache:'no-store'}})).arrayBuffer();let seconds=(performance.now()-t)/1000;
 let result={{phase,latency_ms:latency,throughput_mbps:(buffer.byteLength*8/1e6)/seconds,integrity:intact(buffer)}};
 let response=await fetch('/result?token='+token,{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(result)}});if(!response.ok)throw new Error(await response.text());
 out.textContent=`${{i+1}}/${{rounds}} tamamlandı`;
}}if(phase==='baseline'){{out.innerHTML='Baseline tamamlandı. KonsolLink’i açıp sabit konsol ağ ayarlarını girin. Ardından <a href="/?phase=enabled&token='+token+'">etkin ölçümü açın</a>.'}}else{{out.textContent='Etkin ölçüm tamamlandı. Test bilgisayarda otomatik sonuçlanacak.'}}}}catch(e){{out.textContent='Ölçüm durdu: '+e}}}};
</script>""".encode("utf-8")


class BenchmarkHandler(BaseHTTPRequestHandler):
    server_version = "KonsolLinkM3/1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def authorized(self) -> tuple[bool, dict[str, list[str]]]:
        query = parse_qs(urlparse(self.path).query)
        return secrets.compare_digest(query.get("token", [""])[0], self.server.token), query

    def send_bytes(self, content: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:  # noqa: N802
        allowed, query = self.authorized()
        if not allowed:
            self.send_error(403)
            return
        route = urlparse(self.path).path
        if route == "/":
            phase = query.get("phase", [""])[0]
            if phase not in PHASES:
                self.send_error(400, "invalid phase")
                return
            self.send_bytes(page(self.server.token, phase), "text/html; charset=utf-8")
        elif route == "/ping":
            self.send_bytes(b"K", "application/octet-stream")
        elif route == "/payload":
            self.send_bytes(PAYLOAD, "application/octet-stream")
        else:
            self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        allowed, _ = self.authorized()
        if not allowed or urlparse(self.path).path != "/result":
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                raise ValueError("invalid body length")
            raw = json.loads(self.rfile.read(length))
            if set(raw) != {"phase", "latency_ms", "throughput_mbps", "integrity"}:
                raise ValueError("invalid result fields")
            if raw["phase"] not in PHASES or not isinstance(raw["integrity"], bool):
                raise ValueError("invalid result values")
            latency = finite(raw["latency_ms"], 0, 60_000)
            throughput = finite(raw["throughput_mbps"], 0.001, 100_000)
            cpu, rss = resource_snapshot()
            item = {
                "schema": SCHEMA, "phase": raw["phase"],
                "latency_ms": round(latency, 6), "throughput_mbps": round(throughput, 6),
                "integrity": raw["integrity"], "engine_cpu_percent": cpu,
                "engine_rss_mib": rss,
            }
            with self.server.output.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item, separators=(",", ":")) + "\n")
                stream.flush()
            with self.server.count_lock:
                self.server.counts[raw["phase"]] += 1
                complete = all(self.server.counts[phase] >= ROUNDS for phase in PHASES)
            if complete:
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            self.send_bytes(b"ok", "text/plain; charset=utf-8")
        except (ValueError, json.JSONDecodeError) as error:
            self.send_error(400, str(error))


def serve(path: Path, port: int, report_path: Path | None) -> None:
    if path.exists() and path.stat().st_size:
        raise ValueError("measurement output already contains data")
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("0.0.0.0", port), BenchmarkHandler)
    server.token = token
    server.output = path
    server.counts = {phase: 0 for phase in PHASES}
    server.count_lock = threading.Lock()
    ip = local_ipv4()
    print("Ölçüm sunucusu hazır. Konsol tarayıcısında bu baseline adresini açın:")
    print(f"Baseline : http://{ip}:{port}/?phase=baseline&token={token}")
    print("Baseline sayfası tamamlandığında etkin ölçüm bağlantısını gösterecek.")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    try:
        report = evaluate(path)
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        print(rendered)
        if report_path is not None:
            report_path.write_text(rendered + "\n", encoding="utf-8")
    except ValueError as error:
        if report_path is not None:
            report_path.write_text(json.dumps({"schema": SCHEMA, "passed": False, "error": str(error)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Henüz kabul raporu üretilemedi: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("serve")
    run.add_argument("output", type=Path)
    run.add_argument("--port", type=int, default=PORT)
    run.add_argument("--report", type=Path)
    check = sub.add_parser("evaluate")
    check.add_argument("input", type=Path)
    args = parser.parse_args()
    if args.command == "serve":
        if not 1024 <= args.port <= 65535:
            parser.error("port must be between 1024 and 65535")
        serve(args.output.resolve(), args.port, args.report.resolve() if args.report else None)
        return 0
    try:
        report = evaluate(args.input.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": SCHEMA, "passed": False, "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
