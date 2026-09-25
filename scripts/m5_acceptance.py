#!/usr/bin/env python3
"""One-pass, cross-platform physical acceptance recorder for KonsolLink 1.0."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

CHECKS = (
    ("services", "Konsol ağ testinde tüm hizmetler kullanılabilir mi?"),
    ("game", "Çevrimiçi oyun hesabına bağlanıp maç açılabiliyor mu?"),
    ("video", "YouTube videosu normal hızda oynuyor mu?"),
    ("discord_join", "Discord ses kanalına katılabiliyor mu?"),
    ("discord_downlink", "Karşı tarafın sesi duyuluyor mu?"),
    ("discord_uplink", "Mikrofon sesi karşı tarafa ulaşıyor mu?"),
    ("game_and_voice", "Discord açıkken oyun yeniden bağlanıp çalışıyor mu?"),
    ("download_and_voice", "İndirme sırasında Discord sesi kesintisiz mi?"),
    ("reconnect", "Konsol uyku/açılış sonrasında yeniden bağlanıyor mu?"),
    ("off_restores", "KonsolLink kapatılıp konsol Otomatik ağa alınınca normal bağlantı geri geliyor mu?"),
)


def answer(question: str) -> bool:
    while True:
        value = input(f"{question} [e/h]: ").strip().lower()
        if value in {"e", "evet", "y", "yes"}:
            return True
        if value in {"h", "hayır", "hayir", "n", "no"}:
            return False
        print("Evet için e, hayır için h yazın.")


def performance(path: Path | None) -> dict:
    if path is None:
        return {"passed": False, "reason": "missing_m3_report"}
    report = json.loads(path.read_text(encoding="utf-8"))
    required = {"passed", "checks", "delta"}
    if not required.issubset(report) or not isinstance(report["passed"], bool):
        raise ValueError("M3 performance report has an invalid schema")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True, choices=["ps5", "xbox-one", "xbox-series"])
    parser.add_argument("--host-os", required=True, choices=["macos-arm64", "windows-x64", "linux-x64"])
    parser.add_argument("--isp", required=True, choices=["turk-telekom", "turknet", "superonline", "vodafone"])
    parser.add_argument("--access", required=True, help="fiber, vdsl, cable, mobile, etc.")
    parser.add_argument("--ip-mode", required=True, choices=["ipv4", "cgnat", "dual-stack"])
    parser.add_argument("--performance-report", type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()

    print("KonsolLink 1.0 — tek birleşik fiziksel kabul")
    print("Önce normal Otomatik ağda oyun/video/NAT durumunu kontrol edin.")
    baseline_nat = input("Baseline NAT türü: ").strip()
    if not baseline_nat:
        raise SystemExit("Baseline NAT türü boş olamaz.")
    print("KonsolLink'i açın; konsolda 172.24.2.10/16, gateway 172.24.2.1, DNS 1.1.1.1, MTU 1486 kullanın.")
    input("Ağ hazır olduğunda Enter: ")
    enabled_nat = input("Etkin NAT türü: ").strip()
    checks = {key: answer(question) for key, question in CHECKS}
    checks["nat_unchanged"] = enabled_nat.casefold() == baseline_nat.casefold()
    perf = performance(args.performance_report)
    passed = all(checks.values()) and bool(perf.get("passed"))
    report = {
        "schema": 1,
        "product": "KonsolLink",
        "version": "1.0.0",
        "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "recorder_host": platform.platform(),
        "device": args.device,
        "host_os": args.host_os,
        "isp": args.isp,
        "access": args.access,
        "ip_mode": args.ip_mode,
        "baseline_nat": baseline_nat,
        "enabled_nat": enabled_nat,
        "checks": checks,
        "performance": perf,
        "passed": passed,
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Sonuç: {'GEÇTİ' if passed else 'GEÇMEDİ'} — {args.result}")
    print("Konsol ağ ayarını yeniden Otomatik yapın.")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Kabul kaydı üretilemedi: {error}", file=sys.stderr)
        raise SystemExit(2)
