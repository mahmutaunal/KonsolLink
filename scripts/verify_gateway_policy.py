#!/usr/bin/env python3
"""Fail closed if the shipped userspace routing policy broadens."""

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
profile_lines = (root / "services/discord/profile.toml").read_text(encoding="utf-8").splitlines()
profile_domains = []
inside_domains = False
for line in profile_lines:
    stripped = line.strip()
    if stripped == "domains = [":
        inside_domains = True
    elif inside_domains and stripped == "]":
        break
    elif inside_domains and stripped:
        profile_domains.append(stripped.strip(',').strip('"'))

config = json.loads((root / "engines/gateway.json").read_text(encoding="utf-8"))
expected = {
    "pcap": {"network": "172.24.0.0/16", "localIP": "172.24.2.1", "mtu": 1486},
    "dns": {"servers": [{"address": "local"}]},
    "routing": {"rules": [
        {"network": "udp", "dstPort": "53", "outboundTag": "dns-out"},
        {"network": "tcp", "dstPort": "80,443", "dstDomain": profile_domains, "outboundTag": "discord-tcp"},
    ]},
    "outbounds": [
        {"tag": "", "direct": {}},
        {"tag": "discord-tcp", "socks": {"address": "127.0.0.1:19081"}},
        {"tag": "dns-out", "dns": {}},
    ],
    "capture": {"enabled": False},
}
if config != expected:
    print("Linux gateway policy is broader than the reviewed M3 allowlist.", file=sys.stderr)
    raise SystemExit(1)

macos_config = json.loads((root / "engines/gateway-macos.json").read_text(encoding="utf-8"))
macos_expected = {
    "pcap": {"network": "172.24.0.0/16", "localIP": "172.24.2.1", "mtu": 1486},
    "dns": {"servers": [{"address": "local"}]},
    "routing": {"rules": [
        {"network": "udp", "dstPort": "53", "outboundTag": "dns-out"},
        {
            "network": "tcp",
            "dstPort": "80,443",
            "dstDomain": [
                "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                "discord.net", "discord.media", "discordcdn.com", "gateway.discord.gg",
                "cdn.discordapp.com", "media.discordapp.net", "images-ext-1.discordapp.net",
                "dl.discordapp.net", "stable.dl2.discordapp.net", "updates.discord.com",
            ],
            "outboundTag": "",
        },
    ]},
    "outbounds": [
        {"tag": "", "direct": {}},
        {"tag": "dns-out", "dns": {}},
    ],
    "capture": {"enabled": False},
}
if macos_config != macos_expected:
    print("macOS gateway policy no longer keeps sessions direct while tracking Discord DNS authority.", file=sys.stderr)
    raise SystemExit(1)

direct_expected = {
    "pcap": {"network": "172.24.0.0/16", "localIP": "172.24.2.1", "mtu": 1486},
    "dns": {"servers": [{"address": "local"}]},
    "routing": {"rules": [
        {"network": "udp", "dstPort": "53", "outboundTag": "dns-out"},
    ]},
    "outbounds": [
        {"tag": "", "direct": {}},
        {"tag": "dns-out", "dns": {}},
    ],
    "capture": {"enabled": False},
}
windows_config = json.loads((root / "engines/gateway-windows.json").read_text(encoding="utf-8"))
if windows_config != direct_expected:
    print("Windows gateway policy no longer keeps all non-DNS traffic direct.", file=sys.stderr)
    raise SystemExit(1)

hosts = (root / "services/discord/hosts.txt").read_text(encoding="ascii").splitlines()
if hosts != profile_domains or len(hosts) != len(set(hosts)):
    print("Native engine hostlist differs from the embedded Discord profile.", file=sys.stderr)
    raise SystemExit(1)
patch = (root / "engines/go-pcap2socks-ec407738-konsollink.patch").read_text(encoding="utf-8")
required_patch_controls = (
    "Network",
    "DstDomain",
    "DomainTracker",
    'rule.Network != metadata.Network.String()',
    'http.ListenAndServe(":8085"',
    "AfterCaptureOpen",
    "platformPrivilegeDrop()",
    "const runtimeUID = 65534",
    "syscall.Setgroups([]int{runtimeUID})",
    "syscall.Setgid(runtimeUID)",
    "syscall.Setuid(runtimeUID)",
    "diff --git a/proxy/domain_tracker.go b/proxy/domain_tracker.go",
    "diff --git a/proxy/domain_tracker_test.go b/proxy/domain_tracker_test.go",
    "diff --git a/proxy/policy.go b/proxy/policy.go",
    "diff --git a/proxy/doh.go b/proxy/doh.go",
    '"https://cloudflare-dns.com/dns-query"',
    '"https://dns.google/dns-query"',
    'request.Header.Set("Content-Type", "application/dns-message")',
    "policyRefreshInterval",
    "Discord DNS policy was not installed",
)
if any(control not in patch for control in required_patch_controls):
    print("Pinned gateway patch is missing a reviewed routing or privilege control.", file=sys.stderr)
    raise SystemExit(1)

engine_source = (root / "helper/src/engine/macos.rs").read_text(encoding="utf-8")
gateway_source = (root / "helper/src/gateway/macos.rs").read_text(encoding="utf-8")
pfctl_source = (root / "vendor/pfctl/src/lib.rs").read_text(encoding="utf-8")
service_source = (root / "scripts/m0-service.sh").read_text(encoding="utf-8")
if "pub const GATEWAY_RUNTIME_UID: u32 = 65_534;" not in engine_source:
    print("The helper gateway UID differs from the reviewed macOS runtime UID.", file=sys.stderr)
    raise SystemExit(1)
if "--user=root" not in engine_source or "--uid=65534" in engine_source:
    print("The macOS tpws policy must retain root for PF DIOCNATLOOK.", file=sys.stderr)
    raise SystemExit(1)
if ".user(GATEWAY_RUNTIME_UID)" not in gateway_source:
    print("The macOS PF rule no longer excludes the gateway runtime UID.", file=sys.stderr)
    raise SystemExit(1)
if "resolve_macos_discord" in gateway_source or "resolve_macos_discord" in engine_source:
    print("macOS must not authorize PF destinations from an independent host DNS snapshot.", file=sys.stderr)
    raise SystemExit(1)
if "KONSOLLINK_POLICY_FD" not in engine_source or "acknowledge_userspace_policy" not in gateway_source:
    print("The process-private DNS policy acknowledgement channel is missing.", file=sys.stderr)
    raise SystemExit(1)
health_source = gateway_source.split("fn interception_health", 1)[1].split("impl ProcessBackend", 1)[0]
if 'Command::new("/usr/bin/curl")' in health_source:
    print("PF installation health must not perform an independent DNS-based curl probe.", file=sys.stderr)
    raise SystemExit(1)
if gateway_source.count('arg("--resolve")') < 2:
    print("Discord readiness must pin both REST and WebSocket probes to acknowledged IPs.", file=sys.stderr)
    raise SystemExit(1)
if "has_uid_routes" not in gateway_source or "pub fn has_uid_routes" not in pfctl_source:
    print("Transparent PF health no longer verifies the exact gateway-UID route rules.", file=sys.stderr)
    raise SystemExit(1)
if "--user=root" not in service_source or "--uid=65534" in service_source:
    print("The service dry-run no longer mirrors the reviewed tpws identity.", file=sys.stderr)
    raise SystemExit(1)
print("KonsolLink gateway policy: macOS and Windows keep sessions host-local/direct; Linux allowlist closed; capture off.")
