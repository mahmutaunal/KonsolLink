# Security policy and design

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** in the repository's Security tab.
Include the affected KonsolLink version, host operating system, reproduction
steps and the smallest diagnostics needed to reproduce the issue. Do not include
Discord credentials, packet payloads or unrelated browsing data, and do not open
a public issue before a coordinated fix is available.

The release owner acknowledges a private report within seven calendar days,
assigns severity and affected versions, and publishes a GitHub Security Advisory
with the fixed release. There is no remote telemetry or in-app report upload.

## Trust boundaries

- The Tauri UI is unprivileged. It sends structured start/stop/status requests
  and cannot supply paths, commands, service names, engine arguments or rules.
- macOS authenticates the local UID over a root-owned Unix socket. Windows uses
  a fixed LocalSystem SCM service with a start/stop-only ACL. Linux uses a fixed
  systemd unit and a local, active admin polkit rule.
- Runtime artifacts live in root/administrator-owned directories and are
  verified against closed SHA-256 manifests before execution.
- macOS process groups, Windows kill-on-close Job Objects and Linux systemd
  control groups prevent orphan engines. A required child exit closes the whole
  session.
- The userspace gateway changes no host NAT, forwarding, firewall or DNS state.
  It opens no WAN management listener and uses no remote VPN or proxy.
- DPI transformation is constrained to the exact Discord host roots embedded in
  `services/discord/profile.toml`; source verification rejects hostlist drift.
- Packet capture output is disabled. Payloads, tokens, credentials, DNS history
  and browsing history are never written to diagnostics.

## Supply chain

`Cargo.lock`, `apps/desktop/package-lock.json` and `platform/windows/service/go.sum`
are mandatory. Native engines are pinned by commit/release and official archive
SHA-256 in `engines/platforms.toml`. Release packages carry the corresponding
go-pcap2socks source, local patch, native licenses, CycloneDX 1.6 SBOM, complete
license inventory, per-platform manifest and SHA-256 list.

The release workflow requires RustSec cargo-audit 0.22.2 and npm audit to report
zero known vulnerabilities. Seven current RustSec informational warnings are
reviewed by exact advisory ID and any change fails the build:

- `RUSTSEC-2024-0370`: unmaintained proc-macro build dependency.
- `RUSTSEC-2025-0075`, `0080`, `0081`, `0098`, `0100`: unmaintained UNIC
  dependencies in the Linux GTK/WebKit build graph.
- `RUSTSEC-2024-0429`: an unsound `glib::VariantStrIter` implementation in the
  target-specific Linux Tauri GTK graph. KonsolLink does not call that iterator;
  it remains recorded until the upstream Tauri/WebKitGTK graph removes glib
  0.18.5.

These are warnings rather than known exploitable vulnerabilities in KonsolLink.
They are visible in the published audit report and are not wildcard-suppressed.

macOS stable artifacts require Developer ID Application/Installer signatures,
Apple notarization and stapling. Windows stable artifacts require Authenticode
signatures on the Tauri installer, service and patched gateway. Missing secrets
fail the workflow; only explicitly named local RC builds may use ad-hoc/unsigned
signatures. GitHub release assets receive build-provenance attestations.
