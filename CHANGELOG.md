# KonsolLink 1.0.0

- Added the fixed `172.24.2.10/16` userspace console gateway for PlayStation and
  Xbox without host NAT, forwarding, firewall mutation or a remote VPN.
- Kept ordinary game, video, download and Discord UDP traffic on direct sockets;
  DPI transformation uses the exact Discord host profile only.
- Added recovery-safe macOS launch daemon, Windows SCM/Job Object and Linux
  systemd/polkit runtimes with fixed paths, hash verification and child health.
- Added controlled performance measurement with full payload integrity, at most
  1% non-Discord throughput-loss and below 1 ms median added-latency gates.
- Added signed/notarized platform release pipelines, CycloneDX SBOM, complete
  license inventory, corresponding GPL source, SHA-256 manifests and GitHub
  provenance attestations.
- Added one consolidated physical acceptance flow and a publication gate that
  rejects incomplete console/OS/ISP evidence.
