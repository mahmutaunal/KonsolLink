# Architecture

## Data path

The console uses a fixed virtual IPv4 network whose gateway is announced by
go-pcap2socks on the existing LAN interface. No host address, route, NAT, DNS
or forwarding setting is changed. macOS temporarily owns only its namespaced,
journaled PF filter/redirect anchors.

```text
console 172.24.2.10/16
        |
        v Ethernet capture/ARP (172.24.2.1)
go-pcap2socks userspace TCP/IP stack
        |
        +-- UDP + ordinary TCP --> direct host sockets --> Internet
        +-- ordinary DNS --------> local resolver
        +-- Discord DNS ---------> fixed DoH fallback -- exact IP/TTL policy ACK
        +-- authorized TCP/443 --> host-scoped DPI adapter
                                      |-- macOS: PF + transparent tpws
                                      |-- Linux: tpws SOCKS hostlist
                                      `-- Windows: GoodbyeDPI WinDivert hostlist
```

On macOS, go-pcap2socks opens BPF while privileged and drops to fixed uid 65534
before the stack can create a socket. For Discord answers, the internal resolver
uses fixed Cloudflare/Google DNS-over-HTTPS endpoints because the target ISP can
drop plain Discord DNS while leaving unrelated DNS intact. It sends the actual
IPv4/TTL set through an inherited bidirectional socket and
withholds the console response until the helper acknowledges the exact rules.
A journal-backed PF anchor routes only that UID's TCP/443 connections for this
set to transparent tpws. Readiness is pinned to an acknowledged IP rather than
performing an independent host DNS lookup. tpws stays root for macOS `/dev/pf` destination lookup, so
its upstream sockets cannot loop back into the uid-65534 rule. The hostlist
still limits tampering to Discord names.
Linux routes only DNS-learned Discord TCP destinations through its explicit
tpws SOCKS outbound. Windows direct sockets
traverse a host-local WinDivert adapter configured with the same exact allowlist. Game,
download and Discord UDP voice traffic remain direct. The service domain list
is generated from `services/discord/profile.toml` and source verification
rejects drift.

## Privilege and lifecycle

The Tauri UI is unprivileged and issues structured start/stop/status commands.
It cannot provide executable paths, engine arguments, service names or network
rules. The platform service verifies fixed artifacts and owns both child
processes. macOS uses a journal and process group, Windows a Job Object, and
Linux a systemd control group. A child failure invalidates the session and stops
its sibling. No remote control API or WAN listener exists.

## Performance boundary

All console flows necessarily cross the userspace TCP/IP gateway because the
console uses its separate virtual address. DPI transformation remains
Discord-only; direct flows never enter the DPI engine. M3 measures the gateway
cost separately and enforces the release targets of no more than 1% non-Discord
throughput loss and under 1 ms median added LAN latency.
