# DPI engine integration policy

KonsolLink does not silently download or execute an arbitrary third-party binary.

Production packages may integrate a pinned, checksum-verified DPI engine after its license and platform behavior have been reviewed.

Planned adapters:

- macOS: zapret-family BSD/macOS mechanism where technically viable.
- Linux: `nfqws`/NFQUEUE-style adapter with nftables/iptables selection scoped to the chosen console and Discord address set.
- Windows: WinDivert-based adapter, using either a reviewed GoodbyeDPI/zapret implementation or a small KonsolLink-specific adapter.

## macOS M2-A candidate

Legacy zapret `tpws` v72.13 is pinned and source-build qualified for adapter
development only. The exact source, license, toolchain and output hashes are in
`zapret-tpws-v72.13.toml`; `scripts/build_tpws_macos.sh` rejects every other
archive or build result. No engine executable is committed or approved for
distribution. See `docs/M2_ENGINE_QUALIFICATION.md`.

The developer-only `install-with-engine` path and non-root loopback lifecycle
fixture are documented in `docs/M2_ENGINE_PACKAGING.md`. They do not approve a
binary for release or enable interception.

## macOS userspace gateway candidate

The M2 acceptance build uses go-pcap2socks commit
`ec40773869e835bd09cb134e638e4e3333d89e0c` plus
`go-pcap2socks-ec407738-konsollink.patch`. The console uses `172.24.2.10/16`
with gateway `172.24.2.1`. UDP and default traffic use the direct outbound.
On macOS the gateway keeps all non-DNS sessions direct, matching the working
Windows reference. It reports the exact IPv4/TTL authority from each real
Discord DNS response over an inherited private channel. The privileged helper
installs the journal-backed, gateway-UID TCP/443 PF route and acknowledges it
before the gateway releases that DNS answer to the console.
The gateway drops to uid 65534 only after opening BPF; PF matches that UID.
tpws stays root because macOS requires root for `/dev/pf` destination lookup,
and its upstream sockets therefore cannot re-enter the gateway-only rule. Every
other TCP and UDP flow remains direct.

## Hard requirements

1. Interception filter MUST include the selected console identity/source address.
2. Discord TCP interception MUST be limited by dynamically maintained Discord destination sets and/or SNI/host classification.
3. UDP media interception MUST NOT be enabled globally just because a port falls in a broad media range.
4. Non-Discord traffic MUST use the direct outbound and MUST NOT receive DPI
   modification. M3 must measure the userspace gateway overhead before release.
5. Engine process lifetime MUST be owned by the privileged helper and terminated on rollback.
6. Version + SHA-256 + upstream license MUST be recorded in `THIRD_PARTY_NOTICES.md`.
