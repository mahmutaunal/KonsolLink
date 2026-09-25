# Third-party notices

No third-party DPI engine executable is included in this source tree. Build outputs
and installed package-manager dependencies are excluded from the source archive.

Engine components (not bundled in the source tree):

- **zapret `tpws` v72.13** by bol-van — MIT; integrated macOS M2 test engine,
  source-build qualified but not approved for binary distribution. Pinned
  commit `87e058624c72863db53bdaf7fb6f16576dddb6ab`; official release archive
  SHA-256 `25c74e6c5f48963fa244c2955e76694a07c39447245a0457e2efdc74b3317e68`;
  license SHA-256 `dcf5abd3e5d876c1065982871c0cec7368c0e61fc795c541798729516bb6b54f`.
  The exact build record is in `engines/zapret-tpws-v72.13.toml`. Preserve the
  upstream MIT notice if source or binary is distributed.
- **go-pcap2socks** by Daniil Sokolyuk — GPL-3.0; macOS M2 acceptance gateway,
  pinned to commit `ec40773869e835bd09cb134e638e4e3333d89e0c` (upstream
  0.3.0 development line). KonsolLink's reviewed patch adds transport-specific
  routing and removes the debug HTTP listener. The patch and license are in
  `engines/`; the arm64 test artifact SHA-256 is
  `0345531054e54fbcb4f66d065a700b3f847b4b4c8ec9a8884f383619d6d046ed`.
  Every M4/M5 binary package includes the corresponding pinned upstream source,
  the KonsolLink patch and GPL terms.
- **zapret2** by bol-van — current upstream generation, MIT; not a macOS
  candidate because upstream marks macOS unsupported.
- **GoodbyeDPI 0.2.2** by ValdikSS — Windows DPI circumvention utility,
  Apache-2.0. Official archive SHA-256
  `00a2f8b99cd817f8c7fc4c449033015f039d18af213de78cb66bf202277c0628`;
  x64 executable SHA-256
  `331ac6c1d22ba5a0a217f3f27d0d823051869cafc8b8ef7f2002fa2accebc74e`.
- **WinDivert** — Windows packet capture/diversion driver/library. M4 packages
  the matching DLL/driver shipped in GoodbyeDPI 0.2.2 (SHA-256
  `a97859785a2df1d4462e7d48d33ccbd89fedd40dac4970f4afd89e63f59ee1ec`
  and `53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af`)
  and preserves the bundled license directory. Official WinDivert 2.2.2-A
  archive hash is recorded as an independent reference in `engines/platforms.toml`.
- **Tauri** and Rust crates — retain notices required by their respective licenses.

M5 generates the complete dependency/license report and CycloneDX SBOM into
`target/release-metadata`; release packages publish both with these notices.

## P0 dependency inventory

The exact Rust dependency graph is recorded in `Cargo.lock`; frontend/build tools
are recorded in `apps/desktop/package-lock.json`. Direct dependencies resolved at
P0 are serde 1.0.229, serde_json 1.0.151, thiserror 2.0.20, toml 0.8.23,
tauri 2.11.6, tauri-build 2.6.3, @tauri-apps/api 2.11.1,
@tauri-apps/cli 2.11.5, TypeScript 5.9.3, and Vite 6.4.3.

This P0 snapshot is superseded by the generated M5 transitive license report and
SBOM. Desktop icons are original
KonsolLink assets generated from `apps/desktop/app-icon.svg` are original
project material under GPL-3.0-only. Third-party names and marks remain the
property of their respective owners.

M0-B1 additionally uses libc 0.2.189 directly in the Unix helper infrastructure
(previously present transitively in the lockfile). No third-party networking
executable was added.

M2 uses sha2 0.10.9 directly for descriptor-based engine artifact verification;
it was already present transitively in `Cargo.lock`. The M2 acceptance package
builds the artifact into ignored `target/` output from the hash-checked official
archive. No engine executable is stored in the source package.

## M0 PF implementation

The macOS helper links **pfctl 0.7.0**, upstream Mullvad VPN AB, under the
MIT OR Apache-2.0 license. Audited source is in `vendor/pfctl`; retain its
`LICENSE-MIT`, `LICENSE-APACHE` and `KONSOLLINK_PATCH.md` when redistributing.
Upstream archive SHA-256:
`944d2c073758b6bda57f517cff54cf69d74eae3593fe1e9aa9918666543456a9`.
Local patches fix address masks/direction/ports in state cleanup, pool storage
and lifetime, state snapshot bounds, and add scoped health/state inspection.
Tests and exact scope are documented in the vendor patch record.

New transitive packages include derive_builder/darling 0.20.x, ioctl-sys 0.8.0,
and ipnetwork 0.21.1; exact versions remain in the lockfiles. No DPI engine or
networking executable is committed to the repository; M5 builds them from pinned
sources and publishes the generated SBOM and transitive license aggregation.
