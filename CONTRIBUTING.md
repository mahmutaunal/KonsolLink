# Contributing

KonsolLink is deliberately narrow: PlayStation/Xbox + Discord connectivity for Türkiye without a remote VPN.

By submitting a contribution, you agree that your contribution is licensed
under GPL-3.0-only, the same license as the original KonsolLink code. Do not
submit code, media or other material that you do not have the right to license
under compatible terms. Third-party material must retain its own notices.

macOS on Apple Silicon with Türk Telekom and PlayStation 5 is currently the
only physically verified target. Do not describe Windows, Linux, Xbox or other
ISPs as supported until their physical acceptance evidence has been completed.

Pull requests that route all console traffic through a remote proxy/VPN, add telemetry by default, or broaden DPI interception to unrelated traffic conflict with the product architecture.

Use the Rust version in `rust-toolchain.toml` and Node version in `.nvmrc`.
Commit both dependency lockfiles. Use `npm ci` and Cargo `--locked` for validation;
do not regenerate lockfiles as part of ordinary CI. Follow the complete local
validation sequence in README before submitting changes. Full workspace checks
include Tauri and require its platform dependencies and a frontend build.

The source-policy check excludes known dependency/build directories but rejects
vendored executables elsewhere, including `engines/`. Desktop icons are generated
from the project's own `apps/desktop/app-icon.svg`; they are not third-party assets.

Before network-backend changes:
1. document the OS rule/filter;
2. show its console scope;
3. show its Discord scope;
4. provide rollback behavior;
5. include packet-capture evidence that non-Discord flows are not sent to the DPI engine.
