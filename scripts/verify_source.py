from pathlib import Path
import os
import sys

root = Path(__file__).resolve().parents[1]
required = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "README.md",
    "LICENSE",
    "crates/konsollink-core/src/lib.rs",
    "crates/konsollink-platform/src/lib.rs",
    "helper/src/main.rs",
    "apps/desktop/src-tauri/tauri.conf.json",
    "apps/desktop/package-lock.json",
    "apps/desktop/src-tauri/icons/icon.png",
    "services/discord/profile.toml",
    "docs/RELEASE_CHECKLIST.md",
    "docs/M2_ENGINE_QUALIFICATION.md",
    "docs/M2_ENGINE_LIFECYCLE.md",
    "docs/M2_MACOS_PROCESS_ADAPTER.md",
    "docs/M2_ENGINE_PACKAGING.md",
    "docs/M2_TCP_INTERCEPTION.md",
    "docs/M2_RUNTIME_CONTROLLER.md",
    "docs/M2_ACCEPTANCE_TEST.md",
    "engines/zapret-tpws-v72.13.toml",
    "scripts/build_tpws_macos.sh",
    "scripts/test_tpws_lifecycle_macos.sh",
    "KonsolLink M2 Kabul Testi.command",
    "KonsolLink M3 Performans Testi.command",
    "docs/M3_PERFORMANCE_ALPHA.md",
    "engines/gateway.json",
    "engines/gateway-macos.json",
    "engines/go-pcap2socks-LICENSE",
    "engines/go-pcap2socks-ec407738-konsollink.patch",
    "scripts/build_macos_alpha.sh",
    "scripts/m3_benchmark.py",
    "scripts/package_manifest.py",
    "scripts/verify_gateway_policy.py",
    "engines/gateway-windows.json",
    "engines/platforms.toml",
    "services/discord/hosts.txt",
    "platform/windows/service/go.mod",
    "platform/windows/service/policy.go",
    "platform/windows/service/main_windows.go",
    "platform/windows/install.ps1",
    "platform/linux/konsollink-runtime.sh",
    "platform/linux/konsollink.service",
    "platform/linux/49-konsollink.rules",
    "platform/linux/install.sh",
    "scripts/build_windows_package.ps1",
    "scripts/build_linux_package.sh",
    "scripts/test_linux_runtime.sh",
    "docs/M4_CROSS_PLATFORM.md",
    "docs/M5_RELEASE.md",
    "CHANGELOG.md",
    "release/qualification.json",
    "helper/build.rs",
    "platform/macos/pkg-scripts/preinstall",
    "platform/macos/pkg-scripts/postinstall",
    "platform/macos/uninstall.sh",
    "scripts/build_macos_release.sh",
    "scripts/build_windows_release.ps1",
    "scripts/build_linux_release.sh",
    "scripts/generate_release_metadata.py",
    "scripts/security_audit.sh",
    "scripts/make_release_checksums.py",
    "scripts/m5_acceptance.py",
    "scripts/compile_qualification.py",
    "scripts/verify_release_qualification.py",
    "scripts/verify_release_source.py",
    "KonsolLink 1.0 Son Kabul Testi.command",
    ".github/workflows/release.yml",
]
missing = [p for p in required if not (root / p).exists()]
if missing:
    print("Missing:", *missing, sep="\n- ")
    sys.exit(1)

bad = []
executable_magic = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xca\xfe\xba\xbe": "Mach-O universal",
    b"\xbe\xba\xfe\xca": "Mach-O universal",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
    b"\xcf\xfa\xed\xfe": "Mach-O",
}
# Build output and installed dependencies are not vendored source. Prune only
# known output locations, so binaries elsewhere (including engines/) still fail.
generated = {
    ".git", "target", "apps/desktop/node_modules", "apps/desktop/dist",
    "vendor/pfctl/target", "apps/desktop/src-tauri/target", "apps/desktop/src-tauri/gen",
}
for directory, dirs, files in os.walk(root):
    parent = Path(directory)
    dirs[:] = [d for d in dirs if (parent / d).relative_to(root).as_posix() not in generated]
    for name in files:
        p = parent / name
        if p.suffix.lower() in {".exe", ".dll", ".sys", ".dylib", ".so"}:
            bad.append(str(p.relative_to(root)))
            continue
        try:
            with p.open("rb") as source:
                header = source.read(4)
        except OSError as error:
            print(f"Cannot inspect {p.relative_to(root)}: {error}")
            sys.exit(1)
        if any(header.startswith(magic) for magic in executable_magic):
            bad.append(str(p.relative_to(root)))
if bad:
    print("Unexpected vendored binaries:", bad)
    sys.exit(1)

print("KonsolLink source package structure: OK")
