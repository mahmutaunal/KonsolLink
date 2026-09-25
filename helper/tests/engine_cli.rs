#[cfg(target_os = "macos")]
#[test]
fn hidden_engine_child_mode_rejects_unprivileged_callers_and_extra_arguments() {
    let binary = env!("CARGO_BIN_EXE_konsollink-helper");
    // The normal test account is intentionally unprivileged. If a test runner
    // is root, skip this half rather than attempting the fixed engine path.
    if unsafe { libc::geteuid() } != 0 {
        let output = std::process::Command::new(binary)
            .args(["__engine-child", "gateway"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("root engine wrapper required"));
    }

    let output = std::process::Command::new(binary)
        .args(["__engine-child", "gateway", "/tmp/other-engine"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
