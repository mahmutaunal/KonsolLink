use std::process::Command;

#[test]
fn journal_command_cannot_select_filesystem_paths() {
    let result = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
        .args(["journal-status", "--path", "/tmp/untrusted"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["mode"], "journal-status");
    assert_eq!(
        error["error"],
        "journal-status accepts no arguments or custom paths"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn journal_command_does_not_self_elevate() {
    // Never initialize system storage in a root-run test suite.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let result = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
        .arg("journal-status")
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert!(error["error"].as_str().unwrap().contains("root required"));
}
