use std::process::Command;

#[test]
fn preflight_rejects_invalid_input_before_observing_network() {
    for args in [
        vec!["preflight", "--console", "not-an-ip"],
        vec!["preflight", "--console", "::1"],
        vec!["preflight", "--console", "192.0.2.10;echo bad"],
        vec!["preflight", "--apply"],
        vec!["preflight", "--console"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["ok"], false);
        assert_eq!(error["mode"], "preflight");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn preflight_reports_unsupported_platform() {
    let output = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
        .arg("preflight")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["error"], "unsupported platform");
}
