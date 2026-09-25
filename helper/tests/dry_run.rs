use std::process::Command;

#[test]
fn dry_run_completes_in_off_state() {
    for (family, ip) in [("playstation", "192.0.2.10"), ("xbox", "2001:db8::10")] {
        let output = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
            .args(["dry-run", family, ip])
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["ok"], true);
        assert_eq!(status["mode"], "dry-run");
        assert_eq!(status["state"], "Off");
        assert_eq!(status["ip"], ip);
    }
}

#[test]
fn invalid_cli_input_fails_without_panic() {
    for args in [
        vec![],
        vec!["enable", "playstation", "192.0.2.10"],
        vec!["dry-run", "unknown", "192.0.2.10"],
        vec!["dry-run", "playstation", "not-an-ip"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_konsollink-helper"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("\"ok\":false"));
        assert!(!stderr.contains("panicked"));
    }
}
