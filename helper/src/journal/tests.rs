use super::*;
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static ID: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "konsollink-journal-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> Store {
        Store::open_test(&self.0).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// A real disk-backed test fixture, never system networking. Backend writes are
// fsynced so subprocess exits exercise journal vs external-state crash windows.
struct Fixture {
    path: PathBuf,
    writes: Vec<Setting>,
    exit_after_write: bool,
    fail_write: bool,
}
impl Fixture {
    fn new(root: &Path) -> Self {
        let path = root.join("fixture.json");
        if !path.exists() {
            fs::write(&path, "[0,0,1]").unwrap();
        }
        Self {
            path,
            writes: vec![],
            exit_after_write: false,
            fail_write: false,
        }
    }
    fn values(&self) -> [u32; 3] {
        serde_json::from_slice(&fs::read(&self.path).unwrap()).unwrap()
    }
    fn put(&self, values: [u32; 3]) {
        let mut file = File::create(&self.path).unwrap();
        file.write_all(&serde_json::to_vec(&values).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
}
fn index(setting: Setting) -> usize {
    match setting {
        Setting::Ipv4Forwarding => 0,
        Setting::Ipv6Forwarding => 1,
        Setting::IcmpRedirects => 2,
    }
}
impl SettingsBackend for Fixture {
    fn read(&mut self, setting: Setting) -> Result<u32> {
        Ok(self.values()[index(setting)])
    }
    fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
        if self.fail_write {
            return Err(Error::Backend("injected write failure".into()));
        }
        let mut values = self.values();
        values[index(setting)] = value;
        self.put(values);
        self.writes.push(setting);
        if self.exit_after_write {
            std::process::exit(78);
        }
        Ok(())
    }
}
const PLAN: &[(Setting, u32)] = &[(Setting::Ipv4Forwarding, 1), (Setting::IcmpRedirects, 0)];

#[test]
fn userspace_gateway_does_not_change_kernel_forwarding() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = GatewayFixture::new(&temp.0);
    let mut plan = crate::gateway::tests::plan();
    plan.mode = crate::gateway::Mode::Userspace;
    plan.console = "172.24.2.10".parse().unwrap();
    plan.host = "172.24.2.1".parse().unwrap();
    plan.uplink_host = Some("192.168.1.165".parse().unwrap());
    plan.prefix = 16;
    store.prepare_gateway(&mut backend, plan).unwrap();
    store.apply(&mut backend).unwrap();
    assert!(backend.settings.writes.is_empty());
    assert_eq!(backend.settings.values(), [0, 0, 1]);
    assert_eq!(backend.pf_values(), [false, false, false]);
    store.rollback(&mut backend).unwrap();
    assert!(backend.settings.writes.is_empty());
}

#[test]
fn apply_and_reverse_rollback_are_persistent_and_idempotent() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    store.apply(&mut backend).unwrap();
    assert_eq!(backend.values(), [1, 0, 0]);
    assert_eq!(store.load().unwrap().unwrap().phase, Phase::Active);
    assert!(matches!(
        store.prepare(&mut backend, PLAN),
        Err(Error::RecoveryRequired)
    ));
    drop(store);
    let mut store = temp.store();
    backend.writes.clear();
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.values(), [0, 0, 1]);
    assert_eq!(
        backend.writes,
        [Setting::IcmpRedirects, Setting::Ipv4Forwarding]
    );
    let writes = backend.writes.len();
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.writes.len(), writes);
    store.prepare(&mut backend, PLAN).unwrap();
    assert_eq!(store.load().unwrap().unwrap().generation, 2);
}

#[test]
fn second_owner_cannot_take_lock_and_lock_is_released_on_drop() {
    let temp = Temp::new();
    let store = temp.store();
    assert!(matches!(Store::open_test(&temp.0), Err(Error::Locked)));
    drop(store);
    assert!(Store::open_test(&temp.0).is_ok());
}

#[test]
fn journal_failure_prevents_side_effects_and_poisoned_store_cannot_continue() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    store.fail_save = true;
    assert!(store.apply(&mut backend).is_err());
    assert!(backend.writes.is_empty());
    assert!(matches!(store.rollback(&mut backend), Err(Error::Poisoned)));
    drop(store);
    let mut reopened = temp.store();
    reopened.rollback(&mut backend).unwrap();
    assert_eq!(backend.values(), [0, 0, 1]);
}

#[test]
fn backend_write_error_leaves_recoverable_intent() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    backend.fail_write = true;
    assert!(store.apply(&mut backend).is_err());
    assert_eq!(store.load().unwrap().unwrap().changes[0].step, Step::Intent);
    backend.fail_write = false;
    store.rollback(&mut backend).unwrap();
    assert!(backend.writes.is_empty());
}

#[test]
fn persistence_failure_after_mutation_retains_intent_for_restart() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    store.fail_save_number = Some(4); // Applied marker, after external write.
    assert!(store.apply(&mut backend).is_err());
    assert_eq!(backend.values(), [1, 0, 1]);
    assert!(matches!(store.load(), Err(Error::Poisoned)));
    drop(store);
    let mut store = temp.store();
    assert_eq!(store.load().unwrap().unwrap().changes[0].step, Step::Intent);
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.values(), [0, 0, 1]);
}

#[test]
fn rollback_error_preserves_evidence_and_retry_finishes() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    store.apply(&mut backend).unwrap();
    backend.fail_write = true;
    assert!(store.rollback(&mut backend).is_err());
    assert_eq!(store.load().unwrap().unwrap().phase, Phase::RollingBack);
    backend.fail_write = false;
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.values(), [0, 0, 1]);
}

#[test]
fn oversized_journal_is_rejected() {
    let temp = Temp::new();
    private_file(&temp.0.join("journal.json"), &vec![b' '; 65_537]);
    assert!(matches!(
        Store::open_test(&temp.0),
        Err(Error::Invalid("journal size limit"))
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_is_rejected_even_when_mode_is_private() {
    let temp = Temp::new();
    let result = Command::new("/bin/chmod")
        .args(["+a", "everyone allow readattr"])
        .arg(&temp.0)
        .status()
        .unwrap();
    assert!(result.success());
    assert!(matches!(
        Store::open_test(&temp.0),
        Err(Error::Unsafe("extended ACL entries are not accepted"))
    ));
}

#[test]
fn unexpected_external_value_is_preserved_and_blocks_rollback() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    store.apply(&mut backend).unwrap();
    backend.put([2, 0, 0]);
    assert!(matches!(
        store.rollback(&mut backend),
        Err(Error::Conflict(Setting::Ipv4Forwarding))
    ));
    assert_eq!(backend.values(), [2, 0, 1]);
    assert_eq!(store.load().unwrap().unwrap().phase, Phase::RollingBack);
}

#[test]
fn pending_operations_do_not_undo_external_changes() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    backend.put([1, 0, 1]);
    assert!(matches!(store.apply(&mut backend), Err(Error::Conflict(_))));
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.values(), [1, 0, 1]);
    assert!(backend.writes.is_empty());
}

#[test]
fn invalid_plans_have_no_side_effects_or_journal() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    for plan in [
        vec![(Setting::Ipv4Forwarding, 2)],
        vec![(Setting::Ipv4Forwarding, 1), (Setting::Ipv4Forwarding, 0)],
    ] {
        assert!(store.prepare(&mut backend, &plan).is_err());
    }
    assert!(store.load().unwrap().is_none());
    assert!(backend.writes.is_empty());
}

fn private_file(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn corrupt_or_future_journal_is_preserved_not_reset() {
    for data in [
        b"not json".as_slice(),
        br#"{"schema_version":4,"generation":1,"phase":"complete","changes":[]}"#,
        br#"{"schema_version":1,"generation":1,"phase":"active","changes":[],"shell":"bad"}"#,
    ] {
        let temp = Temp::new();
        private_file(&temp.0.join("journal.json"), data);
        assert!(Store::open_test(&temp.0).is_err());
        assert_eq!(fs::read(temp.0.join("journal.json")).unwrap(), data);
    }
}

#[test]
fn unsafe_files_and_directory_are_rejected() {
    let temp = Temp::new();
    let victim = temp.0.join("victim");
    private_file(&victim, b"original");
    for name in ["helper.lock", "journal.json", "journal.next"] {
        let path = temp.0.join(name);
        symlink(&victim, &path).unwrap();
        assert!(Store::open_test(&temp.0).is_err());
        fs::remove_file(path).unwrap();
    }
    assert_eq!(fs::read(&victim).unwrap(), b"original");
    fs::hard_link(&victim, temp.0.join("journal.json")).unwrap();
    assert!(Store::open_test(&temp.0).is_err());
    fs::remove_file(temp.0.join("journal.json")).unwrap();
    fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Store::open_test(&temp.0).is_err());
}

#[test]
fn stale_uncommitted_temp_is_discarded_without_hiding_committed_journal() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = Fixture::new(&temp.0);
    store.prepare(&mut backend, PLAN).unwrap();
    drop(store);
    private_file(&temp.0.join("journal.next"), b"truncated write");
    let store = temp.store();
    assert_eq!(store.load().unwrap().unwrap().phase, Phase::Prepared);
    assert!(!temp.0.join("journal.next").exists());
}

#[test]
fn invalid_phase_ordering_is_rejected() {
    let journal = Journal {
        gateway: None,
        gateway_step: GatewayStep::Pending,
        engine: None,
        interception: None,
        schema_version: 1,
        generation: 1,
        phase: Phase::Applying,
        changes: vec![
            Change {
                setting: Setting::Ipv4Forwarding,
                before: 0,
                after: 1,
                step: Step::Pending,
            },
            Change {
                setting: Setting::IcmpRedirects,
                before: 1,
                after: 0,
                step: Step::Applied,
            },
        ],
    };
    assert!(journal.validate().is_err());
}

#[test]
fn schema_one_without_engine_remains_recoverable() {
    let temp = Temp::new();
    private_file(
        &temp.0.join("journal.json"),
        br#"{"schema_version":1,"generation":7,"phase":"complete","changes":[],"gateway_step":"pending"}"#,
    );
    let store = temp.store();
    let journal = store.load().unwrap().unwrap();
    assert_eq!(journal.schema_version, 1);
    assert!(journal.engine.is_none());
}

#[test]
fn completed_journal_accepts_a_retired_engine_hash_but_active_one_does_not() {
    let gateway = crate::gateway::tests::plan();
    let retired = EngineRecord {
        plan: EnginePlan {
            artifact_sha256: "a".repeat(64),
            ..EnginePlan::konsollink_gateway()
        },
        process: None,
        step: EngineStep::Restored,
    };
    let completed = Journal {
        schema_version: 2,
        generation: 1,
        phase: Phase::Complete,
        changes: vec![],
        gateway: Some(gateway.clone()),
        gateway_step: GatewayStep::Restored,
        engine: Some(retired.clone()),
        interception: None,
    };
    assert!(completed.validate().is_ok());

    let active = Journal {
        phase: Phase::Active,
        gateway_step: GatewayStep::Applied,
        engine: Some(EngineRecord {
            step: EngineStep::Applied,
            process: Some(crate::engine::ProcessIdentity {
                pid: 4242,
                birth_seconds: 1,
                birth_micros: 0,
            }),
            ..retired
        }),
        ..completed
    };
    assert!(matches!(
        active.validate(),
        Err(Error::Invalid("engine plan is not allowlisted"))
    ));
}

// Invoked only by the subprocess recovery test. exit() skips Rust destructors,
// exercising kernel lock release and restart from persisted journal evidence.
#[test]
fn crash_child() {
    let Ok(root) = std::env::var("KONSOLLINK_TEST_JOURNAL") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut store = Store::open_test(&root).unwrap();
    let mut backend = Fixture::new(&root);
    let mode = std::env::var("KONSOLLINK_TEST_CRASH").unwrap();
    if mode == "external-write" {
        backend.exit_after_write = true;
    } else {
        let (save, point) = mode.split_once(':').unwrap();
        store.crash_at = Some((save.parse().unwrap(), point.parse().unwrap()));
    }
    store
        .prepare(&mut backend, &[(Setting::Ipv4Forwarding, 1)])
        .unwrap();
    store.apply(&mut backend).unwrap();
    store.rollback(&mut backend).unwrap();
    panic!("crash checkpoint was not reached");
}

#[test]
fn subprocess_crashes_at_every_persistence_boundary_recover() {
    // One-operation lifecycle makes 8 journal saves. Each crash stops before
    // rename, after file sync, after rename, or after the final directory sync.
    let mut modes = vec!["external-write".to_owned()];
    for save in 1..=8 {
        for point in 1..=4 {
            modes.push(format!("{save}:{point}"));
        }
    }
    for mode in modes {
        let temp = Temp::new();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "journal::tests::crash_child", "--nocapture"])
            .env("KONSOLLINK_TEST_JOURNAL", &temp.0)
            .env("KONSOLLINK_TEST_CRASH", &mode)
            .output()
            .unwrap();
        assert!(
            matches!(result.status.code(), Some(77 | 78)),
            "{mode}: {:?}",
            result
        );
        let mut store = temp.store();
        let mut backend = Fixture::new(&temp.0);
        store.rollback(&mut backend).unwrap();
        assert_eq!(backend.values(), [0, 0, 1], "{mode}");
        store.rollback(&mut backend).unwrap();
        assert_eq!(backend.values(), [0, 0, 1]);
    }
}

struct GatewayFixture {
    settings: Fixture,
    pf: PathBuf,
    boot_matches: bool,
    mutations: usize,
    crash_after: usize,
}
impl GatewayFixture {
    fn new(path: &Path) -> Self {
        let pf = path.join("pf-fixture.json");
        if !pf.exists() {
            fs::write(&pf, "[false,false,false]").unwrap();
        }
        Self {
            settings: Fixture::new(path),
            pf,
            boot_matches: true,
            mutations: 0,
            crash_after: usize::MAX,
        }
    }
    fn checkpoint(&mut self) {
        self.mutations += 1;
        if self.mutations == self.crash_after {
            std::process::exit(78);
        }
    }
    fn pf_values(&self) -> [bool; 3] {
        serde_json::from_slice(&fs::read(&self.pf).unwrap()).unwrap()
    }
    fn pf_write(&mut self, index: usize, value: bool) {
        let mut values = self.pf_values();
        values[index] = value;
        // The synthetic state is present once the hook is applied.
        if index == 1 && value {
            values[2] = true;
        }
        let mut file = File::create(&self.pf).unwrap();
        file.write_all(&serde_json::to_vec(&values).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        self.checkpoint();
    }
}
impl SettingsBackend for GatewayFixture {
    fn read(&mut self, setting: Setting) -> Result<u32> {
        self.settings.read(setting)
    }
    fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
        self.settings.write(setting, value)?;
        self.checkpoint();
        Ok(())
    }
    fn same_boot(&mut self, _: &crate::gateway::Plan) -> Result<bool> {
        Ok(self.boot_matches)
    }
    fn gateway(&mut self, plan: &crate::gateway::Plan, enable: bool) -> Result<()> {
        if matches!(
            plan.mode,
            crate::gateway::Mode::Routed | crate::gateway::Mode::Userspace
        ) {
            return Ok(());
        }
        if enable {
            self.pf_write(0, true);
            self.pf_write(1, true);
        } else {
            assert_eq!(
                self.settings.values()[0],
                0,
                "forwarding must stop before PF cleanup"
            );
            self.pf_write(0, false);
            self.pf_write(2, false);
            self.pf_write(1, false);
        }
        Ok(())
    }
}
#[test]
fn gateway_crash_child() {
    let Ok(root) = std::env::var("KONSOLLINK_TEST_GATEWAY") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut store = Store::open_test(&root).unwrap();
    let mut backend = GatewayFixture::new(&root);
    let mode = std::env::var("KONSOLLINK_TEST_CRASH").unwrap();
    let (left, right) = mode.split_once(':').unwrap();
    if left == "mutation" {
        backend.crash_after = right.parse().unwrap();
    } else {
        store.crash_at = Some((left.parse().unwrap(), right.parse().unwrap()));
    }
    let mut plan = crate::gateway::tests::plan();
    plan.mode = crate::gateway::Mode::Nat;
    store.prepare_gateway(&mut backend, plan).unwrap();
    store.apply(&mut backend).unwrap();
    store.rollback(&mut backend).unwrap();
    panic!("gateway crash point was not reached");
}
#[test]
fn gateway_subprocess_crashes_cover_pf_sysctl_and_all_journal_boundaries() {
    let mut modes: Vec<String> = (1..=9).map(|n| format!("mutation:{n}")).collect();
    for save in 1..=14 {
        for point in 1..=4 {
            modes.push(format!("{save}:{point}"));
        }
    }
    for mode in modes {
        let temp = Temp::new();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal::tests::gateway_crash_child",
                "--nocapture",
            ])
            .env("KONSOLLINK_TEST_GATEWAY", &temp.0)
            .env("KONSOLLINK_TEST_CRASH", &mode)
            .output()
            .unwrap();
        assert!(
            matches!(result.status.code(), Some(77 | 78)),
            "{mode}: {result:?}"
        );
        let mut store = temp.store();
        let mut backend = GatewayFixture::new(&temp.0);
        store.rollback(&mut backend).unwrap();
        store.rollback(&mut backend).unwrap();
        assert_eq!(backend.settings.values(), [0, 0, 1], "{mode}");
        assert_eq!(backend.pf_values(), [false; 3], "{mode}");
    }
}
#[test]
fn previous_boot_journal_never_overwrites_new_boot_networking() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = GatewayFixture::new(&temp.0);
    store
        .prepare_gateway(&mut backend, crate::gateway::tests::plan())
        .unwrap();
    store.apply(&mut backend).unwrap();
    backend.boot_matches = false;
    let mutations = backend.mutations;
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.mutations, mutations);
    assert_eq!(store.load().unwrap().unwrap().phase, Phase::Complete);
}

#[test]
fn routed_gateway_changes_no_pf_fixture_state() {
    let temp = Temp::new();
    let mut store = temp.store();
    let mut backend = GatewayFixture::new(&temp.0);
    store
        .prepare_gateway(&mut backend, crate::gateway::tests::plan())
        .unwrap();
    store.apply(&mut backend).unwrap();
    assert_eq!(backend.settings.values(), [1, 0, 0]);
    assert_eq!(backend.pf_values(), [false; 3]);
    store.rollback(&mut backend).unwrap();
    assert_eq!(backend.settings.values(), [0, 0, 1]);
    assert_eq!(backend.pf_values(), [false; 3]);
}
