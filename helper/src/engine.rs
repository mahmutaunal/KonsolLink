//! Closed, journal-backed DPI engine lifecycle contract.
//!
//! Callers cannot supply executable paths or argument vectors. The macOS
//! adapter is compiled from fixed paths and arguments and remains dormant until
//! the separately packaged, checksum-matching artifact exists.
use crate::journal::{Error, Result, Store};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
pub mod macos;

pub const TPWS_V72_13_SHA256: &str = env!("KONSOLLINK_TPWS_SHA256");
pub const LOOPBACK_PORT: u16 = 19081;
pub const PCAP2SOCKS_SHA256: &str = env!("KONSOLLINK_PCAP2SOCKS_SHA256");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    ZapretTpwsV72_13,
    KonsolLinkGatewayEc407738,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnginePlan {
    pub kind: EngineKind,
    pub artifact_sha256: String,
    pub loopback_port: u16,
}

impl EnginePlan {
    pub fn tpws_v72_13() -> Self {
        Self {
            kind: EngineKind::ZapretTpwsV72_13,
            artifact_sha256: TPWS_V72_13_SHA256.into(),
            loopback_port: LOOPBACK_PORT,
        }
    }

    pub fn konsollink_gateway() -> Self {
        Self {
            kind: EngineKind::KonsolLinkGatewayEc407738,
            artifact_sha256: PCAP2SOCKS_SHA256.into(),
            loopback_port: LOOPBACK_PORT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let hash_ok = match self.kind {
            EngineKind::ZapretTpwsV72_13 => self.artifact_sha256 == TPWS_V72_13_SHA256,
            EngineKind::KonsolLinkGatewayEc407738 => self.artifact_sha256 == PCAP2SOCKS_SHA256,
        };
        if !hash_ok || self.loopback_port != LOOPBACK_PORT {
            return Err(Error::Invalid("engine plan is not allowlisted"));
        }
        Ok(())
    }
}

/// PID reuse is handled by pairing the PID with an OS-observed process birth
/// token. The platform adapter must compare both before signalling a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub birth_seconds: u64,
    pub birth_micros: u32,
}

impl ProcessIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.pid <= 1
            || self.pid > i32::MAX as u32
            || self.birth_seconds == 0
            || self.birth_micros >= 1_000_000
        {
            return Err(Error::Invalid("invalid engine process identity"));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineStep {
    #[default]
    Pending,
    Intent,
    Applied,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRecord {
    pub plan: EnginePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    #[serde(default)]
    pub step: EngineStep,
}

impl EngineRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        match (self.step, self.process) {
            (EngineStep::Pending, None) => Ok(()),
            (EngineStep::Restored, None) => Ok(()),
            (EngineStep::Intent | EngineStep::Applied | EngineStep::Restored, Some(process)) => {
                process.validate()
            }
            _ => Err(Error::Invalid("engine process/step ordering")),
        }
    }
}

/// Platform implementations must spawn a non-networking, suspended child that
/// exits if the helper disappears before `resume_engine`. They must verify the
/// allowlisted artifact before spawn and compare the full identity on health or
/// stop. M2-B implements only a fake backend for this contract.
pub trait ProcessBackend: crate::journal::SettingsBackend {
    fn spawn_engine_suspended(&mut self, plan: &EnginePlan) -> Result<ProcessIdentity>;
    fn cancel_engine_suspended(&mut self, process: ProcessIdentity) -> Result<()>;
    fn resume_engine(&mut self, process: ProcessIdentity) -> Result<()>;
    fn engine_health(&mut self, process: ProcessIdentity) -> Result<()>;
}

/// Persist plan -> spawn suspended -> persist identity -> resume -> persist
/// applied. A failure while suspended requests immediate cancellation; durable
/// intent lets startup recovery retry cleanup after resume.
pub fn start(
    store: &mut Store,
    backend: &mut impl ProcessBackend,
    plan: EnginePlan,
) -> Result<ProcessIdentity> {
    plan.validate()?;
    store.prepare_engine(plan.clone())?;
    let process = backend.spawn_engine_suspended(&plan)?;
    if let Err(error) = process.validate() {
        let _ = backend.cancel_engine_suspended(process);
        return Err(error);
    }
    if let Err(error) = store.mark_engine_spawned(process) {
        let _ = backend.cancel_engine_suspended(process);
        return Err(error);
    }
    if let Err(error) = backend.resume_engine(process) {
        let _ = backend.cancel_engine_suspended(process);
        return Err(error);
    }
    if let Err(error) = store.mark_engine_started() {
        let record = EngineRecord {
            plan,
            process: Some(process),
            step: EngineStep::Intent,
        };
        let _ = backend.stop_engine(&record);
        return Err(error);
    }
    if let Err(health_error) = backend.engine_health(process) {
        return match store.rollback(backend) {
            Ok(()) => Err(health_error),
            Err(recovery_error) => Err(recovery_error),
        };
    }
    Ok(process)
}

pub fn poll(backend: &mut impl ProcessBackend, process: ProcessIdentity) -> Result<()> {
    process.validate()?;
    backend.engine_health(process)
}

/// A failed identity/health check immediately enters journal rollback. If
/// cleanup also fails, its error wins because durable recovery is still owed.
pub fn watchdog(
    store: &mut Store,
    backend: &mut impl ProcessBackend,
    process: ProcessIdentity,
) -> Result<()> {
    match poll(backend, process) {
        Ok(()) => Ok(()),
        Err(health_error) => match store.rollback(backend) {
            Ok(()) => Err(health_error),
            Err(recovery_error) => Err(recovery_error),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::Plan,
        journal::{Setting, SettingsBackend},
    };
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static ID: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "konsollink-engine-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct Fake {
        values: [u32; 3],
        gateway: bool,
        engine: bool,
        fail_health: bool,
        fail_resume: bool,
        fail_stop: bool,
        events: Vec<&'static str>,
    }

    impl SettingsBackend for Fake {
        fn read(&mut self, setting: Setting) -> Result<u32> {
            Ok(self.values[setting as usize])
        }

        fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
            if setting == Setting::Ipv4Forwarding && value == 0 {
                assert!(!self.engine, "engine must stop before forwarding");
            }
            self.values[setting as usize] = value;
            self.events.push("setting");
            Ok(())
        }

        fn same_boot(&mut self, _: &Plan) -> Result<bool> {
            Ok(true)
        }

        fn gateway(&mut self, _: &Plan, enable: bool) -> Result<()> {
            self.gateway = enable;
            Ok(())
        }

        fn stop_engine(&mut self, record: &EngineRecord) -> Result<()> {
            assert_eq!(record.process, Some(identity()));
            if self.fail_stop {
                return Err(Error::Backend("injected stop failure".into()));
            }
            self.engine = false;
            self.events.push("stop");
            Ok(())
        }
    }

    impl ProcessBackend for Fake {
        fn spawn_engine_suspended(&mut self, plan: &EnginePlan) -> Result<ProcessIdentity> {
            plan.validate()?;
            assert!(!self.engine);
            self.engine = true;
            self.events.push("spawn_suspended");
            Ok(identity())
        }

        fn cancel_engine_suspended(&mut self, process: ProcessIdentity) -> Result<()> {
            assert_eq!(process, identity());
            self.engine = false;
            self.events.push("cancel");
            Ok(())
        }

        fn resume_engine(&mut self, process: ProcessIdentity) -> Result<()> {
            assert_eq!(process, identity());
            self.events.push("resume");
            if self.fail_resume {
                return Err(Error::Backend("injected resume failure".into()));
            }
            Ok(())
        }

        fn engine_health(&mut self, process: ProcessIdentity) -> Result<()> {
            assert_eq!(process, identity());
            self.events.push("health");
            if self.fail_health {
                return Err(Error::Backend("injected engine exit".into()));
            }
            Ok(())
        }
    }

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: 4242,
            birth_seconds: 1_784_614_671,
            birth_micros: 42,
        }
    }

    fn fixture() -> (Temp, Store, Fake) {
        let temp = Temp::new();
        let mut store = Store::open_test(&temp.0).unwrap();
        let mut backend = Fake {
            values: [0, 0, 1],
            gateway: false,
            engine: false,
            fail_health: false,
            fail_resume: false,
            fail_stop: false,
            events: vec![],
        };
        store
            .prepare_gateway(&mut backend, crate::gateway::tests::plan())
            .unwrap();
        store.apply(&mut backend).unwrap();
        (temp, store, backend)
    }

    #[test]
    fn plan_and_identity_are_closed_allowlists() {
        assert!(EnginePlan::tpws_v72_13().validate().is_ok());
        assert!(EnginePlan::konsollink_gateway().validate().is_ok());
        for raw in [
            r#"{"kind":"zapret_tpws_v72_13","artifact_sha256":"bad","loopback_port":19081}"#,
            r#"{"kind":"zapret_tpws_v72_13","artifact_sha256":"f2749747f9fee28d92bbf149211b21492308c0c9bc6c818a829adc08dd722225","loopback_port":1}"#,
            r#"{"kind":"zapret_tpws_v72_13","artifact_sha256":"f2749747f9fee28d92bbf149211b21492308c0c9bc6c818a829adc08dd722225","loopback_port":19081,"path":"/tmp/x"}"#,
        ] {
            let parsed = serde_json::from_str::<EnginePlan>(raw);
            assert!(
                parsed.is_err() || parsed.unwrap().validate().is_err(),
                "{raw}"
            );
        }
        for invalid in [
            ProcessIdentity {
                pid: 1,
                ..identity()
            },
            ProcessIdentity {
                birth_micros: 1_000_000,
                ..identity()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[test]
    fn journaled_lifecycle_stops_engine_before_gateway_rollback() {
        let (temp, mut store, mut backend) = fixture();
        let process = start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).unwrap();
        let journal = store.load().unwrap().unwrap();
        assert_eq!(journal.engine.unwrap().step, EngineStep::Applied);
        assert_eq!(
            backend.events,
            ["setting", "setting", "spawn_suspended", "resume", "health"]
        );
        poll(&mut backend, process).unwrap();
        drop(store);
        let mut store = Store::open_test(&temp.0).unwrap();
        backend.fail_health = true;
        assert!(watchdog(&mut store, &mut backend, process).is_err());
        assert!(!backend.engine);
        assert!(!backend.gateway);
        assert_eq!(backend.values, [0, 0, 1]);
        assert_eq!(
            store.load().unwrap().unwrap().engine.unwrap().step,
            EngineStep::Restored
        );
        let stop = backend
            .events
            .iter()
            .position(|event| *event == "stop")
            .unwrap();
        let restore = backend.events[stop + 1..]
            .iter()
            .position(|event| *event == "setting")
            .unwrap()
            + stop
            + 1;
        assert!(stop < restore);
    }

    #[test]
    fn engine_cannot_attach_without_active_gateway_or_attach_twice() {
        let temp = Temp::new();
        let mut store = Store::open_test(&temp.0).unwrap();
        assert!(store.prepare_engine(EnginePlan::tpws_v72_13()).is_err());
        drop(store);

        let (_temp, mut store, mut backend) = fixture();
        start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).unwrap();
        assert!(store.prepare_engine(EnginePlan::tpws_v72_13()).is_err());
    }

    #[test]
    fn persistence_or_resume_failure_requests_immediate_process_stop() {
        let (_temp, mut store, mut backend) = fixture();
        store.fail_save_in(2); // Plan save succeeds; identity save fails.
        assert!(start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).is_err());
        assert!(!backend.engine);
        assert_eq!(backend.events.last(), Some(&"cancel"));

        let (_temp, mut store, mut backend) = fixture();
        backend.fail_resume = true;
        assert!(start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).is_err());
        assert!(!backend.engine);
        assert_eq!(backend.events.last(), Some(&"cancel"));
        store.rollback(&mut backend).unwrap();
        assert_eq!(backend.values, [0, 0, 1]);

        let (_temp, mut store, mut backend) = fixture();
        backend.fail_health = true;
        assert!(start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).is_err());
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
        assert_eq!(
            store.load().unwrap().unwrap().engine.unwrap().step,
            EngineStep::Restored
        );
    }

    #[test]
    fn failed_stop_preserves_recovery_evidence_for_retry() {
        let (_temp, mut store, mut backend) = fixture();
        start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).unwrap();
        backend.fail_stop = true;
        assert!(store.rollback(&mut backend).is_err());
        let journal = store.load().unwrap().unwrap();
        assert_eq!(journal.phase, crate::journal::Phase::RollingBack);
        assert_eq!(journal.engine.unwrap().step, EngineStep::Applied);
        assert!(backend.engine);

        backend.fail_stop = false;
        store.rollback(&mut backend).unwrap();
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
    }
}
