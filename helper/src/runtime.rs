//! Dormant M2 controller joining live evidence, engine and PF lifecycles.

use crate::{
    engine::{self, EnginePlan, EngineStep, ProcessBackend},
    gateway,
    interception::{self, Plan},
    journal::{Error, InterceptionStep, Phase, Result, Store},
};
use konsollink_core::{classifier::QualifiedTcpDestination, qualification::CaptureHealth};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Observing,
    Active { destinations: usize },
}

pub struct ObserverSnapshot {
    pub now_secs: u64,
    pub capture: CaptureHealth,
    pub destinations: Vec<QualifiedTcpDestination>,
}

fn capture_healthy(capture: CaptureHealth) -> bool {
    capture.observer_active && capture.captured_packets != 0 && capture.dropped_packets == 0
}

fn rollback_error(store: &mut Store, backend: &mut impl ProcessBackend, original: Error) -> Error {
    match store.rollback(backend) {
        Ok(()) => original,
        Err(recovery) => recovery,
    }
}

/// Reconcile one monotonic-time observer snapshot. This API is intentionally
/// not exposed through IPC while the physical qualification gate is pending.
pub fn reconcile(
    store: &mut Store,
    backend: &mut impl ProcessBackend,
    gateway: &gateway::Plan,
    qualified: &[QualifiedTcpDestination],
    capture: CaptureHealth,
    now_secs: u64,
) -> Result<State> {
    gateway.validate().map_err(Error::Backend)?;
    let journal = store
        .load()?
        .ok_or(Error::Invalid("missing gateway journal"))?;
    if journal.phase != Phase::Active || journal.gateway.as_ref() != Some(gateway) {
        return Err(Error::RecoveryRequired);
    }
    if !backend.same_boot(gateway)? {
        return Err(rollback_error(store, backend, Error::RecoveryRequired));
    }

    if !capture_healthy(capture) || qualified.is_empty() {
        if journal.engine.is_some() || journal.interception.is_some() {
            if let Err(error) = store.stop_m2(backend) {
                return Err(rollback_error(store, backend, error));
            }
        }
        return Ok(State::Observing);
    }

    let plan = match Plan::from_qualified(gateway, qualified, now_secs) {
        Ok(plan) => plan,
        Err(error) => {
            if journal.engine.is_some() || journal.interception.is_some() {
                return match store.stop_m2(backend) {
                    Ok(()) => Err(error),
                    Err(stop_error) => Err(rollback_error(store, backend, stop_error)),
                };
            }
            return Err(error);
        }
    };
    let destinations = plan.destinations.len();
    let journal = store.load()?.expect("checked above");

    if let Some(engine) = journal.engine.as_ref() {
        if engine.step != EngineStep::Applied {
            return Err(rollback_error(store, backend, Error::RecoveryRequired));
        }
        let process = engine
            .process
            .ok_or(Error::Invalid("missing engine process"))?;
        if let Err(error) = backend.engine_health(process) {
            return Err(rollback_error(store, backend, error));
        }
    } else if let Err(error) = engine::start(store, backend, EnginePlan::tpws_v72_13()) {
        return Err(rollback_error(store, backend, error));
    }

    let journal = store.load()?.expect("active journal exists");
    match journal.interception.as_ref() {
        None => {
            if let Err(error) = interception::start(store, backend, plan, now_secs) {
                return Err(rollback_error(store, backend, error));
            }
        }
        Some(current) => {
            if current.step != InterceptionStep::Applied {
                return Err(rollback_error(store, backend, Error::RecoveryRequired));
            }
            if let Err(error) = backend.interception_health(&current.plan) {
                return Err(rollback_error(store, backend, error));
            }
            let result = if current.plan.same_kernel_rules(&plan) {
                if current.plan.same_authority(&plan) {
                    Ok(())
                } else {
                    store.renew_interception(plan, now_secs)
                }
            } else {
                store.replace_interception(backend, plan, now_secs)
            };
            if let Err(error) = result {
                return Err(rollback_error(store, backend, error));
            }
        }
    }
    Ok(State::Active { destinations })
}

pub fn reconcile_snapshot(
    store: &mut Store,
    backend: &mut impl ProcessBackend,
    gateway: &gateway::Plan,
    snapshot: &ObserverSnapshot,
) -> Result<State> {
    reconcile(
        store,
        backend,
        gateway,
        &snapshot.destinations,
        snapshot.capture,
        snapshot.now_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{EngineRecord, ProcessIdentity},
        journal::{Setting, SettingsBackend},
    };
    use konsollink_core::{
        classifier::{DiscordClassifier, DnsRecord, FlowObservation, Transport},
        qualification::{qualify, QualificationReport, QualificationRequirements},
        ServiceProfile,
    };
    use std::{
        fs,
        net::IpAddr,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static ID: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "konsollink-runtime-{}-{}",
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
        engine: bool,
        redirects: usize,
        fail_engine_health: bool,
        fail_redirect_enable: bool,
        events: Vec<&'static str>,
    }
    impl SettingsBackend for Fake {
        fn read(&mut self, setting: Setting) -> Result<u32> {
            Ok(self.values[setting as usize])
        }
        fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
            self.values[setting as usize] = value;
            self.events.push("setting");
            Ok(())
        }
        fn gateway(&mut self, _: &gateway::Plan, _: bool) -> Result<()> {
            Ok(())
        }
        fn same_boot(&mut self, _: &gateway::Plan) -> Result<bool> {
            Ok(true)
        }
        fn stop_engine(&mut self, _: &EngineRecord) -> Result<()> {
            assert_eq!(self.redirects, 0);
            self.engine = false;
            self.events.push("engine_off");
            Ok(())
        }
        fn interception(&mut self, plan: &Plan, enable: bool) -> Result<()> {
            assert!(self.engine || !enable);
            if enable && self.fail_redirect_enable {
                return Err(Error::Backend("redirect apply".into()));
            }
            self.redirects = if enable { plan.destinations.len() } else { 0 };
            self.events.push(if enable { "rdr_on" } else { "rdr_off" });
            Ok(())
        }
        fn interception_health(&mut self, plan: &Plan) -> Result<()> {
            if self.redirects != plan.destinations.len() {
                return Err(Error::Backend("redirect health".into()));
            }
            self.events.push("rdr_health");
            Ok(())
        }
    }
    impl ProcessBackend for Fake {
        fn spawn_engine_suspended(&mut self, _: &EnginePlan) -> Result<ProcessIdentity> {
            self.engine = true;
            self.events.push("engine_spawn");
            Ok(ProcessIdentity {
                pid: 4242,
                birth_seconds: 1_784_614_671,
                birth_micros: 42,
            })
        }
        fn cancel_engine_suspended(&mut self, _: ProcessIdentity) -> Result<()> {
            self.engine = false;
            Ok(())
        }
        fn resume_engine(&mut self, _: ProcessIdentity) -> Result<()> {
            self.events.push("engine_resume");
            Ok(())
        }
        fn engine_health(&mut self, _: ProcessIdentity) -> Result<()> {
            if self.fail_engine_health || !self.engine {
                return Err(Error::Backend("engine health".into()));
            }
            self.events.push("engine_health");
            Ok(())
        }
    }

    fn proof() -> konsollink_core::qualification::QualifiedShadowRun {
        qualify(
            QualificationReport {
                non_discord_samples: 2,
                discord_control_samples: 1,
                discord_media_samples: 1,
                ..QualificationReport::default()
            },
            healthy_capture(),
            QualificationRequirements::default(),
        )
        .unwrap()
    }
    fn healthy_capture() -> CaptureHealth {
        CaptureHealth {
            observer_active: true,
            captured_packets: 100,
            dropped_packets: 0,
        }
    }
    fn evidence(addresses: &[&str], now: u64) -> Vec<QualifiedTcpDestination> {
        let console = IpAddr::V4("192.168.1.20".parse().unwrap());
        let resolver = IpAddr::V4("192.168.1.1".parse().unwrap());
        let mut classifier = DiscordClassifier::new(console, ServiceProfile::discord_tr().unwrap());
        for (index, address) in addresses.iter().enumerate() {
            let port = 53_000 + index as u16;
            let transaction = 10 + index as u16;
            classifier
                .observe_dns_query(
                    console,
                    port,
                    resolver,
                    transaction,
                    "gateway.discord.gg",
                    now,
                )
                .unwrap();
            classifier
                .observe_dns_response(
                    resolver,
                    console,
                    port,
                    transaction,
                    &[DnsRecord::Address {
                        owner: "gateway.discord.gg".into(),
                        address: address.parse().unwrap(),
                        ttl_secs: 120,
                    }],
                    now + 1,
                )
                .unwrap();
            classifier.observe_flow(
                &FlowObservation {
                    source: console,
                    source_port: 51_000 + index as u16,
                    destination: address.parse().unwrap(),
                    destination_port: 443,
                    transport: Transport::Tcp,
                    tls_server_name: Some("gateway.discord.gg".into()),
                },
                now + 2,
            );
        }
        classifier.qualified_tcp_destinations(&proof(), now + 2)
    }
    fn fixture() -> (Temp, Store, Fake, gateway::Plan) {
        let temp = Temp::new();
        let mut store = Store::open_test(&temp.0).unwrap();
        let mut backend = Fake {
            values: [0, 0, 1],
            engine: false,
            redirects: 0,
            fail_engine_health: false,
            fail_redirect_enable: false,
            events: vec![],
        };
        let plan = crate::gateway::tests::plan();
        store.prepare_gateway(&mut backend, plan.clone()).unwrap();
        store.apply(&mut backend).unwrap();
        backend.events.clear();
        (temp, store, backend, plan)
    }

    #[test]
    fn starts_renews_replaces_stops_and_restarts_m2_without_gateway_churn() {
        let (_temp, mut store, mut backend, gateway) = fixture();
        let first = evidence(&["1.1.1.20"], 10);
        assert_eq!(
            reconcile(
                &mut store,
                &mut backend,
                &gateway,
                &first,
                healthy_capture(),
                12
            )
            .unwrap(),
            State::Active { destinations: 1 }
        );
        assert_eq!(backend.redirects, 1);

        let mutations = backend
            .events
            .iter()
            .filter(|event| **event == "rdr_on")
            .count();
        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &first,
            healthy_capture(),
            13,
        )
        .unwrap();
        assert_eq!(
            backend
                .events
                .iter()
                .filter(|event| **event == "rdr_on")
                .count(),
            mutations,
            "unchanged kernel rules must not be rewritten"
        );

        let expanded = evidence(&["1.1.1.20", "1.1.1.21"], 20);
        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &expanded,
            healthy_capture(),
            22,
        )
        .unwrap();
        assert_eq!(backend.redirects, 2);

        assert_eq!(
            reconcile(
                &mut store,
                &mut backend,
                &gateway,
                &[],
                healthy_capture(),
                23
            )
            .unwrap(),
            State::Observing
        );
        assert_eq!(backend.values, [1, 0, 0]);
        assert!(!backend.engine);
        assert_eq!(backend.redirects, 0);
        let journal = store.load().unwrap().unwrap();
        assert!(journal.engine.is_none() && journal.interception.is_none());
        assert_eq!(journal.phase, Phase::Active);

        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &expanded,
            healthy_capture(),
            24,
        )
        .unwrap();
        assert!(backend.engine);
        assert_eq!(backend.redirects, 2);
    }

    #[test]
    fn capture_drop_disables_only_m2_but_health_failure_rolls_back_all() {
        let (_temp, mut store, mut backend, gateway) = fixture();
        let targets = evidence(&["1.1.1.20"], 10);
        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &targets,
            healthy_capture(),
            12,
        )
        .unwrap();
        let dropped = CaptureHealth {
            dropped_packets: 1,
            ..healthy_capture()
        };
        assert_eq!(
            reconcile(&mut store, &mut backend, &gateway, &targets, dropped, 13).unwrap(),
            State::Observing
        );
        assert_eq!(backend.values, [1, 0, 0]);

        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &targets,
            healthy_capture(),
            14,
        )
        .unwrap();
        backend.fail_engine_health = true;
        assert!(reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &targets,
            healthy_capture(),
            15
        )
        .is_err());
        assert_eq!(backend.values, [0, 0, 1]);
        assert_eq!(store.load().unwrap().unwrap().phase, Phase::Complete);
    }

    #[test]
    fn failed_atomic_refresh_uses_intent_to_remove_old_rules() {
        let (_temp, mut store, mut backend, gateway) = fixture();
        let first = evidence(&["1.1.1.20"], 10);
        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &first,
            healthy_capture(),
            12,
        )
        .unwrap();
        backend.fail_redirect_enable = true;
        let expanded = evidence(&["1.1.1.20", "1.1.1.21"], 20);
        assert!(reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &expanded,
            healthy_capture(),
            22
        )
        .is_err());
        assert_eq!(backend.redirects, 0);
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
        assert_eq!(store.load().unwrap().unwrap().phase, Phase::Complete);
    }

    #[test]
    fn refresh_persist_failure_is_recoverable_after_reopen() {
        let (temp, mut store, mut backend, gateway) = fixture();
        let first = evidence(&["1.1.1.20"], 10);
        reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &first,
            healthy_capture(),
            12,
        )
        .unwrap();
        let expanded = evidence(&["1.1.1.20", "1.1.1.21"], 20);
        store.fail_save_in(2); // Applied marker after atomic backend replacement.
        assert!(reconcile(
            &mut store,
            &mut backend,
            &gateway,
            &expanded,
            healthy_capture(),
            22
        )
        .is_err());
        assert_eq!(backend.redirects, 2);
        drop(store);

        let mut store = Store::open_test(&temp.0).unwrap();
        assert_eq!(
            store
                .load()
                .unwrap()
                .unwrap()
                .interception
                .as_ref()
                .unwrap()
                .step,
            InterceptionStep::Intent
        );
        store.rollback(&mut backend).unwrap();
        assert_eq!(backend.redirects, 0);
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
    }
}
