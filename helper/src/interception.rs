//! Closed, journal-backed M2 TCP interception plan.

use crate::{
    engine::ProcessBackend,
    gateway,
    journal::{Error, InterceptionStep, Result, Store},
};
use konsollink_core::classifier::QualifiedTcpDestination;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::Ipv4Addr};

pub const DESTINATION_PORT: u16 = 443;
pub const LOOPBACK_PORT: u16 = 19_081;
const MAX_DESTINATIONS: usize = 64;
const MAX_AUTHORITY_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicyLease {
    pub address: Ipv4Addr,
    pub domain: String,
    pub ttl: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicyUpdate {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub generation: u64,
    pub domains: Vec<String>,
    pub leases: Vec<DnsPolicyLease>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    ConsoleInbound,
    HostTransparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub address: Ipv4Addr,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(default)]
    pub mode: Mode,
    pub anchor: String,
    pub console: Ipv4Addr,
    pub interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<Ipv4Addr>,
    pub observed_at: u64,
    pub destination_port: u16,
    pub redirect_address: Ipv4Addr,
    pub redirect_port: u16,
    pub destinations: Vec<Destination>,
}

impl Plan {
    /// Qualified destination values can only be obtained from the classifier
    /// with an opaque successful shadow-run proof.
    pub fn from_qualified(
        gateway: &gateway::Plan,
        qualified: &[QualifiedTcpDestination],
        now_secs: u64,
    ) -> Result<Self> {
        gateway.validate().map_err(Error::Backend)?;
        let suffix = gateway
            .anchor
            .strip_prefix("tr.konsollink.m0.")
            .ok_or(Error::Invalid("gateway anchor"))?;
        let mut destinations = qualified
            .iter()
            .copied()
            .map(|destination| Destination {
                address: destination.address(),
                expires_at: destination.expires_at(),
            })
            .collect::<Vec<_>>();
        destinations.sort_unstable_by_key(|destination| destination.address);
        destinations.dedup_by_key(|destination| destination.address);
        let plan = Self {
            mode: Mode::ConsoleInbound,
            anchor: format!("tr.konsollink.m2.{suffix}"),
            console: gateway.console,
            interface: gateway.interface.clone(),
            source_address: None,
            observed_at: now_secs,
            destination_port: DESTINATION_PORT,
            redirect_address: Ipv4Addr::LOCALHOST,
            redirect_port: LOOPBACK_PORT,
            destinations,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn from_dns_policy(
        gateway: &gateway::Plan,
        leases: &[DnsPolicyLease],
        now_secs: u64,
    ) -> Result<Self> {
        gateway.validate().map_err(Error::Backend)?;
        if gateway.mode != gateway::Mode::Userspace {
            return Err(Error::Invalid("transparent interception gateway"));
        }
        let suffix = gateway
            .anchor
            .strip_prefix("tr.konsollink.m0.")
            .ok_or(Error::Invalid("gateway anchor"))?;
        let profile = konsollink_core::ServiceProfile::discord_tr()
            .map_err(|error| Error::Backend(error.to_string()))?;
        let mut destinations: BTreeMap<Ipv4Addr, u64> = BTreeMap::new();
        for lease in leases {
            if lease.ttl == 0
                || lease.ttl > MAX_AUTHORITY_SECS
                || !eligible_public(lease.address)
                || !profile.domain_matches(&lease.domain)
            {
                return Err(Error::Invalid("Discord DNS policy lease"));
            }
            let expires_at = now_secs
                .checked_add(lease.ttl)
                .ok_or(Error::Invalid("interception authority"))?;
            destinations
                .entry(lease.address)
                .and_modify(|current| *current = (*current).max(expires_at))
                .or_insert(expires_at);
        }
        let destinations = destinations
            .into_iter()
            .take(MAX_DESTINATIONS + 1)
            .map(|(address, expires_at)| Destination {
                address,
                expires_at,
            })
            .collect::<Vec<_>>();
        let plan = Self {
            mode: Mode::HostTransparent,
            anchor: format!("tr.konsollink.m2.{suffix}"),
            console: gateway.console,
            interface: gateway.interface.clone(),
            source_address: gateway.uplink_host,
            observed_at: now_secs,
            destination_port: DESTINATION_PORT,
            redirect_address: Ipv4Addr::LOCALHOST,
            redirect_port: LOOPBACK_PORT,
            destinations,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        let suffix = self.anchor.strip_prefix("tr.konsollink.m2.").unwrap_or("");
        if suffix.len() != 32
            || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.interface.len() < 3
            || self.interface.len() > 15
            || !self.interface.starts_with("en")
            || !self.interface[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || !self.console.is_private()
            || self.destination_port != DESTINATION_PORT
            || self.redirect_address != Ipv4Addr::LOCALHOST
            || self.redirect_port != LOOPBACK_PORT
            || self.destinations.is_empty()
            || self.destinations.len() > MAX_DESTINATIONS
            || match self.mode {
                Mode::ConsoleInbound => self.source_address.is_some(),
                Mode::HostTransparent => !self
                    .source_address
                    .is_some_and(|address| address.is_private()),
            }
        {
            return Err(Error::Invalid("interception plan"));
        }
        for (index, destination) in self.destinations.iter().enumerate() {
            if !eligible_public(destination.address)
                || destination.expires_at <= self.observed_at
                || destination.expires_at - self.observed_at > MAX_AUTHORITY_SECS
                || self.destinations[..index]
                    .iter()
                    .any(|prior| prior.address == destination.address)
            {
                return Err(Error::Invalid("interception destination"));
            }
        }
        Ok(())
    }

    pub fn matches_gateway(&self, gateway: &gateway::Plan) -> bool {
        matches!(
            (self.mode, gateway.mode),
            (
                Mode::ConsoleInbound,
                gateway::Mode::Nat | gateway::Mode::Routed
            ) | (Mode::HostTransparent, gateway::Mode::Userspace)
        ) && self.console == gateway.console
            && self.interface == gateway.interface
            && self.anchor.strip_prefix("tr.konsollink.m2.")
                == gateway.anchor.strip_prefix("tr.konsollink.m0.")
    }

    pub fn is_current(&self, now_secs: u64) -> bool {
        self.destinations
            .iter()
            .all(|destination| destination.expires_at > now_secs)
    }

    pub fn same_kernel_rules(&self, other: &Self) -> bool {
        self.anchor == other.anchor
            && self.mode == other.mode
            && self.console == other.console
            && self.interface == other.interface
            && self.source_address == other.source_address
            && self.destination_port == other.destination_port
            && self.redirect_address == other.redirect_address
            && self.redirect_port == other.redirect_port
            && self
                .destinations
                .iter()
                .map(|destination| destination.address)
                .eq(other
                    .destinations
                    .iter()
                    .map(|destination| destination.address))
    }

    /// Equality of the classifier authority, excluding only the instant at
    /// which the same evidence was read. This prevents needless journal
    /// writes while the observer returns an unchanged destination set.
    pub fn same_authority(&self, other: &Self) -> bool {
        self.same_kernel_rules(other)
            && self
                .destinations
                .iter()
                .map(|destination| destination.expires_at)
                .eq(other
                    .destinations
                    .iter()
                    .map(|destination| destination.expires_at))
    }
}

fn eligible_public(address: Ipv4Addr) -> bool {
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_unspecified()
        && address.octets() != [255, 255, 255, 255]
}

/// Engine health is checked immediately before durable PF intent is recorded.
pub fn start(
    store: &mut Store,
    backend: &mut impl ProcessBackend,
    plan: Plan,
    now_secs: u64,
) -> Result<()> {
    plan.validate()?;
    if !plan.is_current(now_secs) {
        return Err(Error::Invalid("expired interception plan"));
    }
    let journal = store
        .load()?
        .ok_or(Error::Invalid("missing active journal"))?;
    let engine = journal
        .engine
        .as_ref()
        .ok_or(Error::Invalid("missing engine"))?;
    if engine.step != crate::engine::EngineStep::Applied
        || journal.interception.is_some()
        || !plan.matches_gateway(
            journal
                .gateway
                .as_ref()
                .ok_or(Error::Invalid("missing gateway"))?,
        )
    {
        return Err(Error::RecoveryRequired);
    }
    if !backend.same_boot(journal.gateway.as_ref().expect("checked above"))? {
        return Err(Error::RecoveryRequired);
    }
    let process = engine
        .process
        .ok_or(Error::Invalid("missing engine process"))?;
    backend.engine_health(process)?;
    store.prepare_interception(backend, plan)?;
    store.apply_interception(backend, now_secs)?;
    let journal = store.load()?.expect("active journal exists");
    let plan = &journal.interception.expect("applied above").plan;
    if let Err(health_error) = backend.interception_health(plan) {
        return match store.rollback(backend) {
            Ok(()) => Err(health_error),
            Err(recovery_error) => Err(recovery_error),
        };
    }
    Ok(())
}

/// Expiry or engine failure removes interception before stopping the engine
/// and restoring gateway state.
pub fn watchdog(store: &mut Store, backend: &mut impl ProcessBackend, now_secs: u64) -> Result<()> {
    let journal = store
        .load()?
        .ok_or(Error::Invalid("missing active journal"))?;
    let interception = journal
        .interception
        .as_ref()
        .ok_or(Error::Invalid("missing interception"))?;
    let engine = journal
        .engine
        .as_ref()
        .ok_or(Error::Invalid("missing engine"))?;
    let process = engine
        .process
        .ok_or(Error::Invalid("missing engine process"))?;
    let health = if interception.step != InterceptionStep::Applied {
        Err(Error::RecoveryRequired)
    } else if !interception.plan.is_current(now_secs) {
        Err(Error::Backend("interception authority expired".into()))
    } else {
        backend
            .engine_health(process)
            .and_then(|()| backend.interception_health(&interception.plan))
    };
    match health {
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
        engine::{self, EnginePlan, EngineRecord, ProcessIdentity},
        journal::{Phase, Setting, SettingsBackend},
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
                "konsollink-interception-{}-{}",
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
        interception: bool,
        pf_enabled: bool,
        fail_interception_enable: bool,
        events: Vec<&'static str>,
    }

    impl SettingsBackend for Fake {
        fn read(&mut self, setting: Setting) -> Result<u32> {
            Ok(self.values[setting as usize])
        }

        fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
            if setting == Setting::Ipv4Forwarding && value == 0 {
                assert!(!self.interception);
                assert!(!self.engine);
            }
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
            assert!(!self.interception, "redirect must be removed before engine");
            self.engine = false;
            self.events.push("stop");
            Ok(())
        }

        fn interception(&mut self, _: &Plan, enable: bool) -> Result<()> {
            if enable {
                assert!(self.engine, "engine must be live before redirect");
                assert!(self.pf_enabled, "PF must be live before redirect");
                if self.fail_interception_enable {
                    return Err(Error::Backend("injected interception failure".into()));
                }
                self.interception = true;
                self.events.push("interception_on");
            } else {
                self.interception = false;
                self.events.push("interception_off");
            }
            Ok(())
        }

        fn interception_health(&mut self, _: &Plan) -> Result<()> {
            if !self.interception {
                return Err(Error::Backend("redirect missing".into()));
            }
            self.events.push("interception_health");
            Ok(())
        }

        fn packet_filter_enabled(&mut self) -> Result<bool> {
            Ok(self.pf_enabled)
        }

        fn packet_filter(&mut self, enable: bool) -> Result<()> {
            assert!(!self.interception, "redirect must be removed before PF");
            self.pf_enabled = enable;
            self.events.push(if enable { "pf_on" } else { "pf_off" });
            Ok(())
        }
    }

    impl ProcessBackend for Fake {
        fn spawn_engine_suspended(&mut self, _: &EnginePlan) -> Result<ProcessIdentity> {
            self.engine = true;
            Ok(identity())
        }

        fn cancel_engine_suspended(&mut self, _: ProcessIdentity) -> Result<()> {
            self.engine = false;
            Ok(())
        }

        fn resume_engine(&mut self, _: ProcessIdentity) -> Result<()> {
            Ok(())
        }

        fn engine_health(&mut self, _: ProcessIdentity) -> Result<()> {
            if !self.engine {
                return Err(Error::Backend("engine stopped".into()));
            }
            self.events.push("health");
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

    fn plan() -> Plan {
        let gateway = crate::gateway::tests::plan();
        Plan {
            mode: Mode::ConsoleInbound,
            anchor: gateway.anchor.replacen(".m0.", ".m2.", 1),
            console: gateway.console,
            interface: gateway.interface,
            source_address: None,
            observed_at: 10,
            destination_port: DESTINATION_PORT,
            redirect_address: Ipv4Addr::LOCALHOST,
            redirect_port: LOOPBACK_PORT,
            destinations: vec![Destination {
                address: "1.1.1.20".parse().unwrap(),
                expires_at: 100,
            }],
        }
    }

    #[test]
    fn transparent_plan_requires_userspace_gateway_and_exact_host_source() {
        let mut gateway = crate::gateway::tests::plan();
        gateway.mode = crate::gateway::Mode::Userspace;
        gateway.console = "172.24.2.10".parse().unwrap();
        gateway.host = "172.24.2.1".parse().unwrap();
        gateway.uplink_host = Some("192.168.1.20".parse().unwrap());
        gateway.prefix = 16;
        let plan = Plan::from_dns_policy(
            &gateway,
            &[
                DnsPolicyLease {
                    address: "1.1.1.20".parse().unwrap(),
                    domain: "gateway.discord.gg".into(),
                    ttl: 60,
                },
                DnsPolicyLease {
                    address: "1.1.1.20".parse().unwrap(),
                    domain: "gateway.discord.gg".into(),
                    ttl: 60,
                },
            ],
            10,
        )
        .unwrap();
        assert_eq!(plan.mode, Mode::HostTransparent);
        assert_eq!(plan.source_address, gateway.uplink_host);
        assert_eq!(plan.destinations.len(), 1);
        assert!(plan.matches_gateway(&gateway));

        let mut invalid = plan;
        invalid.source_address = None;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn dns_policy_rejects_unrelated_domains_and_unbounded_ttl() {
        let mut gateway = crate::gateway::tests::plan();
        gateway.mode = crate::gateway::Mode::Userspace;
        gateway.console = "172.24.2.10".parse().unwrap();
        gateway.host = "172.24.2.1".parse().unwrap();
        gateway.uplink_host = Some("192.168.1.20".parse().unwrap());
        gateway.prefix = 16;

        for lease in [
            DnsPolicyLease {
                address: "1.1.1.20".parse().unwrap(),
                domain: "example.com".into(),
                ttl: 60,
            },
            DnsPolicyLease {
                address: "1.1.1.20".parse().unwrap(),
                domain: "discord.com".into(),
                ttl: 0,
            },
            DnsPolicyLease {
                address: "1.1.1.20".parse().unwrap(),
                domain: "discord.com".into(),
                ttl: 121,
            },
        ] {
            assert!(Plan::from_dns_policy(&gateway, &[lease], 10).is_err());
        }
    }

    fn fixture() -> (Temp, Store, Fake) {
        let temp = Temp::new();
        let mut store = Store::open_test(&temp.0).unwrap();
        let mut backend = Fake {
            values: [0, 0, 1],
            engine: false,
            interception: false,
            pf_enabled: true,
            fail_interception_enable: false,
            events: vec![],
        };
        store
            .prepare_gateway(&mut backend, crate::gateway::tests::plan())
            .unwrap();
        store.apply(&mut backend).unwrap();
        engine::start(&mut store, &mut backend, EnginePlan::tpws_v72_13()).unwrap();
        backend.events.clear();
        (temp, store, backend)
    }

    #[test]
    fn closed_plan_rejects_broad_expired_or_non_tcp_scope() {
        assert!(plan().validate().is_ok());
        let mut invalid = plan();
        invalid.destination_port = 80;
        assert!(invalid.validate().is_err());
        let mut invalid = plan();
        invalid.destinations[0].address = "192.168.1.2".parse().unwrap();
        assert!(invalid.validate().is_err());
        let mut invalid = plan();
        invalid.destinations[0].expires_at = 131;
        assert!(invalid.validate().is_err());
        let mut invalid = plan();
        invalid.destinations.clear();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn journal_removes_redirect_before_engine_and_gateway() {
        let (_temp, mut store, mut backend) = fixture();
        start(&mut store, &mut backend, plan(), 20).unwrap();
        assert_eq!(
            backend.events,
            ["health", "interception_on", "interception_health"]
        );
        assert!(backend.interception);
        assert_eq!(store.load().unwrap().unwrap().schema_version, 3);

        store.rollback(&mut backend).unwrap();
        assert!(!backend.interception);
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
        let off = backend
            .events
            .iter()
            .position(|event| *event == "interception_off")
            .unwrap();
        let stop = backend
            .events
            .iter()
            .position(|event| *event == "stop")
            .unwrap();
        assert!(off < stop);
        assert_eq!(store.load().unwrap().unwrap().phase, Phase::Complete);
    }

    #[test]
    fn packet_filter_is_leased_and_restored_when_initially_disabled() {
        let (_temp, mut store, mut backend) = fixture();
        backend.pf_enabled = false;
        start(&mut store, &mut backend, plan(), 20).unwrap();
        assert!(backend.pf_enabled);
        assert!(backend.interception);
        store.stop_m2(&mut backend).unwrap();
        assert!(!backend.pf_enabled);
        assert!(!backend.interception);
        let redirect_off = backend
            .events
            .iter()
            .position(|event| *event == "interception_off")
            .unwrap();
        let pf_off = backend
            .events
            .iter()
            .position(|event| *event == "pf_off")
            .unwrap();
        assert!(redirect_off < pf_off);
    }

    #[test]
    fn failed_pf_apply_keeps_intent_and_recovery_removes_it() {
        let (_temp, mut store, mut backend) = fixture();
        backend.fail_interception_enable = true;
        assert!(start(&mut store, &mut backend, plan(), 20).is_err());
        assert_eq!(
            store.load().unwrap().unwrap().interception.unwrap().step,
            InterceptionStep::Intent
        );
        backend.fail_interception_enable = false;
        store.rollback(&mut backend).unwrap();
        assert!(!backend.interception);
        assert!(!backend.engine);
    }

    #[test]
    fn persistence_failure_after_pf_apply_recovers_from_durable_intent() {
        let (temp, mut store, mut backend) = fixture();
        store.fail_save_in(3); // Applied marker after the backend mutation.
        assert!(start(&mut store, &mut backend, plan(), 20).is_err());
        assert!(backend.interception);
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
        assert!(!backend.interception);
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
    }

    #[test]
    fn expiry_watchdog_fails_closed_through_full_rollback() {
        let (_temp, mut store, mut backend) = fixture();
        start(&mut store, &mut backend, plan(), 20).unwrap();
        assert!(watchdog(&mut store, &mut backend, 99).is_ok());
        assert!(watchdog(&mut store, &mut backend, 100).is_err());
        assert!(!backend.interception);
        assert!(!backend.engine);
        assert_eq!(backend.values, [0, 0, 1]);
    }
}
