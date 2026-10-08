use super::{Mode, Plan};
use crate::dns_proxy::DnsProxy;
use crate::engine::{
    macos::{ProcessAdapter, GATEWAY_RUNTIME_UID},
    EnginePlan, EngineRecord, ProcessBackend, ProcessIdentity,
};
use crate::ipc::ObservationStatus;
use crate::journal::{Error, Result, Setting, SettingsBackend};
use konsollink_platform::preflight::{self, Observation, SharingService};
use pfctl::{
    AnchorChange, AnchorKind, Direction, Endpoint, FilterRuleAction, FilterRuleBuilder, Ip,
    NatRuleAction, NatRuleBuilder, PfCtl, PoolAddr, Proto, RedirectRuleAction, RedirectRuleBuilder,
    Route, RulesetKind, StatePolicy,
};
use serde::Serialize;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Instant;
use std::{ffi::CStr, mem, net::Ipv4Addr};

use konsollink_core::qualification::{CaptureHealth, QualifiedShadowRun};
use konsollink_core::ServiceProfile;
use konsollink_platform::observer::{macos::BpfObserver, ObservationResult};

fn fail(error: impl std::fmt::Display) -> Error {
    Error::Backend(error.to_string())
}
fn known<T>(value: &Observation<T>) -> Result<&T> {
    match value {
        Observation::Known { value } => Ok(value),
        _ => Err(fail("required preflight value is unknown")),
    }
}
fn name(setting: Setting) -> &'static CStr {
    match setting {
        Setting::Ipv4Forwarding => c"net.inet.ip.forwarding",
        Setting::Ipv6Forwarding => c"net.inet6.ip6.forwarding",
        Setting::IcmpRedirects => c"net.inet.ip.redirect",
    }
}
fn boot() -> Result<i64> {
    let mut value: libc::timeval = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&value);
    // SAFETY: fixed name, correctly sized live output, no new value.
    if unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&mut value as *mut libc::timeval).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || len != mem::size_of_val(&value)
    {
        return Err(fail("cannot read boot identity"));
    }
    Ok(value.tv_sec)
}

pub struct Backend {
    // Userspace sessions open PF lazily for the narrowly scoped, journaled
    // host-transparent Discord route and for recovery of older journals.
    pf: Option<PfCtl>,
    observer: Option<BpfObserver>,
    dns_proxy: Option<DnsProxy>,
    observer_started: Option<Instant>,
    ignored_packets: u64,
    malformed_packets: u64,
    engine: ProcessAdapter,
    policy_input: Vec<u8>,
    policy_generation: u64,
    readiness_targets: Vec<(String, Ipv4Addr)>,
    readiness_job: Option<(u64, Receiver<Result<()>>)>,
    health_job: Option<Receiver<Result<()>>>,
}

#[derive(Serialize)]
struct PolicyAck<'a> {
    version: u32,
    generation: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}
impl Backend {
    pub fn new() -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(fail("root helper required"));
        }
        Ok(Self {
            pf: None,
            observer: None,
            dns_proxy: None,
            observer_started: None,
            ignored_packets: 0,
            malformed_packets: 0,
            engine: ProcessAdapter::new(),
            policy_input: Vec::new(),
            policy_generation: 0,
            readiness_targets: Vec::new(),
            readiness_job: None,
            health_job: None,
        })
    }
    fn pf(&mut self) -> Result<&mut PfCtl> {
        if self.pf.is_none() {
            self.pf = Some(PfCtl::new().map_err(fail)?);
        }
        Ok(self.pf.as_mut().expect("PF initialized above"))
    }
    fn reject_external_dpi_conflicts(&self) -> Result<()> {
        for process in ["tpws", "dvtws", "nfqws", "goodbyedpi"] {
            let status = Command::new("/usr/bin/pgrep")
                .args(["-x", process])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            match status.code() {
                Some(1) => {}
                Some(0) => return Err(fail(format!("external DPI process is active: {process}"))),
                _ => return Err(fail("could not inspect external DPI processes")),
            }
        }
        let anchor = Command::new("/sbin/pfctl")
            .args(["-a", "zapret-v4", "-sr"])
            .stdin(Stdio::null())
            .output()?;
        if anchor.status.success() && !anchor.stdout.iter().all(u8::is_ascii_whitespace) {
            return Err(fail(
                "external Zapret PF rules are active; stop Zapret before starting KonsolLink",
            ));
        }
        Ok(())
    }
    pub fn plan(&mut self, _console: Ipv4Addr) -> Result<Plan> {
        self.reject_external_dpi_conflicts()?;
        let r = preflight::collect(None).map_err(fail)?;
        if *known(&r.ipv4_forwarding)?
            || *known(&r.ipv6_forwarding)?
            || *known(&r.sharing_service)? != SharingService::NotLoaded
        {
            return Err(fail(
                "existing forwarding or Internet Sharing conflicts with the exclusive M0 trial",
            ));
        }
        let route = known(&r.ipv4_default_route)?;
        let interface = known(&r.uplink)?;
        if !interface.active
            || interface.ipv4.len() != 1
            || interface.has_non_link_local_ipv6
            || interface.name != route.interface
        {
            return Err(fail(
                "M0 needs one active IPv4 uplink address without routable IPv6",
            ));
        }
        let mut random = [0u8; 16];
        // SAFETY: getentropy initializes the complete writable buffer.
        if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let plan = Plan {
            mode: Mode::Userspace,
            console: Ipv4Addr::new(172, 24, 2, 10),
            host: Ipv4Addr::new(172, 24, 2, 1),
            uplink_host: Some(interface.ipv4[0].ip),
            router: route.gateway.parse().map_err(fail)?,
            prefix: 16,
            interface: interface.name.clone(),
            anchor: format!(
                "tr.konsollink.m0.{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            boot_seconds: boot()?,
        };
        plan.validate().map_err(fail)?;
        Ok(plan)
    }
    pub fn start_observer(&mut self, plan: &Plan) -> Result<ObservationStatus> {
        self.stop_observer();
        if plan.mode == Mode::Userspace {
            return Ok(ObservationStatus {
                state: "integrated".into(),
                ..ObservationStatus::off()
            });
        }
        let profile = ServiceProfile::discord_tr().map_err(fail)?;
        let dns_proxy = DnsProxy::start(plan.host, plan.console, plan.router).map_err(fail)?;
        let observer = BpfObserver::open(&plan.interface, plan.console, profile).map_err(fail)?;
        self.dns_proxy = Some(dns_proxy);
        self.observer = Some(observer);
        self.observer_started = Some(Instant::now());
        self.poll_observer()
    }
    pub fn poll_observer(&mut self) -> Result<ObservationStatus> {
        if self.observer.is_none() {
            return Ok(ObservationStatus {
                state: "integrated".into(),
                ..ObservationStatus::off()
            });
        }
        let now_secs = self
            .observer_started
            .ok_or_else(|| fail("observer is not active"))?
            .elapsed()
            .as_secs();
        self.poll_observer_at(now_secs)
    }
    fn poll_observer_at(&mut self, now_secs: u64) -> Result<ObservationStatus> {
        self.dns_proxy
            .as_ref()
            .ok_or_else(|| fail("console DNS relay is not active"))?
            .health()
            .map_err(fail)?;
        let observer = self
            .observer
            .as_mut()
            .ok_or_else(|| fail("observer is not active"))?;
        for result in observer.poll(now_secs).map_err(fail)? {
            match result {
                ObservationResult::Ignored => {
                    self.ignored_packets = self.ignored_packets.saturating_add(1)
                }
                ObservationResult::Malformed => {
                    self.malformed_packets = self.malformed_packets.saturating_add(1)
                }
                _ => {}
            }
        }
        let diagnostics = observer.diagnostics(now_secs);
        let capture = observer.capture_stats().map_err(fail)?;
        Ok(ObservationStatus {
            state: "active".into(),
            captured_packets: capture.received,
            dropped_packets: capture.dropped,
            ignored_packets: self.ignored_packets,
            malformed_packets: self.malformed_packets,
            pending_dns_queries: diagnostics.pending_dns_queries,
            learned_destinations: diagnostics.learned_destinations,
            tracked_flow_entries: diagnostics.tracked_flows,
            direct_observations: diagnostics.direct_observations,
            discord_control_candidates: diagnostics.discord_control_candidates,
            discord_media_candidates: diagnostics.discord_media_candidates,
        })
    }
    pub fn stop_observer(&mut self) {
        self.observer = None;
        if let Some(mut proxy) = self.dns_proxy.take() {
            let _ = proxy.stop();
        }
        self.observer_started = None;
        self.ignored_packets = 0;
        self.malformed_packets = 0;
        self.policy_input.clear();
        self.policy_generation = 0;
        self.readiness_targets.clear();
        self.readiness_job = None;
        self.health_job = None;
    }
    pub fn m2_snapshot(
        &mut self,
        proof: &QualifiedShadowRun,
    ) -> Result<crate::runtime::ObserverSnapshot> {
        let now_secs = self
            .observer_started
            .ok_or_else(|| fail("observer is not active"))?
            .elapsed()
            .as_secs();
        let status = self.poll_observer_at(now_secs)?;
        let destinations = self
            .observer
            .as_mut()
            .ok_or_else(|| fail("observer is not active"))?
            .qualified_tcp_destinations(proof, now_secs);
        Ok(crate::runtime::ObserverSnapshot {
            now_secs,
            capture: CaptureHealth {
                observer_active: status.state == "active",
                captured_packets: status.captured_packets,
                dropped_packets: status.dropped_packets,
            },
            destinations,
        })
    }
    pub fn userspace_readiness(&mut self) -> Result<()> {
        Self::probe_readiness(&self.readiness_targets)
    }

    /// Background jobs own immutable snapshots; old-session results are dropped
    /// at stop and cannot mutate PF or a replacement session.
    pub fn runtime_readiness(&mut self) -> Result<Option<()>> {
        if let Some((generation, job)) = &self.readiness_job {
            match job.try_recv() {
                Ok(result) => {
                    let current = *generation == self.policy_generation;
                    self.readiness_job = None;
                    // Never act on old DNS policy results or run overlapping
                    // probes when policy changes during a pending check.
                    return if current { result.map(Some) } else { Ok(None) };
                }
                Err(TryRecvError::Empty) => return Ok(None),
                Err(TryRecvError::Disconnected) => {
                    self.readiness_job = None;
                    return Err(fail("readiness worker stopped"));
                }
            }
        }
        let targets = self.readiness_targets.clone();
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("gateway-readiness".into())
            .spawn(move || {
                let _ = tx.send(Self::probe_readiness(&targets));
            })?;
        self.readiness_job = Some((self.policy_generation, rx));
        Ok(None)
    }

    pub fn runtime_health(&mut self, plan: &Plan) -> Result<()> {
        if let Some(job) = &self.health_job {
            match job.try_recv() {
                Ok(result) => {
                    self.health_job = None;
                    return result;
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    self.health_job = None;
                    return Err(fail("health worker stopped"));
                }
            }
        }
        let plan = plan.clone();
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("gateway-health".into())
            .spawn(move || {
                let result = Self::new().and_then(|mut backend| backend.health(&plan));
                let _ = tx.send(result);
            })?;
        self.health_job = Some(rx);
        Ok(())
    }

    fn probe_readiness(targets: &[(String, Ipv4Addr)]) -> Result<()> {
        let api_address = targets
            .iter()
            .find(|(domain, _)| domain == "discord.com")
            .map(|(_, address)| *address)
            .ok_or(Error::Invalid("missing Discord API DNS policy"))?;
        let mut api_command = Command::new("/usr/bin/curl");
        api_command
            .uid(GATEWAY_RUNTIME_UID)
            .gid(GATEWAY_RUNTIME_UID)
            .args([
                "--ipv4",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
            ])
            .arg("--resolve")
            .arg(format!("discord.com:443:{api_address}"))
            .arg("https://discord.com/api/v10/gateway")
            .stdin(Stdio::null());
        let api = api_command.output()?;
        let api_status = String::from_utf8_lossy(&api.stdout)
            .trim()
            .parse::<u16>()
            .unwrap_or(0);
        if !api.status.success() || !(100..600).contains(&api_status) {
            let stderr = String::from_utf8_lossy(&api.stderr).trim().to_owned();
            let detail = if stderr.is_empty() {
                format!(
                    "Discord API curl exited with {} and HTTP status {api_status:03}",
                    api.status
                )
            } else {
                stderr
            };
            return Err(fail(format!(
                "transparent Discord API readiness probe failed: {detail}"
            )));
        }

        // The console needs Discord's persistent Gateway, not merely one REST
        // response. A valid WebSocket upgrade proves TCP, TLS, SNI, HTTP/1.1
        // upgrade and the gateway.discord.gg path through transparent tpws.
        let gateway_address = targets
            .iter()
            .find(|(domain, _)| domain == "gateway.discord.gg")
            .map(|(_, address)| *address)
            .ok_or(Error::Invalid("missing Discord Gateway DNS policy"))?;
        let mut gateway_command = Command::new("/usr/bin/curl");
        gateway_command
            .uid(GATEWAY_RUNTIME_UID)
            .gid(GATEWAY_RUNTIME_UID)
            .args([
                "--ipv4",
                "--http1.1",
                "--connect-timeout",
                "5",
                "--max-time",
                "4",
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--header",
                "Connection: Upgrade",
                "--header",
                "Upgrade: websocket",
                "--header",
                "Sec-WebSocket-Version: 13",
                "--header",
                "Sec-WebSocket-Key: S29uc29sTGlua1Byb2JlIQ==",
            ])
            .arg("--resolve")
            .arg(format!("gateway.discord.gg:443:{gateway_address}"))
            .arg("https://gateway.discord.gg/?v=10&encoding=json")
            .stdin(Stdio::null());
        let gateway = gateway_command.output()?;
        let gateway_status = String::from_utf8_lossy(&gateway.stdout)
            .trim()
            .parse::<u16>()
            .unwrap_or(0);
        // curl normally reaches max-time after a successful 101 because the
        // upgraded socket remains open. The status code is the proof here.
        if gateway_status == 101 {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&gateway.stderr).trim().to_owned();
        let detail = if stderr.is_empty() {
            format!(
                "Discord Gateway curl exited with {} and HTTP status {gateway_status:03}",
                gateway.status
            )
        } else {
            stderr
        };
        Err(fail(format!(
            "transparent Discord WebSocket readiness probe failed: {detail}"
        )))
    }

    pub fn userspace_policy_update(
        &mut self,
    ) -> Result<Option<crate::interception::DnsPolicyUpdate>> {
        let stream = self.engine.policy_stream()?;
        let mut chunk = [0u8; 2048];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => return Err(self.engine.policy_channel_closed_error()),
                Ok(read) => {
                    self.policy_input.extend_from_slice(&chunk[..read]);
                    if self.policy_input.len() > 16 * 1024 {
                        return Err(Error::Invalid("gateway DNS policy size limit"));
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let Some(newline) = self.policy_input.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let line = self.policy_input.drain(..=newline).collect::<Vec<_>>();
        let update: crate::interception::DnsPolicyUpdate =
            serde_json::from_slice(&line[..line.len() - 1])?;
        let profile = ServiceProfile::discord_tr().map_err(fail)?;
        if update.version != 1
            || update.kind != "discord_dns"
            || update.generation <= self.policy_generation
            || update.domains.is_empty()
            || update.domains.len() > 32
            || update
                .domains
                .iter()
                .any(|domain| !profile.domain_matches(domain))
        {
            return Err(Error::Invalid("gateway DNS policy envelope"));
        }
        Ok(Some(update))
    }

    pub fn acknowledge_userspace_policy(
        &mut self,
        update: &crate::interception::DnsPolicyUpdate,
        error: Option<&str>,
    ) -> Result<()> {
        let ack = serde_json::to_vec(&PolicyAck {
            version: 1,
            generation: update.generation,
            ok: error.is_none(),
            error,
        })?;
        let stream = self.engine.policy_stream()?;
        stream.write_all(&ack)?;
        stream.write_all(b"\n")?;
        if error.is_none() {
            self.policy_generation = update.generation;
            self.readiness_targets = update
                .leases
                .iter()
                .map(|lease| (lease.domain.clone(), lease.address))
                .collect();
        }
        Ok(())
    }

    pub fn userspace_interception_plan(
        &mut self,
        gateway: &Plan,
        update: &crate::interception::DnsPolicyUpdate,
        now_secs: u64,
    ) -> Result<crate::interception::Plan> {
        crate::interception::Plan::from_dns_policy(gateway, &update.leases, now_secs)
    }
    pub fn health(&mut self, plan: &Plan) -> Result<()> {
        let expected_forwarding = if plan.mode == Mode::Userspace { 0 } else { 1 };
        if !self.same_boot(plan)?
            || self.read(Setting::Ipv4Forwarding)? != expected_forwarding
            || (plan.mode != Mode::Userspace && self.read(Setting::IcmpRedirects)? != 0)
            || self.read(Setting::Ipv6Forwarding)? != 0
        {
            return Err(fail("gateway settings changed; recovery required"));
        }
        if plan.mode == Mode::Nat {
            let pf = self.pf()?;
            if !pf
                .anchor_exists(&plan.anchor, AnchorKind::Nat)
                .map_err(fail)?
                || !pf
                    .has_console_nat(&plan.anchor, &plan.interface, plan.console)
                    .map_err(fail)?
            {
                return Err(fail("owned NAT rule or hook changed; recovery required"));
            }
        }
        let r = preflight::collect(Some(plan.console)).map_err(fail)?;
        let route = known(&r.ipv4_default_route)?;
        let uplink = known(&r.uplink)?;
        if route.interface != plan.interface
            || route.gateway != plan.router.to_string()
            || !uplink.active
            || uplink.name != plan.interface
            || uplink.ipv4.len() != 1
            || uplink.ipv4[0].ip != plan.uplink_host.unwrap_or(plan.host)
            || (plan.mode != Mode::Userspace && uplink.ipv4[0].prefix != plan.prefix)
            || uplink.has_non_link_local_ipv6
            || *known(&r.sharing_service)? != SharingService::NotLoaded
        {
            return Err(fail("topology changed; recovery required"));
        }
        Ok(())
    }
}
impl SettingsBackend for Backend {
    fn packet_filter_enabled(&mut self) -> Result<bool> {
        self.pf()?.is_enabled().map_err(fail)
    }

    fn packet_filter(&mut self, enable: bool) -> Result<()> {
        if enable {
            self.pf()?.try_enable().map_err(fail)
        } else {
            self.pf()?.try_disable().map_err(fail)
        }
    }

    fn read(&mut self, setting: Setting) -> Result<u32> {
        let mut value: libc::c_int = -1;
        let mut len = mem::size_of_val(&value);
        // SAFETY: closed allowlist, sized output pointer, read only.
        if unsafe {
            libc::sysctlbyname(
                name(setting).as_ptr(),
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if len != mem::size_of_val(&value) || !(0..=1).contains(&value) {
            return Err(fail("invalid sysctl value"));
        }
        Ok(value as u32)
    }
    fn write(&mut self, setting: Setting, value: u32) -> Result<()> {
        if value > 1 || setting == Setting::Ipv6Forwarding {
            return Err(fail("unsupported setting write"));
        }
        let mut value = value as libc::c_int;
        // SAFETY: closed name/value allowlists, correctly sized input, no output.
        if unsafe {
            libc::sysctlbyname(
                name(setting).as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                (&mut value as *mut libc::c_int).cast(),
                mem::size_of_val(&value),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn same_boot(&mut self, plan: &Plan) -> Result<bool> {
        Ok(boot()? == plan.boot_seconds)
    }
    fn gateway(&mut self, plan: &Plan, enable: bool) -> Result<()> {
        plan.validate().map_err(fail)?;
        if matches!(plan.mode, Mode::Routed | Mode::Userspace) {
            return Ok(());
        }
        if enable && !self.same_boot(plan)? {
            return Err(fail("PF/boot changed"));
        }
        let pf = self.pf()?;
        if enable {
            if !pf.is_enabled().map_err(fail)? {
                return Err(fail("PF/boot changed"));
            }
            // Exact /32 source, no pass rule overriding an existing firewall.
            let rule = NatRuleBuilder::default()
                .interface(plan.interface.as_str())
                .from(plan.console)
                .action(NatRuleAction::Nat {
                    nat_to: Ip::from(plan.host).into(),
                })
                .build()
                .map_err(fail)?;
            let mut change = AnchorChange::new();
            change.set_nat_rules(vec![rule]);
            // Populate first, hook last; all intermediate states have durable intent.
            pf.set_rules(&plan.anchor, change).map_err(fail)?;
            pf.add_anchor(&plan.anchor, AnchorKind::Nat).map_err(fail)?;
        } else {
            // Forwarding is restored before reaching this point. Stop new NAT
            // states before removing just this trial's forwarded-console states.
            pf.flush_rules(&plan.anchor, RulesetKind::Nat)
                .map_err(fail)?;
            for state in pf.get_states().map_err(fail)? {
                let local = state.local_address().map_err(fail)?;
                let remote = state.remote_address().map_err(fail)?;
                if local.ip() == plan.console
                    && remote.ip() != plan.host
                    && state.gateway_address().map_err(fail)?.ip() == plan.host
                {
                    pf.kill_state(&state).map_err(fail)?;
                }
            }
            pf.try_remove_anchor(&plan.anchor, AnchorKind::Nat)
                .map_err(fail)?;
        }
        Ok(())
    }
    fn stop_engine(&mut self, record: &EngineRecord) -> Result<()> {
        self.engine.stop(record)
    }
    fn interception(&mut self, plan: &crate::interception::Plan, enable: bool) -> Result<()> {
        plan.validate()?;
        let pf = self.pf()?;
        if enable {
            if !pf.is_enabled().map_err(fail)? {
                return Err(fail("PF is disabled"));
            }
            let transparent = plan.mode == crate::interception::Mode::HostTransparent;
            let rules = plan
                .destinations
                .iter()
                .map(|destination| {
                    let mut rule = RedirectRuleBuilder::default();
                    rule.action(RedirectRuleAction::Redirect)
                        .direction(Direction::In)
                        .quick(true)
                        .interface(if transparent {
                            "lo0"
                        } else {
                            plan.interface.as_str()
                        })
                        .proto(Proto::Tcp)
                        .to(Endpoint::new(destination.address, plan.destination_port))
                        .label("konsollink-m2")
                        .redirect_to(Endpoint::new(plan.redirect_address, plan.redirect_port));
                    if transparent {
                        rule.from(plan.source_address.expect("validated transparent source"));
                    } else {
                        rule.from(plan.console);
                    }
                    rule.build().map_err(fail)
                })
                .collect::<Result<Vec<_>>>()?;
            let mut change = AnchorChange::new();
            change.set_redirect_rules(rules);
            if transparent {
                let filter_rules = plan
                    .destinations
                    .iter()
                    .map(|destination| {
                        FilterRuleBuilder::default()
                            .action(FilterRuleAction::Pass)
                            .direction(Direction::Out)
                            .quick(true)
                            .route(Route::route_to(PoolAddr::new("lo0", Ipv4Addr::LOCALHOST)))
                            .keep_state(StatePolicy::Keep)
                            .interface(plan.interface.as_str())
                            .proto(Proto::Tcp)
                            .to(Endpoint::new(destination.address, plan.destination_port))
                            .user(GATEWAY_RUNTIME_UID)
                            .label("konsollink-m2")
                            .build()
                            .map_err(fail)
                    })
                    .collect::<Result<Vec<_>>>()?;
                change.set_filter_rules(filter_rules);
            }
            // Exact rules first, root hook last. The journal already contains
            // durable intent, so every crash window is recoverable.
            pf.set_rules(&plan.anchor, change).map_err(fail)?;
            pf.try_add_anchor(&plan.anchor, AnchorKind::Redirect)
                .map_err(fail)?;
            if transparent {
                pf.try_add_anchor(&plan.anchor, AnchorKind::Filter)
                    .map_err(fail)?;
            }
        } else {
            if plan.mode == crate::interception::Mode::HostTransparent {
                pf.flush_rules(&plan.anchor, RulesetKind::Filter)
                    .map_err(fail)?;
                pf.clear_states(&plan.anchor, AnchorKind::Filter)
                    .map_err(fail)?;
                pf.try_remove_anchor(&plan.anchor, AnchorKind::Filter)
                    .map_err(fail)?;
            }
            pf.flush_rules(&plan.anchor, RulesetKind::Redirect)
                .map_err(fail)?;
            pf.clear_states(&plan.anchor, AnchorKind::Redirect)
                .map_err(fail)?;
            pf.try_remove_anchor(&plan.anchor, AnchorKind::Redirect)
                .map_err(fail)?;
        }
        Ok(())
    }
    fn interception_health(&mut self, plan: &crate::interception::Plan) -> Result<()> {
        plan.validate()?;
        if plan.mode == crate::interception::Mode::HostTransparent {
            let destinations = plan
                .destinations
                .iter()
                .map(|destination| destination.address)
                .collect::<Vec<_>>();
            let pf = self.pf()?;
            if !pf
                .anchor_exists(&plan.anchor, AnchorKind::Filter)
                .map_err(fail)?
                || !pf
                    .anchor_exists(&plan.anchor, AnchorKind::Redirect)
                    .map_err(fail)?
                || !pf
                    .has_uid_routes(
                        &plan.anchor,
                        &plan.interface,
                        GATEWAY_RUNTIME_UID,
                        &destinations,
                        plan.destination_port,
                    )
                    .map_err(fail)?
                || !pf
                    .has_console_redirects(
                        &plan.anchor,
                        "lo0",
                        plan.source_address.expect("validated transparent source"),
                        &destinations,
                        plan.destination_port,
                        plan.redirect_port,
                    )
                    .map_err(fail)?
            {
                return Err(fail("owned transparent rules changed; recovery required"));
            }
            return Ok(());
        }
        let destinations = plan
            .destinations
            .iter()
            .map(|destination| destination.address)
            .collect::<Vec<_>>();
        let pf = self.pf()?;
        if !pf
            .anchor_exists(&plan.anchor, AnchorKind::Redirect)
            .map_err(fail)?
            || !pf
                .has_console_redirects(
                    &plan.anchor,
                    &plan.interface,
                    plan.console,
                    &destinations,
                    plan.destination_port,
                    plan.redirect_port,
                )
                .map_err(fail)?
        {
            return Err(fail("owned redirect rules changed; recovery required"));
        }
        Ok(())
    }
}

impl ProcessBackend for Backend {
    fn spawn_engine_suspended(&mut self, plan: &EnginePlan) -> Result<ProcessIdentity> {
        self.engine.spawn_suspended(plan)
    }

    fn cancel_engine_suspended(&mut self, process: ProcessIdentity) -> Result<()> {
        self.engine.cancel_suspended(process)
    }

    fn resume_engine(&mut self, process: ProcessIdentity) -> Result<()> {
        self.engine.resume(process)
    }

    fn engine_health(&mut self, process: ProcessIdentity) -> Result<()> {
        self.engine.health(process)
    }
}

#[cfg(test)]
mod background_tests {
    use super::*;

    fn backend() -> Backend {
        Backend {
            pf: None,
            observer: None,
            dns_proxy: None,
            observer_started: None,
            ignored_packets: 0,
            malformed_packets: 0,
            engine: ProcessAdapter::new(),
            policy_input: Vec::new(),
            policy_generation: 0,
            readiness_targets: Vec::new(),
            readiness_job: None,
            health_job: None,
        }
    }

    #[test]
    fn pending_probe_does_not_block_and_stop_discards_old_results() {
        let mut backend = backend();
        let (tx, rx) = mpsc::channel();
        backend.readiness_job = Some((0, rx));
        let started = Instant::now();
        assert!(backend.runtime_readiness().unwrap().is_none());
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        assert!(backend.readiness_job.is_some());
        backend.stop_observer();
        assert!(tx.send(Err(fail("old session"))).is_err());
        assert!(backend.readiness_job.is_none());
    }

    #[test]
    fn old_policy_probe_failure_cannot_stop_current_policy() {
        let mut backend = backend();
        let (tx, rx) = mpsc::channel();
        backend.readiness_job = Some((0, rx));
        backend.policy_generation = 1;
        assert!(backend.runtime_readiness().unwrap().is_none());
        assert!(backend.readiness_job.is_some());
        tx.send(Err(fail("old DNS policy"))).unwrap();
        assert!(backend.runtime_readiness().unwrap().is_none());
        assert!(backend.readiness_job.is_none());
    }

    #[test]
    fn completed_probe_error_is_consumed_once() {
        let mut backend = backend();
        let (tx, rx) = mpsc::channel();
        backend.readiness_job = Some((0, rx));
        tx.send(Err(fail("probe failed"))).unwrap();
        assert!(backend.runtime_readiness().is_err());
        assert!(backend.readiness_job.is_none());
    }
}
