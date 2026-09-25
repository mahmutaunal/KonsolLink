use super::*;
use crate::{
    engine::{self, EnginePlan, ProcessBackend},
    gateway::{Backend, Mode},
    journal::{Phase, Store},
};
use konsollink_core::{
    classifier::FlowClass,
    qualification::{
        qualify, CaptureHealth, ExpectedClass, QualificationError, QualificationRequirements,
        QualifiedShadowRun, ShadowEvaluator,
    },
};
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime},
};

const USERSPACE_READINESS_REFRESH: Duration = Duration::from_secs(45);

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn recover() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = Store::open_system()?;
    store.rollback(&mut Backend::new()?)?;
    Ok(())
}
struct Peer {
    stream: UnixStream,
    input: Vec<u8>,
    id: u64,
    partial_since: Option<Instant>,
}
trait BackendOps: ProcessBackend {
    fn plan(&mut self, console: Ipv4Addr) -> crate::journal::Result<Plan>;
    fn health(&mut self, plan: &Plan) -> crate::journal::Result<()>;
    fn start_observer(&mut self, plan: &Plan) -> crate::journal::Result<ObservationStatus>;
    fn poll_observer(&mut self) -> crate::journal::Result<ObservationStatus>;
    fn m2_snapshot(
        &mut self,
        proof: &QualifiedShadowRun,
    ) -> crate::journal::Result<crate::runtime::ObserverSnapshot>;
    fn userspace_readiness(&mut self) -> crate::journal::Result<()>;
    fn userspace_policy_update(
        &mut self,
    ) -> crate::journal::Result<Option<crate::interception::DnsPolicyUpdate>>;
    fn acknowledge_userspace_policy(
        &mut self,
        update: &crate::interception::DnsPolicyUpdate,
        error: Option<&str>,
    ) -> crate::journal::Result<()>;
    fn userspace_interception_plan(
        &mut self,
        gateway: &Plan,
        update: &crate::interception::DnsPolicyUpdate,
        now_secs: u64,
    ) -> crate::journal::Result<crate::interception::Plan>;
    fn stop_observer(&mut self);
}
impl BackendOps for Backend {
    fn plan(&mut self, console: Ipv4Addr) -> crate::journal::Result<Plan> {
        Backend::plan(self, console)
    }
    fn health(&mut self, plan: &Plan) -> crate::journal::Result<()> {
        Backend::health(self, plan)
    }
    fn start_observer(&mut self, plan: &Plan) -> crate::journal::Result<ObservationStatus> {
        Backend::start_observer(self, plan)
    }
    fn poll_observer(&mut self) -> crate::journal::Result<ObservationStatus> {
        Backend::poll_observer(self)
    }
    fn m2_snapshot(
        &mut self,
        proof: &QualifiedShadowRun,
    ) -> crate::journal::Result<crate::runtime::ObserverSnapshot> {
        Backend::m2_snapshot(self, proof)
    }
    fn userspace_readiness(&mut self) -> crate::journal::Result<()> {
        Backend::userspace_readiness(self)
    }
    fn userspace_policy_update(
        &mut self,
    ) -> crate::journal::Result<Option<crate::interception::DnsPolicyUpdate>> {
        Backend::userspace_policy_update(self)
    }
    fn acknowledge_userspace_policy(
        &mut self,
        update: &crate::interception::DnsPolicyUpdate,
        error: Option<&str>,
    ) -> crate::journal::Result<()> {
        Backend::acknowledge_userspace_policy(self, update, error)
    }
    fn userspace_interception_plan(
        &mut self,
        gateway: &Plan,
        update: &crate::interception::DnsPolicyUpdate,
        now_secs: u64,
    ) -> crate::journal::Result<crate::interception::Plan> {
        Backend::userspace_interception_plan(self, gateway, update, now_secs)
    }
    fn stop_observer(&mut self) {
        Backend::stop_observer(self)
    }
}

struct ActiveSample {
    expected: ExpectedSample,
    before: ObservationStatus,
}

struct Runtime<B: BackendOps> {
    store: Store,
    backend: B,
    status: Status,
    owner: Option<u64>,
    last_heartbeat: Instant,
    last_wall_heartbeat: SystemTime,
    evaluator: ShadowEvaluator,
    active_sample: Option<ActiveSample>,
    proof: Option<QualifiedShadowRun>,
    userspace_readiness_at: Instant,
    userspace_started_at: Instant,
}
impl<B: BackendOps> Runtime<B> {
    fn start_userspace(&mut self, gateway: &Plan) -> crate::journal::Result<usize> {
        self.userspace_started_at = Instant::now();
        let process = engine::start(
            &mut self.store,
            &mut self.backend,
            EnginePlan::konsollink_gateway(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            // Check the supervised process before every network attempt. This
            // reports an engine/configuration failure instead of masking it as
            // a generic curl timeout until the readiness deadline expires.
            engine::poll(&mut self.backend, process)?;
            if let Some(update) = self.backend.userspace_policy_update()? {
                let prepared = (|| {
                    let interception = self
                        .backend
                        .userspace_interception_plan(gateway, &update, 0)?;
                    let destinations = interception.destinations.len();
                    crate::interception::start(
                        &mut self.store,
                        &mut self.backend,
                        interception,
                        0,
                    )?;
                    Ok::<usize, crate::journal::Error>(destinations)
                })();
                match prepared {
                    Ok(destinations) => {
                        self.backend.acknowledge_userspace_policy(&update, None)?;
                        loop {
                            engine::poll(&mut self.backend, process)?;
                            match self.backend.userspace_readiness() {
                                Ok(()) => {
                                    self.userspace_readiness_at = Instant::now();
                                    return Ok(destinations);
                                }
                                Err(error) if Instant::now() < deadline => {
                                    thread::sleep(Duration::from_millis(150));
                                    if Instant::now() >= deadline {
                                        return Err(error);
                                    }
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    Err(error) => {
                        let detail = error.to_string();
                        self.backend
                            .acknowledge_userspace_policy(&update, Some(&detail))?;
                        return Err(error);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(crate::journal::Error::Backend(
                    "gateway produced no acknowledged Discord DNS policy".into(),
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn expired(&self) -> bool {
        self.last_heartbeat.elapsed() >= LEASE
            || self.last_wall_heartbeat.elapsed().unwrap_or(LEASE) >= LEASE
    }
    fn disconnected(&mut self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        if self.owner == Some(id) {
            self.stop()?;
        }
        Ok(())
    }
    fn watchdog(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.owner.is_some() && self.expired() {
            self.stop()?;
        }
        Ok(())
    }
    fn poll_observer(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.owner.is_none() {
            return Ok(());
        }
        match self.backend.poll_observer() {
            Ok(observation) => self.status.observation = observation,
            Err(error) => {
                let message = format!("observation stopped safely: {error}");
                self.stop()?;
                self.status.error = Some(message);
            }
        }
        Ok(())
    }
    fn poll_m2(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self
            .status
            .gateway
            .as_ref()
            .is_some_and(|plan| plan.mode == Mode::Userspace)
        {
            let gateway = self.status.gateway.clone().expect("checked above");
            let now_secs = self.userspace_started_at.elapsed().as_secs();
            if let Some(update) = self.backend.userspace_policy_update()? {
                let refresh = (|| -> crate::journal::Result<usize> {
                    let next = self
                        .backend
                        .userspace_interception_plan(&gateway, &update, now_secs)?;
                    let destinations = next.destinations.len();
                    let current = self
                        .store
                        .load()?
                        .and_then(|journal| journal.interception)
                        .ok_or(crate::journal::Error::Invalid(
                            "missing transparent interception",
                        ))?;
                    if current.plan.same_kernel_rules(&next) {
                        self.store.renew_interception(next, now_secs)?;
                    } else {
                        self.store
                            .replace_interception(&mut self.backend, next, now_secs)?;
                    }
                    Ok(destinations)
                })();
                match refresh {
                    Ok(destinations) => {
                        self.backend.acknowledge_userspace_policy(&update, None)?;
                        self.status.intercepted_destinations = destinations;
                    }
                    Err(error) => {
                        let detail = error.to_string();
                        self.backend
                            .acknowledge_userspace_policy(&update, Some(&detail))?;
                        let message = format!("Discord DNS policy stopped safely: {error}");
                        self.stop()?;
                        self.status.error = Some(message);
                        return Ok(());
                    }
                }
            }
            if self.userspace_readiness_at.elapsed() >= USERSPACE_READINESS_REFRESH {
                if let Err(error) = self.backend.userspace_readiness() {
                    let current_is_valid = self
                        .store
                        .load()?
                        .and_then(|journal| journal.interception)
                        .is_some_and(|record| record.plan.is_current(now_secs));
                    if !current_is_valid {
                        let message = format!("Discord transparent route stopped safely: {error}");
                        self.stop()?;
                        self.status.error = Some(message);
                    }
                } else {
                    self.userspace_readiness_at = Instant::now();
                }
            }
            return Ok(());
        }
        let (Some(proof), Some(plan)) = (self.proof.as_ref(), self.status.gateway.clone()) else {
            return Ok(());
        };
        let result = (|| -> crate::journal::Result<crate::runtime::State> {
            let snapshot = self.backend.m2_snapshot(proof)?;
            crate::runtime::reconcile_snapshot(&mut self.store, &mut self.backend, &plan, &snapshot)
        })();
        match result {
            Ok(crate::runtime::State::Observing) => {
                self.status.discord_bypass = false;
                self.status.intercepted_destinations = 0;
            }
            Ok(crate::runtime::State::Active { destinations }) => {
                self.status.discord_bypass = true;
                self.status.intercepted_destinations = destinations;
            }
            Err(error) => {
                let message = format!("Discord bypass stopped safely: {error}");
                self.stop()?;
                self.status.error = Some(message);
            }
        }
        Ok(())
    }
    fn update_qualification_status(&mut self, state: &str) {
        let report = self.evaluator.report();
        self.status.qualification = QualificationStatus {
            state: state.into(),
            active_sample: self
                .active_sample
                .as_ref()
                .map(|sample| match sample.expected {
                    ExpectedSample::NonDiscord => "non_discord".into(),
                    ExpectedSample::DiscordControl => "discord_control".into(),
                }),
            non_discord_samples: report.non_discord_samples,
            discord_control_samples: report.discord_control_samples,
            false_positives: report.false_positives,
            false_negatives: report.false_negatives,
            class_mismatches: report.class_mismatches,
        };
    }
    fn begin_sample(&mut self, expected: ExpectedSample) -> Status {
        if self.owner.is_none() {
            return self.denied("gateway is not active");
        }
        if self.proof.is_some() {
            return self.denied("qualification already completed");
        }
        if self.active_sample.is_some() {
            return self.denied("finish the active qualification sample first");
        }
        self.active_sample = Some(ActiveSample {
            expected,
            before: self.status.observation.clone(),
        });
        self.update_qualification_status("sampling");
        self.status.clone()
    }
    fn finish_sample(&mut self) -> Result<Status, Box<dyn std::error::Error>> {
        let Some(sample) = self.active_sample.take() else {
            return Ok(self.denied("no active qualification sample"));
        };
        let current = self.backend.poll_observer()?;
        self.status.observation = current.clone();
        let direct = current
            .direct_observations
            .saturating_sub(sample.before.direct_observations);
        let control = current
            .discord_control_candidates
            .saturating_sub(sample.before.discord_control_candidates);
        let media = current
            .discord_media_candidates
            .saturating_sub(sample.before.discord_media_candidates);
        if direct == 0 && control == 0 && media == 0 {
            self.update_qualification_status("collecting");
            return Ok(self.denied("sample contained no observable console traffic; retry it"));
        }
        let observed = if control > 0 {
            FlowClass::DiscordControlCandidate
        } else if media > 0 {
            FlowClass::DiscordMediaCandidate
        } else {
            FlowClass::Direct
        };
        let expected = match sample.expected {
            ExpectedSample::NonDiscord => ExpectedClass::NonDiscord,
            ExpectedSample::DiscordControl => ExpectedClass::DiscordControl,
        };
        self.evaluator.observe(expected, observed);
        let report = self.evaluator.report();
        let requirements = QualificationRequirements::tcp_control_m2();
        let enough = report.non_discord_samples >= requirements.min_non_discord_samples
            && report.discord_control_samples >= requirements.min_control_samples;
        if enough {
            let capture = CaptureHealth {
                observer_active: current.state == "active",
                captured_packets: current.captured_packets,
                dropped_packets: current.dropped_packets,
            };
            match qualify(report, capture, requirements) {
                Ok(proof) => {
                    self.proof = Some(proof);
                    self.update_qualification_status("qualified");
                }
                Err(
                    QualificationError::FalsePositive
                    | QualificationError::FalseNegative
                    | QualificationError::ClassMismatch,
                ) => self.update_qualification_status("failed"),
                Err(error) => {
                    self.update_qualification_status("collecting");
                    return Ok(self.denied(&error.to_string()));
                }
            }
        } else {
            self.update_qualification_status("collecting");
        }
        Ok(self.status.clone())
    }
    fn reset_qualification(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.owner.is_none() {
            return Ok(());
        }
        if self.status.discord_bypass {
            self.store.stop_m2(&mut self.backend)?;
        }
        self.evaluator = ShadowEvaluator::default();
        self.active_sample = None;
        self.proof = None;
        self.status.discord_bypass = false;
        self.status.intercepted_destinations = 0;
        self.update_qualification_status("pending");
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.owner = None;
        self.backend.stop_observer();
        self.store.rollback(&mut self.backend)?;
        self.status = Status::off();
        self.evaluator = ShadowEvaluator::default();
        self.active_sample = None;
        self.proof = None;
        Ok(())
    }
    fn command(&mut self, id: u64, command: Command) -> Result<Status, Box<dyn std::error::Error>> {
        self.watchdog()?;
        match command {
            Command::Status {} => {}
            Command::Stop {} => self.stop()?,
            Command::Heartbeat {} => {
                if self.owner != Some(id) {
                    return Ok(self.denied("connection does not own the gateway lease"));
                }
                self.last_heartbeat = Instant::now();
                self.last_wall_heartbeat = SystemTime::now();
            }
            Command::BeginSample { expected } => {
                if self.owner != Some(id) {
                    return Ok(self.denied("connection does not own the gateway lease"));
                }
                return Ok(self.begin_sample(expected));
            }
            Command::FinishSample {} => {
                if self.owner != Some(id) {
                    return Ok(self.denied("connection does not own the gateway lease"));
                }
                return self.finish_sample();
            }
            Command::ResetQualification {} => {
                if self.owner != Some(id) {
                    return Ok(self.denied("connection does not own the gateway lease"));
                }
                self.reset_qualification()?
            }
            Command::Start {
                console,
                ipv4_only_confirmed,
                exclusive_host_confirmed,
            } => {
                if self.owner.is_some() {
                    return Ok(self
                        .denied("gateway already has an owner; stop it before changing console"));
                }
                if !ipv4_only_confirmed || !exclusive_host_confirmed {
                    return Ok(self.denied("M0 requires confirmed IPv4-only console/router and exclusive test-host use"));
                }
                let result =
                    (|| -> Result<(Plan, ObservationStatus, bool, usize), Box<dyn std::error::Error>> {
                        let plan = self.backend.plan(console)?;
                        self.store
                            .prepare_gateway(&mut self.backend, plan.clone())?;
                        self.store.apply(&mut self.backend)?;
                        self.backend.health(&plan)?;
                        let observation = self.backend.start_observer(&plan)?;
                        let integrated = plan.mode == Mode::Userspace;
                        let destinations = if integrated {
                            self.start_userspace(&plan)?
                        } else {
                            0
                        };
                        Ok((plan, observation, integrated, destinations))
                    })();
                match result {
                    Ok((plan, observation, integrated, destinations)) => {
                        self.status = Status {
                            version: VERSION,
                            state: "gateway_active".into(),
                            gateway: Some(plan),
                            discord_bypass: integrated,
                            intercepted_destinations: destinations,
                            qualification: if integrated {
                                QualificationStatus::qualified()
                            } else {
                                QualificationStatus::pending()
                            },
                            observation,
                            error: None,
                        };
                        self.owner = Some(id);
                        self.last_heartbeat = Instant::now();
                        self.last_wall_heartbeat = SystemTime::now();
                    }
                    Err(error) => {
                        let message = error.to_string();
                        // Persistence failures poison the Store: exiting lets launchd
                        // reopen durable evidence and recover, without erasing it.
                        self.stop()?;
                        return Ok(self.denied(&message));
                    }
                }
            }
        }
        Ok(self.status.clone())
    }
    fn denied(&self, error: &str) -> Status {
        let mut status = self.status.clone();
        status.error = Some(error.into());
        status
    }
}

pub fn serve(uid: u32) -> Result<(), Box<dyn std::error::Error>> {
    if uid == 0 {
        return Err("client UID must identify an unprivileged account".into());
    }
    let mut store = Store::open_system()?;
    let mut backend = Backend::new()?;
    store.rollback(&mut backend)?; // No socket/ON before successful recovery.
    for path in ["/private", "/private/var", "/private/var/db"] {
        crate::journal::verify_socket_ancestor(path)?;
    }
    match fs::symlink_metadata(SOCKET_DIR) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(SOCKET_DIR)?;
            fs::set_permissions(SOCKET_DIR, fs::Permissions::from_mode(0o755))?;
        }
        Err(e) => return Err(e.into()),
    }
    crate::journal::verify_socket_ancestor(SOCKET_DIR)?;
    let socket_dir = fs::symlink_metadata(SOCKET_DIR)?;
    if !socket_dir.is_dir() || socket_dir.uid() != 0 || socket_dir.mode() & 0o7777 != 0o755 {
        return Err("unsafe IPC directory ownership or permissions".into());
    }
    match fs::symlink_metadata(SOCKET) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => fs::remove_file(SOCKET)?,
        Ok(_) => return Err("refusing to replace unsafe socket path".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))?;
    listener.set_nonblocking(true)?;
    // SAFETY: handlers only write a lock-free atomic flag; normal loop performs rollback.
    unsafe {
        libc::signal(libc::SIGTERM, signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal as *const () as libc::sighandler_t);
    }
    let mut runtime = Runtime {
        store,
        backend,
        status: Status::off(),
        owner: None,
        last_heartbeat: Instant::now(),
        last_wall_heartbeat: SystemTime::now(),
        evaluator: ShadowEvaluator::default(),
        active_sample: None,
        proof: None,
        userspace_readiness_at: Instant::now(),
        userspace_started_at: Instant::now(),
    };
    let mut peers: Vec<Peer> = Vec::new();
    let mut next_id = 0u64;
    let mut health_at = Instant::now();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        while !STOP.load(Ordering::SeqCst) {
            runtime.watchdog()?;
            runtime.poll_observer()?;
            runtime.poll_m2()?;
            if runtime.owner.is_some() && health_at.elapsed() >= Duration::from_secs(3) {
                health_at = Instant::now();
                if let Some(plan) = &runtime.status.gateway {
                    let health = runtime.backend.health(plan).and_then(|_| {
                        let journal = runtime.store.load()?;
                        if let Some(process) =
                            journal.and_then(|j| j.engine).and_then(|e| e.process)
                        {
                            engine::poll(&mut runtime.backend, process)?;
                        }
                        Ok(())
                    });
                    if let Err(error) = health {
                        let message = error.to_string();
                        runtime.stop()?;
                        runtime.status.error = Some(message);
                    }
                }
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let peer = peer_uid(&stream)?;
                    if peers.len() < 8 && (peer == uid || peer == 0) {
                        stream.set_nonblocking(true)?;
                        next_id = next_id
                            .checked_add(1)
                            .ok_or("connection counter overflow")?;
                        peers.push(Peer {
                            stream,
                            input: vec![],
                            id: next_id,
                            partial_since: None,
                        });
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            let mut index = 0;
            while index < peers.len() {
                let p = &mut peers[index];
                let mut buffer = [0; MAX_FRAME + 1];
                let mut closed = p
                    .partial_since
                    .is_some_and(|t| t.elapsed() > Duration::from_secs(2));
                if !closed {
                    match p.stream.read(&mut buffer) {
                        Ok(0) => closed = true,
                        Ok(n) => {
                            p.partial_since.get_or_insert_with(Instant::now);
                            p.input.extend_from_slice(&buffer[..n]);
                            if p.input.len() > MAX_FRAME {
                                closed = true;
                            } else if let Some(end) = p.input.iter().position(|b| *b == b'\n') {
                                // Exactly one request at a time; no pipelining or trailing commands.
                                if end + 1 != p.input.len() {
                                    closed = true;
                                } else {
                                    match decode(&p.input[..end]) {
                                        Ok(request) => {
                                            let response =
                                                runtime.command(p.id, request.command)?;
                                            let mut bytes = serde_json::to_vec(&response)?;
                                            bytes.push(b'\n');
                                            // Small bounded response; a slow reader loses its lease.
                                            if p.stream.write_all(&bytes).is_err() {
                                                closed = true;
                                            }
                                        }
                                        Err(_) => closed = true,
                                    }
                                    p.input.clear();
                                    p.partial_since = None;
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => closed = true,
                    }
                }
                if closed {
                    runtime.disconnected(p.id)?;
                    peers.swap_remove(index);
                } else {
                    index += 1;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        runtime.stop()?;
        Ok(())
    })();
    // On errors preserve journal. Supervisor restarts and recovers it.
    if result.is_ok()
        && runtime
            .store
            .load()?
            .is_some_and(|j| j.phase != Phase::Complete)
    {
        return Err("recovery incomplete".into());
    }
    fs::remove_file(SOCKET)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::{EnginePlan, ProcessIdentity},
        journal::{Result as JournalResult, Setting, SettingsBackend},
    };
    use std::os::unix::fs::DirBuilderExt;
    struct Fake {
        values: [u32; 3],
        gateway_active: bool,
        observer_active: bool,
        observer_fail: bool,
        observation: ObservationStatus,
    }
    impl SettingsBackend for Fake {
        fn read(&mut self, setting: Setting) -> JournalResult<u32> {
            Ok(self.values[setting as usize])
        }
        fn write(&mut self, setting: Setting, value: u32) -> JournalResult<()> {
            self.values[setting as usize] = value;
            Ok(())
        }
        fn same_boot(&mut self, _: &Plan) -> JournalResult<bool> {
            Ok(true)
        }
        fn gateway(&mut self, _: &Plan, enable: bool) -> JournalResult<()> {
            self.gateway_active = enable;
            Ok(())
        }
    }
    impl ProcessBackend for Fake {
        fn spawn_engine_suspended(&mut self, _: &EnginePlan) -> JournalResult<ProcessIdentity> {
            Err(crate::journal::Error::Backend(
                "M2 unavailable in lease fixture".into(),
            ))
        }
        fn cancel_engine_suspended(&mut self, _: ProcessIdentity) -> JournalResult<()> {
            Ok(())
        }
        fn resume_engine(&mut self, _: ProcessIdentity) -> JournalResult<()> {
            Ok(())
        }
        fn engine_health(&mut self, _: ProcessIdentity) -> JournalResult<()> {
            Err(crate::journal::Error::Backend(
                "M2 unavailable in lease fixture".into(),
            ))
        }
    }
    impl BackendOps for Fake {
        fn plan(&mut self, _: Ipv4Addr) -> JournalResult<Plan> {
            Ok(crate::gateway::tests::plan())
        }
        fn health(&mut self, _: &Plan) -> JournalResult<()> {
            Ok(())
        }
        fn start_observer(&mut self, _: &Plan) -> JournalResult<ObservationStatus> {
            self.observer_active = true;
            self.observation.state = "active".into();
            Ok(self.observation.clone())
        }
        fn poll_observer(&mut self) -> JournalResult<ObservationStatus> {
            if !self.observer_active || self.observer_fail {
                return Err(crate::journal::Error::Backend("observer inactive".into()));
            }
            self.observation.state = "active".into();
            self.observation.captured_packets = self.observation.captured_packets.max(1);
            Ok(self.observation.clone())
        }
        fn m2_snapshot(
            &mut self,
            _: &QualifiedShadowRun,
        ) -> JournalResult<crate::runtime::ObserverSnapshot> {
            Err(crate::journal::Error::Backend(
                "M2 unavailable in lease fixture".into(),
            ))
        }
        fn userspace_readiness(&mut self) -> JournalResult<()> {
            Ok(())
        }
        fn userspace_policy_update(
            &mut self,
        ) -> JournalResult<Option<crate::interception::DnsPolicyUpdate>> {
            Ok(None)
        }
        fn acknowledge_userspace_policy(
            &mut self,
            _: &crate::interception::DnsPolicyUpdate,
            _: Option<&str>,
        ) -> JournalResult<()> {
            Ok(())
        }
        fn userspace_interception_plan(
            &mut self,
            _: &Plan,
            _: &crate::interception::DnsPolicyUpdate,
            _: u64,
        ) -> JournalResult<crate::interception::Plan> {
            Err(crate::journal::Error::Backend(
                "userspace unavailable in routed fixture".into(),
            ))
        }
        fn stop_observer(&mut self) {
            self.observer_active = false;
        }
    }
    #[test]
    fn lease_owner_disconnect_timeout_and_explicit_stop_restore_settings() {
        let path =
            std::env::temp_dir().join(format!("konsollink-lease-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let mut runtime = Runtime {
            store: Store::open_test(&path).unwrap(),
            backend: Fake {
                values: [0, 0, 1],
                gateway_active: false,
                observer_active: false,
                observer_fail: false,
                observation: ObservationStatus::off(),
            },
            status: Status::off(),
            owner: None,
            last_heartbeat: Instant::now(),
            last_wall_heartbeat: SystemTime::now(),
            evaluator: ShadowEvaluator::default(),
            active_sample: None,
            proof: None,
            userspace_readiness_at: Instant::now(),
            userspace_started_at: Instant::now(),
        };
        let start = || Command::Start {
            console: "192.168.1.20".parse().unwrap(),
            ipv4_only_confirmed: true,
            exclusive_host_confirmed: true,
        };
        let response = runtime
            .command(
                1,
                Command::Start {
                    console: "192.168.1.20".parse().unwrap(),
                    ipv4_only_confirmed: false,
                    exclusive_host_confirmed: true,
                },
            )
            .unwrap();
        assert!(response.error.is_some());
        assert!(runtime.store.load().unwrap().is_none());
        for mode in 0..4 {
            assert_eq!(runtime.command(1, start()).unwrap().state, "gateway_active");
            let deadline = runtime.last_heartbeat;
            assert!(runtime
                .command(2, Command::Heartbeat {})
                .unwrap()
                .error
                .is_some());
            assert_eq!(deadline, runtime.last_heartbeat);
            assert!(runtime.command(2, start()).unwrap().error.is_some());
            runtime.disconnected(2).unwrap();
            assert!(runtime.backend.gateway_active);
            assert!(runtime.backend.observer_active);
            runtime.poll_observer().unwrap();
            assert_eq!(runtime.status.observation.captured_packets, 1);
            match mode {
                0 => runtime.disconnected(1).unwrap(),
                1 => {
                    runtime.last_heartbeat = Instant::now() - LEASE;
                    runtime.watchdog().unwrap();
                }
                2 => {
                    runtime.last_wall_heartbeat = SystemTime::now() - LEASE;
                    runtime.watchdog().unwrap();
                }
                _ => {
                    runtime.command(2, Command::Stop {}).unwrap();
                }
            }
            assert_eq!(runtime.status.state, "off");
            assert_eq!(runtime.backend.values, [0, 0, 1]);
            assert!(!runtime.backend.gateway_active);
            assert!(!runtime.backend.observer_active);
        }
        drop(runtime);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn observer_failure_stops_gateway_and_restores_settings() {
        let path = std::env::temp_dir().join(format!(
            "konsollink-observer-failure-test-{}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let mut runtime = Runtime {
            store: Store::open_test(&path).unwrap(),
            backend: Fake {
                values: [0, 0, 1],
                gateway_active: false,
                observer_active: false,
                observer_fail: false,
                observation: ObservationStatus::off(),
            },
            status: Status::off(),
            owner: None,
            last_heartbeat: Instant::now(),
            last_wall_heartbeat: SystemTime::now(),
            evaluator: ShadowEvaluator::default(),
            active_sample: None,
            proof: None,
            userspace_readiness_at: Instant::now(),
            userspace_started_at: Instant::now(),
        };
        runtime
            .command(
                1,
                Command::Start {
                    console: "192.168.1.20".parse().unwrap(),
                    ipv4_only_confirmed: true,
                    exclusive_host_confirmed: true,
                },
            )
            .unwrap();
        runtime.backend.observer_fail = true;
        runtime.poll_observer().unwrap();
        assert_eq!(runtime.status.state, "off");
        assert!(runtime
            .status
            .error
            .as_deref()
            .unwrap()
            .contains("observation"));
        assert_eq!(runtime.backend.values, [0, 0, 1]);
        assert!(!runtime.backend.gateway_active);
        assert!(!runtime.backend.observer_active);
        assert!(runtime
            .store
            .load()
            .unwrap()
            .is_none_or(|journal| journal.phase == Phase::Complete));
        drop(runtime);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn labeled_samples_gate_m2_and_reject_other_clients() {
        let path = std::env::temp_dir().join(format!(
            "konsollink-qualification-test-{}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let mut runtime = Runtime {
            store: Store::open_test(&path).unwrap(),
            backend: Fake {
                values: [0, 0, 1],
                gateway_active: false,
                observer_active: false,
                observer_fail: false,
                observation: ObservationStatus::off(),
            },
            status: Status::off(),
            owner: None,
            last_heartbeat: Instant::now(),
            last_wall_heartbeat: SystemTime::now(),
            evaluator: ShadowEvaluator::default(),
            active_sample: None,
            proof: None,
            userspace_readiness_at: Instant::now(),
            userspace_started_at: Instant::now(),
        };
        runtime
            .command(
                1,
                Command::Start {
                    console: "192.168.1.20".parse().unwrap(),
                    ipv4_only_confirmed: true,
                    exclusive_host_confirmed: true,
                },
            )
            .unwrap();
        assert!(runtime
            .command(
                2,
                Command::BeginSample {
                    expected: ExpectedSample::NonDiscord,
                },
            )
            .unwrap()
            .error
            .is_some());

        for expected in [ExpectedSample::NonDiscord, ExpectedSample::NonDiscord] {
            runtime
                .command(1, Command::BeginSample { expected })
                .unwrap();
            runtime.backend.observation.direct_observations += 1;
            runtime.backend.observation.captured_packets += 1;
            runtime.command(1, Command::FinishSample {}).unwrap();
        }
        runtime
            .command(
                1,
                Command::BeginSample {
                    expected: ExpectedSample::DiscordControl,
                },
            )
            .unwrap();
        runtime.backend.observation.discord_control_candidates += 1;
        runtime.backend.observation.captured_packets += 1;
        let result = runtime.command(1, Command::FinishSample {}).unwrap();
        assert_eq!(result.qualification.state, "qualified");
        assert!(runtime.proof.is_some());
        assert!(!result.discord_bypass);

        runtime.command(1, Command::Stop {}).unwrap();
        drop(runtime);
        fs::remove_dir_all(path).unwrap();
    }
}
