use super::{
    EngineKind, EnginePlan, EngineRecord, ProcessIdentity, LOOPBACK_PORT, PCAP2SOCKS_SHA256,
    TPWS_V72_13_SHA256,
};
use crate::journal::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem,
    os::{
        fd::AsRawFd,
        unix::fs::MetadataExt,
        unix::net::UnixStream,
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const ENGINE_PATH: &str = "/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/tpws-v72.13";
pub const PCAP2SOCKS_PATH: &str =
    "/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/go-pcap2socks-ec407738-konsollink";
pub const CONFIG_PATH: &str =
    "/Library/PrivilegedHelperTools/tr.konsollink.m0/engines/gateway-macos.json";
pub const GATEWAY_RUNTIME_UID: u32 = 65_534;
const CONFIG_SHA256: &str = "33491fa98e3cf6a64244c5052aa9b14e5d1dd47aa8e8d69e7fd536254b4af66e";
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const STOP_GRACE: Duration = Duration::from_secs(2);
const EXEC_GRACE: Duration = Duration::from_secs(2);
const POLICY_FD: libc::c_int = 9;

fn engine_arguments() -> Result<Vec<String>> {
    let domains = konsollink_core::ServiceProfile::discord_tr()
        .map_err(fail)?
        .domains
        .join(",");
    Ok(vec![
        "--bind-addr=127.0.0.1".into(),
        format!("--port={LOOPBACK_PORT}"),
        "--maxconn=256".into(),
        // macOS requires root at each /dev/pf DIOCNATLOOK query. The gateway
        // drops to GATEWAY_RUNTIME_UID after opening BPF, so root tpws sockets
        // are outside the PF owner rule and cannot loop back into tpws.
        "--user=root".into(),
        "--filter-tcp=80".into(),
        "--hostspell=hoSt".into(),
        format!("--hostlist-domains={domains}"),
        "--new".into(),
        "--filter-tcp=443".into(),
        "--split-pos=2".into(),
        "--oob".into(),
        format!("--hostlist-domains={domains}"),
        "--debug=0".into(),
    ])
}

fn fail(message: impl std::fmt::Display) -> Error {
    Error::Backend(message.to_string())
}

fn digest(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        if copied > MAX_ARTIFACT_BYTES {
            return Err(Error::Invalid("engine artifact size limit"));
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn verify_artifact(path: &Path, expected_hash: &str, owner: u32) -> Result<File> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o555
        || metadata.len() == 0
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        return Err(Error::Unsafe("engine artifact ownership or permissions"));
    }
    if digest(&mut file)? != expected_hash {
        return Err(Error::Invalid("engine artifact SHA-256"));
    }
    Ok(file)
}

fn verify_production_artifacts(kind: EngineKind) -> Result<()> {
    for directory in [
        "/Library",
        "/Library/PrivilegedHelperTools",
        "/Library/PrivilegedHelperTools/tr.konsollink.m0",
        "/Library/PrivilegedHelperTools/tr.konsollink.m0/engines",
    ] {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Error::Unsafe(
                "engine artifact directory ownership or permissions",
            ));
        }
    }
    verify_artifact(Path::new(ENGINE_PATH), TPWS_V72_13_SHA256, 0)?;
    if kind == EngineKind::KonsolLinkGatewayEc407738 {
        verify_artifact(Path::new(PCAP2SOCKS_PATH), PCAP2SOCKS_SHA256, 0)?;
        let mut config = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(CONFIG_PATH)?;
        let metadata = config.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o444
            || metadata.nlink() != 1
            || digest(&mut config)? != CONFIG_SHA256
        {
            return Err(Error::Unsafe(
                "gateway config ownership, permissions or content",
            ));
        }
    }
    Ok(())
}

fn process_identity(pid: u32) -> Result<Option<ProcessIdentity>> {
    if pid > i32::MAX as u32 {
        return Ok(None);
    }
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    // SAFETY: fixed flavor and a correctly sized writable output structure.
    let read = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            mem::size_of_val(&info) as i32,
        )
    };
    if read == 0 {
        return Ok(None);
    }
    if read as usize != mem::size_of_val(&info) || info.pbi_pid != pid {
        return Err(fail("invalid process identity response"));
    }
    let birth_micros = u32::try_from(info.pbi_start_tvusec)
        .map_err(|_| Error::Invalid("invalid process birth identity"))?;
    let identity = ProcessIdentity {
        pid,
        birth_seconds: info.pbi_start_tvsec,
        birth_micros,
    };
    identity.validate()?;
    Ok(Some(identity))
}

fn identity_matches(expected: ProcessIdentity) -> Result<bool> {
    Ok(process_identity(expected.pid)? == Some(expected))
}

fn process_path(pid: u32) -> Result<Option<PathBuf>> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is writable and its exact capacity is supplied.
    let length =
        unsafe { libc::proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return Ok(None);
    }
    buffer.truncate(length as usize);
    Ok(Some(PathBuf::from(
        std::str::from_utf8(&buffer).map_err(|_| fail("non-UTF-8 process path"))?,
    )))
}

struct PendingChild {
    child: Child,
    control: Option<ChildStdin>,
    stderr: Option<ChildStderr>,
    identity: ProcessIdentity,
    kind: EngineKind,
    policy: Option<UnixStream>,
}

impl PendingChild {
    fn spawn(mut command: Command, kind: EngineKind) -> Result<Self> {
        let (policy, policy_child) = if kind == EngineKind::KonsolLinkGatewayEc407738 {
            let (parent, child) = UnixStream::pair()?;
            parent.set_nonblocking(true)?;
            command.env("KONSOLLINK_POLICY_FD", POLICY_FD.to_string());
            (Some(parent), Some(child))
        } else {
            (None, None)
        };
        let policy_child_fd = policy_child.as_ref().map(AsRawFd::as_raw_fd);
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(fd) = policy_child_fd {
                    if libc::dup2(fd, POLICY_FD) < 0 || libc::fcntl(POLICY_FD, libc::F_SETFD, 0) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let control = child
            .stdin
            .take()
            .ok_or_else(|| fail("missing engine control pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| fail("missing engine diagnostic pipe"))?;
        let identity = process_identity(child.id())?
            .ok_or_else(|| fail("spawned engine wrapper disappeared"))?;
        Ok(Self {
            child,
            control: Some(control),
            stderr: Some(stderr),
            identity,
            kind,
            policy,
        })
    }

    fn resume(&mut self) -> Result<()> {
        let mut control = self
            .control
            .take()
            .ok_or_else(|| fail("engine wrapper already resumed"))?;
        control.write_all(b"R")?;
        drop(control);
        Ok(())
    }

    fn cancel(mut self) -> Result<()> {
        drop(self.control.take());
        wait_child(&mut self.child, STOP_GRACE)
    }

    fn exit_detail(&mut self) -> String {
        let mut detail = String::new();
        if let Some(mut stderr) = self.stderr.take() {
            let _ = stderr.read_to_string(&mut detail);
        }
        let detail = detail.trim();
        if detail.chars().count() > 1024 {
            format!("{}…", detail.chars().take(1024).collect::<String>())
        } else {
            detail.to_owned()
        }
    }
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(fail("engine child did not exit before timeout"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub struct ProcessAdapter {
    pending: Option<PendingChild>,
}

impl Default for ProcessAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAdapter {
    pub fn new() -> Self {
        Self { pending: None }
    }

    pub fn spawn_suspended(&mut self, plan: &EnginePlan) -> Result<ProcessIdentity> {
        plan.validate()?;
        if self.pending.is_some() {
            return Err(Error::Invalid("engine wrapper already pending"));
        }
        verify_production_artifacts(plan.kind)?;
        let helper = std::env::current_exe()?;
        let metadata = helper.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Error::Unsafe("helper executable ownership or permissions"));
        }
        let pending = PendingChild::spawn(
            {
                let mut command = Command::new(helper);
                command.args([
                    "__engine-child",
                    match plan.kind {
                        EngineKind::ZapretTpwsV72_13 => "tpws",
                        EngineKind::KonsolLinkGatewayEc407738 => "gateway",
                    },
                ]);
                command
            },
            plan.kind,
        )?;
        let identity = pending.identity;
        self.pending = Some(pending);
        Ok(identity)
    }

    pub fn cancel_suspended(&mut self, process: ProcessIdentity) -> Result<()> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| fail("no suspended engine wrapper"))?;
        if pending.identity != process {
            self.pending = Some(pending);
            return Err(Error::Invalid("engine wrapper identity mismatch"));
        }
        pending.cancel()
    }

    pub fn resume(&mut self, process: ProcessIdentity) -> Result<()> {
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| fail("no suspended engine wrapper"))?;
        if pending.identity != process {
            return Err(Error::Invalid("engine wrapper identity mismatch"));
        }
        pending.resume()?;
        let deadline = Instant::now() + EXEC_GRACE;
        while Instant::now() < deadline {
            if !identity_matches(process)? {
                return Err(fail("engine exited during exec"));
            }
            let expected = match pending.kind {
                EngineKind::ZapretTpwsV72_13 => PathBuf::from(ENGINE_PATH),
                EngineKind::KonsolLinkGatewayEc407738 => std::env::current_exe()?,
            };
            if process_path(process.pid)?.as_ref() == Some(&expected) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(fail("engine did not exec before timeout"))
    }

    pub fn health(&mut self, process: ProcessIdentity) -> Result<()> {
        // While this helper instance owns the engine, Child is the authoritative
        // process handle. macOS may report a different proc_pidpath spelling (or
        // transient identity data) after the fixed wrapper enters its supervised
        // engine mode; treating that as a replacement stopped a healthy engine
        // on the first three-second health check.
        if let Some(pending) = self.pending.as_mut() {
            if pending.identity != process {
                return Err(fail("engine child identity does not match journal"));
            }
            if let Some(status) = pending.child.try_wait()? {
                let detail = pending.exit_detail();
                return Err(fail(if detail.is_empty() {
                    format!("engine process exited: {status}")
                } else {
                    format!("engine process exited: {status}; {detail}")
                }));
            }
            return Ok(());
        }

        // Recovery-only fallback when this helper did not spawn the process.
        let path = process_path(process.pid)?;
        let helper = std::env::current_exe()?;
        if !identity_matches(process)?
            || !matches!(path.as_deref(), Some(p) if p == Path::new(ENGINE_PATH) || p == helper)
        {
            return Err(fail("engine process identity or image changed"));
        }
        Ok(())
    }

    pub fn policy_stream(&mut self) -> Result<&mut UnixStream> {
        self.pending
            .as_mut()
            .and_then(|pending| pending.policy.as_mut())
            .ok_or_else(|| fail("gateway DNS policy channel is unavailable"))
    }

    pub fn policy_channel_closed_error(&mut self) -> Error {
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            let Some(pending) = self.pending.as_mut() else {
                return fail("gateway DNS policy channel closed without an owned process");
            };
            match pending.child.try_wait() {
                Ok(Some(status)) => {
                    let detail = pending.exit_detail();
                    return fail(if detail.is_empty() {
                        format!("gateway DNS policy channel closed; engine exited: {status}")
                    } else {
                        format!(
                            "gateway DNS policy channel closed; engine exited: {status}; {detail}"
                        )
                    });
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => return fail(format!("gateway DNS policy channel closed: {error}")),
            }
        }
        fail("gateway DNS policy channel closed while engine wrapper remained active")
    }

    pub fn stop(&mut self, record: &EngineRecord) -> Result<()> {
        record.validate()?;
        let process = record
            .process
            .ok_or(Error::Invalid("missing engine process identity"))?;
        if let Some(mut pending) = self.pending.take() {
            if pending.identity == process {
                if pending.control.is_some() {
                    return pending.cancel();
                }
                return signal_child_and_wait(process, &mut pending.child);
            }
            self.pending = Some(pending);
        }
        signal_and_wait(process)
    }
}

fn signal_child_and_wait(process: ProcessIdentity, child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if child.id() != process.pid {
        return Err(fail("engine child identity does not match journal"));
    }
    // SAFETY: an unreaped Child handle still owns this exact PID and process
    // group, so PID reuse is impossible until wait completes.
    if unsafe { libc::kill(-(process.pid as i32), libc::SIGTERM) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait()?.is_none() {
        // Terminate the owned group so supervised tpws/gateway children cannot
        // survive if the wrapper's signal handler is itself stuck.
        if unsafe { libc::kill(-(process.pid as i32), libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
    }
    wait_child(child, STOP_GRACE)
}

fn signal_and_wait(process: ProcessIdentity) -> Result<()> {
    if !identity_matches(process)? {
        return Ok(());
    }
    // SAFETY: full birth identity was matched immediately before signalling.
    if unsafe { libc::kill(-(process.pid as i32), libc::SIGTERM) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if !identity_matches(process)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !identity_matches(process)? {
        return Ok(());
    }
    // SAFETY: identity is rechecked after the grace period to prevent PID reuse.
    if unsafe { libc::kill(-(process.pid as i32), libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    let kill_deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < kill_deadline {
        if !identity_matches(process)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(fail("engine process survived SIGKILL"))
}

/// Hidden fixed child mode. It cannot accept a path or arguments.
pub fn child_main(kind: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Unsafe("root engine wrapper required"));
    }
    let mut byte = [0u8; 1];
    std::io::stdin().read_exact(&mut byte)?;
    if byte != *b"R" {
        return Err(Error::Invalid("invalid engine control message"));
    }
    let kind = match kind {
        "tpws" => EngineKind::ZapretTpwsV72_13,
        "gateway" => EngineKind::KonsolLinkGatewayEc407738,
        _ => return Err(Error::Invalid("invalid engine child kind")),
    };
    verify_production_artifacts(kind)?;
    if kind == EngineKind::ZapretTpwsV72_13 {
        let error = Command::new(ENGINE_PATH).args(engine_arguments()?).exec();
        return Err(error.into());
    }
    supervise_gateway()
}

static CHILD_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn child_signal(_: libc::c_int) {
    CHILD_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn terminate(child: &mut Child) {
    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = wait_child(child, STOP_GRACE);
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn supervise_gateway() -> Result<()> {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            child_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            child_signal as *const () as libc::sighandler_t,
        );
    }
    // Do not leak the policy capability into tpws. It is inherited only by
    // the fixed gateway child below.
    if unsafe { libc::fcntl(POLICY_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut tpws = Command::new(ENGINE_PATH)
        .args(engine_arguments()?)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    thread::sleep(Duration::from_millis(150));
    if let Some(status) = tpws.try_wait()? {
        return Err(fail(format!("tpws exited during startup: {status}")));
    }
    let mut gateway_command = Command::new(PCAP2SOCKS_PATH);
    gateway_command
        .arg(CONFIG_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // The gateway logs only bounded operational diagnostics. Preserve them
        // on the wrapper's captured stderr so an early child failure is not
        // reduced to an unhelpful policy-channel EOF.
        .stderr(Stdio::inherit());
    unsafe {
        gateway_command.pre_exec(|| {
            if libc::fcntl(POLICY_FD, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut gateway = match gateway_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            terminate(&mut tpws);
            return Err(error.into());
        }
    };
    // The Go child now owns the inherited endpoint. Closing the supervisor's
    // duplicate makes channel loss observable by the root helper.
    unsafe {
        libc::close(POLICY_FD);
    }
    loop {
        if CHILD_STOP.load(std::sync::atomic::Ordering::SeqCst) {
            terminate(&mut gateway);
            terminate(&mut tpws);
            return Ok(());
        }
        if let Some(status) = tpws.try_wait()? {
            terminate(&mut gateway);
            return Err(fail(format!("tpws exited: {status}")));
        }
        if let Some(status) = gateway.try_wait()? {
            terminate(&mut tpws);
            return Err(fail(format!("gateway exited: {status}")));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    };

    #[test]
    fn artifact_hash_permissions_and_links_are_checked() {
        let root = std::env::temp_dir().join(format!("konsollink-artifact-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let artifact = root.join("engine");
        fs::copy("/usr/bin/true", &artifact).unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o555)).unwrap();
        let owner = artifact.metadata().unwrap().uid();
        let expected = digest(&mut File::open(&artifact).unwrap()).unwrap();
        assert!(verify_artifact(&artifact, &expected, owner).is_ok());
        assert!(verify_artifact(&artifact, &"0".repeat(64), owner).is_err());
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_artifact(&artifact, &expected, owner).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn control_pipe_eof_cancels_wrapper_and_identity_detects_reuse() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "read token || exit 0; exec /bin/sleep 30"]);
        let pending = PendingChild::spawn(command, EngineKind::ZapretTpwsV72_13).unwrap();
        let identity = pending.identity;
        assert!(identity_matches(identity).unwrap());
        let wrong = ProcessIdentity {
            birth_micros: (identity.birth_micros + 1) % 1_000_000,
            ..identity
        };
        assert!(!identity_matches(wrong).unwrap());
        pending.cancel().unwrap();
        assert!(!identity_matches(identity).unwrap());
    }

    #[test]
    fn gateway_policy_descriptor_is_private_and_bidirectional() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "cat >/dev/null || exit 1; IFS= read -r policy <&9 || exit 2; printf '%s\\n' \"$policy\" >&9",
        ]);
        let mut pending =
            PendingChild::spawn(command, EngineKind::KonsolLinkGatewayEc407738).unwrap();
        pending.resume().unwrap();
        let policy = pending.policy.as_mut().unwrap();
        policy.set_nonblocking(false).unwrap();
        policy.write_all(b"policy-proof\n").unwrap();
        let mut reply = String::new();
        policy.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "policy-proof\n");
        wait_child(&mut pending.child, STOP_GRACE).unwrap();
    }

    #[test]
    fn term_then_identity_checked_kill_stops_process() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let identity = process_identity(child.id()).unwrap().unwrap();
        assert_eq!(
            process_path(identity.pid).unwrap().as_deref(),
            Some(Path::new("/bin/sleep"))
        );
        signal_child_and_wait(identity, &mut child).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn arguments_are_fixed_tcp_only_transparent_policy() {
        let arguments = engine_arguments().unwrap();
        assert!(arguments.contains(&"--bind-addr=127.0.0.1".to_owned()));
        assert!(arguments.contains(&"--port=19081".to_owned()));
        assert!(arguments.contains(&"--user=root".to_owned()));
        assert!(!arguments
            .iter()
            .any(|argument| argument.starts_with("--uid")));
        assert!(!arguments.contains(&"--socks".to_owned()));
        assert!(!arguments.contains(&"--no-resolve".to_owned()));
        assert!(arguments.contains(&"--filter-tcp=80".to_owned()));
        assert!(arguments.contains(&"--hostspell=hoSt".to_owned()));
        assert!(arguments.contains(&"--filter-tcp=443".to_owned()));
        assert!(arguments.contains(&"--split-pos=2".to_owned()));
        assert!(arguments.contains(&"--oob".to_owned()));
        assert!(!arguments.iter().any(|argument| argument.contains("udp")));
        let domains = arguments
            .iter()
            .filter_map(|argument| argument.strip_prefix("--hostlist-domains="))
            .collect::<Vec<_>>();
        assert_eq!(domains.len(), 2);
        for domains in domains {
            assert_eq!(
                domains.split(',').collect::<Vec<_>>(),
                konsollink_core::ServiceProfile::discord_tr()
                    .unwrap()
                    .domains
            );
        }
    }
}
