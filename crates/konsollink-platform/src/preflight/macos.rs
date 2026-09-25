use super::{parse, Observation, Report, SharingService, SyntaxSupport};
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: u64 = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(3);
// TEST-NET addresses and loopback interface; -n parses only, never loads rules.
const NAT_RDR: &str = "nat on lo0 inet from 192.0.2.10 to any -> (lo0)\nrdr on lo0 inet proto tcp from 192.0.2.10 to 198.51.100.10 port 443 -> 127.0.0.1 port 988\n";
const DIVERT: &str = "pass in on lo0 inet proto tcp from 192.0.2.10 to 198.51.100.10 port 443 divert-packet port 989\n";

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn bounded_read(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

// Private runner: callers below supply only fixed absolute OS executable paths
// and fixed args. No shell, PATH lookup, sudo, user-controlled command or env.
fn run(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    timeout: Duration,
) -> Result<Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn_failed:{:?}", error.kind()))?;
    // Piped handles are guaranteed by Command on successful spawn.
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = thread::spawn(move || bounded_read(stdout));
    let err = thread::spawn(move || bounded_read(stderr));
    let started = Instant::now();
    let status = (|| {
        if let Some(input) = input {
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(input.as_bytes())
                .map_err(|_| "stdin_write_failed")?;
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
                Ok(None) => return Err("timeout"),
                Err(_) => return Err("wait_failed"),
            }
        }
    })();
    if status.is_err() {
        // Kill only this probe child; always reap it before reporting failure.
        let kill = child.kill();
        let wait = child.wait();
        if wait.is_err() || (kill.is_err() && child.try_wait().ok().flatten().is_none()) {
            return Err("probe_cleanup_failed".into());
        }
    }
    let stdout = out
        .join()
        .map_err(|_| "stdout_reader_failed")?
        .map_err(|_| "stdout_read_failed")?;
    let stderr = err
        .join()
        .map_err(|_| "stderr_reader_failed")?
        .map_err(|_| "stderr_read_failed")?;
    let status = status?;
    if stdout.len() as u64 > LIMIT || stderr.len() as u64 > LIMIT {
        return Err("output_limit_exceeded".into());
    }
    Ok(Output {
        code: status.code(),
        stdout: String::from_utf8(stdout).map_err(|_| "stdout_not_utf8")?,
        stderr: String::from_utf8(stderr).map_err(|_| "stderr_not_utf8")?,
    })
}

fn failure(output: &Output) -> String {
    if output.stderr.contains("Permission denied")
        || output.stderr.contains("Operation not permitted")
    {
        "permission_denied".into()
    } else {
        format!("command_failed_exit:{:?}", output.code)
    }
}

fn read<T>(
    program: &str,
    args: &[&str],
    parser: impl FnOnce(&str) -> Result<T, &'static str>,
) -> Observation<T> {
    match run(program, args, None, TIMEOUT) {
        Ok(output) if output.code == Some(0) => match parser(&output.stdout) {
            Ok(value) => Observation::known(value),
            Err(reason) => Observation::unknown(reason),
        },
        Ok(output) => Observation::unknown(failure(&output)),
        Err(reason) => Observation::unknown(reason),
    }
}

fn syntax(rules: &str) -> Observation<SyntaxSupport> {
    match run("/sbin/pfctl", &["-n", "-f", "-"], Some(rules), TIMEOUT) {
        Ok(output) if output.code == Some(0) => Observation::known(SyntaxSupport::Accepted),
        Ok(output) if output.stderr.contains("syntax error") => {
            Observation::known(SyntaxSupport::Rejected)
        }
        Ok(output) => Observation::unknown(failure(&output)),
        Err(reason) => Observation::unknown(reason),
    }
}

fn sharing() -> Observation<SharingService> {
    match run(
        "/bin/launchctl",
        &["print", "system/com.apple.InternetSharing"],
        None,
        TIMEOUT,
    ) {
        Ok(output) if output.code == Some(0) => Observation::known(SharingService::Loaded),
        Ok(output)
            if output
                .stderr
                .contains("Could not find service \"com.apple.InternetSharing\"") =>
        {
            Observation::known(SharingService::NotLoaded)
        }
        Ok(output) => Observation::unknown(failure(&output)),
        Err(reason) => Observation::unknown(reason),
    }
}

fn scalar(text: &str) -> Result<String, &'static str> {
    let value = text.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
    {
        Err("version_format_unrecognized")
    } else {
        Ok(value.into())
    }
}

pub(super) fn collect(console: Option<Ipv4Addr>) -> Report {
    let ipv4_default_route = read(
        "/sbin/route",
        &["-n", "get", "-inet", "default"],
        parse::route,
    );
    let ipv6_default_route = read(
        "/sbin/route",
        &["-n", "get", "-inet6", "default"],
        parse::route,
    );
    let (uplink, uplink_is_wifi) = match ipv4_default_route.value() {
        Some(route) => (
            read("/sbin/ifconfig", &["-a"], |text| {
                parse::interface(text, &route.interface)
            }),
            read(
                "/usr/sbin/networksetup",
                &["-listallhardwareports"],
                |text| parse::wifi(text, &route.interface),
            ),
        ),
        None => (
            Observation::unknown("default_route_unknown"),
            Observation::unknown("default_route_unknown"),
        ),
    };
    let mut report = Report {
        schema_version: 1,
        mode: "preflight",
        network_changed: false,
        can_enable: false,
        os_version: read("/usr/bin/sw_vers", &["-productVersion"], scalar),
        os_build: read("/usr/bin/sw_vers", &["-buildVersion"], scalar),
        ipv4_default_route,
        ipv6_default_route,
        uplink,
        uplink_is_wifi,
        ipv4_forwarding: read(
            "/usr/sbin/sysctl",
            &["-n", "net.inet.ip.forwarding"],
            parse::boolean,
        ),
        ipv6_forwarding: read(
            "/usr/sbin/sysctl",
            &["-n", "net.inet6.ip6.forwarding"],
            parse::boolean,
        ),
        icmp_redirects: read(
            "/usr/sbin/sysctl",
            &["-n", "net.inet.ip.redirect"],
            parse::boolean,
        ),
        pf_enabled: read("/sbin/pfctl", &["-s", "info"], parse::pf),
        sharing_service: sharing(),
        nat_rdr_syntax: syntax(NAT_RDR),
        divert_packet_syntax: syntax(DIVERT),
        console_ipv4: console,
        findings: vec![],
    };
    report.assess();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stalled_probe_is_killed_and_reaped() {
        let start = Instant::now();
        let result = run("/bin/sleep", &["10"], None, Duration::from_millis(30));
        assert!(matches!(result, Err(ref reason) if reason == "timeout"));
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn output_is_bounded() {
        assert_eq!(
            bounded_read(vec![0u8; 100_000].as_slice()).unwrap().len(),
            LIMIT as usize + 1
        );
    }
    #[test]
    fn permission_failure_does_not_leak_raw_diagnostics() {
        let result = failure(&Output {
            code: Some(1),
            stdout: "private".into(),
            stderr: "Permission denied private".into(),
        });
        assert_eq!(result, "permission_denied");
    }
}
