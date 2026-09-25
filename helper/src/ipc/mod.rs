//! Versioned, bounded Unix-socket protocol. The root installer selects one UID.
use crate::gateway::Plan;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    time::Duration,
};

pub const SOCKET_DIR: &str = "/private/var/db/konsollink-ipc";
pub const SOCKET: &str = "/private/var/db/konsollink-ipc/helper.sock";
pub const VERSION: u32 = 3;
pub const MAX_FRAME: usize = 4096;
pub const LEASE: Duration = Duration::from_secs(15);
#[cfg(target_os = "macos")]
mod server;
#[cfg(target_os = "macos")]
pub use server::{recover, serve};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub command: Command,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Start {
        console: Ipv4Addr,
        ipv4_only_confirmed: bool,
        exclusive_host_confirmed: bool,
    },
    Heartbeat {},
    BeginSample {
        expected: ExpectedSample,
    },
    FinishSample {},
    ResetQualification {},
    Stop {},
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedSample {
    NonDiscord,
    DiscordControl,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub version: u32,
    pub state: String,
    pub gateway: Option<Plan>,
    pub discord_bypass: bool,
    pub intercepted_destinations: usize,
    pub qualification: QualificationStatus,
    pub observation: ObservationStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationStatus {
    pub state: String,
    pub active_sample: Option<String>,
    pub non_discord_samples: u64,
    pub discord_control_samples: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub class_mismatches: u64,
}

impl QualificationStatus {
    pub fn pending() -> Self {
        Self {
            state: "pending".into(),
            active_sample: None,
            non_discord_samples: 0,
            discord_control_samples: 0,
            false_positives: 0,
            false_negatives: 0,
            class_mismatches: 0,
        }
    }

    pub fn qualified() -> Self {
        Self {
            state: "qualified".into(),
            active_sample: None,
            non_discord_samples: 0,
            discord_control_samples: 0,
            false_positives: 0,
            false_negatives: 0,
            class_mismatches: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationStatus {
    pub state: String,
    pub captured_packets: u32,
    pub dropped_packets: u32,
    pub ignored_packets: u64,
    pub malformed_packets: u64,
    pub pending_dns_queries: usize,
    pub learned_destinations: usize,
    pub tracked_flow_entries: usize,
    pub direct_observations: u64,
    pub discord_control_candidates: u64,
    pub discord_media_candidates: u64,
}
impl ObservationStatus {
    pub fn off() -> Self {
        Self {
            state: "off".into(),
            captured_packets: 0,
            dropped_packets: 0,
            ignored_packets: 0,
            malformed_packets: 0,
            pending_dns_queries: 0,
            learned_destinations: 0,
            tracked_flow_entries: 0,
            direct_observations: 0,
            discord_control_candidates: 0,
            discord_media_candidates: 0,
        }
    }
}
impl Status {
    pub fn off() -> Self {
        Self {
            version: VERSION,
            state: "off".into(),
            gateway: None,
            discord_bypass: false,
            intercepted_destinations: 0,
            qualification: QualificationStatus::pending(),
            observation: ObservationStatus::off(),
            error: None,
        }
    }
}

/// No socket path from UI; verify the privileged peer before sending anything.
pub struct Client {
    stream: UnixStream,
}
impl Client {
    pub fn connect() -> io::Result<Self> {
        let stream = UnixStream::connect(SOCKET)?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        #[cfg(target_os = "macos")]
        if peer_uid(&stream)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper peer is not root",
            ));
        }
        #[cfg(not(target_os = "macos"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "M0 IPC is macOS-only",
        ));
        #[cfg(target_os = "macos")]
        Ok(Self { stream })
    }
    pub fn request(&mut self, command: Command) -> io::Result<Status> {
        let mut bytes = serde_json::to_vec(&Request {
            version: VERSION,
            command,
        })?;
        bytes.push(b'\n');
        self.stream.write_all(&bytes)?;
        let bytes = read_frame(&mut self.stream)?;
        let status: Status = serde_json::from_slice(&bytes)?;
        if status.version != VERSION {
            return Err(io::Error::other("helper protocol mismatch"));
        }
        Ok(status)
    }
}
fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return Ok(bytes);
        }
        if bytes.len() == MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        bytes.push(byte[0]);
    }
}
pub fn decode(bytes: &[u8]) -> io::Result<Request> {
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    let request: Request = serde_json::from_slice(bytes)?;
    if request.version != VERSION {
        return Err(io::Error::other("unsupported protocol version"));
    }
    Ok(request)
}
#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: live socket and valid scalar out parameters. Kernel-authenticated.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_is_closed_versioned_and_bounded() {
        for raw in [
            r#"{"version":4,"command":{"type":"status"}}"#,
            r#"{"version":3,"command":{"type":"shell","args":"id"}}"#,
            r#"{"version":3,"command":{"type":"status","path":"/etc/pf.conf"}}"#,
            r#"{"version":3,"command":{"type":"start","console":"127.0.0.1"}}"#,
            r#"{"version":3,"command":{"type":"status"},"extra":true}"#,
        ] {
            assert!(decode(raw.as_bytes()).is_err(), "{raw}");
        }
        assert!(decode(&vec![b' '; MAX_FRAME + 1]).is_err());
        assert!(decode(br#"{"version":3,"command":{"type":"status"}}"#).is_ok());
    }
    #[test]
    fn framing_rejects_truncated_and_oversized_input() {
        assert!(read_frame(&mut &b"{}"[..]).is_err());
        assert!(read_frame(&mut &vec![b'a'; MAX_FRAME + 2][..]).is_err());
        assert_eq!(read_frame(&mut &b"{}\nnext"[..]).unwrap(), b"{}");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn peer_credentials_come_from_kernel() {
        let (a, _) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }
}
