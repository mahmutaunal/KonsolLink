//! IPv4-only, leased gateway trial. No DNS observation or Discord interception.
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Backend;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(default)]
    pub mode: Mode,
    pub console: Ipv4Addr,
    pub host: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_host: Option<Ipv4Addr>,
    pub router: Ipv4Addr,
    pub prefix: u8,
    pub interface: String,
    pub anchor: String,
    pub boot_seconds: i64,
}

/// `Nat` remains the deserialization default so recovery can understand an
/// interrupted journal written by the first M0 build. New same-subnet trials
/// use `Routed`, leaving NAT and UPnP ownership with the upstream router.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Nat,
    Routed,
    Userspace,
}

impl Plan {
    pub fn validate(&self) -> Result<(), String> {
        let suffix = self.anchor.strip_prefix("tr.konsollink.m0.").unwrap_or("");
        if suffix.len() != 32
            || !suffix.bytes().all(|b| b.is_ascii_hexdigit())
            || self.boot_seconds <= 0
            || self.interface.len() > 15
            || !self.interface.starts_with("en")
            || self.interface.len() < 3
            || !self.interface[2..].bytes().all(|b| b.is_ascii_digit())
            || !self.console.is_private()
            || !self.host.is_private()
            || !self.router.is_private()
            || !(8..=30).contains(&self.prefix)
            || self.console == self.host
            || self.console == self.router
            || self.host == self.router
        {
            return Err("unsupported or invalid gateway plan".into());
        }
        let mask = u32::MAX << (32 - self.prefix);
        let network = u32::from(self.host) & mask;
        let same_subnet = match self.mode {
            Mode::Userspace => vec![self.host, self.console],
            Mode::Nat | Mode::Routed => vec![self.host, self.console, self.router],
        };
        for ip in same_subnet {
            let ip = u32::from(ip);
            if ip & mask != network || ip == network || ip == (network | !mask) {
                return Err(
                    "gateway addresses must be distinct usable addresses in one subnet".into(),
                );
            }
        }
        if self.mode == Mode::Userspace
            && (!self.uplink_host.is_some_and(|ip| ip.is_private())
                || self.host != Ipv4Addr::new(172, 24, 2, 1)
                || self.console != Ipv4Addr::new(172, 24, 2, 10)
                || self.prefix != 16)
        {
            return Err("userspace gateway must use the fixed virtual network".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn plan() -> Plan {
        Plan {
            mode: Mode::Routed,
            console: "192.168.1.20".parse().unwrap(),
            host: "192.168.1.165".parse().unwrap(),
            uplink_host: None,
            router: "192.168.1.1".parse().unwrap(),
            prefix: 24,
            interface: "en0".into(),
            anchor: format!("tr.konsollink.m0.{}", "a".repeat(32)),
            boot_seconds: 123,
        }
    }
    #[test]
    fn journal_cannot_name_arbitrary_pf_anchors_or_interfaces() {
        let valid = plan();
        assert!(valid.validate().is_ok());
        for anchor in [
            "",
            "com.apple/x",
            "tr.konsollink.m0.*/../",
            "tr.konsollink.m0.a",
        ] {
            let mut p = valid.clone();
            p.anchor = anchor.into();
            assert!(p.validate().is_err());
        }
        for interface in ["en0;id", "en", "utun0", "en0\n", "é"] {
            let mut p = valid.clone();
            p.interface = interface.into();
            assert!(p.validate().is_err());
        }
        for ip in [
            "192.168.1.0",
            "192.168.1.255",
            "192.168.1.165",
            "192.168.1.1",
            "8.8.8.8",
            "192.168.2.20",
        ] {
            let mut p = valid.clone();
            p.console = ip.parse().unwrap();
            assert!(p.validate().is_err());
        }
    }

    #[test]
    fn old_journal_without_mode_defaults_to_nat_for_recovery() {
        let mut value = serde_json::to_value(plan()).unwrap();
        value.as_object_mut().unwrap().remove("mode");
        let restored: Plan = serde_json::from_value(value).unwrap();
        assert_eq!(restored.mode, Mode::Nat);
    }
}
