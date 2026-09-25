//! Read-only macOS capability and topology observations. Never authorizes ON.
use serde::Serialize;
use std::net::Ipv4Addr;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod parse;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Observation<T> {
    Known { value: T },
    Unknown { reason: String },
}

#[cfg(any(target_os = "macos", test))]
impl<T> Observation<T> {
    fn known(value: T) -> Self {
        Self::Known { value }
    }
    fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }
    fn value(&self) -> Option<&T> {
        match self {
            Self::Known { value } => Some(value),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Route {
    pub gateway: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Address {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub active: bool,
    pub ipv4: Vec<Address>,
    pub has_non_link_local_ipv6: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SharingService {
    Loaded,
    NotLoaded,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxSupport {
    Accepted,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub mode: &'static str,
    pub network_changed: bool,
    pub can_enable: bool,
    pub os_version: Observation<String>,
    pub os_build: Observation<String>,
    pub ipv4_default_route: Observation<Route>,
    pub ipv6_default_route: Observation<Route>,
    pub uplink: Observation<Interface>,
    pub uplink_is_wifi: Observation<bool>,
    pub ipv4_forwarding: Observation<bool>,
    pub ipv6_forwarding: Observation<bool>,
    pub icmp_redirects: Observation<bool>,
    pub pf_enabled: Observation<bool>,
    pub sharing_service: Observation<SharingService>,
    pub nat_rdr_syntax: Observation<SyntaxSupport>,
    pub divert_packet_syntax: Observation<SyntaxSupport>,
    pub console_ipv4: Option<Ipv4Addr>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: &'static str,
}

#[cfg(any(target_os = "macos", test))]
impl Report {
    fn add(&mut self, severity: &'static str, code: &'static str, message: &'static str) {
        self.findings.push(Finding {
            severity,
            code,
            message,
        });
    }

    fn assess(&mut self) {
        // A parser accepting a rule is not a runtime gateway qualification.
        self.add("blocker", "backend_not_qualified", "This read-only report does not authorize ON. Use the M0 helper trial and complete physical gateway qualification.");
        if self.divert_packet_syntax.value() == Some(&SyntaxSupport::Rejected) {
            self.add("blocker", "divert_packet_rejected", "The local PF parser rejects divert-packet. Do not select dvtws as a working macOS packet engine.");
        }
        self.add("blocker", "udp_strategy_unqualified", "Discord bypass remains unqualified (M1/M2); this does not block the separate M0 IPv4 gateway trial.");
        if self.pf_enabled.value().is_none() {
            self.add("blocker", "pf_state_unknown", "PF state could not be read; it must not be treated as disabled. Read-only privileged inspection is required before mutations.");
        }
        if self.os_version.value().is_none()
            || self.os_build.value().is_none()
            || self.ipv4_default_route.value().is_none()
            || self.uplink.value().is_none()
            || self.ipv4_forwarding.value().is_none()
            || self.ipv6_forwarding.value().is_none()
            || self.icmp_redirects.value().is_none()
        {
            self.add("blocker", "incomplete_observation", "One or more essential OS/network observations failed. Resolve unknown values before planning mutations.");
        }
        if self.sharing_service.value() != Some(&SharingService::NotLoaded) {
            self.add("blocker", "sharing_conflict_or_unknown", "Internet Sharing is loaded or its service state is unknown; do not modify its rules.");
        }
        self.add("warning", "sharing_configuration_unverified", "An unloaded Internet Sharing service does not prove the saved sharing configuration is disabled.");
        if self.nat_rdr_syntax.value() != Some(&SyntaxSupport::Accepted) {
            self.add(
                "blocker",
                "nat_rdr_syntax_unavailable",
                "The local PF parser has not accepted the NAT/TCP-rdr capability probe.",
            );
        }
        if self.uplink_is_wifi.value() == Some(&true) {
            self.add("warning", "wifi_performance_unqualified", "A Wi-Fi gateway adds airtime for forwarded traffic; throughput and latency budgets require comparison with the direct-router baseline.");
        }
        if self.icmp_redirects.value() == Some(&true) {
            self.add("warning", "icmp_redirects_enabled", "Same-interface routing may send ICMP redirects. A gateway implementation must account for this and journal any change.");
        }
        if self.ipv4_forwarding.value() == Some(&true) {
            self.add("warning", "forwarding_already_enabled", "Forwarding is already enabled. Existing users and unrelated traffic must be preserved.");
        }
        self.add("warning", "ipv6_not_qualified", "IPv6 is outside the initial IPv4 gateway trial; absence of a host IPv6 route does not prove the console has no IPv6 path.");
        self.add("warning", "console_gateway_persists", "Host rollback cannot restore a manually changed console gateway. OFF, helper crash and host power loss need separate recovery instructions.");
        self.add("warning", "observation_not_transaction_snapshot", "These sequential read-only observations can become stale. Revalidate under the helper lock before any future mutation; this report is not a rollback journal.");
        let Some(console) = self.console_ipv4 else {
            self.add("blocker", "console_not_selected", "Supply the console IPv4 address for subnet checks; discovery and device identity are not verified by this report.");
            return;
        };
        if !console.is_private() {
            self.add(
                "blocker",
                "console_not_private_ipv4",
                "The initial compatibility trial requires an RFC1918 console address.",
            );
        }
        if self
            .ipv4_default_route
            .value()
            .is_some_and(|r| r.gateway.parse::<Ipv4Addr>() == Ok(console))
        {
            self.add(
                "blocker",
                "console_is_router",
                "The supplied console address is the upstream gateway.",
            );
        }
        if let Some(interface) = self.uplink.value() {
            let active = interface.active;
            let is_host = interface.ipv4.iter().any(|a| a.ip == console);
            let in_subnet = interface
                .ipv4
                .iter()
                .any(|a| usable_same_subnet(a, console));
            if !active {
                self.add(
                    "blocker",
                    "uplink_inactive",
                    "The default-route interface is not active.",
                );
            }
            if is_host {
                self.add(
                    "blocker",
                    "console_is_host",
                    "The supplied console address belongs to this Mac.",
                );
            }
            if !in_subnet {
                self.add("blocker", "console_subnet_mismatch", "No unambiguous usable console address exists in an observed uplink IPv4 subnet.");
            }
        }
        self.add("warning", "console_identity_unverified", "Matching a subnet does not prove that the console owns this address, is reachable, or permits same-LAN gateway routing.");
    }
}

#[cfg(any(target_os = "macos", test))]
fn usable_same_subnet(address: &Address, console: Ipv4Addr) -> bool {
    if address.prefix == 0 || address.prefix > 30 {
        return false;
    }
    let mask = u32::MAX << (32 - address.prefix);
    let network = u32::from(address.ip) & mask;
    let ip = u32::from(console);
    ip & mask == network && ip != network && ip != (network | !mask)
}

/// Runs fixed read-only probes. Addresses are local diagnostics; no MAC, SSID,
/// packet payload, DNS history, firewall contents or credentials are returned.
pub fn collect(console: Option<Ipv4Addr>) -> Result<Report, crate::PlatformError> {
    #[cfg(target_os = "macos")]
    {
        Ok(macos::collect(console))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = console;
        Err(crate::PlatformError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            schema_version: 1,
            mode: "preflight",
            network_changed: false,
            can_enable: false,
            os_version: Observation::known("27.0".into()),
            os_build: Observation::known("test".into()),
            ipv4_default_route: Observation::known(Route {
                gateway: "192.168.1.1".into(),
                interface: "en0".into(),
            }),
            ipv6_default_route: Observation::unknown("no route"),
            uplink: Observation::known(Interface {
                name: "en0".into(),
                active: true,
                ipv4: vec![Address {
                    ip: "192.168.1.165".parse().unwrap(),
                    prefix: 24,
                }],
                has_non_link_local_ipv6: false,
            }),
            uplink_is_wifi: Observation::known(true),
            ipv4_forwarding: Observation::known(false),
            ipv6_forwarding: Observation::known(false),
            icmp_redirects: Observation::known(true),
            pf_enabled: Observation::unknown("permission_denied"),
            sharing_service: Observation::known(SharingService::NotLoaded),
            nat_rdr_syntax: Observation::known(SyntaxSupport::Accepted),
            divert_packet_syntax: Observation::known(SyntaxSupport::Rejected),
            console_ipv4: None,
            findings: vec![],
        }
    }

    #[test]
    fn unknown_pf_and_absent_console_never_authorize_enable() {
        let mut r = report();
        r.assess();
        for code in [
            "pf_state_unknown",
            "console_not_selected",
            "divert_packet_rejected",
            "udp_strategy_unqualified",
        ] {
            assert!(r.findings.iter().any(|f| f.code == code));
        }
        assert!(!r.can_enable);
        assert!(!r.network_changed);
    }

    #[test]
    fn console_addresses_are_checked_without_probing_devices() {
        for (ip, code) in [
            ("192.168.1.165", "console_is_host"),
            ("192.168.1.1", "console_is_router"),
            ("192.168.2.10", "console_subnet_mismatch"),
            ("192.168.1.255", "console_subnet_mismatch"),
            ("192.168.1.0", "console_subnet_mismatch"),
            ("8.8.8.8", "console_not_private_ipv4"),
        ] {
            let mut r = report();
            r.console_ipv4 = Some(ip.parse().unwrap());
            r.assess();
            assert!(r.findings.iter().any(|f| f.code == code), "{ip}");
        }
        let mut r = report();
        r.console_ipv4 = Some("192.168.1.20".parse().unwrap());
        r.assess();
        assert!(!r
            .findings
            .iter()
            .any(|f| f.code == "console_subnet_mismatch"));
        assert!(!r.can_enable);
    }
}
