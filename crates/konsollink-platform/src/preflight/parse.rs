use super::{Address, Interface, Route};
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn route(text: &str) -> Result<Route, &'static str> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
    };
    let gateway = field("gateway:").ok_or("default_gateway_missing")?;
    let interface = field("interface:").ok_or("default_interface_missing")?;
    // Reject link# routes and unrecognized format; do not guess the gateway.
    if gateway
        .split('%')
        .next()
        .unwrap_or("")
        .parse::<std::net::IpAddr>()
        .is_err()
        || interface.is_empty()
        || !interface.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err("default_route_format_unrecognized");
    }
    Ok(Route {
        gateway: gateway.into(),
        interface: interface.into(),
    })
}

pub(super) fn boolean(text: &str) -> Result<bool, &'static str> {
    match text.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("boolean_format_unrecognized"),
    }
}

pub(super) fn pf(text: &str) -> Result<bool, &'static str> {
    let value = text
        .lines()
        .find_map(|l| l.strip_prefix("Status: "))
        .ok_or("pf_status_missing")?;
    match value.split_whitespace().next() {
        Some("Enabled") => Ok(true),
        Some("Disabled") => Ok(false),
        _ => Err("pf_status_unrecognized"),
    }
}

pub(super) fn wifi(text: &str, name: &str) -> Result<bool, &'static str> {
    let mut port = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("Hardware Port: ") {
            port = Some(p);
        }
        if line.strip_prefix("Device: ") == Some(name) {
            return port
                .map(|p| p == "Wi-Fi" || p == "AirPort")
                .ok_or("hardware_port_missing");
        }
    }
    Err("hardware_port_unrecognized")
}

pub(super) fn interface(text: &str, name: &str) -> Result<Interface, &'static str> {
    let mut result = Interface {
        name: name.into(),
        active: false,
        ipv4: vec![],
        has_non_link_local_ipv6: false,
    };
    let mut found = false;
    let mut up = false;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            if found {
                break;
            }
            if line.split(':').next() == Some(name) {
                found = true;
                up = line
                    .split('<')
                    .nth(1)
                    .and_then(|s| s.split('>').next())
                    .is_some_and(|s| s.split(',').any(|v| v == "UP"));
            }
            continue;
        }
        if !found {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("status:") => result.active = fields.get(1) == Some(&"active"),
            Some("inet") => {
                let ip: Ipv4Addr = fields
                    .get(1)
                    .ok_or("ipv4_address_missing")?
                    .parse()
                    .map_err(|_| "invalid_ipv4_address")?;
                let mask = fields
                    .iter()
                    .position(|v| *v == "netmask")
                    .and_then(|i| fields.get(i + 1))
                    .ok_or("netmask_missing")?;
                let mask = if let Some(hex) = mask.strip_prefix("0x") {
                    u32::from_str_radix(hex, 16).map_err(|_| "invalid_netmask")?
                } else {
                    u32::from(mask.parse::<Ipv4Addr>().map_err(|_| "invalid_netmask")?)
                };
                let prefix = mask.leading_ones();
                if mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) {
                    return Err("non_contiguous_netmask");
                }
                result.ipv4.push(Address {
                    ip,
                    prefix: prefix as u8,
                });
            }
            Some("inet6") => {
                let ip: Ipv6Addr = fields
                    .get(1)
                    .and_then(|s| s.split('%').next())
                    .ok_or("ipv6_address_missing")?
                    .parse()
                    .map_err(|_| "invalid_ipv6_address")?;
                if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_unicast_link_local() {
                    result.has_non_link_local_ipv6 = true;
                }
            }
            _ => {}
        }
    }
    if !found {
        return Err("route_interface_missing");
    }
    result.active &= up;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_parsing_rejects_missing_or_link_gateway() {
        assert_eq!(
            route("gateway: 192.168.1.1\ninterface: en0\n")
                .unwrap()
                .interface,
            "en0"
        );
        assert!(route("gateway: link#12\ninterface: en0\n").is_err());
        assert!(route("interface: en0\n").is_err());
    }
    #[test]
    fn interface_parser_keeps_only_selected_interface_without_mac() {
        let text = "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n\tinet 192.168.1.20 netmask 0xffffff00\n\tinet6 fe80::1%en0 prefixlen 64\n\tstatus: active\nen1: flags=8863<UP,RUNNING> mtu 1500\n\tinet 10.1.1.1 netmask 0xff000000\n";
        let parsed = interface(text, "en0").unwrap();
        assert!(parsed.active);
        assert_eq!(parsed.ipv4.len(), 1);
        assert_eq!(parsed.ipv4[0].prefix, 24);
        assert!(!parsed.has_non_link_local_ipv6);
        assert!(interface(&text.replace("0xffffff00", "0xff00ff00"), "en0").is_err());
        assert!(interface(text, "en9").is_err());
        assert!(
            interface(&text.replace("fe80::1%en0", "fd00::1"), "en0")
                .unwrap()
                .has_non_link_local_ipv6
        );
    }
    #[test]
    fn unknown_states_are_not_disabled_states() {
        assert_eq!(boolean("0\n"), Ok(false));
        assert!(boolean("error").is_err());
        assert_eq!(pf("Status: Enabled for 0 days\n"), Ok(true));
        assert!(pf("permission denied").is_err());
        assert_eq!(wifi("Hardware Port: Wi-Fi\nDevice: en0\n", "en0"), Ok(true));
        assert!(wifi("", "en0").is_err());
    }
}
