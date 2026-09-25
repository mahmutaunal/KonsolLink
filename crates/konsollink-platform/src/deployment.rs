//! Closed, platform-neutral deployment contract for the privileged runtime.
//!
//! Platform adapters may implement these commands differently, but they may
//! not broaden the virtual network, Discord allowlist, or child process set.

use konsollink_core::ServiceProfile;
use std::net::Ipv4Addr;

pub const CONSOLE: Ipv4Addr = Ipv4Addr::new(172, 24, 2, 10);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 24, 2, 1);
pub const PREFIX: u8 = 16;
pub const MTU: u16 = 1486;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    MacOs,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiAdapter {
    TpwsTransparentPf,
    TpwsSocks,
    GoodbyeDpiWinDivert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentContract {
    pub platform: HostPlatform,
    pub service_name: &'static str,
    pub install_root: &'static str,
    pub privilege_boundary: &'static str,
    pub gateway_config: &'static str,
    pub dpi_adapter: DpiAdapter,
    pub domains: Vec<String>,
}

impl DeploymentContract {
    pub fn for_platform(platform: HostPlatform) -> Result<Self, String> {
        let domains = ServiceProfile::discord_tr()
            .map_err(|error| error.to_string())?
            .domains;
        let contract = match platform {
            HostPlatform::MacOs => Self {
                platform,
                service_name: "tr.konsollink.m0",
                install_root: "/Library/PrivilegedHelperTools/tr.konsollink.m0",
                privilege_boundary: "root launch daemon + uid-bound Unix socket",
                gateway_config: "engines/gateway-macos.json",
                dpi_adapter: DpiAdapter::TpwsTransparentPf,
                domains,
            },
            HostPlatform::Windows => Self {
                platform,
                service_name: "KonsolLink",
                install_root: r"C:\Program Files\KonsolLink",
                privilege_boundary: "LocalSystem SCM service + user start/stop ACL",
                gateway_config: "engines/gateway-windows.json",
                dpi_adapter: DpiAdapter::GoodbyeDpiWinDivert,
                domains,
            },
            HostPlatform::Linux => Self {
                platform,
                service_name: "konsollink.service",
                install_root: "/opt/konsollink",
                privilege_boundary: "root systemd service + local-admin polkit rule",
                gateway_config: "engines/gateway.json",
                dpi_adapter: DpiAdapter::TpwsSocks,
                domains,
            },
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected = ServiceProfile::discord_tr()
            .map_err(|error| error.to_string())?
            .domains;
        if self.domains != expected || self.domains.is_empty() {
            return Err("deployment domain policy differs from embedded Discord profile".into());
        }
        if self.service_name.is_empty()
            || self.install_root.is_empty()
            || self.privilege_boundary.is_empty()
            || !self.gateway_config.starts_with("engines/gateway")
        {
            return Err("deployment contract contains an open or empty platform field".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_platform_has_a_closed_contract() {
        for platform in [
            HostPlatform::MacOs,
            HostPlatform::Windows,
            HostPlatform::Linux,
        ] {
            DeploymentContract::for_platform(platform).unwrap();
        }
        assert_eq!(CONSOLE.to_string(), "172.24.2.10");
        assert_eq!(GATEWAY.to_string(), "172.24.2.1");
        assert_eq!(PREFIX, 16);
        assert_eq!(MTU, 1486);
    }

    #[test]
    fn every_host_uses_its_closed_dpi_adapter() {
        assert_eq!(
            DeploymentContract::for_platform(HostPlatform::Windows)
                .unwrap()
                .dpi_adapter,
            DpiAdapter::GoodbyeDpiWinDivert
        );
        assert_eq!(
            DeploymentContract::for_platform(HostPlatform::MacOs)
                .unwrap()
                .dpi_adapter,
            DpiAdapter::TpwsTransparentPf
        );
        assert_eq!(
            DeploymentContract::for_platform(HostPlatform::Linux)
                .unwrap()
                .dpi_adapter,
            DpiAdapter::TpwsSocks
        );
    }

    #[test]
    fn a_broadened_domain_policy_is_rejected() {
        let mut contract = DeploymentContract::for_platform(HostPlatform::Linux).unwrap();
        contract.domains.push("example.org".into());
        assert!(contract.validate().is_err());
    }
}
