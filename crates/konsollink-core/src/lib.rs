use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

pub mod classifier;
pub mod qualification;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsoleFamily {
    PlayStation,
    Xbox,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleDevice {
    pub id: String,
    pub display_name: String,
    pub family: ConsoleFamily,
    pub ip: IpAddr,
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeState {
    Off,
    Starting,
    On,
    Stopping,
    Faulted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProfile {
    pub id: String,
    pub display_name: String,
    pub market: String,
    pub domains: Vec<String>,
    pub tcp_ports: Vec<u16>,
    pub udp_ranges: Vec<(u16, u16)>,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("invalid service profile TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid service profile: {0}")]
    Invalid(&'static str),
}

impl ServiceProfile {
    /// The bundled TOML is the only source of Discord policy data.
    pub fn discord_tr() -> Result<Self, ProfileError> {
        Self::from_toml(include_str!("../../../services/discord/profile.toml"))
    }

    pub fn from_toml(source: &str) -> Result<Self, ProfileError> {
        let profile: Self = toml::from_str(source)?;
        if profile.id.trim().is_empty()
            || profile.display_name.trim().is_empty()
            || profile.market.trim().is_empty()
        {
            return Err(ProfileError::Invalid("metadata must not be empty"));
        }
        if profile.domains.is_empty()
            || profile.domains.iter().any(|domain| {
                domain.len() > 253
                    || !domain.contains('.')
                    || domain.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                    })
            })
        {
            return Err(ProfileError::Invalid(
                "domains must be lowercase DNS names without wildcards",
            ));
        }
        if profile.tcp_ports.contains(&0)
            || profile
                .udp_ranges
                .iter()
                .any(|(start, end)| *start == 0 || start > end)
        {
            return Err(ProfileError::Invalid("invalid port or UDP range"));
        }
        Ok(profile)
    }

    pub fn domain_matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains
            .iter()
            .any(|d| h == *d || h.ends_with(&format!(".{d}")))
    }

    /// Port metadata alone MUST NOT authorize Discord interception.
    pub fn udp_port_matches(&self, port: u16) -> bool {
        self.udp_ranges
            .iter()
            .any(|(a, b)| port >= *a && port <= *b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformancePolicy {
    pub max_idle_cpu_percent: u8,
    pub max_active_cpu_percent_target: u8,
    pub max_non_discord_throughput_loss_percent: u8,
    pub max_median_added_latency_ms: u8,
}

impl Default for PerformancePolicy {
    fn default() -> Self {
        Self {
            max_idle_cpu_percent: 1,
            max_active_cpu_percent_target: 2,
            max_non_discord_throughput_loss_percent: 1,
            max_median_added_latency_ms: 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("no console selected")]
    NoConsole,
    #[error("bridge transition is invalid")]
    InvalidTransition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub selected_console: Option<ConsoleDevice>,
    pub service: ServiceProfile,
    pub performance: PerformancePolicy,
}

impl RuntimeConfig {
    pub fn discord_tr() -> Result<Self, ProfileError> {
        Ok(Self {
            selected_console: None,
            service: ServiceProfile::discord_tr()?,
            performance: PerformancePolicy::default(),
        })
    }
}

#[derive(Debug)]
pub struct BridgeController {
    state: BridgeState,
    config: RuntimeConfig,
}

impl BridgeController {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            state: BridgeState::Off,
            config,
        }
    }

    pub fn state(&self) -> BridgeState {
        self.state
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn select_console(&mut self, device: ConsoleDevice) {
        self.config.selected_console = Some(device);
    }

    pub fn begin_start(&mut self) -> Result<(), CoreError> {
        if self.config.selected_console.is_none() {
            return Err(CoreError::NoConsole);
        }
        if self.state != BridgeState::Off {
            return Err(CoreError::InvalidTransition);
        }
        self.state = BridgeState::Starting;
        Ok(())
    }

    pub fn mark_started(&mut self) -> Result<(), CoreError> {
        if self.state != BridgeState::Starting {
            return Err(CoreError::InvalidTransition);
        }
        self.state = BridgeState::On;
        Ok(())
    }

    pub fn begin_stop(&mut self) -> Result<(), CoreError> {
        if !matches!(self.state, BridgeState::On | BridgeState::Faulted) {
            return Err(CoreError::InvalidTransition);
        }
        self.state = BridgeState::Stopping;
        Ok(())
    }

    pub fn mark_stopped(&mut self) -> Result<(), CoreError> {
        if self.state != BridgeState::Stopping {
            return Err(CoreError::InvalidTransition);
        }
        self.state = BridgeState::Off;
        Ok(())
    }

    pub fn mark_faulted(&mut self) {
        self.state = BridgeState::Faulted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discord_subdomains_match_without_overmatching() {
        let p = ServiceProfile::discord_tr().unwrap();
        assert!(p.domain_matches("gateway.discord.gg"));
        assert!(p.domain_matches("cdn.discordapp.com"));
        assert!(!p.domain_matches("discord.com.example.org"));
        assert!(!p.domain_matches("example.com"));
        assert!(p.domain_matches("GATEWAY.DISCORD.GG."));
        assert!(!p.domain_matches("evildiscord.com"));
    }

    #[test]
    fn bridge_requires_console() {
        let mut c = BridgeController::new(RuntimeConfig::discord_tr().unwrap());
        assert!(matches!(c.begin_start(), Err(CoreError::NoConsole)));
    }

    #[test]
    fn bundled_profile_loads_all_fields() {
        let profile = ServiceProfile::discord_tr().unwrap();
        assert_eq!(profile.id, "discord");
        assert_eq!(profile.market, "TR");
        assert!(!profile.display_name.is_empty());
        assert!(!profile.tcp_ports.is_empty());
        assert!(!profile.udp_ranges.is_empty());
    }

    #[test]
    fn invalid_profiles_are_rejected_without_fallback() {
        let source = include_str!("../../../services/discord/profile.toml");
        for invalid in [
            source.replace("discord.com", "*.discord.com"),
            source.replace("discord.com", "discord..com"),
            source.replace("[443]", "[0]"),
            source.replace("[19294, 19344]", "[19344, 19294]"),
            source.replace("market = \"TR\"", "market = \"\""),
            format!("unknown_field = true\n{source}"),
            "not TOML".to_owned(),
        ] {
            assert!(ServiceProfile::from_toml(&invalid).is_err());
        }
    }
}
