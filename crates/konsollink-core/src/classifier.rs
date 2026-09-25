//! Fail-closed, observation-only Discord destination classification.
//!
//! This module consumes already parsed DNS metadata. It never receives packet
//! payloads or credentials and it does not authorize interception by itself.

use crate::ServiceProfile;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use thiserror::Error;

const DNS_QUERY_TIMEOUT_SECS: u64 = 10;
const MAX_EVIDENCE_TTL_SECS: u32 = 300;
const FLOW_TTL_SECS: u64 = 120;
const MAX_PENDING_QUERIES: usize = 128;
const MAX_DESTINATIONS: usize = 512;
const MAX_FLOWS: usize = 2048;
const MAX_CNAME_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    Address {
        owner: String,
        address: IpAddr,
        ttl_secs: u32,
    },
    Cname {
        owner: String,
        target: String,
        ttl_secs: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowObservation {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
    pub transport: Transport,
    /// SNI only when it is visible without TLS decryption.
    pub tls_server_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowClass {
    Direct,
    DiscordControlCandidate,
    DiscordMediaCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierDiagnostics {
    pub pending_dns_queries: usize,
    pub learned_destinations: usize,
    pub tracked_flows: usize,
    pub direct_observations: u64,
    pub discord_control_candidates: u64,
    pub discord_media_candidates: u64,
}

/// Short-lived authority for M2 TCP interception. Values are emitted only
/// after an exact DNS-origin and visible-SNI match on a console TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedTcpDestination {
    address: Ipv4Addr,
    expires_at: u64,
}

impl QualifiedTcpDestination {
    pub fn address(self) -> Ipv4Addr {
        self.address
    }

    pub fn expires_at(self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClassifierError {
    #[error("invalid DNS name")]
    InvalidDnsName,
    #[error("observation capacity reached")]
    Capacity,
}

#[derive(Debug, Clone)]
struct PendingQuery {
    name: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PendingKey {
    resolver: IpAddr,
    client_port: u16,
    transaction_id: u16,
}

#[derive(Debug, Clone)]
struct DestinationEvidence {
    origins: HashMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    transport: Transport,
}

#[derive(Debug, Clone)]
struct TrackedFlow {
    class: FlowClass,
    expires_at: u64,
}

/// Monotonic timestamps are caller-supplied seconds. Wall-clock changes cannot
/// extend evidence lifetime.
pub struct DiscordClassifier {
    console: IpAddr,
    profile: ServiceProfile,
    pending: HashMap<PendingKey, PendingQuery>,
    destinations: HashMap<IpAddr, DestinationEvidence>,
    flows: HashMap<FlowKey, TrackedFlow>,
    confirmed_control: HashMap<Ipv4Addr, u64>,
    direct_observations: u64,
    discord_control_candidates: u64,
    discord_media_candidates: u64,
}

impl DiscordClassifier {
    pub fn new(console: IpAddr, profile: ServiceProfile) -> Self {
        Self {
            console,
            profile,
            pending: HashMap::new(),
            destinations: HashMap::new(),
            flows: HashMap::new(),
            confirmed_control: HashMap::new(),
            direct_observations: 0,
            discord_control_candidates: 0,
            discord_media_candidates: 0,
        }
    }

    pub fn observe_dns_query(
        &mut self,
        source: IpAddr,
        source_port: u16,
        resolver: IpAddr,
        transaction_id: u16,
        name: &str,
        now_secs: u64,
    ) -> Result<bool, ClassifierError> {
        self.expire(now_secs);
        if source != self.console || source_port == 0 {
            return Ok(false);
        }
        let name = normalize_dns_name(name)?;
        if !self.profile.domain_matches(&name) {
            return Ok(false);
        }
        let key = PendingKey {
            resolver,
            client_port: source_port,
            transaction_id,
        };
        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_QUERIES {
            return Err(ClassifierError::Capacity);
        }
        self.pending.insert(
            key,
            PendingQuery {
                name,
                expires_at: now_secs.saturating_add(DNS_QUERY_TIMEOUT_SECS),
            },
        );
        Ok(true)
    }

    /// Accepts a response only when its resolver, destination, transaction ID,
    /// and unexpired query all match an observed console DNS query.
    pub fn observe_dns_response(
        &mut self,
        resolver: IpAddr,
        destination: IpAddr,
        destination_port: u16,
        transaction_id: u16,
        records: &[DnsRecord],
        now_secs: u64,
    ) -> Result<usize, ClassifierError> {
        self.expire(now_secs);
        if destination != self.console {
            return Ok(0);
        }
        let key = PendingKey {
            resolver,
            client_port: destination_port,
            transaction_id,
        };
        let Some(query) = self.pending.remove(&key) else {
            return Ok(0);
        };
        if query.expires_at <= now_secs {
            return Ok(0);
        }

        let mut cnames: HashMap<String, Vec<(String, u32)>> = HashMap::new();
        let mut addresses: HashMap<String, Vec<(IpAddr, u32)>> = HashMap::new();
        for record in records {
            match record {
                DnsRecord::Cname {
                    owner,
                    target,
                    ttl_secs,
                } => cnames
                    .entry(normalize_dns_name(owner)?)
                    .or_default()
                    .push((normalize_dns_name(target)?, *ttl_secs)),
                DnsRecord::Address {
                    owner,
                    address,
                    ttl_secs,
                } => addresses
                    .entry(normalize_dns_name(owner)?)
                    .or_default()
                    .push((*address, *ttl_secs)),
            }
        }

        let origin = query.name;
        let mut queue = VecDeque::from([(origin.clone(), MAX_EVIDENCE_TTL_SECS, 0usize)]);
        let mut visited = HashSet::new();
        let mut learned = 0usize;
        while let Some((name, chain_ttl, depth)) = queue.pop_front() {
            if !visited.insert(name.clone()) || depth > MAX_CNAME_DEPTH {
                continue;
            }
            if let Some(values) = addresses.get(&name) {
                for (address, ttl) in values {
                    if !is_eligible_destination(*address) {
                        continue;
                    }
                    let ttl = chain_ttl.min(*ttl).min(MAX_EVIDENCE_TTL_SECS);
                    if ttl == 0 {
                        continue;
                    }
                    if !self.destinations.contains_key(address)
                        && self.destinations.len() >= MAX_DESTINATIONS
                    {
                        return Err(ClassifierError::Capacity);
                    }
                    let expires_at = now_secs.saturating_add(u64::from(ttl));
                    self.destinations
                        .entry(*address)
                        .or_insert_with(|| DestinationEvidence {
                            origins: HashMap::new(),
                        })
                        .origins
                        .entry(origin.clone())
                        .and_modify(|current| *current = (*current).max(expires_at))
                        .or_insert(expires_at);
                    learned += 1;
                }
            }
            if depth == MAX_CNAME_DEPTH {
                continue;
            }
            if let Some(values) = cnames.get(&name) {
                for (target, ttl) in values {
                    let ttl = chain_ttl.min(*ttl).min(MAX_EVIDENCE_TTL_SECS);
                    if ttl != 0 {
                        queue.push_back((target.clone(), ttl, depth + 1));
                    }
                }
            }
        }
        Ok(learned)
    }

    /// Classifies outbound candidates and already-related reverse traffic.
    /// `Direct` is the fail-closed result for every missing or conflicting fact.
    pub fn observe_flow(&mut self, flow: &FlowObservation, now_secs: u64) -> FlowClass {
        self.expire(now_secs);
        let key = flow_key(flow);
        if let Some(tracked) = self.flows.get_mut(&key) {
            tracked.expires_at = now_secs.saturating_add(FLOW_TTL_SECS);
            return tracked.class;
        }

        let class = self.classify_new_outbound(flow, now_secs);
        if class == FlowClass::Direct {
            self.direct_observations = self.direct_observations.saturating_add(1);
            return class;
        }
        if self.flows.len() > MAX_FLOWS.saturating_sub(2) {
            self.direct_observations = self.direct_observations.saturating_add(1);
            return FlowClass::Direct;
        }

        let reverse = FlowKey {
            source: flow.destination,
            source_port: flow.destination_port,
            destination: flow.source,
            destination_port: flow.source_port,
            transport: flow.transport,
        };
        let tracked = TrackedFlow {
            class,
            expires_at: now_secs.saturating_add(FLOW_TTL_SECS),
        };
        self.flows.insert(key, tracked.clone());
        self.flows.insert(reverse, tracked);
        match class {
            FlowClass::DiscordControlCandidate => {
                if let (IpAddr::V4(address), Some(expires_at)) = (
                    flow.destination,
                    self.control_authorization_expiry(flow, now_secs),
                ) {
                    self.confirmed_control
                        .entry(address)
                        .and_modify(|current| *current = (*current).max(expires_at))
                        .or_insert(expires_at);
                }
                self.discord_control_candidates = self.discord_control_candidates.saturating_add(1)
            }
            FlowClass::DiscordMediaCandidate => {
                self.discord_media_candidates = self.discord_media_candidates.saturating_add(1)
            }
            FlowClass::Direct => {}
        }
        class
    }

    pub fn diagnostics(&mut self, now_secs: u64) -> ClassifierDiagnostics {
        self.expire(now_secs);
        ClassifierDiagnostics {
            pending_dns_queries: self.pending.len(),
            learned_destinations: self.destinations.len(),
            tracked_flows: self.flows.len(),
            direct_observations: self.direct_observations,
            discord_control_candidates: self.discord_control_candidates,
            discord_media_candidates: self.discord_media_candidates,
        }
    }

    /// Produces a sorted snapshot only when the independent shadow gate has
    /// yielded its opaque proof. IPv6 remains direct in the current macOS M2.
    pub fn qualified_tcp_destinations(
        &mut self,
        _: &crate::qualification::QualifiedShadowRun,
        now_secs: u64,
    ) -> Vec<QualifiedTcpDestination> {
        self.expire(now_secs);
        let mut destinations = self
            .confirmed_control
            .iter()
            .map(|(address, expires_at)| QualifiedTcpDestination {
                address: *address,
                expires_at: *expires_at,
            })
            .collect::<Vec<_>>();
        destinations.sort_unstable_by_key(|destination| destination.address);
        destinations
    }

    fn classify_new_outbound(&self, flow: &FlowObservation, now_secs: u64) -> FlowClass {
        if flow.source != self.console
            || flow.source_port == 0
            || flow.destination_port == 0
            || !self.destinations.contains_key(&flow.destination)
        {
            return FlowClass::Direct;
        }
        match flow.transport {
            Transport::Tcp if self.profile.tcp_ports.contains(&flow.destination_port) => {
                if self.control_authorization_expiry(flow, now_secs).is_some() {
                    FlowClass::DiscordControlCandidate
                } else {
                    FlowClass::Direct
                }
            }
            Transport::Udp
                if self.profile.udp_port_matches(flow.destination_port)
                    && self.flows.values().any(|tracked| {
                        tracked.class == FlowClass::DiscordControlCandidate
                            && tracked.expires_at > now_secs
                    }) =>
            {
                FlowClass::DiscordMediaCandidate
            }
            _ => FlowClass::Direct,
        }
    }

    fn control_authorization_expiry(&self, flow: &FlowObservation, now_secs: u64) -> Option<u64> {
        if flow.source != self.console
            || flow.transport != Transport::Tcp
            || !self.profile.tcp_ports.contains(&flow.destination_port)
        {
            return None;
        }
        let host = flow
            .tls_server_name
            .as_deref()
            .and_then(|host| normalize_dns_name(host).ok())?;
        if !self.profile.domain_matches(&host) {
            return None;
        }
        let dns_expiry = *self
            .destinations
            .get(&flow.destination)?
            .origins
            .get(&host)?;
        (dns_expiry > now_secs).then(|| dns_expiry.min(now_secs.saturating_add(FLOW_TTL_SECS)))
    }

    fn expire(&mut self, now_secs: u64) {
        self.pending.retain(|_, value| value.expires_at > now_secs);
        self.destinations.retain(|_, value| {
            value.origins.retain(|_, expires_at| *expires_at > now_secs);
            !value.origins.is_empty()
        });
        self.flows.retain(|_, value| value.expires_at > now_secs);
        self.confirmed_control
            .retain(|_, expires_at| *expires_at > now_secs);
    }
}

fn is_eligible_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_unspecified()
                && address.octets() != [255, 255, 255, 255]
        }
        IpAddr::V6(address) => {
            !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unspecified()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
        }
    }
}

fn flow_key(flow: &FlowObservation) -> FlowKey {
    FlowKey {
        source: flow.source,
        source_port: flow.source_port,
        destination: flow.destination,
        destination_port: flow.destination_port,
        transport: flow.transport,
    }
}

fn normalize_dns_name(name: &str) -> Result<String, ClassifierError> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(ClassifierError::InvalidDnsName);
    }
    Ok(name)
}
