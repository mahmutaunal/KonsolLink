//! Read-only packet metadata adapter. Raw frames never leave this module.

use konsollink_core::classifier::{
    ClassifierDiagnostics, DiscordClassifier, DnsRecord, FlowClass, FlowObservation,
    QualifiedTcpDestination, Transport,
};
use konsollink_core::ServiceProfile;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
pub mod macos;

const MAX_FRAME_BYTES: usize = 4096;
const MAX_DNS_RECORDS: usize = 64;
const MAX_DNS_NAME_JUMPS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationResult {
    Ignored,
    Direct,
    DiscordControlCandidate,
    DiscordMediaCandidate,
    Malformed,
}

pub struct FrameObserver {
    console: Ipv4Addr,
    classifier: DiscordClassifier,
}

impl FrameObserver {
    pub fn new(console: Ipv4Addr, profile: ServiceProfile) -> Self {
        Self {
            console,
            classifier: DiscordClassifier::new(IpAddr::V4(console), profile),
        }
    }

    /// Parses one bounded Ethernet frame and immediately discards its bytes.
    pub fn observe_ethernet_frame(&mut self, frame: &[u8], now_secs: u64) -> ObservationResult {
        if frame.len() > MAX_FRAME_BYTES {
            return ObservationResult::Malformed;
        }
        match parse_frame(frame, self.console) {
            Ok(Some(PacketMetadata::DnsQuery {
                source,
                source_port,
                resolver,
                transaction_id,
                name,
            })) => match self.classifier.observe_dns_query(
                source,
                source_port,
                resolver,
                transaction_id,
                &name,
                now_secs,
            ) {
                Ok(true) => ObservationResult::Direct,
                Ok(false) => ObservationResult::Ignored,
                Err(_) => ObservationResult::Malformed,
            },
            Ok(Some(PacketMetadata::DnsResponse {
                resolver,
                destination,
                destination_port,
                transaction_id,
                records,
            })) => match self.classifier.observe_dns_response(
                resolver,
                destination,
                destination_port,
                transaction_id,
                &records,
                now_secs,
            ) {
                Ok(_) => ObservationResult::Direct,
                Err(_) => ObservationResult::Malformed,
            },
            Ok(Some(PacketMetadata::Flow(flow))) => match self
                .classifier
                .observe_flow(&flow, now_secs)
            {
                FlowClass::Direct => ObservationResult::Direct,
                FlowClass::DiscordControlCandidate => ObservationResult::DiscordControlCandidate,
                FlowClass::DiscordMediaCandidate => ObservationResult::DiscordMediaCandidate,
            },
            Ok(None) => ObservationResult::Ignored,
            Err(()) => ObservationResult::Malformed,
        }
    }

    pub fn diagnostics(&mut self, now_secs: u64) -> ClassifierDiagnostics {
        self.classifier.diagnostics(now_secs)
    }

    pub fn qualified_tcp_destinations(
        &mut self,
        proof: &konsollink_core::qualification::QualifiedShadowRun,
        now_secs: u64,
    ) -> Vec<QualifiedTcpDestination> {
        self.classifier.qualified_tcp_destinations(proof, now_secs)
    }
}

enum PacketMetadata {
    DnsQuery {
        source: IpAddr,
        source_port: u16,
        resolver: IpAddr,
        transaction_id: u16,
        name: String,
    },
    DnsResponse {
        resolver: IpAddr,
        destination: IpAddr,
        destination_port: u16,
        transaction_id: u16,
        records: Vec<DnsRecord>,
    },
    Flow(FlowObservation),
}

fn parse_frame(frame: &[u8], console: Ipv4Addr) -> Result<Option<PacketMetadata>, ()> {
    if frame.len() < 14 {
        return Err(());
    }
    let mut offset = 14usize;
    let mut ether_type = be16(frame, 12)?;
    if matches!(ether_type, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return Err(());
        }
        ether_type = be16(frame, 16)?;
        offset = 18;
    }
    if ether_type != 0x0800 {
        return Ok(None);
    }
    if frame.len() < offset + 20 || frame[offset] >> 4 != 4 {
        return Err(());
    }
    let ihl = usize::from(frame[offset] & 0x0f) * 4;
    if ihl < 20 || frame.len() < offset + ihl {
        return Err(());
    }
    let total = usize::from(be16(frame, offset + 2)?);
    if total < ihl || frame.len() < offset + total {
        return Err(());
    }
    let fragment = be16(frame, offset + 6)?;
    if fragment & 0x3fff != 0 {
        return Ok(None);
    }
    let source = Ipv4Addr::new(
        frame[offset + 12],
        frame[offset + 13],
        frame[offset + 14],
        frame[offset + 15],
    );
    let destination = Ipv4Addr::new(
        frame[offset + 16],
        frame[offset + 17],
        frame[offset + 18],
        frame[offset + 19],
    );
    if source != console && destination != console {
        return Ok(None);
    }
    let payload = &frame[offset + ihl..offset + total];
    match frame[offset + 9] {
        17 => parse_udp(source, destination, payload),
        6 => parse_tcp(source, destination, payload),
        _ => Ok(None),
    }
}

fn parse_udp(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &[u8],
) -> Result<Option<PacketMetadata>, ()> {
    if payload.len() < 8 {
        return Err(());
    }
    let source_port = be16(payload, 0)?;
    let destination_port = be16(payload, 2)?;
    let length = usize::from(be16(payload, 4)?);
    if length < 8 || length > payload.len() {
        return Err(());
    }
    let body = &payload[8..length];
    if destination_port == 53 {
        return parse_dns_query(source, source_port, destination, body).map(Some);
    }
    if source_port == 53 {
        return parse_dns_response(source, destination, destination_port, body).map(Some);
    }
    Ok(Some(PacketMetadata::Flow(FlowObservation {
        source: IpAddr::V4(source),
        source_port,
        destination: IpAddr::V4(destination),
        destination_port,
        transport: Transport::Udp,
        tls_server_name: None,
    })))
}

fn parse_tcp(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &[u8],
) -> Result<Option<PacketMetadata>, ()> {
    if payload.len() < 20 {
        return Err(());
    }
    let source_port = be16(payload, 0)?;
    let destination_port = be16(payload, 2)?;
    let header = usize::from(payload[12] >> 4) * 4;
    if header < 20 || header > payload.len() {
        return Err(());
    }
    let body = &payload[header..];
    let tls_server_name = if destination_port == 443 {
        parse_tls_sni(body).ok().flatten()
    } else {
        None
    };
    Ok(Some(PacketMetadata::Flow(FlowObservation {
        source: IpAddr::V4(source),
        source_port,
        destination: IpAddr::V4(destination),
        destination_port,
        transport: Transport::Tcp,
        tls_server_name,
    })))
}

fn parse_dns_query(
    source: Ipv4Addr,
    source_port: u16,
    resolver: Ipv4Addr,
    dns: &[u8],
) -> Result<PacketMetadata, ()> {
    let header = dns_header(dns)?;
    if header.response || header.questions != 1 {
        return Err(());
    }
    let (name, offset) = dns_name(dns, 12)?;
    if offset + 4 > dns.len()
        || !matches!(be16(dns, offset)?, 1 | 28)
        || be16(dns, offset + 2)? != 1
    {
        return Err(());
    }
    Ok(PacketMetadata::DnsQuery {
        source: IpAddr::V4(source),
        source_port,
        resolver: IpAddr::V4(resolver),
        transaction_id: header.id,
        name,
    })
}

fn parse_dns_response(
    resolver: Ipv4Addr,
    destination: Ipv4Addr,
    destination_port: u16,
    dns: &[u8],
) -> Result<PacketMetadata, ()> {
    let header = dns_header(dns)?;
    if !header.response || header.questions != 1 || header.answers > MAX_DNS_RECORDS as u16 {
        return Err(());
    }
    let (_, mut offset) = dns_name(dns, 12)?;
    offset = offset.checked_add(4).ok_or(())?;
    if offset > dns.len() {
        return Err(());
    }
    let mut records = Vec::new();
    for _ in 0..header.answers {
        let (owner, next) = dns_name(dns, offset)?;
        offset = next;
        let kind = be16(dns, offset)?;
        let class = be16(dns, offset + 2)?;
        let ttl_secs = be32(dns, offset + 4)?;
        let size = usize::from(be16(dns, offset + 8)?);
        offset = offset.checked_add(10).ok_or(())?;
        let end = offset.checked_add(size).ok_or(())?;
        if end > dns.len() {
            return Err(());
        }
        if class == 1 {
            match (kind, size) {
                (1, 4) => records.push(DnsRecord::Address {
                    owner,
                    address: IpAddr::V4(Ipv4Addr::new(
                        dns[offset],
                        dns[offset + 1],
                        dns[offset + 2],
                        dns[offset + 3],
                    )),
                    ttl_secs,
                }),
                (28, 16) => {
                    let bytes: [u8; 16] = dns[offset..end].try_into().map_err(|_| ())?;
                    records.push(DnsRecord::Address {
                        owner,
                        address: IpAddr::V6(Ipv6Addr::from(bytes)),
                        ttl_secs,
                    });
                }
                (5, _) => {
                    let (target, consumed) = dns_name(dns, offset)?;
                    if consumed > end {
                        return Err(());
                    }
                    records.push(DnsRecord::Cname {
                        owner,
                        target,
                        ttl_secs,
                    });
                }
                _ => {}
            }
        }
        offset = end;
    }
    Ok(PacketMetadata::DnsResponse {
        resolver: IpAddr::V4(resolver),
        destination: IpAddr::V4(destination),
        destination_port,
        transaction_id: header.id,
        records,
    })
}

struct DnsHeader {
    id: u16,
    response: bool,
    questions: u16,
    answers: u16,
}

fn dns_header(bytes: &[u8]) -> Result<DnsHeader, ()> {
    if bytes.len() < 12 {
        return Err(());
    }
    Ok(DnsHeader {
        id: be16(bytes, 0)?,
        response: be16(bytes, 2)? & 0x8000 != 0,
        questions: be16(bytes, 4)?,
        answers: be16(bytes, 6)?,
    })
}

fn dns_name(bytes: &[u8], start: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut end = None;
    let mut jumps = 0usize;
    loop {
        let length = *bytes.get(cursor).ok_or(())?;
        if length & 0xc0 == 0xc0 {
            let low = usize::from(*bytes.get(cursor + 1).ok_or(())?);
            let pointer = (usize::from(length & 0x3f) << 8) | low;
            end.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            if jumps > MAX_DNS_NAME_JUMPS {
                return Err(());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(());
        }
        cursor += 1;
        if length == 0 {
            break;
        }
        let length = usize::from(length);
        let label = bytes.get(cursor..cursor + length).ok_or(())?;
        if !label.iter().all(u8::is_ascii) {
            return Err(());
        }
        labels.push(std::str::from_utf8(label).map_err(|_| ())?);
        cursor += length;
        if labels.len() > 127 {
            return Err(());
        }
    }
    let name = labels.join(".");
    if name.is_empty() || name.len() > 253 {
        return Err(());
    }
    Ok((name, end.unwrap_or(cursor)))
}

fn parse_tls_sni(bytes: &[u8]) -> Result<Option<String>, ()> {
    if bytes.len() < 9 || bytes[0] != 22 || bytes[5] != 1 {
        return Ok(None);
    }
    let record_len = usize::from(be16(bytes, 3)?);
    if record_len + 5 > bytes.len() {
        return Ok(None);
    }
    let handshake_len =
        (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
    if handshake_len + 4 > record_len || handshake_len < 38 {
        return Err(());
    }
    let hello = &bytes[9..9 + handshake_len];
    let mut offset = 34usize;
    let session = usize::from(*hello.get(offset).ok_or(())?);
    offset = offset.checked_add(1 + session).ok_or(())?;
    let cipher_len = usize::from(be16(hello, offset)?);
    offset = offset.checked_add(2 + cipher_len).ok_or(())?;
    let compression_len = usize::from(*hello.get(offset).ok_or(())?);
    offset = offset.checked_add(1 + compression_len).ok_or(())?;
    let extensions_len = usize::from(be16(hello, offset)?);
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len).ok_or(())?;
    if extensions_end > hello.len() {
        return Err(());
    }
    while offset + 4 <= extensions_end {
        let kind = be16(hello, offset)?;
        let size = usize::from(be16(hello, offset + 2)?);
        offset += 4;
        let end = offset.checked_add(size).ok_or(())?;
        if end > extensions_end {
            return Err(());
        }
        if kind == 0 {
            if size < 5 || usize::from(be16(hello, offset)?) + 2 != size {
                return Err(());
            }
            let name_type = hello[offset + 2];
            let name_len = usize::from(be16(hello, offset + 3)?);
            if name_type != 0 || offset + 5 + name_len > end {
                return Err(());
            }
            let name =
                std::str::from_utf8(&hello[offset + 5..offset + 5 + name_len]).map_err(|_| ())?;
            return Ok(Some(name.to_owned()));
        }
        offset = end;
    }
    Ok(None)
}

fn be16(bytes: &[u8], offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ))
}

fn be32(bytes: &[u8], offset: usize) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_name_bytes(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    fn dns_query() -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        dns.extend(dns_name_bytes("gateway.discord.gg"));
        dns.extend_from_slice(&[0, 1, 0, 1]);
        dns
    }

    fn dns_response() -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        dns.extend(dns_name_bytes("gateway.discord.gg"));
        dns.extend_from_slice(&[0, 1, 0, 1]);
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        dns.extend_from_slice(&[1, 1, 1, 20]);
        dns
    }

    fn tls_client_hello(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let mut extension = vec![0, 0];
        let extension_size = 2 + 1 + 2 + name.len();
        extension.extend_from_slice(&(extension_size as u16).to_be_bytes());
        extension.extend_from_slice(&((extension_size - 2) as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extension.extend_from_slice(name);

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        hello.extend(extension);

        let mut handshake = vec![1];
        let size = hello.len();
        handshake.extend_from_slice(&[
            ((size >> 16) & 0xff) as u8,
            ((size >> 8) & 0xff) as u8,
            (size & 0xff) as u8,
        ]);
        handshake.extend(hello);

        let mut record = vec![22, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    fn ethernet_ipv4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
    ) -> Vec<u8> {
        let total = 20 + transport.len();
        let mut frame = vec![0; 14 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(total as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&source.octets());
        frame[30..34].copy_from_slice(&destination.octets());
        frame.extend_from_slice(transport);
        frame
    }

    fn udp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&source_port.to_be_bytes());
        packet.extend_from_slice(&destination_port.to_be_bytes());
        packet.extend_from_slice(&((body.len() + 8) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(body);
        packet
    }

    fn tcp(source_port: u16, destination_port: u16, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0..2].copy_from_slice(&source_port.to_be_bytes());
        packet[2..4].copy_from_slice(&destination_port.to_be_bytes());
        packet[12] = 0x50;
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn wire_dns_and_visible_sni_feed_the_classifier_without_payload_output() {
        let console = Ipv4Addr::new(192, 168, 1, 191);
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let discord = Ipv4Addr::new(1, 1, 1, 20);
        let mut observer = FrameObserver::new(console, ServiceProfile::discord_tr().unwrap());

        let query = ethernet_ipv4(console, router, 17, &udp(53000, 53, &dns_query()));
        assert_eq!(
            observer.observe_ethernet_frame(&query, 0),
            ObservationResult::Direct
        );
        let response = ethernet_ipv4(router, console, 17, &udp(53, 53000, &dns_response()));
        assert_eq!(
            observer.observe_ethernet_frame(&response, 1),
            ObservationResult::Direct
        );
        let hello = ethernet_ipv4(
            console,
            discord,
            6,
            &tcp(51000, 443, &tls_client_hello("gateway.discord.gg")),
        );
        assert_eq!(
            observer.observe_ethernet_frame(&hello, 2),
            ObservationResult::DiscordControlCandidate
        );
        let diagnostics = observer.diagnostics(2);
        assert_eq!(diagnostics.learned_destinations, 1);
        assert_eq!(diagnostics.discord_control_candidates, 1);
        let proof = konsollink_core::qualification::qualify(
            konsollink_core::qualification::QualificationReport {
                non_discord_samples: 2,
                discord_control_samples: 1,
                discord_media_samples: 1,
                ..Default::default()
            },
            konsollink_core::qualification::CaptureHealth {
                observer_active: true,
                captured_packets: 3,
                dropped_packets: 0,
            },
            Default::default(),
        )
        .unwrap();
        let qualified = observer.qualified_tcp_destinations(&proof, 2);
        assert_eq!(qualified.len(), 1);
        assert_eq!(qualified[0].address(), discord);
        assert_eq!(qualified[0].expires_at(), 61);
    }

    #[test]
    fn truncated_frames_and_compression_loops_fail_closed_without_panics() {
        let console = Ipv4Addr::new(192, 168, 1, 191);
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let valid = ethernet_ipv4(console, router, 17, &udp(53000, 53, &dns_query()));
        for end in 0..valid.len() {
            let mut observer = FrameObserver::new(console, ServiceProfile::discord_tr().unwrap());
            assert_ne!(
                observer.observe_ethernet_frame(&valid[..end], 0),
                ObservationResult::DiscordControlCandidate
            );
        }

        let mut looped = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        let frame = ethernet_ipv4(console, router, 17, &udp(53000, 53, &looped));
        let mut observer = FrameObserver::new(console, ServiceProfile::discord_tr().unwrap());
        assert_eq!(
            observer.observe_ethernet_frame(&frame, 0),
            ObservationResult::Malformed
        );
    }

    #[test]
    fn unrelated_hosts_and_ipv4_fragments_are_not_observed() {
        let console = Ipv4Addr::new(192, 168, 1, 191);
        let mut observer = FrameObserver::new(console, ServiceProfile::discord_tr().unwrap());
        let unrelated = ethernet_ipv4(
            Ipv4Addr::new(192, 168, 1, 20),
            Ipv4Addr::new(1, 1, 1, 1),
            17,
            &udp(50000, 50000, &[1, 2, 3]),
        );
        assert_eq!(
            observer.observe_ethernet_frame(&unrelated, 0),
            ObservationResult::Ignored
        );
        let mut fragmented = ethernet_ipv4(
            console,
            Ipv4Addr::new(1, 1, 1, 20),
            17,
            &udp(50000, 50000, &[1, 2, 3]),
        );
        fragmented[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        assert_eq!(
            observer.observe_ethernet_frame(&fragmented, 0),
            ObservationResult::Ignored
        );
    }
}
