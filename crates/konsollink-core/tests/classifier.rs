use konsollink_core::classifier::{
    DiscordClassifier, DnsRecord, FlowClass, FlowObservation, Transport,
};
use konsollink_core::qualification::{
    qualify, CaptureHealth, QualificationReport, QualificationRequirements,
};
use konsollink_core::ServiceProfile;
use std::net::IpAddr;

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn classifier() -> DiscordClassifier {
    DiscordClassifier::new(ip("192.168.1.191"), ServiceProfile::discord_tr().unwrap())
}

fn learn_discord(classifier: &mut DiscordClassifier, now: u64) {
    assert!(classifier
        .observe_dns_query(
            ip("192.168.1.191"),
            53000,
            ip("192.168.1.1"),
            7,
            "gateway.discord.gg",
            now,
        )
        .unwrap());
    assert_eq!(
        classifier
            .observe_dns_response(
                ip("192.168.1.1"),
                ip("192.168.1.191"),
                53000,
                7,
                &[
                    DnsRecord::Cname {
                        owner: "gateway.discord.gg".into(),
                        target: "edge.example-cdn.net".into(),
                        ttl_secs: 90,
                    },
                    DnsRecord::Address {
                        owner: "edge.example-cdn.net".into(),
                        address: ip("1.1.1.20"),
                        ttl_secs: 60,
                    },
                ],
                now + 1,
            )
            .unwrap(),
        1
    );
}

fn flow(destination: &str, port: u16, transport: Transport) -> FlowObservation {
    FlowObservation {
        source: ip("192.168.1.191"),
        source_port: 51000,
        destination: ip(destination),
        destination_port: port,
        transport,
        tls_server_name: None,
    }
}

fn control_flow() -> FlowObservation {
    let mut observation = flow("1.1.1.20", 443, Transport::Tcp);
    observation.tls_server_name = Some("gateway.discord.gg".into());
    observation
}

fn proof() -> konsollink_core::qualification::QualifiedShadowRun {
    qualify(
        QualificationReport {
            non_discord_samples: 2,
            discord_control_samples: 1,
            discord_media_samples: 1,
            ..QualificationReport::default()
        },
        CaptureHealth {
            observer_active: true,
            captured_packets: 10,
            dropped_packets: 0,
        },
        QualificationRequirements::default(),
    )
    .unwrap()
}

#[test]
fn interception_snapshot_requires_confirmed_control_flow_and_expires() {
    let mut classifier = classifier();
    learn_discord(&mut classifier, 10);
    let proof = proof();
    assert!(classifier.qualified_tcp_destinations(&proof, 20).is_empty());

    assert_eq!(
        classifier.observe_flow(&control_flow(), 20),
        FlowClass::DiscordControlCandidate
    );
    let destinations = classifier.qualified_tcp_destinations(&proof, 20);
    assert_eq!(destinations.len(), 1);
    assert_eq!(destinations[0].address().to_string(), "1.1.1.20");
    assert_eq!(destinations[0].expires_at(), 71);
    assert!(classifier.qualified_tcp_destinations(&proof, 71).is_empty());
}

#[test]
fn dns_evidence_requires_console_query_and_matching_response_tuple() {
    let mut classifier = classifier();
    assert!(!classifier
        .observe_dns_query(
            ip("192.168.1.50"),
            53000,
            ip("192.168.1.1"),
            1,
            "discord.com",
            0,
        )
        .unwrap());
    assert!(!classifier
        .observe_dns_query(
            ip("192.168.1.191"),
            53000,
            ip("192.168.1.1"),
            2,
            "example.com",
            0,
        )
        .unwrap());
    assert_eq!(
        classifier
            .observe_dns_response(
                ip("192.168.1.1"),
                ip("192.168.1.191"),
                53000,
                99,
                &[DnsRecord::Address {
                    owner: "discord.com".into(),
                    address: ip("1.1.1.21"),
                    ttl_secs: 60,
                }],
                1,
            )
            .unwrap(),
        0
    );
    assert_eq!(classifier.diagnostics(1).learned_destinations, 0);
}

#[test]
fn cname_chain_uses_shortest_ttl_and_does_not_trust_unrelated_records() {
    let mut classifier = classifier();
    learn_discord(&mut classifier, 10);
    let candidate = control_flow();
    assert_eq!(
        classifier.observe_flow(&candidate, 70),
        FlowClass::DiscordControlCandidate
    );
    let mut new_flow = candidate;
    new_flow.source_port += 1;
    assert_eq!(classifier.observe_flow(&new_flow, 72), FlowClass::Direct);
}

#[test]
fn independently_labelled_flows_fail_closed() {
    let mut classifier = classifier();
    learn_discord(&mut classifier, 100);
    let cases = [
        (
            "discord control",
            control_flow(),
            FlowClass::DiscordControlCandidate,
        ),
        (
            "discord voice candidate",
            flow("1.1.1.20", 50000, Transport::Udp),
            FlowClass::DiscordMediaCandidate,
        ),
        (
            "game on learned shared address",
            flow("1.1.1.20", 3074, Transport::Udp),
            FlowClass::Direct,
        ),
        (
            "unlearned https",
            flow("1.1.1.21", 443, Transport::Tcp),
            FlowClass::Direct,
        ),
    ];
    for (label, observation, expected) in cases {
        assert_eq!(
            classifier.observe_flow(&observation, 102),
            expected,
            "{label}"
        );
    }

    let mut conflicting_sni = flow("1.1.1.20", 443, Transport::Tcp);
    conflicting_sni.source_port = 51001;
    conflicting_sni.tls_server_name = Some("example.com".into());
    assert_eq!(
        classifier.observe_flow(&conflicting_sni, 102),
        FlowClass::Direct
    );
}

#[test]
fn only_tracked_reverse_flow_is_related() {
    let mut classifier = classifier();
    learn_discord(&mut classifier, 0);
    assert_eq!(
        classifier.observe_flow(&control_flow(), 2),
        FlowClass::DiscordControlCandidate
    );
    let outbound = flow("1.1.1.20", 50000, Transport::Udp);
    let mut outbound = outbound;
    outbound.source_port += 1;
    assert_eq!(
        classifier.observe_flow(&outbound, 2),
        FlowClass::DiscordMediaCandidate
    );
    let reverse = FlowObservation {
        source: outbound.destination,
        source_port: outbound.destination_port,
        destination: outbound.source,
        destination_port: outbound.source_port,
        transport: outbound.transport,
        tls_server_name: None,
    };
    assert_eq!(
        classifier.observe_flow(&reverse, 3),
        FlowClass::DiscordMediaCandidate
    );
    let mut unsolicited = reverse;
    unsolicited.destination_port += 1;
    assert_eq!(classifier.observe_flow(&unsolicited, 3), FlowClass::Direct);
}

#[test]
fn port_metadata_alone_never_classifies_discord() {
    let mut classifier = classifier();
    assert_eq!(
        classifier.observe_flow(&flow("1.1.1.20", 50000, Transport::Udp), 0),
        FlowClass::Direct
    );
    assert_eq!(
        classifier.observe_flow(&flow("1.1.1.20", 443, Transport::Tcp), 0),
        FlowClass::Direct
    );
}

#[test]
fn shared_address_requires_matching_visible_sni_and_control_before_udp() {
    let mut classifier = classifier();
    learn_discord(&mut classifier, 0);

    assert_eq!(
        classifier.observe_flow(&flow("1.1.1.20", 443, Transport::Tcp), 2),
        FlowClass::Direct
    );
    assert_eq!(
        classifier.observe_flow(&flow("1.1.1.20", 50000, Transport::Udp), 2),
        FlowClass::Direct
    );

    let mut wrong_name = flow("1.1.1.20", 443, Transport::Tcp);
    wrong_name.source_port += 1;
    wrong_name.tls_server_name = Some("discord.com".into());
    assert_eq!(classifier.observe_flow(&wrong_name, 2), FlowClass::Direct);
    assert_eq!(
        classifier.observe_flow(&control_flow(), 2),
        FlowClass::DiscordControlCandidate
    );

    let mut media = flow("1.1.1.20", 50000, Transport::Udp);
    media.source_port += 2;
    assert_eq!(
        classifier.observe_flow(&media, 2),
        FlowClass::DiscordMediaCandidate
    );
}

#[test]
fn dns_tuple_includes_client_port_and_private_answers_are_rejected() {
    let mut classifier = classifier();
    for client_port in [53000, 53001] {
        assert!(classifier
            .observe_dns_query(
                ip("192.168.1.191"),
                client_port,
                ip("192.168.1.1"),
                42,
                "discord.com",
                0,
            )
            .unwrap());
    }
    assert_eq!(classifier.diagnostics(0).pending_dns_queries, 2);
    assert_eq!(
        classifier
            .observe_dns_response(
                ip("192.168.1.1"),
                ip("192.168.1.191"),
                53000,
                42,
                &[DnsRecord::Address {
                    owner: "discord.com".into(),
                    address: ip("192.168.1.1"),
                    ttl_secs: 60,
                }],
                1,
            )
            .unwrap(),
        0
    );
    assert_eq!(classifier.diagnostics(1).pending_dns_queries, 1);
    assert_eq!(classifier.diagnostics(1).learned_destinations, 0);
}
