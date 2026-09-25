use konsollink_core::classifier::FlowClass;
use konsollink_core::qualification::{
    m2_path, qualify, CaptureHealth, ExpectedClass, M2Path, QualificationError,
    QualificationRequirements, ShadowEvaluator,
};

fn healthy_capture() -> CaptureHealth {
    CaptureHealth {
        observer_active: true,
        captured_packets: 100,
        dropped_packets: 0,
    }
}

fn passing_evaluator() -> ShadowEvaluator {
    let mut evaluator = ShadowEvaluator::default();
    evaluator.observe(ExpectedClass::NonDiscord, FlowClass::Direct);
    evaluator.observe(ExpectedClass::NonDiscord, FlowClass::Direct);
    evaluator.observe(
        ExpectedClass::DiscordControl,
        FlowClass::DiscordControlCandidate,
    );
    evaluator.observe(
        ExpectedClass::DiscordMedia,
        FlowClass::DiscordMediaCandidate,
    );
    evaluator
}

#[test]
fn passing_shadow_run_only_exposes_tcp_control_candidate() {
    let evaluator = passing_evaluator();
    let proof = qualify(
        evaluator.report(),
        healthy_capture(),
        QualificationRequirements::default(),
    )
    .unwrap();
    assert_eq!(
        m2_path(
            &proof,
            FlowClass::DiscordControlCandidate,
            healthy_capture()
        ),
        M2Path::TcpProxyCandidate
    );
    assert_eq!(
        m2_path(&proof, FlowClass::DiscordMediaCandidate, healthy_capture()),
        M2Path::Direct
    );
    assert_eq!(
        m2_path(&proof, FlowClass::Direct, healthy_capture()),
        M2Path::Direct
    );
}

#[test]
fn any_non_discord_selection_blocks_qualification() {
    let mut evaluator = passing_evaluator();
    evaluator.observe(ExpectedClass::NonDiscord, FlowClass::DiscordMediaCandidate);
    assert!(matches!(
        qualify(
            evaluator.report(),
            healthy_capture(),
            QualificationRequirements::default()
        ),
        Err(QualificationError::FalsePositive)
    ));
}

#[test]
fn drops_missing_samples_and_false_negatives_block_qualification() {
    let evaluator = passing_evaluator();
    let mut dropped = healthy_capture();
    dropped.dropped_packets = 1;
    assert!(matches!(
        qualify(
            evaluator.report(),
            dropped,
            QualificationRequirements::default()
        ),
        Err(QualificationError::CaptureDrops)
    ));

    let mut missing = ShadowEvaluator::default();
    missing.observe(ExpectedClass::NonDiscord, FlowClass::Direct);
    assert!(matches!(
        qualify(
            missing.report(),
            healthy_capture(),
            QualificationRequirements::default()
        ),
        Err(QualificationError::InsufficientSamples)
    ));

    let mut false_negative = passing_evaluator();
    false_negative.observe(ExpectedClass::DiscordControl, FlowClass::Direct);
    assert!(matches!(
        qualify(
            false_negative.report(),
            healthy_capture(),
            QualificationRequirements::default()
        ),
        Err(QualificationError::FalseNegative)
    ));
}

#[test]
fn live_capture_health_failure_returns_to_direct() {
    let evaluator = passing_evaluator();
    let proof = qualify(
        evaluator.report(),
        healthy_capture(),
        QualificationRequirements::default(),
    )
    .unwrap();
    for capture in [
        CaptureHealth {
            observer_active: false,
            ..healthy_capture()
        },
        CaptureHealth {
            dropped_packets: 1,
            ..healthy_capture()
        },
    ] {
        assert_eq!(
            m2_path(&proof, FlowClass::DiscordControlCandidate, capture),
            M2Path::Direct
        );
    }
}
