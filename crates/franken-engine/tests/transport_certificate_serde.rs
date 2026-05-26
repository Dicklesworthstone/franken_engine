#![forbid(unsafe_code)]
//! H5.2 (bd-o4cbn.7.2): dedicated TransportCertificate JSON serde round-trip
//! tests.
//!
//! H5.1 (bd-o4cbn.7.1) confirmed that no production path round-trips a
//! `TransportCertificate`, so the `hot_paths` bench dropped its
//! `serde_json::from_str` step. Round-trip fidelity that the bench used to
//! exercise incidentally is pinned here explicitly instead, so a serde
//! regression fails a fast test rather than silently changing a benchmark.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::transport_certificate_ledger::{
    ArtifactKind, HardwareCell, TransportCertificate, evaluate_transport,
};

fn sample_certificate() -> TransportCertificate {
    let source = HardwareCell::new("rch-x86-source", "x86_64", "zen4", 256, 64);
    let target = HardwareCell::new("rch-x86-target", "x86_64", "zen4", 256, 64);
    evaluate_transport(
        ArtifactKind::AotModule,
        ContentHash::compute(b"test"),
        &source,
        &target,
        1_000_000,
        990_000,
    )
    .expect("transport eval must succeed")
}

#[test]
fn transport_certificate_json_roundtrip() {
    let cert = sample_certificate();
    let json = serde_json::to_string(&cert).expect("serialize");
    let back: TransportCertificate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cert, back, "round-trip must preserve value");
}

#[test]
fn transport_certificate_field_byte_equal_after_roundtrip() {
    let cert = sample_certificate();
    let json = serde_json::to_string(&cert).expect("serialize");
    let back: TransportCertificate = serde_json::from_str(&json).expect("deserialize");

    // Compare every public field individually so a diff shows the breaking
    // field, not just "struct mismatch".
    assert_eq!(cert.certificate_id, back.certificate_id, "certificate_id");
    assert_eq!(cert.artifact_kind, back.artifact_kind, "artifact_kind");
    assert_eq!(cert.artifact_hash, back.artifact_hash, "artifact_hash");
    assert_eq!(cert.source_cell, back.source_cell, "source_cell");
    assert_eq!(cert.target_cell, back.target_cell, "target_cell");
    assert_eq!(cert.outcome, back.outcome, "outcome");
    assert_eq!(
        cert.source_perf_millionths, back.source_perf_millionths,
        "source_perf_millionths"
    );
    assert_eq!(
        cert.target_perf_millionths, back.target_perf_millionths,
        "target_perf_millionths"
    );
    assert_eq!(
        cert.degradation_reasons, back.degradation_reasons,
        "degradation_reasons"
    );
    assert_eq!(
        cert.residual_fraction_millionths, back.residual_fraction_millionths,
        "residual_fraction_millionths"
    );
    assert_eq!(cert.content_hash, back.content_hash, "content_hash");
}

#[test]
fn transport_certificate_serialized_bytes_are_stable() {
    // The serialized form is exactly what the refactored bench now hashes.
    // Pin that a serialize -> deserialize -> serialize cycle is byte-identical,
    // so the digest over those bytes is stable.
    let cert = sample_certificate();
    let json1 = serde_json::to_string(&cert).expect("serialize");
    let back: TransportCertificate = serde_json::from_str(&json1).expect("deserialize");
    let json2 = serde_json::to_string(&back).expect("re-serialize");
    assert_eq!(json1, json2, "re-serialization must be byte-identical");
    assert_eq!(
        ContentHash::compute(json1.as_bytes()),
        ContentHash::compute(json2.as_bytes()),
        "digest over serialized bytes must be stable across a round-trip"
    );
}
