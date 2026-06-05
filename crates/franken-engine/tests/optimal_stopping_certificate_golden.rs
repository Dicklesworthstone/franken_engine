#![forbid(unsafe_code)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::optimal_stopping::{OptimalStoppingCertificate, STOPPING_SCHEMA_VERSION};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct OptimalStoppingCertificateSnapshot {
    coverage_gap: &'static str,
    certificate_hash_hex: String,
    certificate: OptimalStoppingCertificate,
}

fn certificate_snapshot() -> OptimalStoppingCertificateSnapshot {
    let certificate_hash = ContentHash::compute(b"optimal-stopping-cusum-certificate-v1");
    let certificate = OptimalStoppingCertificate {
        schema: STOPPING_SCHEMA_VERSION.to_string(),
        algorithm: "cusum".to_string(),
        observations_before_stop: 42,
        cusum_statistic_millionths: Some(5_500_000),
        arl0_lower_bound: Some(1_000_000_000),
        snell_optimal_value_millionths: None,
        gittins_index_millionths: None,
        epoch: SecurityEpoch::from_raw(7),
        certificate_hash,
    };

    OptimalStoppingCertificateSnapshot {
        coverage_gap: "optimal stopping certificate JSON serialization",
        certificate_hash_hex: certificate_hash.to_hex(),
        certificate,
    }
}

#[test]
fn optimal_stopping_certificate_json_matches_golden() {
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&certificate_snapshot()).unwrap()
    );
    insta::assert_snapshot!("optimal_stopping_certificate_json_matches_golden", actual);
}
