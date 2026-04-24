#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::optimal_stopping::{OptimalStoppingCertificate, STOPPING_SCHEMA_VERSION};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Serialize;

const GOLDEN_FILE: &str = "tests/golden_vectors/optimal_stopping_certificate_v1.json";

#[derive(Debug, Serialize)]
struct OptimalStoppingCertificateSnapshot {
    coverage_gap: &'static str,
    certificate_hash_hex: String,
    certificate: OptimalStoppingCertificate,
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_FILE)
}

fn assert_golden(actual: &str) {
    let path = golden_path();

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&path, actual).expect("failed to update optimal stopping certificate golden");
        eprintln!("[GOLDEN] updated {}", path.display());
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden fixture: {}\nrun with UPDATE_GOLDENS=1 to generate it",
            path.display()
        )
    });

    if actual != expected {
        let actual_path = path.with_extension("actual");
        fs::write(&actual_path, actual).expect("failed to write optimal stopping actual fixture");
        panic!(
            "optimal stopping certificate golden mismatch\nexpected: {}\nactual: {}",
            path.display(),
            actual_path.display()
        );
    }
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
    assert_golden(&actual);
}
