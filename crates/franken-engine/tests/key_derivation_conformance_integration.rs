use std::collections::BTreeSet;

use frankenengine_engine::key_derivation::{
    DerivationContext, DerivationRequest, DerivedKey, DeterministicTestDeriver, KeyDerivationError,
    KeyDeriver, KeyDomain,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

const MASTER_KEY: &[u8] = b"conformance-master-key-32-bytes!!";
const SECRET_SENTINELS: [&str; 3] = ["do-not-log-me", "super-secret", "deadbeefcafebabe"];

fn context(extension_id: &str, session_id: &str) -> DerivationContext {
    let mut context = DerivationContext::empty();
    context.add("extension_id", extension_id);
    context.add("session_id", session_id);
    context
}

fn request(
    domain: KeyDomain,
    epoch: u64,
    context: DerivationContext,
    output_len: usize,
) -> DerivationRequest {
    DerivationRequest {
        master_key: MASTER_KEY.to_vec(),
        epoch: SecurityEpoch::from_raw(epoch),
        domain,
        context,
        output_len,
    }
}

fn derive_ok<D: KeyDeriver>(deriver: &D, request: &DerivationRequest) -> DerivedKey {
    deriver
        .derive(request)
        .expect("conforming deriver should accept valid request")
}

fn assert_key_deriver_contract<D, F>(make_deriver: F)
where
    D: KeyDeriver,
    F: Fn() -> D,
{
    let deriver = make_deriver();
    let max_output_len = deriver.max_output_len();
    assert!(
        max_output_len >= 32,
        "KeyDeriver must support at least 32-byte keys for engine key material"
    );

    let label = deriver.algorithm_label();
    assert!(
        !label.trim().is_empty(),
        "algorithm label must be non-empty"
    );
    assert_eq!(
        label,
        make_deriver().algorithm_label(),
        "algorithm label must be stable across instances"
    );
    for sentinel in SECRET_SENTINELS {
        assert!(
            !label.contains(sentinel),
            "algorithm label must not leak internal secret material"
        );
    }

    let baseline = request(
        KeyDomain::Session,
        7,
        context("extension-alpha", "session-1"),
        32,
    );
    let first = derive_ok(&deriver, &baseline);
    let second = derive_ok(&deriver, &baseline);
    assert_eq!(
        first, second,
        "fixed input must derive deterministic key material and metadata"
    );
    assert_eq!(first.key_bytes.len(), baseline.output_len);
    assert!(first.key_bytes.len() <= max_output_len);
    assert_eq!(first.domain, baseline.domain);
    assert_eq!(first.epoch, baseline.epoch);
    assert!(!first.context_hash.is_empty());

    let mut by_domain = BTreeSet::new();
    for domain in KeyDomain::ALL {
        let key = derive_ok(
            &deriver,
            &request(*domain, 7, context("extension-alpha", "session-1"), 32),
        );
        assert_eq!(key.domain, *domain);
        // Clone — `DerivedKey` now `Drop`s and zeroizes `key_bytes`
        // (bd-i6vjn), so the field can't be moved out (E0509).
        by_domain.insert(key.key_bytes.clone());
    }
    assert_eq!(
        by_domain.len(),
        KeyDomain::ALL.len(),
        "domain-separated derivation must not collapse distinct domains"
    );

    let different_epoch = derive_ok(
        &deriver,
        &request(
            KeyDomain::Session,
            8,
            context("extension-alpha", "session-1"),
            32,
        ),
    );
    assert_ne!(
        first.key_bytes, different_epoch.key_bytes,
        "epoch separation must change derived key material"
    );

    let different_context = derive_ok(
        &deriver,
        &request(
            KeyDomain::Session,
            7,
            context("extension-alpha", "session-2"),
            32,
        ),
    );
    assert_ne!(
        first.key_bytes, different_context.key_bytes,
        "context separation must change derived key material"
    );
    assert_ne!(
        first.context_hash, different_context.context_hash,
        "context hash must distinguish different binding contexts"
    );

    let zero_len = DerivationRequest {
        output_len: 0,
        ..baseline.clone()
    };
    assert_eq!(
        deriver.derive(&zero_len),
        Err(KeyDerivationError::ZeroOutputLength)
    );

    let empty_master = DerivationRequest {
        master_key: Vec::new(),
        ..baseline.clone()
    };
    assert_eq!(
        deriver.derive(&empty_master),
        Err(KeyDerivationError::EmptyMasterKey)
    );

    let too_long = DerivationRequest {
        output_len: max_output_len + 1,
        ..baseline
    };
    assert_eq!(
        deriver.derive(&too_long),
        Err(KeyDerivationError::OutputTooLong {
            requested: max_output_len + 1,
            max: max_output_len,
        })
    );
}

#[test]
fn deterministic_test_deriver_satisfies_key_deriver_contract() {
    assert_key_deriver_contract(|| DeterministicTestDeriver);
}

#[derive(Debug)]
struct DebugSecretDeriver {
    secret_material: &'static str,
}

impl KeyDeriver for DebugSecretDeriver {
    fn derive(&self, request: &DerivationRequest) -> Result<DerivedKey, KeyDerivationError> {
        DeterministicTestDeriver.derive(request)
    }

    fn max_output_len(&self) -> usize {
        DeterministicTestDeriver::MAX_OUTPUT
    }
}

#[test]
fn default_algorithm_label_satisfies_secret_redaction_contract() {
    let deriver = DebugSecretDeriver {
        secret_material: SECRET_SENTINELS[0],
    };
    assert!(format!("{deriver:?}").contains(deriver.secret_material));

    assert_key_deriver_contract(|| DebugSecretDeriver {
        secret_material: SECRET_SENTINELS[0],
    });
}
