#![forbid(unsafe_code)]

//! Golden regression for `HostcallSinkPolicy` (bd-3v6az).
//!
//! Pre-existing tests assert selected defaults in isolation, but no golden
//! freezes the complete `HostcallType` → `Option<SinkClearance>` clearance
//! matrix or the policy's own three sink defaults. This file pins both, so
//! that any change to:
//!
//!   - `HostcallType::is_sink` (which variants are sinks),
//!   - `HostcallSinkPolicy::default()` (the three default clearance pairs),
//!   - `HostcallSinkPolicy::clearance_for` (the type→clearance mapping), or
//!   - the serde rename rules on `HostcallType`, `SecrecyLevel`,
//!     `IntegrityLevel`, or `SinkClearance` itself,
//!
//! has to be acknowledged by updating the golden JSON next to this file.

use frankenengine_extension_host::{
    HostcallSinkPolicy, HostcallType, IntegrityLevel, SecrecyLevel, SinkClearance,
};
use serde::{Deserialize, Serialize};

const GOLDEN: &str = include_str!("golden_vectors/hostcall_sink_policy_clearance_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HostcallSinkPolicyClearanceMatrixGolden {
    fixture_schema_version: String,
    policy: HostcallSinkPolicy,
    matrix: Vec<HostcallSinkPolicyMatrixRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HostcallSinkPolicyMatrixRow {
    hostcall_type: HostcallType,
    hostcall_type_display: String,
    is_sink: bool,
    clearance: Option<SinkClearance>,
}

/// Every `HostcallType` variant, in declaration order. The order matters —
/// it's part of the golden invariant. Reordering or omitting a variant is a
/// behavior change that must surface as a golden diff.
fn all_hostcall_types() -> [HostcallType; 11] {
    [
        HostcallType::FsRead,
        HostcallType::FsWrite,
        HostcallType::NetworkSend,
        HostcallType::NetworkRecv,
        HostcallType::ProcessSpawn,
        HostcallType::EnvRead,
        HostcallType::MemAlloc,
        HostcallType::TimerCreate,
        HostcallType::CryptoOp,
        HostcallType::IpcSend,
        HostcallType::IpcRecv,
    ]
}

fn golden_fixture() -> HostcallSinkPolicyClearanceMatrixGolden {
    let policy = HostcallSinkPolicy::default();
    let matrix = all_hostcall_types()
        .into_iter()
        .map(|hostcall_type| HostcallSinkPolicyMatrixRow {
            hostcall_type,
            hostcall_type_display: hostcall_type.to_string(),
            is_sink: hostcall_type.is_sink(),
            clearance: policy.clearance_for(hostcall_type),
        })
        .collect();
    HostcallSinkPolicyClearanceMatrixGolden {
        fixture_schema_version:
            "franken-engine.extension-host.hostcall-sink-policy-clearance-matrix.v1".to_string(),
        policy,
        matrix,
    }
}

#[test]
fn hostcall_sink_policy_clearance_matrix_matches_golden_snapshot() {
    let expected = golden_fixture();
    let actual_json = serde_json::to_string_pretty(&expected).expect("serialize golden") + "\n";

    assert_eq!(
        actual_json, GOLDEN,
        "HostcallSinkPolicy clearance matrix drifted from golden. \
         If this change is intentional, re-emit the JSON next to this file."
    );

    let decoded: HostcallSinkPolicyClearanceMatrixGolden =
        serde_json::from_str(GOLDEN).expect("golden fixture should decode");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.matrix.len(), all_hostcall_types().len());
}

#[test]
fn hostcall_sink_policy_clearance_matrix_invariants() {
    let golden = golden_fixture();

    // Sink rows must carry a clearance; non-sink rows must not.
    for row in &golden.matrix {
        assert_eq!(
            row.clearance.is_some(),
            row.is_sink,
            "row `{}`: is_sink={} but clearance.is_some()={}",
            row.hostcall_type_display,
            row.is_sink,
            row.clearance.is_some(),
        );
    }

    // Exactly the three documented sinks should be present.
    let sinks: Vec<&str> = golden
        .matrix
        .iter()
        .filter(|row| row.is_sink)
        .map(|row| row.hostcall_type_display.as_str())
        .collect();
    assert_eq!(
        sinks,
        vec!["fs_write", "network_send", "ipc_send"],
        "the set of sink hostcalls changed; this is a structural policy \
         change that must be reflected in HostcallSinkPolicy itself, not just \
         in is_sink()"
    );

    // Each sink's matrix row must equal the policy field on the struct.
    let policy = golden.policy;
    let expected = [
        (HostcallType::FsWrite, policy.fs_write),
        (HostcallType::NetworkSend, policy.network_send),
        (HostcallType::IpcSend, policy.ipc_send),
    ];
    for (hostcall_type, clearance) in expected {
        let row = golden
            .matrix
            .iter()
            .find(|row| row.hostcall_type == hostcall_type)
            .expect("sink row must be present");
        assert_eq!(
            row.clearance,
            Some(clearance),
            "row `{}` clearance disagrees with HostcallSinkPolicy field",
            row.hostcall_type_display,
        );
    }

    // The three defaults are not all the same — i.e. the policy actually
    // discriminates between sinks. Catches accidental defaulting all three
    // to the same SinkClearance.
    let mut distinct = std::collections::BTreeSet::new();
    distinct.insert((
        policy.fs_write.max_secrecy.rank(),
        policy.fs_write.min_integrity.rank(),
    ));
    distinct.insert((
        policy.network_send.max_secrecy.rank(),
        policy.network_send.min_integrity.rank(),
    ));
    distinct.insert((
        policy.ipc_send.max_secrecy.rank(),
        policy.ipc_send.min_integrity.rank(),
    ));
    assert_eq!(
        distinct.len(),
        3,
        "default HostcallSinkPolicy collapsed two sinks to the same clearance pair"
    );
}

#[test]
fn hostcall_sink_policy_default_pinned() {
    // Spell out the default explicitly — independent of clearance_for — so a
    // change to the default that happens to also be matched by an
    // updated golden JSON still trips this test.
    let policy = HostcallSinkPolicy::default();
    assert_eq!(
        policy.fs_write,
        SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated),
    );
    assert_eq!(
        policy.network_send,
        SinkClearance::new(SecrecyLevel::Public, IntegrityLevel::Validated),
    );
    assert_eq!(
        policy.ipc_send,
        SinkClearance::new(SecrecyLevel::Secret, IntegrityLevel::Untrusted),
    );
}
