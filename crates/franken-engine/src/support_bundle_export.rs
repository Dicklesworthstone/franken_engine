//! Deterministic, redacted support-bundle export for bug reports and migration triage.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema marker for deterministic support-bundle key/value exports.
pub const SUPPORT_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.support-bundle.v1";

const REDACTION_MARKER: &str = "sha256:REDACTED";

/// Deterministic support bundle encoded as sorted string entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SupportBundle(pub BTreeMap<String, String>);

impl SupportBundle {
    /// Borrow the deterministic entry map.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Return one exported entry by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Serialize to stable JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SupportBundleExportError> {
        serde_json::to_vec(self).map_err(|err| SupportBundleExportError::Serialization {
            reason: err.to_string(),
        })
    }

    /// Serialize to stable compact JSON text.
    pub fn to_json_string(&self) -> Result<String, SupportBundleExportError> {
        serde_json::to_string(self).map_err(|err| SupportBundleExportError::Serialization {
            reason: err.to_string(),
        })
    }

    /// Compute a deterministic content hash over the serialized bundle.
    pub fn content_hash(&self) -> Result<String, SupportBundleExportError> {
        self.to_json_bytes().map(|bytes| prefixed_sha256(&bytes))
    }
}

/// Inputs exported into a privacy-aware support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleInput {
    /// Engine crate version or release identifier.
    pub engine_version: String,
    /// Runtime or product version observed by the caller.
    pub runtime_version: String,
    /// Configuration values. Raw values are never exported; only hashes are emitted.
    pub config: BTreeMap<String, String>,
    /// Determinism witnesses such as seed hashes, replay IDs, or canonicalization proofs.
    pub determinism_witnesses: BTreeMap<String, String>,
    /// Decision artifacts related to the bug report or migration blocker.
    pub decision_artifact_ids: Vec<String>,
    /// Diagnostics values. Sensitive keys or values are redacted.
    pub diagnostics: BTreeMap<String, String>,
}

/// Export failure modes. Missing required evidence fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportBundleExportError {
    /// Engine version was blank.
    MissingEngineVersion,
    /// Runtime version was blank.
    MissingRuntimeVersion,
    /// At least one determinism witness is required.
    MissingDeterminismWitness,
    /// A determinism witness had a blank name or value.
    EmptyDeterminismWitness,
    /// At least one decision artifact ID is required.
    MissingDecisionArtifactId,
    /// A decision artifact ID was blank.
    EmptyDecisionArtifactId,
    /// JSON serialization failed.
    Serialization { reason: String },
}

impl fmt::Display for SupportBundleExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEngineVersion => f.write_str("support bundle requires engine_version"),
            Self::MissingRuntimeVersion => f.write_str("support bundle requires runtime_version"),
            Self::MissingDeterminismWitness => {
                f.write_str("support bundle requires at least one determinism witness")
            }
            Self::EmptyDeterminismWitness => {
                f.write_str("support bundle determinism witnesses must be non-empty")
            }
            Self::MissingDecisionArtifactId => {
                f.write_str("support bundle requires at least one decision artifact ID")
            }
            Self::EmptyDecisionArtifactId => {
                f.write_str("support bundle decision artifact IDs must be non-empty")
            }
            Self::Serialization { reason } => {
                write!(f, "support bundle serialization failed: {reason}")
            }
        }
    }
}

impl Error for SupportBundleExportError {}

/// Export a deterministic redacted support bundle.
pub fn export_support_bundle(
    input: &SupportBundleInput,
) -> Result<SupportBundle, SupportBundleExportError> {
    validate_input(input)?;

    let mut entries = BTreeMap::new();
    entries.insert(
        "schema_version".to_string(),
        SUPPORT_BUNDLE_SCHEMA_VERSION.to_string(),
    );
    entries.insert(
        "version.engine".to_string(),
        sanitize_non_sensitive_value(&input.engine_version),
    );
    entries.insert(
        "version.runtime".to_string(),
        sanitize_non_sensitive_value(&input.runtime_version),
    );

    for (key, value) in &input.config {
        insert_unique(
            &mut entries,
            export_key("config_hash", key),
            prefixed_sha256(value.as_bytes()),
        );
    }

    for (key, value) in &input.determinism_witnesses {
        insert_unique(
            &mut entries,
            export_key("determinism_witness", key),
            sanitize_non_sensitive_value(value),
        );
    }

    let decision_artifact_ids = input
        .decision_artifact_ids
        .iter()
        .map(|id| sanitize_non_sensitive_value(id))
        .collect::<BTreeSet<_>>();
    for (index, artifact_id) in decision_artifact_ids.into_iter().enumerate() {
        entries.insert(format!("decision_artifact_id.{index:03}"), artifact_id);
    }

    for (key, value) in &input.diagnostics {
        insert_unique(
            &mut entries,
            export_key("diagnostic", key),
            redact_diagnostic_value(key, value),
        );
    }

    let evidence_hash = evidence_hash_for_entries(&entries);
    entries.insert("bundle.content_hash".to_string(), evidence_hash);
    entries.insert("bundle.entry_count".to_string(), entries.len().to_string());

    Ok(SupportBundle(entries))
}

/// Return true if the label or value should never appear verbatim in a bundle.
#[must_use]
pub fn is_sensitive(input: &str) -> bool {
    let lowered = input.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "auth",
        "bearer",
        "credential",
        "private_key",
        "secret",
        "session",
        "token",
        "password",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

/// Redact a diagnostic value when either the key or value looks sensitive.
#[must_use]
pub fn redact_diagnostic_value(key: &str, value: &str) -> String {
    if is_sensitive(key) || is_sensitive(value) {
        format!("{REDACTION_MARKER}:{}", sha256_hex(value.as_bytes()))
    } else {
        sanitize_non_sensitive_value(value)
    }
}

/// Stable SHA-256 helper used by tests and support-bundle callers.
#[must_use]
pub fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn validate_input(input: &SupportBundleInput) -> Result<(), SupportBundleExportError> {
    if input.engine_version.trim().is_empty() {
        return Err(SupportBundleExportError::MissingEngineVersion);
    }
    if input.runtime_version.trim().is_empty() {
        return Err(SupportBundleExportError::MissingRuntimeVersion);
    }
    if input.determinism_witnesses.is_empty() {
        return Err(SupportBundleExportError::MissingDeterminismWitness);
    }
    if input
        .determinism_witnesses
        .iter()
        .any(|(key, value)| key.trim().is_empty() || value.trim().is_empty())
    {
        return Err(SupportBundleExportError::EmptyDeterminismWitness);
    }
    if input.decision_artifact_ids.is_empty() {
        return Err(SupportBundleExportError::MissingDecisionArtifactId);
    }
    if input
        .decision_artifact_ids
        .iter()
        .any(|artifact_id| artifact_id.trim().is_empty())
    {
        return Err(SupportBundleExportError::EmptyDecisionArtifactId);
    }
    Ok(())
}

fn export_key(prefix: &str, raw_key: &str) -> String {
    if is_sensitive(raw_key) {
        format!("{prefix}.redacted_key.{}", short_hash(raw_key))
    } else {
        format!("{prefix}.{}", stable_label(raw_key))
    }
}

fn stable_label(raw: &str) -> String {
    let mut label = String::with_capacity(raw.len());
    let mut previous_was_separator = false;
    for ch in raw.trim().chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        if normalized == '_' {
            if !previous_was_separator && !label.is_empty() {
                label.push(normalized);
            }
            previous_was_separator = true;
        } else {
            label.push(normalized);
            previous_was_separator = false;
        }
    }
    while label.ends_with('_') {
        label.pop();
    }
    if label.is_empty() {
        "unnamed".to_string()
    } else {
        label
    }
}

fn sanitize_non_sensitive_value(value: &str) -> String {
    let trimmed = value.trim();
    if is_sensitive(trimmed) {
        format!("{REDACTION_MARKER}:{}", sha256_hex(trimmed.as_bytes()))
    } else {
        trimmed.to_string()
    }
}

fn insert_unique(entries: &mut BTreeMap<String, String>, key: String, value: String) {
    let base = key;
    let mut candidate = base.clone();
    let mut suffix = 0usize;
    loop {
        if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(candidate) {
            slot.insert(value);
            return;
        }
        suffix += 1;
        candidate = format!("{base}#{suffix:03}");
    }
}

fn evidence_hash_for_entries(entries: &BTreeMap<String, String>) -> String {
    let mut material = String::new();
    for (key, value) in entries {
        material.push_str(key);
        material.push('=');
        material.push_str(value);
        material.push('\n');
    }
    prefixed_sha256(material.as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn short_hash(input: &str) -> String {
    sha256_hex(input.as_bytes()).chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> SupportBundleInput {
        SupportBundleInput {
            engine_version: "0.1.0".to_string(),
            runtime_version: "runtime-2026.04".to_string(),
            config: BTreeMap::from([
                ("scheduler.max_depth".to_string(), "64".to_string()),
                ("policy.mode".to_string(), "safe".to_string()),
            ]),
            determinism_witnesses: BTreeMap::from([
                ("canonical_seed".to_string(), "seed-hash-1".to_string()),
                ("replay_trace".to_string(), "trace-7".to_string()),
            ]),
            decision_artifact_ids: vec!["decision-b".to_string(), "decision-a".to_string()],
            diagnostics: BTreeMap::from([
                ("panic_count".to_string(), "0".to_string()),
                ("operator_note".to_string(), "migration blocked".to_string()),
            ]),
        }
    }

    fn exported() -> SupportBundle {
        export_support_bundle(&sample_input()).expect("sample support bundle should export")
    }

    #[test]
    fn support_bundle_serializes_as_map() {
        let json = exported().to_json_string().expect("json");
        assert!(json.starts_with('{'));
        assert!(json.contains("\"schema_version\""));
    }

    #[test]
    fn export_includes_schema_version() {
        assert_eq!(
            exported().get("schema_version"),
            Some(SUPPORT_BUNDLE_SCHEMA_VERSION)
        );
    }

    #[test]
    fn export_includes_engine_version() {
        assert_eq!(exported().get("version.engine"), Some("0.1.0"));
    }

    #[test]
    fn export_includes_runtime_version() {
        assert_eq!(exported().get("version.runtime"), Some("runtime-2026.04"));
    }

    #[test]
    fn export_hashes_config_values() {
        let bundle = exported();
        let value = bundle
            .get("config_hash.scheduler_max_depth")
            .expect("config hash");
        assert!(value.starts_with("sha256:"));
        assert_ne!(value, "64");
    }

    #[test]
    fn export_does_not_include_raw_config_values() {
        let json = exported().to_json_string().expect("json");
        assert!(!json.contains("\":\"64\""));
        assert!(!json.contains("\":\"safe\""));
    }

    #[test]
    fn export_includes_determinism_witnesses() {
        let bundle = exported();
        assert_eq!(
            bundle.get("determinism_witness.canonical_seed"),
            Some("seed-hash-1")
        );
        assert_eq!(
            bundle.get("determinism_witness.replay_trace"),
            Some("trace-7")
        );
    }

    #[test]
    fn decision_artifact_ids_are_sorted() {
        let bundle = exported();
        assert_eq!(bundle.get("decision_artifact_id.000"), Some("decision-a"));
        assert_eq!(bundle.get("decision_artifact_id.001"), Some("decision-b"));
    }

    #[test]
    fn duplicate_decision_artifact_ids_are_deduplicated() {
        let mut input = sample_input();
        input.decision_artifact_ids.push("decision-a".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        assert_eq!(bundle.get("decision_artifact_id.000"), Some("decision-a"));
        assert_eq!(bundle.get("decision_artifact_id.001"), Some("decision-b"));
        assert_eq!(bundle.get("decision_artifact_id.002"), None);
    }

    #[test]
    fn diagnostics_are_exported() {
        let bundle = exported();
        assert_eq!(bundle.get("diagnostic.panic_count"), Some("0"));
        assert_eq!(
            bundle.get("diagnostic.operator_note"),
            Some("migration blocked")
        );
    }

    #[test]
    fn sensitive_diagnostic_key_is_redacted() {
        let mut input = sample_input();
        input
            .diagnostics
            .insert("api_token".to_string(), "abc123".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        let json = bundle.to_json_string().expect("json");
        assert!(!json.contains("api_token"));
        assert!(!json.contains("abc123"));
        assert!(json.contains(REDACTION_MARKER));
    }

    #[test]
    fn sensitive_diagnostic_value_is_redacted() {
        let mut input = sample_input();
        input
            .diagnostics
            .insert("note".to_string(), "bearer super-secret-token".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        let json = bundle.to_json_string().expect("json");
        assert!(!json.contains("super-secret-token"));
        assert!(json.contains(REDACTION_MARKER));
    }

    #[test]
    fn sensitive_config_key_is_redacted() {
        let mut input = sample_input();
        input
            .config
            .insert("database.password".to_string(), "pw-value".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        let json = bundle.to_json_string().expect("json");
        assert!(!json.contains("database.password"));
        assert!(!json.contains("pw-value"));
        assert!(json.contains("config_hash.redacted_key."));
    }

    #[test]
    fn support_bundle_export_is_deterministic() {
        let input = sample_input();
        let left = export_support_bundle(&input).expect("left");
        let right = export_support_bundle(&input).expect("right");
        assert_eq!(left, right);
        assert_eq!(
            left.to_json_bytes().expect("left bytes"),
            right.to_json_bytes().expect("right bytes")
        );
    }

    #[test]
    fn content_hash_is_deterministic() {
        let left = exported().content_hash().expect("left");
        let right = exported().content_hash().expect("right");
        assert_eq!(left, right);
        assert!(left.starts_with("sha256:"));
    }

    #[test]
    fn bundle_content_hash_entry_changes_when_input_changes() {
        let mut changed = sample_input();
        changed
            .diagnostics
            .insert("panic_count".to_string(), "1".to_string());
        let left = exported();
        let right = export_support_bundle(&changed).expect("changed");
        assert_ne!(
            left.get("bundle.content_hash"),
            right.get("bundle.content_hash")
        );
    }

    #[test]
    fn missing_engine_version_fails_closed() {
        let mut input = sample_input();
        input.engine_version.clear();
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::MissingEngineVersion)
        );
    }

    #[test]
    fn missing_runtime_version_fails_closed() {
        let mut input = sample_input();
        input.runtime_version.clear();
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::MissingRuntimeVersion)
        );
    }

    #[test]
    fn missing_witness_fails_closed() {
        let mut input = sample_input();
        input.determinism_witnesses.clear();
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::MissingDeterminismWitness)
        );
    }

    #[test]
    fn empty_witness_fails_closed() {
        let mut input = sample_input();
        input
            .determinism_witnesses
            .insert("blank".to_string(), " ".to_string());
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::EmptyDeterminismWitness)
        );
    }

    #[test]
    fn missing_decision_artifact_id_fails_closed() {
        let mut input = sample_input();
        input.decision_artifact_ids.clear();
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::MissingDecisionArtifactId)
        );
    }

    #[test]
    fn empty_decision_artifact_id_fails_closed() {
        let mut input = sample_input();
        input.decision_artifact_ids.push(" ".to_string());
        assert_eq!(
            export_support_bundle(&input),
            Err(SupportBundleExportError::EmptyDecisionArtifactId)
        );
    }

    #[test]
    fn labels_are_normalized() {
        let mut input = sample_input();
        input
            .diagnostics
            .insert("  Weird Label!  ".to_string(), "ok".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        assert_eq!(bundle.get("diagnostic.weird_label"), Some("ok"));
    }

    #[test]
    fn colliding_normalized_labels_keep_both_values() {
        let mut input = sample_input();
        input
            .diagnostics
            .insert("a-b".to_string(), "one".to_string());
        input
            .diagnostics
            .insert("a b".to_string(), "two".to_string());
        let bundle = export_support_bundle(&input).expect("bundle");
        assert_eq!(bundle.get("diagnostic.a_b"), Some("two"));
        assert_eq!(bundle.get("diagnostic.a_b#001"), Some("one"));
    }

    #[test]
    fn prefixed_sha256_is_stable() {
        assert_eq!(prefixed_sha256(b"abc"), prefixed_sha256(b"abc"));
        assert_ne!(prefixed_sha256(b"abc"), prefixed_sha256(b"abcd"));
    }

    #[test]
    fn is_sensitive_matches_expected_terms() {
        assert!(is_sensitive("api_token"));
        assert!(is_sensitive("PRIVATE_KEY"));
        assert!(is_sensitive("password"));
        assert!(!is_sensitive("panic_count"));
    }

    #[test]
    fn serde_round_trip_preserves_entries() {
        let bundle = exported();
        let json = bundle.to_json_string().expect("json");
        let restored: SupportBundle = serde_json::from_str(&json).expect("round trip");
        assert_eq!(bundle, restored);
    }

    #[test]
    fn entry_count_reflects_inserted_metadata_boundary() {
        let bundle = exported();
        let count = bundle
            .get("bundle.entry_count")
            .expect("entry count")
            .parse::<usize>()
            .expect("usize");
        assert_eq!(count + 1, bundle.entries().len());
    }
}
