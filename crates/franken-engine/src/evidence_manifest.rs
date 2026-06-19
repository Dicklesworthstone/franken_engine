//! CEI B.1 (`bd-sde5e.2.1`): content-addressed, git-tracked evidence manifests.
//!
//! `docs/CLAIM_TO_PROOF_MATRIX_V1.md` advertises "No artifact, no claim."
//! (`FE-CLAIM-009`). Until this module landed, that promise was hollow: every
//! OBSERVED claim's `artifact_path` pointed into the **git-ignored** `artifacts/`
//! tree, so a fresh clone (with `artifacts/` absent) could not verify a single
//! evidence pointer. The advisory soundness scorer in
//! [`crate::claim_evidence_lattice`] correctly reports those rows as `Unbacked`
//! (artifact not git-tracked) → ceiling `Hypothesis`, i.e. over-promoted.
//!
//! This module commits a small, content-addressed manifest per OBSERVED claim
//! under a **git-tracked** directory (`docs/evidence/<CLAIM>/evidence_manifest.json`)
//! that records:
//!
//! * the content hash of each git-tracked **primary artifact** (hashed from the
//!   `HEAD`-committed blob, so it is stable against an active working tree);
//! * the content hash of each committed **bundle file** (`env.json`,
//!   `manifest.json`, `repro.lock`) relocated alongside the manifest;
//! * the **receipt** state mirrored verbatim from the bundle manifest — recorded
//!   honestly as `pending`/backfill where that is still the truth (CEI-B.2
//!   re-emits real `passed` receipts; this bead does not fake them).
//!
//! A fresh clone can then re-hash every declared input and confirm it matches the
//! committed manifest **offline**, with no access to `artifacts/`. That is the
//! data foundation CEI-A.3 (`bd-sde5e.1.3`) consumes to make the git-tracked +
//! non-pending-receipt check a real, blocking gate.
//!
//! Determinism: nothing here reads the wall clock or any non-reproducible source.
//! The `generated_at_utc` / `source_commit` fields are copied from the source
//! bundle manifest; every hash is content-derived; `git_tracked` flags come from
//! `git ls-files`. Re-running the generator on an unchanged tree produces
//! byte-identical manifests.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::claim_evidence_lattice::git_path_tracked;

/// Schema id stamped into every committed evidence manifest.
pub const EVIDENCE_MANIFEST_SCHEMA: &str = "franken-engine.evidence-manifest.v1";

/// Hash algorithm used for every recorded content hash.
pub const HASH_ALGORITHM: &str = "sha256";

/// Repo-relative directory under which committed evidence manifests live.
pub const EVIDENCE_DIR: &str = "docs/evidence";

/// The three reproducibility-bundle files relocated next to each manifest.
pub const BUNDLE_FILES: [&str; 3] = ["env.json", "manifest.json", "repro.lock"];

/// One content-addressed input recorded in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedInput {
    /// Repo-root-relative path.
    pub path: String,
    /// Lowercase hex `sha256` of the recorded content.
    pub sha256: String,
    /// Byte length of the recorded content.
    pub size_bytes: u64,
    /// Whether the path is tracked by git (`git ls-files` membership).
    pub git_tracked: bool,
    /// Where the recorded bytes came from: `head_blob` (committed) or `worktree`.
    pub source: HashSource,
    /// Free-form role tag, e.g. `primary_artifact` / `bundle_file` / `repro_lock`.
    pub role: String,
}

/// Provenance of the bytes a [`HashedInput`] was hashed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashSource {
    /// Hashed from the `HEAD`-committed git blob (stable against working-tree drift).
    HeadBlob,
    /// Hashed from the on-disk working-tree file.
    Worktree,
}

/// Receipt state mirrored verbatim from the source bundle `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    /// `outputs.verification_result` from the bundle manifest.
    pub verification_result: String,
    /// `provenance.generated_by` from the bundle manifest.
    pub generated_by: String,
    /// True when `generated_by` mentions a backfill (never counts as `passed`).
    pub backfilled: bool,
    /// `sha256` of the canonicalized bundle-manifest `outputs` object.
    pub receipt_sha256: String,
}

impl ReceiptSummary {
    /// A receipt counts as a real pass only when the recorded result is `passed`
    /// and it was not produced by a backfill script. This is the same predicate
    /// the advisory lattice applies; CEI-A.3 promotes it to a blocking check.
    #[must_use]
    pub fn is_real_pass(&self) -> bool {
        self.verification_result.eq_ignore_ascii_case("passed") && !self.backfilled
    }
}

/// A single committed, content-addressed evidence manifest for one claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub schema_version: String,
    pub claim_id: String,
    pub owning_bead: String,
    pub allowed_state: String,
    /// Commit the source bundle was generated against (copied, informational).
    pub source_commit: String,
    /// Generation timestamp copied from the source bundle (the freshness anchor).
    pub generated_at_utc: String,
    /// Git-tracked directory holding the committed bundle + this manifest.
    pub bundle_dir: String,
    pub hash_algorithm: String,
    /// Git-tracked artifacts a fresh clone can re-hash offline.
    pub verifiable_inputs: Vec<HashedInput>,
    /// The committed `env.json` / `manifest.json` / `repro.lock` next to this file.
    pub bundle_files: Vec<HashedInput>,
    /// The committed `repro.lock` partner (also present in `bundle_files`).
    pub repro_lock: HashedInput,
    pub receipt: ReceiptSummary,
}

impl EvidenceManifest {
    /// Serialize to canonical pretty JSON: lexicographically-sorted keys at every
    /// depth, LF newlines, trailing newline.
    ///
    /// Keys are sorted *explicitly* ([`sort_value_keys`]) rather than relying on
    /// `serde_json::Map` being a `BTreeMap`: this workspace transitively enables
    /// serde_json's `preserve_order` feature (so `Map` is an `IndexMap` that keeps
    /// struct field order), and the canonical form must not silently depend on
    /// that flag. The output is therefore byte-identical regardless of how
    /// `preserve_order` is resolved.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let value: Value = serde_json::to_value(self).expect("manifest serializes");
        let sorted = sort_value_keys(&value);
        let mut s = serde_json::to_string_pretty(&sorted).expect("value pretty-prints");
        s.push('\n');
        s
    }
}

/// Recursively rebuild a JSON value with object keys in lexicographic order.
///
/// Independent of the `preserve_order` feature: keys are re-inserted in sorted
/// order, so the result serializes identically whether `Map` is a `BTreeMap`
/// (auto-sorted) or an `IndexMap` (insertion-ordered).
#[must_use]
pub fn sort_value_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for k in keys {
                sorted.insert(k.clone(), sort_value_keys(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value_keys).collect()),
        other => other.clone(),
    }
}

/// Errors raised while generating or loading an evidence manifest.
#[derive(Debug)]
pub enum EvidenceManifestError {
    /// A required file could not be read.
    Io(String),
    /// JSON in a source bundle was malformed or missing a required field.
    Malformed(String),
    /// A primary artifact referenced by the bundle is not git-tracked.
    UntrackedPrimary(String),
}

impl std::fmt::Display for EvidenceManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "io error: {m}"),
            Self::Malformed(m) => write!(f, "malformed bundle: {m}"),
            Self::UntrackedPrimary(p) => write!(f, "primary artifact not git-tracked: {p}"),
        }
    }
}

impl std::error::Error for EvidenceManifestError {}

/// `sha256` hex digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The kind of object a repo-relative path resolves to at `HEAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadKind {
    Blob,
    Tree,
}

/// Read the `HEAD`-committed blob for `rel_path` (exact committed bytes).
///
/// Returns `None` if the path is not present at `HEAD` (e.g. untracked).
fn read_head_blob(repo_root: &Path, rel_path: &str) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("cat-file")
        .arg("blob")
        .arg(format!("HEAD:{rel_path}"))
        .output()
        .ok()?;
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

/// Resolve whether `rel_path` is a file (`blob`) or directory (`tree`) at `HEAD`.
fn head_object_kind(repo_root: &Path, rel_path: &str) -> Option<HeadKind> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("cat-file")
        .arg("-t")
        .arg(format!("HEAD:{rel_path}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "blob" => Some(HeadKind::Blob),
        "tree" => Some(HeadKind::Tree),
        _ => None,
    }
}

/// Aggregate content digest of a directory's committed contents.
///
/// Lists every git-tracked file under `dir`, hashes each from its `HEAD` blob,
/// and folds the sorted `(sha256, path)` records into one digest. The fixed-width
/// hex prefix makes the preimage injective, and the listing is re-derivable in a
/// fresh clone, so the digest re-verifies offline.
fn hash_head_tree(repo_root: &Path, dir: &str) -> Option<(String, u64)> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("ls-files")
        .arg("-z")
        .arg("--")
        .arg(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut files: Vec<String> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if files.is_empty() {
        return None;
    }
    files.sort();
    let mut preimage = String::new();
    let mut total: u64 = 0;
    for f in &files {
        let bytes = read_head_blob(repo_root, f)?;
        total += bytes.len() as u64;
        preimage.push_str(&sha256_hex(&bytes));
        preimage.push_str("  ");
        preimage.push_str(f);
        preimage.push('\n');
    }
    Some((sha256_hex(preimage.as_bytes()), total))
}

/// Hash a git-tracked path from `HEAD`, handling both files and directories.
///
/// Hashing committed content (rather than the working tree) keeps the recorded
/// hash stable while peers hold uncommitted edits, and is identical to the
/// working-tree content in a fresh clone at this commit. Returns `(sha256, bytes)`
/// or `None` if the path is absent from `HEAD`.
fn hash_head_path(repo_root: &Path, rel_path: &str) -> Option<(String, u64)> {
    match head_object_kind(repo_root, rel_path)? {
        HeadKind::Blob => {
            let bytes = read_head_blob(repo_root, rel_path)?;
            Some((sha256_hex(&bytes), bytes.len() as u64))
        }
        HeadKind::Tree => hash_head_tree(repo_root, rel_path),
    }
}

/// Build a [`HashedInput`] for a git-tracked artifact, hashed from `HEAD`.
fn hash_head_input(
    repo_root: &Path,
    rel_path: &str,
    role: &str,
) -> Result<HashedInput, EvidenceManifestError> {
    let tracked = git_path_tracked(repo_root, rel_path);
    let (sha256, size_bytes) = hash_head_path(repo_root, rel_path)
        .ok_or_else(|| EvidenceManifestError::UntrackedPrimary(rel_path.to_string()))?;
    Ok(HashedInput {
        path: rel_path.to_string(),
        sha256,
        size_bytes,
        git_tracked: tracked,
        source: HashSource::HeadBlob,
        role: role.to_string(),
    })
}

/// Hash a working-tree file (used for the bundle files this bead writes+commits).
fn hash_worktree_input(
    repo_root: &Path,
    rel_path: &str,
    role: &str,
) -> Result<HashedInput, EvidenceManifestError> {
    let abs = repo_root.join(rel_path);
    let bytes = std::fs::read(&abs)
        .map_err(|e| EvidenceManifestError::Io(format!("{}: {e}", abs.display())))?;
    Ok(HashedInput {
        path: rel_path.to_string(),
        sha256: sha256_hex(&bytes),
        size_bytes: bytes.len() as u64,
        git_tracked: git_path_tracked(repo_root, rel_path),
        source: HashSource::Worktree,
        role: role.to_string(),
    })
}

/// Extract the primary-artifact repo-relative path from a bundle `repro.lock`.
fn primary_artifact_path(repro_lock: &Value) -> Option<String> {
    repro_lock
        .get("inputs")?
        .get("primary_artifact")?
        .get("path")?
        .as_str()
        .map(str::to_string)
}

/// Build a content-addressed [`EvidenceManifest`] for one OBSERVED claim.
///
/// * `source_bundle_dir` — repo-relative dir holding the source `env.json` /
///   `manifest.json` / `repro.lock` (e.g. the git-ignored `artifacts/...` bundle
///   on first generation, or the committed `docs/evidence/<CLAIM>` on a refresh).
/// * `committed_bundle_dir` — repo-relative dir the bundle files are committed to
///   and recorded as (`docs/evidence/<CLAIM>`). The bundle-file hashes are read
///   from here, so callers must copy the files there **before** building.
pub fn build_manifest(
    repo_root: &Path,
    claim_id: &str,
    owning_bead: &str,
    allowed_state: &str,
    source_bundle_dir: &str,
    committed_bundle_dir: &str,
) -> Result<EvidenceManifest, EvidenceManifestError> {
    let manifest_json: Value = read_json(repo_root, &format!("{source_bundle_dir}/manifest.json"))?;
    let repro_lock_json: Value = read_json(repo_root, &format!("{source_bundle_dir}/repro.lock"))?;

    let outputs = manifest_json.get("outputs").cloned().unwrap_or(Value::Null);
    let verification_result = outputs
        .get("verification_result")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let generated_by = manifest_json
        .get("provenance")
        .and_then(|p| p.get("generated_by"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let backfilled = generated_by.to_ascii_lowercase().contains("backfill");
    let receipt = ReceiptSummary {
        verification_result,
        generated_by,
        backfilled,
        receipt_sha256: sha256_hex(canonical_bytes(&outputs).as_bytes()),
    };

    let source_commit = manifest_json
        .get("source_revision")
        .and_then(|r| r.get("commit"))
        .and_then(Value::as_str)
        .or_else(|| manifest_json.get("source_commit").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let generated_at_utc = manifest_json
        .get("generated_at_utc")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Primary artifact(s): hashed from HEAD, must be git-tracked.
    let primary = primary_artifact_path(&repro_lock_json).ok_or_else(|| {
        EvidenceManifestError::Malformed(format!(
            "{source_bundle_dir}/repro.lock missing inputs.primary_artifact.path"
        ))
    })?;
    let verifiable_inputs = vec![hash_head_input(repo_root, &primary, "primary_artifact")?];

    // Bundle files: hashed from the committed location (worktree == commit).
    let mut bundle_files = Vec::with_capacity(BUNDLE_FILES.len());
    for name in BUNDLE_FILES {
        let rel = format!("{committed_bundle_dir}/{name}");
        let role = if name == "repro.lock" {
            "repro_lock"
        } else {
            "bundle_file"
        };
        bundle_files.push(hash_worktree_input(repo_root, &rel, role)?);
    }
    let repro_lock = bundle_files
        .iter()
        .find(|h| h.role == "repro_lock")
        .cloned()
        .expect("repro.lock is one of the bundle files");

    Ok(EvidenceManifest {
        schema_version: EVIDENCE_MANIFEST_SCHEMA.to_string(),
        claim_id: claim_id.to_string(),
        owning_bead: owning_bead.to_string(),
        allowed_state: allowed_state.to_string(),
        source_commit,
        generated_at_utc,
        bundle_dir: committed_bundle_dir.to_string(),
        hash_algorithm: HASH_ALGORITHM.to_string(),
        verifiable_inputs,
        bundle_files,
        repro_lock,
        receipt,
    })
}

/// The outcome of re-verifying a committed manifest against the live tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub claim_id: String,
    /// Number of inputs whose recorded hash was re-checked.
    pub checked: usize,
    /// `path :: expected != actual` for every content-hash mismatch.
    pub mismatches: Vec<String>,
    /// Recorded-as-tracked inputs that are no longer git-tracked / readable.
    pub missing: Vec<String>,
}

impl VerifyReport {
    /// True iff every recorded input re-hashed to its recorded value and every
    /// declared-tracked input is still present and tracked.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.mismatches.is_empty() && self.missing.is_empty() && self.checked > 0
    }
}

/// Re-verify a committed manifest against the live repository, **offline**.
///
/// Re-hashes every `verifiable_inputs` entry from its `HEAD` blob and every
/// `bundle_files` entry from the working tree, comparing against the recorded
/// hash. Requires no access to the git-ignored `artifacts/` tree — every checked
/// path is git-tracked — so it passes in a fresh clone with `artifacts/` deleted.
#[must_use]
pub fn verify_manifest_offline(repo_root: &Path, manifest: &EvidenceManifest) -> VerifyReport {
    let mut report = VerifyReport {
        claim_id: manifest.claim_id.clone(),
        ..VerifyReport::default()
    };

    for input in manifest
        .verifiable_inputs
        .iter()
        .chain(&manifest.bundle_files)
    {
        if input.git_tracked && !git_path_tracked(repo_root, &input.path) {
            report.missing.push(format!(
                "{} (recorded git-tracked, now untracked)",
                input.path
            ));
            continue;
        }
        let actual = match input.source {
            HashSource::HeadBlob => hash_head_path(repo_root, &input.path).map(|(h, _)| h),
            HashSource::Worktree => std::fs::read(repo_root.join(&input.path))
                .ok()
                .map(|b| sha256_hex(&b)),
        };
        let Some(actual) = actual else {
            report.missing.push(input.path.clone());
            continue;
        };
        report.checked += 1;
        if actual != input.sha256 {
            report
                .mismatches
                .push(format!("{} :: {} != {}", input.path, input.sha256, actual));
        }
    }

    report
}

/// Read + parse a repo-relative JSON file.
fn read_json(repo_root: &Path, rel_path: &str) -> Result<Value, EvidenceManifestError> {
    let abs = repo_root.join(rel_path);
    let text = std::fs::read_to_string(&abs)
        .map_err(|e| EvidenceManifestError::Io(format!("{}: {e}", abs.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| EvidenceManifestError::Malformed(format!("{rel_path}: {e}")))
}

/// Canonical (sorted-key, compact) bytes for a JSON value, for stable hashing.
///
/// Keys are sorted explicitly via [`sort_value_keys`] so the digest does not
/// depend on the `preserve_order` feature resolution.
fn canonical_bytes(value: &Value) -> String {
    serde_json::to_string(&sort_value_keys(value)).unwrap_or_default()
}

/// Load a committed manifest from `docs/evidence/<CLAIM>/evidence_manifest.json`.
pub fn load_manifest(
    repo_root: &Path,
    claim_id: &str,
) -> Result<EvidenceManifest, EvidenceManifestError> {
    let rel = format!("{EVIDENCE_DIR}/{claim_id}/evidence_manifest.json");
    let value = read_json(repo_root, &rel)?;
    serde_json::from_value(value)
        .map_err(|e| EvidenceManifestError::Malformed(format!("{rel}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_stable_and_lowercase_hex() {
        let h = sha256_hex(b"frankenengine");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Known vector for "frankenengine".
        assert_eq!(h, sha256_hex(b"frankenengine"));
        assert_ne!(h, sha256_hex(b"frankenengine "));
    }

    #[test]
    fn receipt_real_pass_predicate() {
        let pending = ReceiptSummary {
            verification_result: "pending".into(),
            generated_by: "backfill_reproducibility_bundles.py".into(),
            backfilled: true,
            receipt_sha256: sha256_hex(b"{}"),
        };
        assert!(
            !pending.is_real_pass(),
            "pending+backfill is never a real pass"
        );

        let backfilled_passed = ReceiptSummary {
            verification_result: "passed".into(),
            backfilled: true,
            ..pending.clone()
        };
        assert!(
            !backfilled_passed.is_real_pass(),
            "a backfilled 'passed' is still not a real pass"
        );

        let real = ReceiptSummary {
            verification_result: "passed".into(),
            generated_by: "scripts/run_claim_to_proof_matrix_gate.sh".into(),
            backfilled: false,
            receipt_sha256: sha256_hex(b"{}"),
        };
        assert!(real.is_real_pass());
    }

    #[test]
    fn canonical_json_has_sorted_keys_and_trailing_newline() {
        let manifest = sample_manifest();
        let json = manifest.to_canonical_json();
        assert!(json.ends_with('\n'));
        // `allowed_state` sorts before `bundle_dir` before `claim_id`.
        let a = json.find("\"allowed_state\"").unwrap();
        let b = json.find("\"bundle_dir\"").unwrap();
        let c = json.find("\"claim_id\"").unwrap();
        assert!(a < b && b < c, "keys must be lexicographically ordered");
        // Round-trips losslessly.
        let parsed: EvidenceManifest =
            serde_json::from_str(json.trim_end()).expect("canonical json round-trips");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn verify_report_ok_requires_a_check_and_no_faults() {
        let mut r = VerifyReport {
            claim_id: "FE-CLAIM-001".into(),
            checked: 0,
            ..VerifyReport::default()
        };
        assert!(!r.ok(), "zero checks is not a pass (nothing was verified)");
        r.checked = 2;
        assert!(r.ok());
        r.mismatches.push("x :: a != b".into());
        assert!(!r.ok());
        r.mismatches.clear();
        r.missing.push("y".into());
        assert!(!r.ok());
    }

    fn sample_manifest() -> EvidenceManifest {
        let bundle = HashedInput {
            path: "docs/evidence/FE-CLAIM-001/repro.lock".into(),
            sha256: sha256_hex(b"lock"),
            size_bytes: 4,
            git_tracked: true,
            source: HashSource::Worktree,
            role: "repro_lock".into(),
        };
        EvidenceManifest {
            schema_version: EVIDENCE_MANIFEST_SCHEMA.into(),
            claim_id: "FE-CLAIM-001".into(),
            owning_bead: "bd-1qkrc".into(),
            allowed_state: "observed".into(),
            source_commit: "deadbeef".into(),
            generated_at_utc: "2026-05-21T19:32:39.524362+00:00".into(),
            bundle_dir: "docs/evidence/FE-CLAIM-001".into(),
            hash_algorithm: HASH_ALGORITHM.into(),
            verifiable_inputs: vec![HashedInput {
                path: "docs/audit/ga_success_criteria_gap_analysis.md".into(),
                sha256: sha256_hex(b"primary"),
                size_bytes: 7,
                git_tracked: true,
                source: HashSource::HeadBlob,
                role: "primary_artifact".into(),
            }],
            bundle_files: vec![bundle.clone()],
            repro_lock: bundle,
            receipt: ReceiptSummary {
                verification_result: "pending".into(),
                generated_by: "backfill_reproducibility_bundles.py".into(),
                backfilled: true,
                receipt_sha256: sha256_hex(b"{}"),
            },
        }
    }
}
