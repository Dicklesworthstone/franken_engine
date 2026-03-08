#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const VERSION_MATRIX_SCHEMA: &str = "franken-engine.version-matrix-lane.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionSource {
    pub tags: Vec<String>,
    pub branch_names: Vec<String>,
    pub current_override: Option<String>,
    pub previous_override: Option<String>,
    pub next_override: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedVersionCombination {
    pub local_version: String,
    pub remote_version: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryMatrixSpec {
    pub boundary_surface: String,
    pub local_repo: String,
    pub remote_repo: String,
    pub local_versions: VersionSource,
    pub remote_versions: VersionSource,
    #[serde(default)]
    pub pinned_combinations: Vec<PinnedVersionCombination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixLaneKind {
    Current,
    Previous,
    Next,
    Pinned,
}

impl MatrixLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "n_n",
            Self::Previous => "n_n_minus_1",
            Self::Next => "n_n_plus_1",
            Self::Pinned => "pinned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMatrixCell {
    pub cell_id: String,
    pub boundary_surface: String,
    pub local_repo: String,
    pub remote_repo: String,
    pub local_version: String,
    pub remote_version: String,
    pub lane_kind: MatrixLaneKind,
    pub pinned: bool,
    pub expected_conformance_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMatrixPlan {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub cells: Vec<VersionMatrixCell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionSlots {
    pub current: String,
    pub previous: Option<String>,
    pub next: Option<String>,
    pub derivation_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionMatrixError {
    MissingCurrentVersion {
        repo: String,
    },
    InvalidPinnedCombination {
        boundary_surface: String,
        reason: String,
    },
}

impl fmt::Display for VersionMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCurrentVersion { repo } => {
                write!(f, "cannot derive current version for repo `{repo}`")
            }
            Self::InvalidPinnedCombination {
                boundary_surface,
                reason,
            } => write!(
                f,
                "invalid pinned combination for `{boundary_surface}`: {reason}"
            ),
        }
    }
}

impl Error for VersionMatrixError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCellResult {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub cell_id: String,
    pub boundary_surface: String,
    pub lane_kind: MatrixLaneKind,
    pub outcome: MatrixOutcome,
    pub error_code: Option<String>,
    pub failure_fingerprint: Option<String>,
    pub failure_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureScopeKind {
    Universal,
    VersionSpecific,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixFailureScope {
    pub boundary_surface: String,
    pub failure_fingerprint: String,
    pub scope: FailureScopeKind,
    pub failing_cells: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixHealthSummary {
    pub total_cells: usize,
    pub passed_cells: usize,
    pub failed_cells: usize,
    pub universal_failures: usize,
    pub version_specific_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedVersion {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

impl ParsedVersion {
    fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim().trim_start_matches('v');
        let (core, prerelease) = if let Some((core, pre)) = trimmed.split_once('-') {
            (core, Some(pre.to_string()))
        } else {
            (trimmed, None)
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }

    fn is_prerelease(&self) -> bool {
        self.prerelease.is_some()
    }

    fn bump_patch_next(&self) -> String {
        format!("{}.{}.{}-next", self.major, self.minor, self.patch + 1)
    }

    fn format(&self) -> String {
        self.prerelease.as_ref().map_or_else(
            || format!("{}.{}.{}", self.major, self.minor, self.patch),
            |pre| format!("{}.{}.{}-{pre}", self.major, self.minor, self.patch),
        )
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(lhs), Some(rhs)) => lhs.cmp(rhs),
            })
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn derive_version_slots(
    source: &VersionSource,
    repo: &str,
) -> Result<VersionSlots, VersionMatrixError> {
    let parsed = parse_versions_from_tags(&source.tags);
    let mut stable_versions: Vec<ParsedVersion> = parsed
        .iter()
        .filter(|version| !version.is_prerelease())
        .cloned()
        .collect();
    stable_versions.sort();

    let current = if let Some(override_current) = &source.current_override {
        override_current.clone()
    } else if let Some(latest) = stable_versions.last() {
        latest.format()
    } else if let Some(latest_any) = parsed.iter().max() {
        latest_any.format()
    } else {
        return Err(VersionMatrixError::MissingCurrentVersion {
            repo: repo.to_string(),
        });
    };

    let mut notes = Vec::new();
    let previous = if let Some(override_previous) = &source.previous_override {
        Some(override_previous.clone())
    } else {
        let current_parsed = ParsedVersion::parse(&current);
        if let Some(current_parsed) = current_parsed {
            stable_versions
                .iter()
                .filter(|version| {
                    version.major < current_parsed.major
                        || (version.major == current_parsed.major
                            && version.minor < current_parsed.minor)
                        || (version.major == current_parsed.major
                            && version.minor == current_parsed.minor
                            && version.patch < current_parsed.patch)
                })
                .max()
                .map(ParsedVersion::format)
        } else {
            None
        }
    };

    let next = if let Some(override_next) = &source.next_override {
        Some(override_next.clone())
    } else if let Some(prerelease_next) = parsed
        .iter()
        .filter(|version| version.is_prerelease())
        .max()
        .map(ParsedVersion::format)
    {
        notes.push("derived next version from prerelease tag".to_string());
        Some(prerelease_next)
    } else if source.branch_names.iter().any(|branch| {
        let name = branch.to_ascii_lowercase();
        name == "main" || name.contains("next") || name.contains("nightly")
    }) {
        if let Some(current_parsed) = ParsedVersion::parse(&current) {
            notes.push("derived next version from branch convention".to_string());
            Some(current_parsed.bump_patch_next())
        } else {
            None
        }
    } else {
        None
    };

    Ok(VersionSlots {
        current,
        previous,
        next,
        derivation_notes: notes,
    })
}

pub fn derive_version_matrix(
    specs: &[BoundaryMatrixSpec],
) -> Result<VersionMatrixPlan, VersionMatrixError> {
    let mut cells = Vec::new();
    let mut seen = BTreeSet::new();

    for spec in specs {
        let local_slots = derive_version_slots(&spec.local_versions, spec.local_repo.as_str())?;
        let remote_slots = derive_version_slots(&spec.remote_versions, spec.remote_repo.as_str())?;

        let current_cell = build_cell(
            spec,
            MatrixLaneKind::Current,
            local_slots.current.as_str(),
            remote_slots.current.as_str(),
            false,
        );
        if seen.insert(current_cell.cell_id.clone()) {
            cells.push(current_cell);
        }

        if let Some(previous_remote) = remote_slots.previous {
            let previous_cell = build_cell(
                spec,
                MatrixLaneKind::Previous,
                local_slots.current.as_str(),
                previous_remote.as_str(),
                false,
            );
            if seen.insert(previous_cell.cell_id.clone()) {
                cells.push(previous_cell);
            }
        }

        if let Some(next_remote) = remote_slots.next {
            let next_cell = build_cell(
                spec,
                MatrixLaneKind::Next,
                local_slots.current.as_str(),
                next_remote.as_str(),
                false,
            );
            if seen.insert(next_cell.cell_id.clone()) {
                cells.push(next_cell);
            }
        }

        for pinned in &spec.pinned_combinations {
            if pinned.local_version.trim().is_empty() || pinned.remote_version.trim().is_empty() {
                return Err(VersionMatrixError::InvalidPinnedCombination {
                    boundary_surface: spec.boundary_surface.clone(),
                    reason: "local_version and remote_version are required".to_string(),
                });
            }
            let pinned_cell = build_cell(
                spec,
                MatrixLaneKind::Pinned,
                pinned.local_version.as_str(),
                pinned.remote_version.as_str(),
                true,
            );
            if seen.insert(pinned_cell.cell_id.clone()) {
                cells.push(pinned_cell);
            }
        }
    }

    cells.sort_by(|lhs, rhs| {
        lhs.boundary_surface
            .cmp(&rhs.boundary_surface)
            .then(lhs.lane_kind.cmp(&rhs.lane_kind))
            .then(lhs.local_version.cmp(&rhs.local_version))
            .then(lhs.remote_version.cmp(&rhs.remote_version))
    });

    Ok(VersionMatrixPlan {
        schema_version: VERSION_MATRIX_SCHEMA.to_string(),
        generated_at_utc: "1970-01-01T00:00:00Z".to_string(),
        cells,
    })
}

pub fn classify_failure_scopes(
    plan: &VersionMatrixPlan,
    results: &[MatrixCellResult],
) -> Vec<MatrixFailureScope> {
    let mut cells_per_boundary = BTreeMap::new();
    for cell in &plan.cells {
        *cells_per_boundary
            .entry(cell.boundary_surface.clone())
            .or_insert(0usize) += 1;
    }

    let mut grouped = BTreeMap::<(String, String), Vec<String>>::new();
    for result in results {
        if result.outcome == MatrixOutcome::Fail
            && let Some(fingerprint) = &result.failure_fingerprint
        {
            grouped
                .entry((result.boundary_surface.clone(), fingerprint.clone()))
                .or_default()
                .push(result.cell_id.clone());
        }
    }

    let mut scopes = Vec::new();
    for ((boundary, fingerprint), mut failing_cells) in grouped {
        failing_cells.sort();
        let total_cells = cells_per_boundary.get(&boundary).copied().unwrap_or(0);
        let scope = if total_cells > 0 && failing_cells.len() == total_cells {
            FailureScopeKind::Universal
        } else {
            FailureScopeKind::VersionSpecific
        };
        scopes.push(MatrixFailureScope {
            boundary_surface: boundary,
            failure_fingerprint: fingerprint,
            scope,
            failing_cells,
        });
    }

    scopes.sort_by(|lhs, rhs| {
        lhs.boundary_surface
            .cmp(&rhs.boundary_surface)
            .then(lhs.failure_fingerprint.cmp(&rhs.failure_fingerprint))
    });
    scopes
}

pub fn summarize_matrix_health(
    plan: &VersionMatrixPlan,
    results: &[MatrixCellResult],
) -> MatrixHealthSummary {
    let failed_cells = results
        .iter()
        .filter(|result| result.outcome == MatrixOutcome::Fail)
        .count();
    let passed_cells = results
        .iter()
        .filter(|result| result.outcome == MatrixOutcome::Pass)
        .count();
    let scopes = classify_failure_scopes(plan, results);

    MatrixHealthSummary {
        total_cells: plan.cells.len(),
        passed_cells,
        failed_cells,
        universal_failures: scopes
            .iter()
            .filter(|scope| scope.scope == FailureScopeKind::Universal)
            .count(),
        version_specific_failures: scopes
            .iter()
            .filter(|scope| scope.scope == FailureScopeKind::VersionSpecific)
            .count(),
    }
}

fn build_cell(
    spec: &BoundaryMatrixSpec,
    lane_kind: MatrixLaneKind,
    local_version: &str,
    remote_version: &str,
    pinned: bool,
) -> VersionMatrixCell {
    let cell_id = format!(
        "{}::{}::{}::{}",
        spec.boundary_surface,
        lane_kind.as_str(),
        local_version,
        remote_version
    );
    VersionMatrixCell {
        expected_conformance_command: format!(
            "cargo test -p frankenengine-engine --test conformance_assets -- --matrix-cell {cell_id}"
        ),
        cell_id,
        boundary_surface: spec.boundary_surface.clone(),
        local_repo: spec.local_repo.clone(),
        remote_repo: spec.remote_repo.clone(),
        local_version: local_version.to_string(),
        remote_version: remote_version.to_string(),
        lane_kind,
        pinned,
    }
}

fn parse_versions_from_tags(tags: &[String]) -> Vec<ParsedVersion> {
    let mut out = Vec::new();
    for tag in tags {
        for token in tag.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')) {
            if let Some(version) = ParsedVersion::parse(token) {
                out.push(version);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MatrixLaneKind ────────────────────────────────────────────

    #[test]
    fn lane_kind_as_str() {
        assert_eq!(MatrixLaneKind::Current.as_str(), "n_n");
        assert_eq!(MatrixLaneKind::Previous.as_str(), "n_n_minus_1");
        assert_eq!(MatrixLaneKind::Next.as_str(), "n_n_plus_1");
        assert_eq!(MatrixLaneKind::Pinned.as_str(), "pinned");
    }

    #[test]
    fn lane_kind_ordering() {
        assert!(MatrixLaneKind::Current < MatrixLaneKind::Previous);
        assert!(MatrixLaneKind::Previous < MatrixLaneKind::Next);
        assert!(MatrixLaneKind::Next < MatrixLaneKind::Pinned);
    }

    #[test]
    fn lane_kind_serde_round_trip() {
        for kind in [
            MatrixLaneKind::Current,
            MatrixLaneKind::Previous,
            MatrixLaneKind::Next,
            MatrixLaneKind::Pinned,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: MatrixLaneKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── ParsedVersion ─────────────────────────────────────────────

    #[test]
    fn parsed_version_basic() {
        let v = ParsedVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.prerelease.is_none());
    }

    #[test]
    fn parsed_version_with_v_prefix() {
        let v = ParsedVersion::parse("v1.0.5").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 5);
    }

    #[test]
    fn parsed_version_with_prerelease() {
        let v = ParsedVersion::parse("2.0.0-beta.1").unwrap();
        assert_eq!(v.major, 2);
        assert!(v.is_prerelease());
        assert_eq!(v.prerelease.as_deref(), Some("beta.1"));
    }

    #[test]
    fn parsed_version_invalid_too_many_parts() {
        assert!(ParsedVersion::parse("1.2.3.4").is_none());
    }

    #[test]
    fn parsed_version_invalid_non_numeric() {
        assert!(ParsedVersion::parse("abc").is_none());
    }

    #[test]
    fn parsed_version_invalid_two_parts() {
        assert!(ParsedVersion::parse("1.2").is_none());
    }

    #[test]
    fn parsed_version_format_stable() {
        let v = ParsedVersion::parse("1.2.3").unwrap();
        assert_eq!(v.format(), "1.2.3");
    }

    #[test]
    fn parsed_version_format_prerelease() {
        let v = ParsedVersion::parse("1.2.3-alpha").unwrap();
        assert_eq!(v.format(), "1.2.3-alpha");
    }

    #[test]
    fn parsed_version_bump_patch_next() {
        let v = ParsedVersion::parse("1.2.3").unwrap();
        assert_eq!(v.bump_patch_next(), "1.2.4-next");
    }

    #[test]
    fn parsed_version_ordering_by_components() {
        let v1 = ParsedVersion::parse("1.0.0").unwrap();
        let v2 = ParsedVersion::parse("1.0.1").unwrap();
        let v3 = ParsedVersion::parse("1.1.0").unwrap();
        let v4 = ParsedVersion::parse("2.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }

    #[test]
    fn parsed_version_prerelease_sorts_before_stable() {
        let pre = ParsedVersion::parse("1.0.0-alpha").unwrap();
        let stable = ParsedVersion::parse("1.0.0").unwrap();
        assert!(pre < stable);
    }

    // ── MatrixOutcome serde ───────────────────────────────────────

    #[test]
    fn matrix_outcome_serde() {
        for outcome in [MatrixOutcome::Pass, MatrixOutcome::Fail] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: MatrixOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    // ── FailureScopeKind serde ────────────────────────────────────

    #[test]
    fn failure_scope_kind_serde() {
        for scope in [
            FailureScopeKind::Universal,
            FailureScopeKind::VersionSpecific,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            let back: FailureScopeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    // ── VersionMatrixError Display ────────────────────────────────

    #[test]
    fn error_display_missing_current() {
        let e = VersionMatrixError::MissingCurrentVersion {
            repo: "engine".into(),
        };
        assert!(e.to_string().contains("engine"));
    }

    #[test]
    fn error_display_invalid_pinned() {
        let e = VersionMatrixError::InvalidPinnedCombination {
            boundary_surface: "ifc".into(),
            reason: "empty version".into(),
        };
        assert!(e.to_string().contains("ifc"));
        assert!(e.to_string().contains("empty version"));
    }

    // ── derive_version_slots ──────────────────────────────────────

    #[test]
    fn derive_slots_from_tags() {
        let source = VersionSource {
            tags: vec!["v1.0.0".into(), "v1.1.0".into(), "v0.9.0".into()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        };
        let slots = derive_version_slots(&source, "engine").unwrap();
        assert_eq!(slots.current, "1.1.0");
        assert_eq!(slots.previous, Some("1.0.0".into()));
        assert!(slots.next.is_none());
    }

    #[test]
    fn derive_slots_with_overrides() {
        let source = VersionSource {
            tags: vec!["v1.0.0".into()],
            branch_names: vec![],
            current_override: Some("2.0.0".into()),
            previous_override: Some("1.0.0".into()),
            next_override: Some("3.0.0".into()),
        };
        let slots = derive_version_slots(&source, "engine").unwrap();
        assert_eq!(slots.current, "2.0.0");
        assert_eq!(slots.previous, Some("1.0.0".into()));
        assert_eq!(slots.next, Some("3.0.0".into()));
    }

    #[test]
    fn derive_slots_no_versions_errors() {
        let source = VersionSource::default();
        assert!(matches!(
            derive_version_slots(&source, "engine"),
            Err(VersionMatrixError::MissingCurrentVersion { .. })
        ));
    }

    #[test]
    fn derive_slots_prerelease_next() {
        let source = VersionSource {
            tags: vec!["v1.0.0".into(), "v1.1.0-rc.1".into()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        };
        let slots = derive_version_slots(&source, "engine").unwrap();
        assert_eq!(slots.current, "1.0.0");
        assert_eq!(slots.next, Some("1.1.0-rc.1".into()));
    }

    #[test]
    fn derive_slots_branch_derived_next() {
        let source = VersionSource {
            tags: vec!["v1.0.0".into()],
            branch_names: vec!["main".into()],
            current_override: None,
            previous_override: None,
            next_override: None,
        };
        let slots = derive_version_slots(&source, "engine").unwrap();
        assert_eq!(slots.next, Some("1.0.1-next".into()));
        assert!(!slots.derivation_notes.is_empty());
    }

    // ── derive_version_matrix ─────────────────────────────────────

    fn test_spec() -> BoundaryMatrixSpec {
        BoundaryMatrixSpec {
            boundary_surface: "ifc".into(),
            local_repo: "engine".into(),
            remote_repo: "host".into(),
            local_versions: VersionSource {
                tags: vec!["v1.0.0".into(), "v0.9.0".into()],
                branch_names: vec![],
                current_override: None,
                previous_override: None,
                next_override: None,
            },
            remote_versions: VersionSource {
                tags: vec!["v2.0.0".into(), "v1.9.0".into()],
                branch_names: vec![],
                current_override: None,
                previous_override: None,
                next_override: None,
            },
            pinned_combinations: vec![],
        }
    }

    #[test]
    fn derive_matrix_basic() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);
        assert!(!plan.cells.is_empty());
        let current = plan
            .cells
            .iter()
            .find(|c| c.lane_kind == MatrixLaneKind::Current)
            .unwrap();
        assert_eq!(current.local_version, "1.0.0");
        assert_eq!(current.remote_version, "2.0.0");
    }

    #[test]
    fn derive_matrix_includes_previous() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let prev = plan
            .cells
            .iter()
            .find(|c| c.lane_kind == MatrixLaneKind::Previous);
        assert!(prev.is_some());
    }

    #[test]
    fn derive_matrix_pinned_combination() {
        let mut spec = test_spec();
        spec.pinned_combinations.push(PinnedVersionCombination {
            local_version: "0.8.0".into(),
            remote_version: "1.5.0".into(),
            reason: "legacy".into(),
        });
        let plan = derive_version_matrix(&[spec]).unwrap();
        let pinned = plan
            .cells
            .iter()
            .find(|c| c.lane_kind == MatrixLaneKind::Pinned);
        assert!(pinned.is_some());
        assert!(pinned.unwrap().pinned);
    }

    #[test]
    fn derive_matrix_rejects_empty_pinned_version() {
        let mut spec = test_spec();
        spec.pinned_combinations.push(PinnedVersionCombination {
            local_version: "".into(),
            remote_version: "1.0.0".into(),
            reason: "bad".into(),
        });
        assert!(matches!(
            derive_version_matrix(&[spec]),
            Err(VersionMatrixError::InvalidPinnedCombination { .. })
        ));
    }

    #[test]
    fn derive_matrix_dedup_cells() {
        let spec = test_spec();
        let plan = derive_version_matrix(&[spec.clone(), spec]).unwrap();
        let current_count = plan
            .cells
            .iter()
            .filter(|c| c.lane_kind == MatrixLaneKind::Current)
            .count();
        assert_eq!(current_count, 1);
    }

    // ── classify_failure_scopes ───────────────────────────────────

    #[test]
    fn classify_no_failures() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let results: Vec<MatrixCellResult> = plan
            .cells
            .iter()
            .map(|c| MatrixCellResult {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                cell_id: c.cell_id.clone(),
                boundary_surface: c.boundary_surface.clone(),
                lane_kind: c.lane_kind,
                outcome: MatrixOutcome::Pass,
                error_code: None,
                failure_fingerprint: None,
                failure_class: None,
            })
            .collect();
        let scopes = classify_failure_scopes(&plan, &results);
        assert!(scopes.is_empty());
    }

    #[test]
    fn classify_universal_failure() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let results: Vec<MatrixCellResult> = plan
            .cells
            .iter()
            .map(|c| MatrixCellResult {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                cell_id: c.cell_id.clone(),
                boundary_surface: c.boundary_surface.clone(),
                lane_kind: c.lane_kind,
                outcome: MatrixOutcome::Fail,
                error_code: Some("E1".into()),
                failure_fingerprint: Some("fp1".into()),
                failure_class: Some("fc1".into()),
            })
            .collect();
        let scopes = classify_failure_scopes(&plan, &results);
        assert!(!scopes.is_empty());
        assert!(
            scopes
                .iter()
                .any(|s| s.scope == FailureScopeKind::Universal)
        );
    }

    #[test]
    fn classify_version_specific_failure() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        assert!(plan.cells.len() >= 2);
        let mut results: Vec<MatrixCellResult> = plan
            .cells
            .iter()
            .map(|c| MatrixCellResult {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                cell_id: c.cell_id.clone(),
                boundary_surface: c.boundary_surface.clone(),
                lane_kind: c.lane_kind,
                outcome: MatrixOutcome::Pass,
                error_code: None,
                failure_fingerprint: None,
                failure_class: None,
            })
            .collect();
        // Fail only the first cell
        results[0].outcome = MatrixOutcome::Fail;
        results[0].failure_fingerprint = Some("fp-specific".into());
        let scopes = classify_failure_scopes(&plan, &results);
        assert!(
            scopes
                .iter()
                .any(|s| s.scope == FailureScopeKind::VersionSpecific)
        );
    }

    // ── summarize_matrix_health ───────────────────────────────────

    #[test]
    fn health_all_pass() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let results: Vec<MatrixCellResult> = plan
            .cells
            .iter()
            .map(|c| MatrixCellResult {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                cell_id: c.cell_id.clone(),
                boundary_surface: c.boundary_surface.clone(),
                lane_kind: c.lane_kind,
                outcome: MatrixOutcome::Pass,
                error_code: None,
                failure_fingerprint: None,
                failure_class: None,
            })
            .collect();
        let health = summarize_matrix_health(&plan, &results);
        assert_eq!(health.total_cells, plan.cells.len());
        assert_eq!(health.passed_cells, results.len());
        assert_eq!(health.failed_cells, 0);
        assert_eq!(health.universal_failures, 0);
        assert_eq!(health.version_specific_failures, 0);
    }

    // ── build_cell ────────────────────────────────────────────────

    #[test]
    fn build_cell_id_format() {
        let spec = test_spec();
        let cell = build_cell(&spec, MatrixLaneKind::Current, "1.0.0", "2.0.0", false);
        assert_eq!(cell.cell_id, "ifc::n_n::1.0.0::2.0.0");
        assert!(!cell.pinned);
        assert!(cell.expected_conformance_command.contains("--matrix-cell"));
    }

    // ── parse_versions_from_tags ──────────────────────────────────

    #[test]
    fn parse_tags_basic() {
        let tags = ["v1.0.0".into(), "v2.0.0-beta".into()];
        let parsed = parse_versions_from_tags(&tags);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_tags_empty() {
        let parsed = parse_versions_from_tags(&[]);
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_tags_deduplicates() {
        let tags = ["v1.0.0".into(), "v1.0.0".into()];
        let parsed = parse_versions_from_tags(&tags);
        assert_eq!(parsed.len(), 1);
    }

    // ── VersionSource / BoundaryMatrixSpec serde ──────────────────

    #[test]
    fn version_source_default() {
        let vs = VersionSource::default();
        assert!(vs.tags.is_empty());
        assert!(vs.current_override.is_none());
    }

    #[test]
    fn boundary_matrix_spec_serde_round_trip() {
        let spec = test_spec();
        let json = serde_json::to_string(&spec).unwrap();
        let back: BoundaryMatrixSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn version_matrix_plan_serde_round_trip() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        let back: VersionMatrixPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn matrix_cell_result_serde_round_trip() {
        let r = MatrixCellResult {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            cell_id: "c".into(),
            boundary_surface: "b".into(),
            lane_kind: MatrixLaneKind::Current,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: None,
            failure_class: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MatrixCellResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn matrix_health_summary_serde_round_trip() {
        let s = MatrixHealthSummary {
            total_cells: 3,
            passed_cells: 2,
            failed_cells: 1,
            universal_failures: 0,
            version_specific_failures: 1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: MatrixHealthSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn version_slots_serde_round_trip() {
        let s = VersionSlots {
            current: "1.0.0".into(),
            previous: Some("0.9.0".into()),
            next: None,
            derivation_notes: vec!["auto".into()],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: VersionSlots = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- Enrichment tests ---

    #[test]
    fn lane_kind_display_uniqueness_btreeset() {
        let kinds = [
            MatrixLaneKind::Current,
            MatrixLaneKind::Previous,
            MatrixLaneKind::Next,
            MatrixLaneKind::Pinned,
        ];
        let displays: BTreeSet<String> = kinds.iter().map(|k| k.as_str().to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 lane kinds should have unique as_str"
        );
    }

    #[test]
    fn version_matrix_error_is_std_error() {
        let errors: [Box<dyn Error>; 2] = [
            Box::new(VersionMatrixError::MissingCurrentVersion {
                repo: "engine".into(),
            }),
            Box::new(VersionMatrixError::InvalidPinnedCombination {
                boundary_surface: "ifc".into(),
                reason: "empty".into(),
            }),
        ];
        let mut displays = BTreeSet::new();
        for e in &errors {
            let msg = format!("{e}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            2,
            "both error variants produce distinct messages"
        );
    }

    #[test]
    fn parsed_version_prerelease_ordering_lexicographic() {
        let alpha = ParsedVersion::parse("1.0.0-alpha").unwrap();
        let beta = ParsedVersion::parse("1.0.0-beta").unwrap();
        assert!(alpha < beta);
    }

    #[test]
    fn parsed_version_format_roundtrip_stable() {
        let v = ParsedVersion::parse("3.14.159").unwrap();
        let formatted = v.format();
        let reparsed = ParsedVersion::parse(&formatted).unwrap();
        assert_eq!(v, reparsed);
    }

    #[test]
    fn parsed_version_format_roundtrip_prerelease() {
        let v = ParsedVersion::parse("2.0.0-rc.1").unwrap();
        let formatted = v.format();
        let reparsed = ParsedVersion::parse(&formatted).unwrap();
        assert_eq!(v, reparsed);
    }

    #[test]
    fn parsed_version_with_leading_v_and_whitespace() {
        let v = ParsedVersion::parse("  v1.2.3  ").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn derive_slots_only_prereleases_uses_latest_prerelease_as_current() {
        let source = VersionSource {
            tags: vec!["v1.0.0-alpha".into(), "v1.0.0-beta".into()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        };
        let slots = derive_version_slots(&source, "engine").unwrap();
        // No stable versions; should pick latest prerelease as current
        assert_eq!(slots.current, "1.0.0-beta");
    }

    #[test]
    fn health_summary_with_mixed_outcomes() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let mut results: Vec<MatrixCellResult> = plan
            .cells
            .iter()
            .map(|c| MatrixCellResult {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                cell_id: c.cell_id.clone(),
                boundary_surface: c.boundary_surface.clone(),
                lane_kind: c.lane_kind,
                outcome: MatrixOutcome::Fail,
                error_code: Some("E1".into()),
                failure_fingerprint: Some("fp-all".into()),
                failure_class: Some("fc1".into()),
            })
            .collect();
        // Pass first cell
        results[0].outcome = MatrixOutcome::Pass;
        results[0].failure_fingerprint = None;
        let health = summarize_matrix_health(&plan, &results);
        assert_eq!(health.passed_cells, 1);
        assert_eq!(health.failed_cells, plan.cells.len() - 1);
    }

    // ── Enrichment: clone equality ──────────────────────────────

    #[test]
    fn enrichment_version_source_clone_eq() {
        let vs = VersionSource {
            tags: vec!["v1.0.0".into(), "v2.0.0".into()],
            branch_names: vec!["main".into()],
            current_override: Some("1.0.0".into()),
            previous_override: None,
            next_override: Some("3.0.0-next".into()),
        };
        let cloned = vs.clone();
        assert_eq!(vs, cloned);
    }

    #[test]
    fn enrichment_pinned_version_combination_clone_eq() {
        let pvc = PinnedVersionCombination {
            local_version: "1.0.0".into(),
            remote_version: "2.0.0".into(),
            reason: "legacy support".into(),
        };
        let cloned = pvc.clone();
        assert_eq!(pvc, cloned);
    }

    #[test]
    fn enrichment_version_matrix_cell_clone_eq() {
        let cell = build_cell(&test_spec(), MatrixLaneKind::Pinned, "0.8.0", "1.5.0", true);
        let cloned = cell.clone();
        assert_eq!(cell, cloned);
    }

    #[test]
    fn enrichment_matrix_failure_scope_clone_eq() {
        let scope = MatrixFailureScope {
            boundary_surface: "ifc".into(),
            failure_fingerprint: "fp-42".into(),
            scope: FailureScopeKind::Universal,
            failing_cells: vec!["cell-a".into(), "cell-b".into()],
        };
        let cloned = scope.clone();
        assert_eq!(scope, cloned);
    }

    #[test]
    fn enrichment_matrix_health_summary_clone_eq() {
        let summary = MatrixHealthSummary {
            total_cells: 10,
            passed_cells: 7,
            failed_cells: 3,
            universal_failures: 1,
            version_specific_failures: 2,
        };
        let cloned = summary.clone();
        assert_eq!(summary, cloned);
    }

    // ── Enrichment: JSON field presence ─────────────────────────

    #[test]
    fn enrichment_matrix_cell_result_json_fields() {
        let result = MatrixCellResult {
            trace_id: "trace-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            cell_id: "cell-1".into(),
            boundary_surface: "ifc".into(),
            lane_kind: MatrixLaneKind::Next,
            outcome: MatrixOutcome::Fail,
            error_code: Some("E42".into()),
            failure_fingerprint: Some("fp-xyz".into()),
            failure_class: Some("timeout".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"error_code\""));
        assert!(json.contains("\"failure_fingerprint\""));
        assert!(json.contains("\"failure_class\""));
        assert!(json.contains("\"lane_kind\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn enrichment_boundary_matrix_spec_json_fields() {
        let spec = test_spec();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"boundary_surface\""));
        assert!(json.contains("\"local_repo\""));
        assert!(json.contains("\"remote_repo\""));
        assert!(json.contains("\"local_versions\""));
        assert!(json.contains("\"remote_versions\""));
        assert!(json.contains("\"pinned_combinations\""));
    }

    #[test]
    fn enrichment_version_matrix_plan_json_fields() {
        let plan = derive_version_matrix(&[test_spec()]).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"generated_at_utc\""));
        assert!(json.contains("\"cells\""));
        assert!(json.contains("\"cell_id\""));
        assert!(json.contains("\"expected_conformance_command\""));
    }

    // ── Enrichment: serde roundtrip ─────────────────────────────

    #[test]
    fn enrichment_matrix_failure_scope_serde_roundtrip() {
        let scope = MatrixFailureScope {
            boundary_surface: "ifc".into(),
            failure_fingerprint: "fp-round".into(),
            scope: FailureScopeKind::VersionSpecific,
            failing_cells: vec!["c1".into(), "c2".into(), "c3".into()],
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: MatrixFailureScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn enrichment_error_display_variants_all_unique() {
        let errors = [
            VersionMatrixError::MissingCurrentVersion {
                repo: "alpha".into(),
            },
            VersionMatrixError::MissingCurrentVersion {
                repo: "bravo".into(),
            },
            VersionMatrixError::InvalidPinnedCombination {
                boundary_surface: "ifc".into(),
                reason: "bad local".into(),
            },
            VersionMatrixError::InvalidPinnedCombination {
                boundary_surface: "ifc".into(),
                reason: "bad remote".into(),
            },
        ];
        let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            errors.len(),
            "all error messages must be unique"
        );
    }

    // ── Enrichment: boundary condition ──────────────────────────

    #[test]
    fn enrichment_derive_matrix_empty_specs_returns_empty_plan() {
        let plan = derive_version_matrix(&[]).unwrap();
        assert!(plan.cells.is_empty());
        assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);
        assert_eq!(plan.generated_at_utc, "1970-01-01T00:00:00Z");
    }

    // ── Enrichment: Ord / Error source ──────────────────────────

    #[test]
    fn enrichment_parsed_version_ord_same_major_minor_patch_prerelease_matters() {
        let rc1 = ParsedVersion::parse("2.1.0-rc.1").unwrap();
        let rc2 = ParsedVersion::parse("2.1.0-rc.2").unwrap();
        let stable = ParsedVersion::parse("2.1.0").unwrap();
        // rc.1 < rc.2 < stable
        assert!(rc1 < rc2);
        assert!(rc2 < stable);
        // error source is None (blanket impl)
        let err = VersionMatrixError::MissingCurrentVersion {
            repo: "test".into(),
        };
        assert!(err.source().is_none());
    }

    // ── Enrichment batch: clone/eq, Copy, serde, JSON, edge cases ─────

    #[test]
    fn enrichment_matrix_lane_kind_copy_semantics() {
        let kind = MatrixLaneKind::Current;
        let copied = kind;
        assert_eq!(kind, copied);
    }

    #[test]
    fn enrichment_matrix_outcome_copy_semantics() {
        let outcome = MatrixOutcome::Pass;
        let copied = outcome;
        assert_eq!(outcome, copied);
    }

    #[test]
    fn enrichment_failure_scope_kind_copy_semantics() {
        let scope = FailureScopeKind::Universal;
        let copied = scope;
        assert_eq!(scope, copied);
    }

    #[test]
    fn enrichment_version_source_clone_equality() {
        let vs = VersionSource {
            tags: vec!["v1.0.0".into()],
            branch_names: vec!["main".into()],
            current_override: Some("1.0.0".into()),
            previous_override: None,
            next_override: None,
        };
        let cloned = vs.clone();
        assert_eq!(vs, cloned);
    }

    #[test]
    fn enrichment_pinned_version_combination_clone_equality() {
        let pvc = PinnedVersionCombination {
            local_version: "1.0.0".into(),
            remote_version: "2.0.0".into(),
            reason: "compat".into(),
        };
        let cloned = pvc.clone();
        assert_eq!(pvc, cloned);
    }

    #[test]
    fn enrichment_version_matrix_cell_clone_equality() {
        let cell = VersionMatrixCell {
            cell_id: "c1".into(),
            boundary_surface: "ifc".into(),
            local_repo: "local".into(),
            remote_repo: "remote".into(),
            local_version: "1.0.0".into(),
            remote_version: "2.0.0".into(),
            lane_kind: MatrixLaneKind::Current,
            pinned: false,
            expected_conformance_command: "test".into(),
        };
        let cloned = cell.clone();
        assert_eq!(cell, cloned);
    }

    #[test]
    fn enrichment_matrix_health_summary_clone_equality() {
        let mhs = MatrixHealthSummary {
            total_cells: 10,
            passed_cells: 7,
            failed_cells: 3,
            universal_failures: 1,
            version_specific_failures: 2,
        };
        let cloned = mhs.clone();
        assert_eq!(mhs, cloned);
    }

    #[test]
    fn enrichment_matrix_lane_kind_serde_snake_case() {
        let json = serde_json::to_string(&MatrixLaneKind::Current).unwrap();
        assert_eq!(json, "\"current\"");
        let json = serde_json::to_string(&MatrixLaneKind::Previous).unwrap();
        assert_eq!(json, "\"previous\"");
        let json = serde_json::to_string(&MatrixLaneKind::Next).unwrap();
        assert_eq!(json, "\"next\"");
        let json = serde_json::to_string(&MatrixLaneKind::Pinned).unwrap();
        assert_eq!(json, "\"pinned\"");
    }

    #[test]
    fn enrichment_matrix_outcome_serde_snake_case() {
        let json = serde_json::to_string(&MatrixOutcome::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
        let json = serde_json::to_string(&MatrixOutcome::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    #[test]
    fn enrichment_failure_scope_kind_serde_snake_case() {
        let json = serde_json::to_string(&FailureScopeKind::Universal).unwrap();
        assert_eq!(json, "\"universal\"");
        let json = serde_json::to_string(&FailureScopeKind::VersionSpecific).unwrap();
        assert_eq!(json, "\"version_specific\"");
    }

    #[test]
    fn enrichment_matrix_cell_result_json_fields_present() {
        let result = MatrixCellResult {
            trace_id: "t1".into(),
            decision_id: "d1".into(),
            policy_id: "p1".into(),
            cell_id: "c1".into(),
            boundary_surface: "ifc".into(),
            lane_kind: MatrixLaneKind::Current,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: None,
            failure_class: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"cell_id\""));
        assert!(json.contains("\"boundary_surface\""));
        assert!(json.contains("\"lane_kind\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn enrichment_matrix_lane_kind_as_str_all_unique() {
        let kinds = [
            MatrixLaneKind::Current,
            MatrixLaneKind::Previous,
            MatrixLaneKind::Next,
            MatrixLaneKind::Pinned,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), 4, "all lane kinds have unique as_str");
    }

    #[test]
    fn enrichment_matrix_lane_kind_ord_deterministic() {
        let mut kinds = [
            MatrixLaneKind::Pinned,
            MatrixLaneKind::Next,
            MatrixLaneKind::Current,
            MatrixLaneKind::Previous,
        ];
        let mut kinds2 = kinds;
        kinds.sort();
        kinds2.sort();
        assert_eq!(kinds, kinds2);
    }

    #[test]
    fn enrichment_version_source_default_is_empty() {
        let vs = VersionSource::default();
        assert!(vs.tags.is_empty());
        assert!(vs.branch_names.is_empty());
        assert!(vs.current_override.is_none());
        assert!(vs.previous_override.is_none());
        assert!(vs.next_override.is_none());
    }

    #[test]
    fn enrichment_parsed_version_parse_rejects_four_parts() {
        assert!(ParsedVersion::parse("1.2.3.4").is_none());
    }

    #[test]
    fn enrichment_parsed_version_parse_rejects_non_numeric() {
        assert!(ParsedVersion::parse("a.b.c").is_none());
    }

    #[test]
    fn enrichment_parsed_version_strips_v_prefix() {
        let v = ParsedVersion::parse("v1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.prerelease.is_none());
    }

    #[test]
    fn enrichment_parsed_version_bump_patch_next() {
        let v = ParsedVersion::parse("3.5.7").unwrap();
        assert_eq!(v.bump_patch_next(), "3.5.8-next");
    }

    #[test]
    fn enrichment_version_matrix_error_clone() {
        let err = VersionMatrixError::InvalidPinnedCombination {
            boundary_surface: "surf".into(),
            reason: "bad".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn enrichment_schema_constant_nonempty() {
        assert!(!VERSION_MATRIX_SCHEMA.is_empty());
        assert!(VERSION_MATRIX_SCHEMA.contains("version-matrix"));
    }
}
