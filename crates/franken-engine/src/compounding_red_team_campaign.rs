//! Compounding red-team campaign orchestrator (Track U — bd-cixqu.21.4).
//!
//! Ties the three Track-U stages into one deterministic campaign:
//!
//!   1. **U.1 generation** — [`crate::attack_grammar_synthesizer`] synthesizes a
//!      batch of candidate exploit programs.
//!   2. **U.3 novelty** — [`crate::novelty_scoring_contract`] rejects candidates
//!      that are semantic duplicates / near-duplicates of what the campaign has
//!      already accepted, so only genuinely distinct attacks proceed.
//!   3. **U.2 promotion** — [`crate::corpus_promotion`] minimizes each surviving
//!      candidate and gates it through the acquisition oracle; reproduced bypasses
//!      are promoted into the regression corpus.
//!
//! The campaign emits a single [`CampaignBundle`]: the campaign id + config
//! fingerprint, the complete list of explored candidates with their novelty
//! scores and promotion decisions, the promoted scenarios, and a statistical
//! summary. The bundle is content-addressed (`bundle_digest`) and fully
//! deterministic given `(config)` — identical inputs produce byte-identical
//! bundles, which the replay gate verifies.
//!
//! Like [`crate::corpus_promotion`], the promotion stage is driven by a bypass
//! *oracle* (`Fn(&str) -> StepOutcome`). [`engine_containment_oracle`] wires the
//! engine's own ambient-authority containment (parse -> lower -> observe the
//! verdict); tests can substitute a controlled oracle for hermetic determinism.
//!
//! Per bd-cixqu.45 the bundle is the structured audit trail; every explored
//! candidate carries its novelty report, minimization trace, and oracle verdict.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::attack_grammar_synthesizer::{
    AttackGrammarError, AttackGrammarSynthesizer, ExploitCandidate, SynthesisConfig,
};
use crate::corpus_promotion::{
    AttackCandidate, MinimizationTrace, OracleVerdict, PromotedLedger, PromotedScenario,
    build_promotion_plan,
};
use crate::hash_tiers::ContentHash;
use crate::hierarchical_delta_debug::StepOutcome;
use crate::ir_contract::Ir0Module;
use crate::lowering_pipeline::{LoweringPipelineError, lower_ir0_to_ir1};
use crate::novelty_scoring_contract::{
    CandidateKind, MILLIONTHS, NoveltyCandidate, SemanticNoveltyConfig, SemanticNoveltyVerdict,
    classify_semantic_novelty_with_config,
};
use crate::parser_api_stability::parse_module;

// ---------------------------------------------------------------------------
// Schema + policy constants
// ---------------------------------------------------------------------------

/// Schema id for a serialized [`CampaignBundle`].
pub const CAMPAIGN_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.compounding-red-team-bundle.v1";

/// Schema id for the gate `run_manifest.json` wrapper.
pub const CAMPAIGN_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.compounding-red-team-gate.v1";

/// Greppable provenance marker for campaign artifacts.
pub const CAMPAIGN_MARKER: &str = "franken-engine:compounding-red-team:v1";

/// Default duplicate similarity threshold (millionths).
pub const DEFAULT_DUPLICATE_THRESHOLD_MILLIONTHS: u64 = 900_000;

/// Default near-duplicate similarity threshold (millionths).
pub const DEFAULT_NEAR_DUPLICATE_THRESHOLD_MILLIONTHS: u64 = 700_000;

/// Default reproduction trials passed to the promotion gate.
pub const DEFAULT_PROMOTION_TRIALS: u32 = 5;

// ---------------------------------------------------------------------------
// Campaign configuration (gate input)
// ---------------------------------------------------------------------------

/// Deterministic campaign configuration. Every field is an input to the campaign
/// so the config fingerprint fully determines the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CampaignConfig {
    /// Human-readable campaign label (part of the campaign id).
    pub campaign_label: String,
    /// Deterministic generation timestamp seed (ns) — NOT wall-clock.
    pub timestamp_ns: u64,
    /// Max candidates generated per attack strategy.
    pub max_candidates_per_strategy: u32,
    /// Max mutations per base exploit.
    pub max_mutations_per_base: u32,
    /// Whether the synthesizer includes obfuscation mutations.
    pub include_obfuscation: bool,
    /// Novelty duplicate threshold (millionths).
    pub duplicate_threshold_millionths: u64,
    /// Novelty near-duplicate threshold (millionths).
    pub near_duplicate_threshold_millionths: u64,
    /// Reproduction trials for the promotion gate.
    pub promotion_trials: u32,
    /// Target corpus size (advisory cap on promotions this campaign).
    pub target_corpus_size: u32,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            campaign_label: "compounding-red-team".to_string(),
            timestamp_ns: 1_000,
            max_candidates_per_strategy: 6,
            max_mutations_per_base: 4,
            include_obfuscation: true,
            duplicate_threshold_millionths: DEFAULT_DUPLICATE_THRESHOLD_MILLIONTHS,
            near_duplicate_threshold_millionths: DEFAULT_NEAR_DUPLICATE_THRESHOLD_MILLIONTHS,
            promotion_trials: DEFAULT_PROMOTION_TRIALS,
            target_corpus_size: 64,
        }
    }
}

impl CampaignConfig {
    /// Parse a campaign config from TOML text (missing fields take defaults).
    pub fn from_toml(text: &str) -> Result<Self, CampaignError> {
        toml::from_str(text).map_err(|error| CampaignError::Config(error.to_string()))
    }

    /// Content-addressed fingerprint over the canonical config bytes.
    pub fn fingerprint(&self) -> String {
        let mut buf = Vec::new();
        push_field(&mut buf, self.campaign_label.as_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&self.max_candidates_per_strategy.to_be_bytes());
        buf.extend_from_slice(&self.max_mutations_per_base.to_be_bytes());
        buf.push(u8::from(self.include_obfuscation));
        buf.extend_from_slice(&self.duplicate_threshold_millionths.to_be_bytes());
        buf.extend_from_slice(&self.near_duplicate_threshold_millionths.to_be_bytes());
        buf.extend_from_slice(&self.promotion_trials.to_be_bytes());
        buf.extend_from_slice(&self.target_corpus_size.to_be_bytes());
        format!("cfg-{}", &ContentHash::compute(&buf).to_hex()[..16])
    }

    fn to_synthesis_config(&self) -> SynthesisConfig {
        // Start from the synthesizer's default strategy/severity set and override
        // only the campaign-controlled generation parameters.
        SynthesisConfig {
            max_candidates_per_strategy: self.max_candidates_per_strategy,
            max_mutations_per_base: self.max_mutations_per_base,
            include_obfuscation: self.include_obfuscation,
            ..SynthesisConfig::default()
        }
    }

    fn novelty_config(&self) -> SemanticNoveltyConfig {
        SemanticNoveltyConfig {
            duplicate_threshold_millionths: self.duplicate_threshold_millionths,
            near_duplicate_threshold_millionths: self.near_duplicate_threshold_millionths,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from running or writing a campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignError {
    /// The attack generator failed.
    Generation(String),
    /// The campaign config was malformed.
    Config(String),
    /// A bundle artifact could not be written.
    Io(String),
}

impl std::fmt::Display for CampaignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignError::Generation(m) => write!(f, "attack generation failed: {m}"),
            CampaignError::Config(m) => write!(f, "campaign config error: {m}"),
            CampaignError::Io(m) => write!(f, "campaign artifact io error: {m}"),
        }
    }
}

impl std::error::Error for CampaignError {}

impl From<AttackGrammarError> for CampaignError {
    fn from(error: AttackGrammarError) -> Self {
        CampaignError::Generation(format!("{error:?}"))
    }
}

// ---------------------------------------------------------------------------
// Bundle records
// ---------------------------------------------------------------------------

/// The disposition of one explored candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateDisposition {
    /// Promoted into the regression corpus (reproduced bypass).
    Promoted,
    /// Rejected: a semantic duplicate of an already-accepted attack.
    RejectedDuplicate,
    /// Rejected: a near-duplicate requiring no new coverage.
    RejectedNearDuplicate,
    /// Rejected: the minimized attack did not reproduce under the oracle gate.
    RejectedNotReproduced,
}

impl CandidateDisposition {
    /// Stable lower-snake string for serialized output.
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateDisposition::Promoted => "promoted",
            CandidateDisposition::RejectedDuplicate => "rejected_duplicate",
            CandidateDisposition::RejectedNearDuplicate => "rejected_near_duplicate",
            CandidateDisposition::RejectedNotReproduced => "rejected_not_reproduced",
        }
    }
}

/// The novelty assessment recorded for a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyAssessment {
    /// `novel` / `near_duplicate` / `duplicate`.
    pub verdict: String,
    /// Similarity (millionths) to the nearest existing candidate (0 if none).
    pub nearest_similarity_millionths: u64,
    /// The id of the nearest existing candidate, if any.
    pub nearest_candidate_id: Option<String>,
    /// Duplicate threshold in force.
    pub duplicate_threshold_millionths: u64,
    /// Near-duplicate threshold in force.
    pub near_duplicate_threshold_millionths: u64,
}

/// One explored candidate: generation metadata, novelty, and promotion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateExploration {
    /// Deterministic candidate / scenario id.
    pub candidate_id: String,
    /// Attack-vector slug.
    pub attack_vector: String,
    /// Attack strategy (debug slug).
    pub strategy: String,
    /// Severity (debug slug).
    pub severity: String,
    /// Content hash (hex) of the generated attack source.
    pub source_hash: String,
    /// Novelty assessment.
    pub novelty: NoveltyAssessment,
    /// Final disposition.
    pub disposition: String,
    /// Human-readable reason for the disposition.
    pub reason: String,
    /// Minimization trace (present when the candidate reached the promotion gate).
    pub minimization: Option<MinimizationTrace>,
    /// Oracle verdict (present when the candidate reached the promotion gate).
    pub verdict: Option<OracleVerdict>,
    /// Promoted scenario name (present iff promoted).
    pub promoted_scenario_name: Option<String>,
}

/// Novelty verdict distribution across explored candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyDistribution {
    /// Count classified `Novel`.
    pub novel: u32,
    /// Count classified `NearDuplicate`.
    pub near_duplicate: u32,
    /// Count classified `Duplicate`.
    pub duplicate: u32,
}

/// Aggregate campaign statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStatistics {
    /// Total candidates explored.
    pub candidates_explored: u32,
    /// Candidates promoted into the corpus.
    pub promoted: u32,
    /// Candidates rejected (any reason).
    pub rejected: u32,
    /// Novelty verdict distribution.
    pub novelty_distribution: NoveltyDistribution,
    /// Corpus size (ledger entries) before the campaign.
    pub corpus_size_before: u32,
    /// Corpus size after the campaign.
    pub corpus_size_after: u32,
    /// Net corpus growth (`after - before`).
    pub corpus_growth: u32,
    /// Promotion success rate (millionths) per attack-vector class.
    pub success_rate_by_attack_vector_millionths: BTreeMap<String, u64>,
}

/// The complete, content-addressed campaign artifact bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignBundle {
    /// Schema id.
    pub schema_version: String,
    /// Campaign id = `<label>:<config-fingerprint>`.
    pub campaign_id: String,
    /// Campaign label.
    pub campaign_label: String,
    /// Config fingerprint.
    pub config_fingerprint: String,
    /// Deterministic generation timestamp seed (ns) from the config.
    pub generated_at_ns: u64,
    /// Every explored candidate, in deterministic order.
    pub explored: Vec<CandidateExploration>,
    /// The promoted manifest pairs.
    pub promoted_scenarios: Vec<PromotedScenario>,
    /// Aggregate statistics.
    pub statistics: CampaignStatistics,
    /// Content hash (hex) over the canonical bundle sequence.
    pub bundle_digest: String,
}

/// One written bundle artifact and its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifact {
    /// Artifact filename (relative to the bundle dir).
    pub name: String,
    /// Absolute path written.
    pub path: PathBuf,
    /// SHA-256 (hex) of the written bytes.
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Lower-snake, filesystem-safe slug of an arbitrary debug string.
fn slugify(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_underscore = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore && !out.is_empty() {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("attack");
    }
    out
}

/// Deterministic 8-group red-team feature vector for a source program, mirroring
/// the corpus novelty featurization: each group's needle-match count scaled by
/// 125_000 millionths and capped at [`MILLIONTHS`].
fn campaign_feature_vector(source: &str) -> Vec<u64> {
    let normalized = source.to_ascii_lowercase();
    const GROUPS: [&[&str]; 8] = [
        &["frankenhostcall", "capability", "permission"],
        &["eval", "function constructor", "new function"],
        &["process", "env", "environment"],
        &["import", "require", "package", "script"],
        &["prototype", "__proto__", "proxy", "reflect"],
        &["globalthis", "constructor", "computed", "member"],
        &["declass", "receipt", "effect", "typed", "downcast"],
        &["filesystem", "shell", "command", "write", "exfil"],
    ];
    GROUPS
        .into_iter()
        .map(|needles| {
            needles
                .iter()
                .map(|needle| normalized.matches(needle).count() as u64)
                .sum::<u64>()
                .saturating_mul(125_000)
                .min(MILLIONTHS)
        })
        .collect()
}

fn novelty_candidate_for(candidate_id: &str, source: &str) -> NoveltyCandidate {
    NoveltyCandidate::new(
        candidate_id.to_string(),
        CandidateKind::Program,
        (source.len() as u64).saturating_mul(8),
        campaign_feature_vector(source),
        source.as_bytes(),
    )
}

/// The engine's own ambient-authority containment as a bypass oracle: a program
/// "reproduces the bypass" when it still fails closed at lowering time.
pub fn engine_containment_oracle(source: &str) -> StepOutcome {
    let tree = match parse_module(source) {
        Ok(tree) => tree,
        Err(_) => return StepOutcome::SyntaxError,
    };
    let ir0 = Ir0Module::from_syntax_tree(tree, "compounding-red-team-candidate");
    match lower_ir0_to_ir1(&ir0) {
        Err(LoweringPipelineError::AmbientAuthorityViolation { .. }) => {
            StepOutcome::DefectPreserved
        }
        _ => StepOutcome::DefectLost,
    }
}

fn attack_candidate_for(
    candidate_id: &str,
    attack_vector: &str,
    exploit: &ExploitCandidate,
) -> AttackCandidate {
    let mut candidate = AttackCandidate::new(
        candidate_id.to_string(),
        exploit.manifest.description.clone(),
        attack_vector.to_string(),
        exploit.javascript_code.clone(),
        format!("{attack_vector}_contained_at_lowering"),
    );
    candidate.frankenengine_observable = format!(
        "FrankenEngine fails closed on the {attack_vector} attack before it reaches authority"
    );
    candidate.failure_signal = "containment refuses the attack at compile time".to_string();
    candidate
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Run a deterministic compounding red-team campaign: generate (U.1), reject
/// non-novel candidates (U.3), promote reproduced bypasses (U.2), and assemble a
/// content-addressed [`CampaignBundle`]. Side-effect-free (no filesystem writes);
/// use [`write_bundle`] to materialize artifacts.
pub fn run_campaign<F>(
    config: &CampaignConfig,
    existing_ledger: &PromotedLedger,
    oracle: F,
) -> Result<CampaignBundle, CampaignError>
where
    F: Fn(&str) -> StepOutcome,
{
    // U.1: generate a deterministic batch of exploit candidates.
    let mut synthesizer = AttackGrammarSynthesizer::new(config.to_synthesis_config());
    let mut exploits = synthesizer.synthesize_exploits(config.timestamp_ns)?;
    // Deterministic order regardless of the generator's internal ordering.
    exploits.sort_by(|a, b| {
        ContentHash::compute(a.javascript_code.as_bytes())
            .to_hex()
            .cmp(&ContentHash::compute(b.javascript_code.as_bytes()).to_hex())
    });

    let novelty_config = config.novelty_config();
    let mut novelty_corpus: Vec<NoveltyCandidate> = Vec::new();

    // Per-candidate exploration records, plus the novel candidates that advance to
    // the promotion gate (paired with their record index).
    let mut explored: Vec<CandidateExploration> = Vec::new();
    let mut novel_attacks: Vec<AttackCandidate> = Vec::new();
    let mut novel_record_index: BTreeMap<String, usize> = BTreeMap::new();

    for exploit in &exploits {
        let source = &exploit.javascript_code;
        let source_hash = ContentHash::compute(source.as_bytes()).to_hex();
        let attack_vector = slugify(&format!("{:?}", exploit.manifest.vector));
        let candidate_id = format!("campaign_{attack_vector}_{}", &source_hash[..12]);

        let novelty_candidate = novelty_candidate_for(&candidate_id, source);
        let report = classify_semantic_novelty_with_config(
            &novelty_candidate,
            &novelty_corpus,
            &novelty_config,
        );
        let (nearest_sim, nearest_id) = report.nearest.as_ref().map_or((0, None), |m| {
            (
                m.similarity_millionths,
                Some(m.existing_candidate_id.clone()),
            )
        });
        let novelty = NoveltyAssessment {
            verdict: novelty_verdict_str(report.verdict).to_string(),
            nearest_similarity_millionths: nearest_sim,
            nearest_candidate_id: nearest_id,
            duplicate_threshold_millionths: report.duplicate_threshold_millionths,
            near_duplicate_threshold_millionths: report.near_duplicate_threshold_millionths,
        };

        let mut record = CandidateExploration {
            candidate_id: candidate_id.clone(),
            attack_vector: attack_vector.clone(),
            strategy: slugify(&format!("{:?}", exploit.manifest.strategy)),
            severity: slugify(&format!("{:?}", exploit.manifest.severity)),
            source_hash,
            novelty,
            disposition: String::new(),
            reason: String::new(),
            minimization: None,
            verdict: None,
            promoted_scenario_name: None,
        };

        match report.verdict {
            SemanticNoveltyVerdict::Duplicate => {
                record.disposition = CandidateDisposition::RejectedDuplicate.as_str().to_string();
                record.reason = "semantic duplicate of an already-accepted attack".to_string();
                explored.push(record);
            }
            SemanticNoveltyVerdict::NearDuplicate => {
                record.disposition = CandidateDisposition::RejectedNearDuplicate
                    .as_str()
                    .to_string();
                record.reason = "near-duplicate: adds no distinct coverage".to_string();
                explored.push(record);
            }
            SemanticNoveltyVerdict::Novel => {
                novelty_corpus.push(novelty_candidate);
                novel_attacks.push(attack_candidate_for(&candidate_id, &attack_vector, exploit));
                let index = explored.len();
                novel_record_index.insert(candidate_id, index);
                explored.push(record);
            }
        }
    }

    // U.2: minimize + oracle-gate every novel candidate in one deterministic plan.
    let plan = build_promotion_plan(
        &novel_attacks,
        existing_ledger,
        config.promotion_trials,
        &oracle,
    );

    let mut promoted_scenarios: Vec<PromotedScenario> = Vec::new();
    for proposal in &plan.proposals {
        if let Some(&index) = novel_record_index.get(&proposal.candidate_name) {
            let record = &mut explored[index];
            record.disposition = CandidateDisposition::Promoted.as_str().to_string();
            record.reason = "reproduced bypass minimized and admitted".to_string();
            record.minimization = Some(proposal.minimization.clone());
            record.verdict = Some(proposal.verdict.clone());
            record.promoted_scenario_name = Some(proposal.scenario.name.clone());
        }
        promoted_scenarios.push(proposal.scenario.clone());
    }
    for skipped in &plan.skipped {
        if let Some(&index) = novel_record_index.get(&skipped.candidate_name) {
            let record = &mut explored[index];
            record.disposition = CandidateDisposition::RejectedNotReproduced
                .as_str()
                .to_string();
            record.reason = skipped.reason.clone();
            record.verdict = skipped.verdict.clone();
        }
    }

    let statistics = compute_statistics(&explored, existing_ledger, promoted_scenarios.len());
    let config_fingerprint = config.fingerprint();
    let campaign_id = format!("{}:{}", config.campaign_label, config_fingerprint);
    let bundle_digest =
        compute_bundle_digest(&campaign_id, &config_fingerprint, &explored, &statistics);

    Ok(CampaignBundle {
        schema_version: CAMPAIGN_BUNDLE_SCHEMA_VERSION.to_string(),
        campaign_id,
        campaign_label: config.campaign_label.clone(),
        config_fingerprint,
        generated_at_ns: config.timestamp_ns,
        explored,
        promoted_scenarios,
        statistics,
        bundle_digest,
    })
}

fn novelty_verdict_str(verdict: SemanticNoveltyVerdict) -> &'static str {
    match verdict {
        SemanticNoveltyVerdict::Novel => "novel",
        SemanticNoveltyVerdict::NearDuplicate => "near_duplicate",
        SemanticNoveltyVerdict::Duplicate => "duplicate",
    }
}

fn compute_statistics(
    explored: &[CandidateExploration],
    existing_ledger: &PromotedLedger,
    promoted_count: usize,
) -> CampaignStatistics {
    let mut dist = NoveltyDistribution {
        novel: 0,
        near_duplicate: 0,
        duplicate: 0,
    };
    let mut promoted: u32 = 0;
    let mut rejected: u32 = 0;
    // (explored, promoted) per attack vector.
    let mut per_vector: BTreeMap<String, (u64, u64)> = BTreeMap::new();

    for record in explored {
        match record.novelty.verdict.as_str() {
            "novel" => dist.novel = dist.novel.saturating_add(1),
            "near_duplicate" => dist.near_duplicate = dist.near_duplicate.saturating_add(1),
            "duplicate" => dist.duplicate = dist.duplicate.saturating_add(1),
            _ => {}
        }
        let entry = per_vector
            .entry(record.attack_vector.clone())
            .or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        if record.disposition == CandidateDisposition::Promoted.as_str() {
            promoted = promoted.saturating_add(1);
            entry.1 = entry.1.saturating_add(1);
        } else {
            rejected = rejected.saturating_add(1);
        }
    }

    let success_rate_by_attack_vector_millionths = per_vector
        .into_iter()
        .map(|(vector, (explored_n, promoted_n))| {
            let rate = promoted_n
                .saturating_mul(MILLIONTHS)
                .checked_div(explored_n)
                .unwrap_or(0);
            (vector, rate)
        })
        .collect();

    let corpus_size_before = usize_to_u32(existing_ledger.records.len());
    let corpus_growth = usize_to_u32(promoted_count);
    CampaignStatistics {
        candidates_explored: usize_to_u32(explored.len()),
        promoted,
        rejected,
        novelty_distribution: dist,
        corpus_size_before,
        corpus_size_after: corpus_size_before.saturating_add(corpus_growth),
        corpus_growth,
        success_rate_by_attack_vector_millionths,
    }
}

fn usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn compute_bundle_digest(
    campaign_id: &str,
    config_fingerprint: &str,
    explored: &[CandidateExploration],
    statistics: &CampaignStatistics,
) -> String {
    let mut buf = Vec::new();
    push_field(&mut buf, CAMPAIGN_BUNDLE_SCHEMA_VERSION.as_bytes());
    push_field(&mut buf, campaign_id.as_bytes());
    push_field(&mut buf, config_fingerprint.as_bytes());
    for record in explored {
        buf.push(0x01);
        push_field(&mut buf, record.candidate_id.as_bytes());
        push_field(&mut buf, record.source_hash.as_bytes());
        push_field(&mut buf, record.novelty.verdict.as_bytes());
        push_field(&mut buf, record.disposition.as_bytes());
        if let Some(name) = &record.promoted_scenario_name {
            push_field(&mut buf, name.as_bytes());
        } else {
            push_field(&mut buf, b"");
        }
    }
    buf.push(0x02);
    buf.extend_from_slice(&u64::from(statistics.promoted).to_be_bytes());
    buf.extend_from_slice(&u64::from(statistics.rejected).to_be_bytes());
    buf.extend_from_slice(&u64::from(statistics.corpus_growth).to_be_bytes());
    format!("bundle-{}", ContentHash::compute(&buf).to_hex())
}

// ---------------------------------------------------------------------------
// Artifact writer (explicit, gated side effects)
// ---------------------------------------------------------------------------

fn write_artifact(dir: &Path, name: &str, bytes: &str) -> Result<BundleArtifact, CampaignError> {
    let path = dir.join(name);
    fs::write(&path, bytes).map_err(|e| CampaignError::Io(format!("{name}: {e}")))?;
    Ok(BundleArtifact {
        name: name.to_string(),
        path,
        sha256: ContentHash::compute(bytes.as_bytes()).to_hex(),
    })
}

/// Materialize a campaign bundle into `out_dir`: the full bundle JSON, a
/// `run_manifest.json` gate wrapper (with per-artifact SHA-256), a human-readable
/// `summary.md`, and the promoted scenario manifest pairs under `promoted/`.
/// Deterministic: identical bundles produce byte-identical files.
pub fn write_bundle(
    bundle: &CampaignBundle,
    out_dir: &Path,
) -> Result<Vec<BundleArtifact>, CampaignError> {
    fs::create_dir_all(out_dir).map_err(|e| CampaignError::Io(e.to_string()))?;
    let mut artifacts = Vec::new();

    let bundle_json = serde_json::to_string_pretty(bundle)
        .map_err(|e| CampaignError::Io(format!("bundle serialize: {e}")))?;
    artifacts.push(write_artifact(
        out_dir,
        "compounding_red_team_bundle.json",
        &bundle_json,
    )?);

    let summary = render_summary(bundle);
    artifacts.push(write_artifact(out_dir, "summary.md", &summary)?);

    // Promoted scenario manifest pairs.
    if !bundle.promoted_scenarios.is_empty() {
        let promoted_dir = out_dir.join("promoted");
        fs::create_dir_all(&promoted_dir).map_err(|e| CampaignError::Io(e.to_string()))?;
        for scenario in &bundle.promoted_scenarios {
            artifacts.push(write_artifact(
                &promoted_dir,
                &format!("{}.js", scenario.name),
                &scenario.program_js,
            )?);
            artifacts.push(write_artifact(
                &promoted_dir,
                &format!("{}.manifest.json", scenario.name),
                &scenario.manifest_json,
            )?);
        }
    }

    // run_manifest.json references every prior artifact by SHA-256.
    let run_manifest = render_run_manifest(bundle, &artifacts);
    artifacts.push(write_artifact(out_dir, "run_manifest.json", &run_manifest)?);

    Ok(artifacts)
}

fn render_run_manifest(bundle: &CampaignBundle, artifacts: &[BundleArtifact]) -> String {
    let mut artifact_obj = serde_json::Map::new();
    for a in artifacts {
        artifact_obj.insert(a.name.clone(), serde_json::json!({ "sha256": a.sha256 }));
    }
    let artifact_map = serde_json::Value::Object(artifact_obj);
    let manifest = serde_json::json!({
        "schema_version": CAMPAIGN_RUN_MANIFEST_SCHEMA_VERSION,
        "marker": CAMPAIGN_MARKER,
        "bead": "bd-cixqu.21.4",
        "campaign_id": bundle.campaign_id,
        "config_fingerprint": bundle.config_fingerprint,
        "generated_at_ns": bundle.generated_at_ns,
        "bundle_digest": bundle.bundle_digest,
        "outcome": "pass",
        "summary": {
            "candidates_explored": bundle.statistics.candidates_explored,
            "promoted": bundle.statistics.promoted,
            "rejected": bundle.statistics.rejected,
            "corpus_growth": bundle.statistics.corpus_growth,
        },
        "artifacts": artifact_map,
    });
    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_string())
}

fn render_summary(bundle: &CampaignBundle) -> String {
    let stats = &bundle.statistics;
    let mut out = String::new();
    out.push_str(&format!(
        "# Compounding red-team campaign — {}\n\n",
        bundle.campaign_id
    ));
    out.push_str(&format!("- marker: `{CAMPAIGN_MARKER}`\n"));
    out.push_str(&format!(
        "- config fingerprint: `{}`\n",
        bundle.config_fingerprint
    ));
    out.push_str(&format!("- bundle digest: `{}`\n\n", bundle.bundle_digest));
    out.push_str("## Statistics\n\n");
    out.push_str(&format!(
        "- candidates explored: {}\n",
        stats.candidates_explored
    ));
    out.push_str(&format!(
        "- novelty: {} novel / {} near-duplicate / {} duplicate\n",
        stats.novelty_distribution.novel,
        stats.novelty_distribution.near_duplicate,
        stats.novelty_distribution.duplicate,
    ));
    out.push_str(&format!("- promoted: {}\n", stats.promoted));
    out.push_str(&format!("- rejected: {}\n", stats.rejected));
    out.push_str(&format!(
        "- corpus growth: {} ({} -> {})\n\n",
        stats.corpus_growth, stats.corpus_size_before, stats.corpus_size_after
    ));
    out.push_str("## Promotion decisions\n\n");
    out.push_str("| candidate | vector | novelty | disposition |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for record in &bundle.explored {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            record.candidate_id, record.attack_vector, record.novelty.verdict, record.disposition
        ));
    }
    out.push('\n');
    out
}
