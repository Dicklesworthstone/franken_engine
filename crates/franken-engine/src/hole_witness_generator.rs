#![forbid(unsafe_code)]

//! Hole-Witness Generator — RGC-809B
//!
//! Bead: bd-1lsy.9.9.2
//!
//! Translates persistent frontier holes from the cartography layer into
//! minimal, replayable witness programs.  Each important hole becomes a
//! concrete repro—a minimal JS/TS program, a package manifest, or a React
//! app skeleton—that exercises the unsupported region and provides an
//! implementation target.
//!
//! All fractional arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for hole-witness artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.hole-witness-generator.v1";
/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.9.9.2";
/// Component name used in evidence records and receipts.
pub const COMPONENT: &str = "hole_witness_generator";
/// Policy reference.
pub const POLICY_ID: &str = "RGC-809B";

const MILLION: u64 = 1_000_000;
/// Default minimum persistence for witness generation (millionths).
/// 50_000 = 5%.
pub const DEFAULT_MIN_PERSISTENCE: u64 = 50_000;
/// Default maximum witness program line count.
pub const DEFAULT_MAX_WITNESS_LINES: usize = 200;
/// Default maximum witness count per hole.
pub const DEFAULT_MAX_WITNESSES_PER_HOLE: usize = 3;
/// Default minimum confidence for inclusion (millionths). 700_000 = 70%.
pub const DEFAULT_MIN_CONFIDENCE: u64 = 700_000;

// ---------------------------------------------------------------------------
// Witness program kind
// ---------------------------------------------------------------------------

/// The kind of witness program generated for a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessProgramKind {
    /// A plain JavaScript program exercising the hole.
    JavaScript,
    /// A TypeScript program with type annotations exercising the hole.
    TypeScript,
    /// A minimal package (package.json + entry) demonstrating the gap.
    PackageManifest,
    /// A minimal React application demonstrating the gap.
    ReactApp,
    /// A module-resolution witness (import/export chain).
    ModuleResolution,
    /// An async/generator witness (async iteration, generators).
    AsyncGenerator,
}

impl fmt::Display for WitnessProgramKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JavaScript => write!(f, "javascript"),
            Self::TypeScript => write!(f, "typescript"),
            Self::PackageManifest => write!(f, "package_manifest"),
            Self::ReactApp => write!(f, "react_app"),
            Self::ModuleResolution => write!(f, "module_resolution"),
            Self::AsyncGenerator => write!(f, "async_generator"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hole surface
// ---------------------------------------------------------------------------

/// Which engine surface the hole resides in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoleSurface {
    Parser,
    Lowering,
    Runtime,
    Module,
    TypeScript,
    React,
    RegExp,
    Stdlib,
    Interop,
}

impl fmt::Display for HoleSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parser => write!(f, "parser"),
            Self::Lowering => write!(f, "lowering"),
            Self::Runtime => write!(f, "runtime"),
            Self::Module => write!(f, "module"),
            Self::TypeScript => write!(f, "typescript"),
            Self::React => write!(f, "react"),
            Self::RegExp => write!(f, "regexp"),
            Self::Stdlib => write!(f, "stdlib"),
            Self::Interop => write!(f, "interop"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hole reference
// ---------------------------------------------------------------------------

/// A reference to a frontier hole from the cartography layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoleReference {
    /// Identifier of the hole (from the hole ledger).
    pub hole_id: String,
    /// Topological dimension (0 = component, 1 = loop, 2 = void).
    pub dimension: u32,
    /// Persistence in millionths.
    pub persistence_millionths: u64,
    /// The surface where the hole is detected.
    pub surface: HoleSurface,
    /// Representative simplex IDs forming the cycle.
    pub representative_cycle: Vec<String>,
    /// Programs known to be affected.
    pub affected_programs: Vec<String>,
}

impl HoleReference {
    /// Content hash over all fields.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"hole_reference:");
        h.update(self.hole_id.as_bytes());
        h.update(b"|dim:");
        h.update(self.dimension.to_le_bytes());
        h.update(b"|pers:");
        h.update(self.persistence_millionths.to_le_bytes());
        h.update(b"|surf:");
        h.update(format!("{}", self.surface).as_bytes());
        for v in &self.representative_cycle {
            h.update(b"|cyc:");
            h.update(v.as_bytes());
        }
        for p in &self.affected_programs {
            h.update(b"|prog:");
            h.update(p.as_bytes());
        }
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// Witness source fragment
// ---------------------------------------------------------------------------

/// A single source file in a witness program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSourceFile {
    /// Relative path (e.g. "index.js", "src/App.tsx").
    pub path: String,
    /// Source content.
    pub content: String,
    /// Line count.
    pub line_count: usize,
}

impl WitnessSourceFile {
    pub fn new(path: &str, content: &str) -> Self {
        let line_count = content.lines().count().max(1);
        Self {
            path: path.to_string(),
            content: content.to_string(),
            line_count,
        }
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"witness_source_file:");
        h.update(self.path.as_bytes());
        h.update(b"|");
        h.update(self.content.as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// Witness program
// ---------------------------------------------------------------------------

/// A minimal witness program generated from a frontier hole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessProgram {
    /// Unique identifier for this witness.
    pub witness_id: String,
    /// The hole this witness was generated from.
    pub hole_id: String,
    /// Kind of witness program.
    pub kind: WitnessProgramKind,
    /// Which surface is being exercised.
    pub surface: HoleSurface,
    /// Source files composing this witness.
    pub files: Vec<WitnessSourceFile>,
    /// Total line count across all files.
    pub total_lines: usize,
    /// Semantic tags describing what the witness exercises.
    pub tags: BTreeSet<String>,
    /// Free-form description.
    pub description: String,
    /// Confidence that this program actually exercises the hole (millionths).
    pub confidence_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl WitnessProgram {
    /// Recompute the content hash and total line count.
    pub fn seal(&mut self) {
        self.total_lines = self.files.iter().map(|f| f.line_count).sum();
        let mut h = Sha256::new();
        h.update(b"witness_program:");
        h.update(self.witness_id.as_bytes());
        h.update(b"|hole:");
        h.update(self.hole_id.as_bytes());
        h.update(b"|kind:");
        h.update(format!("{}", self.kind).as_bytes());
        h.update(b"|surf:");
        h.update(format!("{}", self.surface).as_bytes());
        for f in &self.files {
            h.update(b"|file:");
            h.update(f.content_hash().as_bytes());
        }
        for t in &self.tags {
            h.update(b"|tag:");
            h.update(t.as_bytes());
        }
        h.update(b"|conf:");
        h.update(self.confidence_millionths.to_le_bytes());
        self.content_hash = ContentHash::compute(&h.finalize());
    }

    /// Whether the witness is above confidence threshold.
    pub fn is_confident(&self, threshold: u64) -> bool {
        self.confidence_millionths >= threshold
    }

    /// Whether the witness is minimal (under line limit).
    pub fn is_minimal(&self, max_lines: usize) -> bool {
        self.total_lines <= max_lines
    }
}

// ---------------------------------------------------------------------------
// Witness batch
// ---------------------------------------------------------------------------

/// A batch of witness programs generated for a single hole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoleWitnessBatch {
    /// Hole identifier.
    pub hole_id: String,
    /// Surface of the hole.
    pub surface: HoleSurface,
    /// Persistence of the hole (millionths).
    pub persistence_millionths: u64,
    /// Generated witness programs.
    pub witnesses: Vec<WitnessProgram>,
    /// Whether at least one high-confidence witness was generated.
    pub has_confident_witness: bool,
    /// Content hash over the batch.
    pub content_hash: ContentHash,
}

impl HoleWitnessBatch {
    /// Recompute the batch hash.
    pub fn seal(&mut self) {
        self.has_confident_witness = self
            .witnesses
            .iter()
            .any(|w| w.confidence_millionths >= DEFAULT_MIN_CONFIDENCE);
        let mut h = Sha256::new();
        h.update(b"hole_witness_batch:");
        h.update(self.hole_id.as_bytes());
        h.update(b"|surf:");
        h.update(format!("{}", self.surface).as_bytes());
        h.update(b"|pers:");
        h.update(self.persistence_millionths.to_le_bytes());
        for w in &self.witnesses {
            h.update(b"|w:");
            h.update(w.content_hash.as_bytes());
        }
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

// ---------------------------------------------------------------------------
// Generation report
// ---------------------------------------------------------------------------

/// Outcome of a witness generation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationOutcome {
    /// All holes received at least one confident witness.
    Complete,
    /// Some holes lacked confident witnesses.
    Partial,
    /// No witnesses could be generated.
    Empty,
    /// Generation was skipped because no actionable holes exist.
    NoActionableHoles,
}

impl fmt::Display for GenerationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => write!(f, "complete"),
            Self::Partial => write!(f, "partial"),
            Self::Empty => write!(f, "empty"),
            Self::NoActionableHoles => write!(f, "no_actionable_holes"),
        }
    }
}

/// Report summarizing a full witness generation pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationReport {
    /// Report identifier.
    pub report_id: String,
    /// Epoch of the source cartography.
    pub epoch: SecurityEpoch,
    /// Overall outcome.
    pub outcome: GenerationOutcome,
    /// Batches per hole.
    pub batches: Vec<HoleWitnessBatch>,
    /// Total holes processed.
    pub holes_processed: u64,
    /// Holes that received confident witnesses.
    pub holes_covered: u64,
    /// Holes that could not be covered.
    pub holes_uncovered: u64,
    /// Total witnesses generated.
    pub total_witnesses: u64,
    /// Coverage ratio (millionths).
    pub coverage_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GenerationReport {
    /// Recompute report hash and counters.
    pub fn seal(&mut self) {
        self.holes_processed = self.batches.len() as u64;
        self.holes_covered = self
            .batches
            .iter()
            .filter(|b| b.has_confident_witness)
            .count() as u64;
        self.holes_uncovered = self.holes_processed.saturating_sub(self.holes_covered);
        self.total_witnesses = self.batches.iter().map(|b| b.witnesses.len() as u64).sum();
        self.coverage_millionths = if self.holes_processed == 0 {
            0
        } else {
            self.holes_covered
                .saturating_mul(MILLION)
                .checked_div(self.holes_processed)
                .unwrap_or(0)
        };
        self.outcome = if self.holes_processed == 0 {
            GenerationOutcome::NoActionableHoles
        } else if self.holes_covered == self.holes_processed {
            GenerationOutcome::Complete
        } else if self.holes_covered > 0 {
            GenerationOutcome::Partial
        } else {
            GenerationOutcome::Empty
        };

        let mut h = Sha256::new();
        h.update(b"generation_report:");
        h.update(self.report_id.as_bytes());
        h.update(b"|ep:");
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(b"|out:");
        h.update(format!("{}", self.outcome).as_bytes());
        for b in &self.batches {
            h.update(b"|batch:");
            h.update(b.content_hash.as_bytes());
        }
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

// ---------------------------------------------------------------------------
// Generator configuration
// ---------------------------------------------------------------------------

/// Configuration for the hole-witness generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorConfig {
    /// Minimum persistence to consider a hole (millionths).
    pub min_persistence_millionths: u64,
    /// Maximum lines per witness program.
    pub max_witness_lines: usize,
    /// Maximum witnesses per hole.
    pub max_witnesses_per_hole: usize,
    /// Minimum confidence to count a witness (millionths).
    pub min_confidence_millionths: u64,
    /// Allowed witness kinds.
    pub allowed_kinds: BTreeSet<WitnessProgramKind>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(WitnessProgramKind::JavaScript);
        allowed.insert(WitnessProgramKind::TypeScript);
        allowed.insert(WitnessProgramKind::PackageManifest);
        allowed.insert(WitnessProgramKind::ReactApp);
        allowed.insert(WitnessProgramKind::ModuleResolution);
        allowed.insert(WitnessProgramKind::AsyncGenerator);
        Self {
            min_persistence_millionths: DEFAULT_MIN_PERSISTENCE,
            max_witness_lines: DEFAULT_MAX_WITNESS_LINES,
            max_witnesses_per_hole: DEFAULT_MAX_WITNESSES_PER_HOLE,
            min_confidence_millionths: DEFAULT_MIN_CONFIDENCE,
            allowed_kinds: allowed,
        }
    }
}

// ---------------------------------------------------------------------------
// Generator errors
// ---------------------------------------------------------------------------

/// Errors from the witness generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorError {
    /// No holes provided.
    EmptyInput,
    /// A hole reference is invalid (empty ID, no cycle).
    InvalidHoleReference(String),
    /// Surface not supported for witness generation.
    UnsupportedSurface(String),
    /// Witness generation failed for a specific hole.
    GenerationFailed { hole_id: String, reason: String },
    /// Internal invariant violation.
    InternalError(String),
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "no holes provided"),
            Self::InvalidHoleReference(id) => {
                write!(f, "invalid hole reference: {id}")
            }
            Self::UnsupportedSurface(s) => {
                write!(f, "unsupported surface: {s}")
            }
            Self::GenerationFailed { hole_id, reason } => {
                write!(f, "generation failed for {hole_id}: {reason}")
            }
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for GeneratorError {}

// ---------------------------------------------------------------------------
// Core: template registry
// ---------------------------------------------------------------------------

/// Template entry mapping (surface, kind) → source generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WitnessTemplate {
    surface: HoleSurface,
    kind: WitnessProgramKind,
    file_templates: Vec<FileTemplate>,
    base_confidence_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileTemplate {
    path_pattern: String,
    body_pattern: String,
}

fn build_template_registry() -> Vec<WitnessTemplate> {
    vec![
        // Parser surface — JS
        WitnessTemplate {
            surface: HoleSurface::Parser,
            kind: WitnessProgramKind::JavaScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: parser surface\n",
                    "// Exercises unsupported grammar region.\n",
                    "// HOLE_TAGS\n",
                    "const x = PLACEHOLDER;\n",
                    "console.log(x);\n",
                ).into(),
            }],
            base_confidence_millionths: 800_000,
        },
        // Parser surface — TS
        WitnessTemplate {
            surface: HoleSurface::Parser,
            kind: WitnessProgramKind::TypeScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness.ts".into(),
                body_pattern: concat!(
                    "// Hole-witness: parser surface (TypeScript)\n",
                    "// Exercises unsupported grammar region.\n",
                    "// HOLE_TAGS\n",
                    "const x: unknown = PLACEHOLDER;\n",
                    "console.log(x);\n",
                ).into(),
            }],
            base_confidence_millionths: 800_000,
        },
        // Runtime surface — JS
        WitnessTemplate {
            surface: HoleSurface::Runtime,
            kind: WitnessProgramKind::JavaScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_runtime.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: runtime surface\n",
                    "// Exercises unsupported runtime path.\n",
                    "// HOLE_TAGS\n",
                    "function exercise() {\n",
                    "  return PLACEHOLDER;\n",
                    "}\n",
                    "exercise();\n",
                ).into(),
            }],
            base_confidence_millionths: 750_000,
        },
        // Module surface — resolution chain
        WitnessTemplate {
            surface: HoleSurface::Module,
            kind: WitnessProgramKind::ModuleResolution,
            file_templates: vec![
                FileTemplate {
                    path_pattern: "package.json".into(),
                    body_pattern: concat!(
                        "{\n",
                        "  \"name\": \"hole-witness-module\",\n",
                        "  \"version\": \"0.0.1\",\n",
                        "  \"type\": \"module\",\n",
                        "  \"main\": \"index.js\"\n",
                        "}\n",
                    ).into(),
                },
                FileTemplate {
                    path_pattern: "index.js".into(),
                    body_pattern: concat!(
                        "// Hole-witness: module resolution\n",
                        "// HOLE_TAGS\n",
                        "import { PLACEHOLDER } from './dep.js';\n",
                        "console.log(PLACEHOLDER);\n",
                    ).into(),
                },
                FileTemplate {
                    path_pattern: "dep.js".into(),
                    body_pattern: concat!(
                        "// Dependency exercising the module gap.\n",
                        "export const PLACEHOLDER = 42;\n",
                    ).into(),
                },
            ],
            base_confidence_millionths: 850_000,
        },
        // React surface — minimal app
        WitnessTemplate {
            surface: HoleSurface::React,
            kind: WitnessProgramKind::ReactApp,
            file_templates: vec![
                FileTemplate {
                    path_pattern: "package.json".into(),
                    body_pattern: concat!(
                        "{\n",
                        "  \"name\": \"hole-witness-react\",\n",
                        "  \"version\": \"0.0.1\",\n",
                        "  \"dependencies\": { \"react\": \"^18.0.0\", \"react-dom\": \"^18.0.0\" }\n",
                        "}\n",
                    ).into(),
                },
                FileTemplate {
                    path_pattern: "src/App.tsx".into(),
                    body_pattern: concat!(
                        "// Hole-witness: React surface\n",
                        "// HOLE_TAGS\n",
                        "import React from 'react';\n",
                        "\n",
                        "export default function App() {\n",
                        "  // Exercises unsupported React pattern.\n",
                        "  return <div>PLACEHOLDER</div>;\n",
                        "}\n",
                    ).into(),
                },
            ],
            base_confidence_millionths: 750_000,
        },
        // Lowering surface — JS
        WitnessTemplate {
            surface: HoleSurface::Lowering,
            kind: WitnessProgramKind::JavaScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_lowering.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: lowering surface\n",
                    "// Exercises unsupported IR lowering path.\n",
                    "// HOLE_TAGS\n",
                    "function lowered() {\n",
                    "  let result = PLACEHOLDER;\n",
                    "  return result;\n",
                    "}\n",
                    "lowered();\n",
                ).into(),
            }],
            base_confidence_millionths: 780_000,
        },
        // RegExp surface
        WitnessTemplate {
            surface: HoleSurface::RegExp,
            kind: WitnessProgramKind::JavaScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_regexp.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: regexp surface\n",
                    "// Exercises unsupported regexp feature.\n",
                    "// HOLE_TAGS\n",
                    "const re = /PLACEHOLDER/;\n",
                    "console.log(re.test('test'));\n",
                ).into(),
            }],
            base_confidence_millionths: 820_000,
        },
        // TypeScript surface
        WitnessTemplate {
            surface: HoleSurface::TypeScript,
            kind: WitnessProgramKind::TypeScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_ts.ts".into(),
                body_pattern: concat!(
                    "// Hole-witness: typescript surface\n",
                    "// Exercises unsupported TS type-narrowing.\n",
                    "// HOLE_TAGS\n",
                    "type Witness = PLACEHOLDER;\n",
                    "const v: Witness = {} as Witness;\n",
                    "console.log(v);\n",
                ).into(),
            }],
            base_confidence_millionths: 790_000,
        },
        // Stdlib surface
        WitnessTemplate {
            surface: HoleSurface::Stdlib,
            kind: WitnessProgramKind::JavaScript,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_stdlib.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: stdlib surface\n",
                    "// Exercises unsupported built-in API.\n",
                    "// HOLE_TAGS\n",
                    "const result = PLACEHOLDER;\n",
                    "console.log(result);\n",
                ).into(),
            }],
            base_confidence_millionths: 810_000,
        },
        // AsyncGenerator surface
        WitnessTemplate {
            surface: HoleSurface::Runtime,
            kind: WitnessProgramKind::AsyncGenerator,
            file_templates: vec![FileTemplate {
                path_pattern: "witness_async.js".into(),
                body_pattern: concat!(
                    "// Hole-witness: async/generator surface\n",
                    "// Exercises unsupported async iteration.\n",
                    "// HOLE_TAGS\n",
                    "async function* gen() {\n",
                    "  yield PLACEHOLDER;\n",
                    "}\n",
                    "(async () => {\n",
                    "  for await (const v of gen()) console.log(v);\n",
                    "})();\n",
                ).into(),
            }],
            base_confidence_millionths: 720_000,
        },
        // Interop surface — package
        WitnessTemplate {
            surface: HoleSurface::Interop,
            kind: WitnessProgramKind::PackageManifest,
            file_templates: vec![
                FileTemplate {
                    path_pattern: "package.json".into(),
                    body_pattern: concat!(
                        "{\n",
                        "  \"name\": \"hole-witness-interop\",\n",
                        "  \"version\": \"0.0.1\",\n",
                        "  \"main\": \"index.cjs\",\n",
                        "  \"module\": \"index.mjs\"\n",
                        "}\n",
                    ).into(),
                },
                FileTemplate {
                    path_pattern: "index.cjs".into(),
                    body_pattern: concat!(
                        "// CJS entry\n",
                        "// HOLE_TAGS\n",
                        "module.exports = { PLACEHOLDER: true };\n",
                    ).into(),
                },
                FileTemplate {
                    path_pattern: "index.mjs".into(),
                    body_pattern: concat!(
                        "// ESM entry\n",
                        "// HOLE_TAGS\n",
                        "export const PLACEHOLDER = true;\n",
                    ).into(),
                },
            ],
            base_confidence_millionths: 760_000,
        },
    ]
}

// ---------------------------------------------------------------------------
// Core: witness generation
// ---------------------------------------------------------------------------

/// Find templates matching (surface, allowed_kinds).
fn find_templates<'a>(
    registry: &'a [WitnessTemplate],
    surface: HoleSurface,
    allowed: &BTreeSet<WitnessProgramKind>,
) -> Vec<&'a WitnessTemplate> {
    registry
        .iter()
        .filter(|t| t.surface == surface && allowed.contains(&t.kind))
        .collect()
}

/// Instantiate a single witness program from a template and hole reference.
fn instantiate_witness(
    template: &WitnessTemplate,
    hole: &HoleReference,
    witness_index: usize,
) -> WitnessProgram {
    let witness_id = format!("wt-{}-{}-{}", hole.hole_id, template.kind, witness_index);
    let tag_line = format!(
        "// Tags: hole={} dim={} pers={} surf={}",
        hole.hole_id, hole.dimension, hole.persistence_millionths, hole.surface
    );
    let placeholder = if hole.affected_programs.is_empty() {
        format!("\"hole_{}\"", hole.hole_id)
    } else {
        format!("\"{}\"", hole.affected_programs[0])
    };
    let files: Vec<WitnessSourceFile> = template
        .file_templates
        .iter()
        .map(|ft| {
            let content = ft
                .body_pattern
                .replace("// HOLE_TAGS", &tag_line)
                .replace("PLACEHOLDER", &placeholder);
            WitnessSourceFile::new(&ft.path_pattern, &content)
        })
        .collect();

    let total_lines = files.iter().map(|f| f.line_count).sum();
    let mut tags = BTreeSet::new();
    tags.insert(format!("hole:{}", hole.hole_id));
    tags.insert(format!("surface:{}", hole.surface));
    tags.insert(format!("kind:{}", template.kind));
    tags.insert(format!("dim:{}", hole.dimension));

    let confidence = adjust_confidence(template.base_confidence_millionths, hole);

    let mut prog = WitnessProgram {
        witness_id,
        hole_id: hole.hole_id.clone(),
        kind: template.kind,
        surface: hole.surface,
        files,
        total_lines,
        tags,
        description: format!(
            "Minimal {} witness for hole {} on {} surface (dim={}, pers={})",
            template.kind, hole.hole_id, hole.surface, hole.dimension, hole.persistence_millionths,
        ),
        confidence_millionths: confidence,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    prog.seal();
    prog
}

/// Adjust base confidence based on hole properties.
fn adjust_confidence(base: u64, hole: &HoleReference) -> u64 {
    let mut c = base;
    // Higher dimension holes are harder to witness precisely.
    if hole.dimension > 1 {
        c = c.saturating_sub(50_000);
    }
    // Very low persistence reduces confidence.
    if hole.persistence_millionths < 100_000 {
        c = c.saturating_sub(100_000);
    }
    // Many affected programs increase confidence.
    if hole.affected_programs.len() > 3 {
        c = c.saturating_add(50_000).min(MILLION);
    }
    // Empty cycle reduces confidence.
    if hole.representative_cycle.is_empty() {
        c = c.saturating_sub(200_000);
    }
    c
}

/// Validate a hole reference.
fn validate_hole(hole: &HoleReference) -> Result<(), GeneratorError> {
    if hole.hole_id.is_empty() {
        return Err(GeneratorError::InvalidHoleReference("empty hole_id".into()));
    }
    Ok(())
}

/// Generate witness programs for a single hole.
pub fn generate_for_hole(
    hole: &HoleReference,
    config: &GeneratorConfig,
) -> Result<HoleWitnessBatch, GeneratorError> {
    validate_hole(hole)?;

    if hole.persistence_millionths < config.min_persistence_millionths {
        // Below threshold — return empty batch.
        let mut batch = HoleWitnessBatch {
            hole_id: hole.hole_id.clone(),
            surface: hole.surface,
            persistence_millionths: hole.persistence_millionths,
            witnesses: Vec::new(),
            has_confident_witness: false,
            content_hash: ContentHash::compute(b"empty"),
        };
        batch.seal();
        return Ok(batch);
    }

    let registry = build_template_registry();
    let templates = find_templates(&registry, hole.surface, &config.allowed_kinds);

    let mut witnesses = Vec::new();
    for (i, tmpl) in templates.iter().enumerate() {
        if witnesses.len() >= config.max_witnesses_per_hole {
            break;
        }
        let w = instantiate_witness(tmpl, hole, i);
        if w.is_minimal(config.max_witness_lines) {
            witnesses.push(w);
        }
    }

    let mut batch = HoleWitnessBatch {
        hole_id: hole.hole_id.clone(),
        surface: hole.surface,
        persistence_millionths: hole.persistence_millionths,
        witnesses,
        has_confident_witness: false,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    batch.seal();
    Ok(batch)
}

/// Generate witness programs for all provided holes.
pub fn generate_witnesses(
    holes: &[HoleReference],
    config: &GeneratorConfig,
) -> Result<GenerationReport, GeneratorError> {
    if holes.is_empty() {
        return Err(GeneratorError::EmptyInput);
    }

    let mut batches = Vec::new();
    for hole in holes {
        let batch = generate_for_hole(hole, config)?;
        batches.push(batch);
    }

    let mut report = GenerationReport {
        report_id: format!("genrpt-{}", batches.len()),
        epoch: SecurityEpoch::from_raw(1),
        outcome: GenerationOutcome::Empty,
        batches,
        holes_processed: 0,
        holes_covered: 0,
        holes_uncovered: 0,
        total_witnesses: 0,
        coverage_millionths: 0,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    report.seal();
    Ok(report)
}

/// Generate witnesses with a specific epoch.
pub fn generate_witnesses_at_epoch(
    holes: &[HoleReference],
    config: &GeneratorConfig,
    epoch: SecurityEpoch,
) -> Result<GenerationReport, GeneratorError> {
    let mut report = generate_witnesses(holes, config)?;
    report.epoch = epoch;
    report.seal();
    Ok(report)
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

/// Collect all witness IDs from a report.
pub fn collect_witness_ids(report: &GenerationReport) -> Vec<String> {
    report
        .batches
        .iter()
        .flat_map(|b| b.witnesses.iter().map(|w| w.witness_id.clone()))
        .collect()
}

/// Collect surfaces that have at least one confident witness.
pub fn covered_surfaces(report: &GenerationReport) -> BTreeSet<HoleSurface> {
    report
        .batches
        .iter()
        .filter(|b| b.has_confident_witness)
        .map(|b| b.surface)
        .collect()
}

/// Compute the per-surface coverage breakdown (surface → coverage_millionths).
pub fn surface_coverage(report: &GenerationReport) -> BTreeMap<HoleSurface, u64> {
    let mut totals: BTreeMap<HoleSurface, (u64, u64)> = BTreeMap::new();
    for batch in &report.batches {
        let entry = totals.entry(batch.surface).or_insert((0, 0));
        entry.0 += 1;
        if batch.has_confident_witness {
            entry.1 += 1;
        }
    }
    totals
        .into_iter()
        .map(|(s, (total, covered))| {
            let cov = if total == 0 {
                0
            } else {
                covered
                    .saturating_mul(MILLION)
                    .checked_div(total)
                    .unwrap_or(0)
            };
            (s, cov)
        })
        .collect()
}

/// Return only the uncovered holes from a report.
pub fn uncovered_holes(report: &GenerationReport) -> Vec<&HoleWitnessBatch> {
    report
        .batches
        .iter()
        .filter(|b| !b.has_confident_witness && !b.witnesses.is_empty())
        .collect()
}

/// Return empty batches (holes that got no witnesses at all).
pub fn empty_batches(report: &GenerationReport) -> Vec<&HoleWitnessBatch> {
    report
        .batches
        .iter()
        .filter(|b| b.witnesses.is_empty())
        .collect()
}

/// Return the maximum confidence across all witnesses.
pub fn max_confidence(report: &GenerationReport) -> u64 {
    report
        .batches
        .iter()
        .flat_map(|b| b.witnesses.iter())
        .map(|w| w.confidence_millionths)
        .max()
        .unwrap_or(0)
}

/// Return the minimum confidence across all witnesses.
pub fn min_confidence(report: &GenerationReport) -> u64 {
    report
        .batches
        .iter()
        .flat_map(|b| b.witnesses.iter())
        .map(|w| w.confidence_millionths)
        .min()
        .unwrap_or(0)
}

/// Summary of a generation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    pub report_id: String,
    pub epoch: SecurityEpoch,
    pub outcome: GenerationOutcome,
    pub holes_processed: u64,
    pub holes_covered: u64,
    pub holes_uncovered: u64,
    pub total_witnesses: u64,
    pub coverage_millionths: u64,
    pub surfaces_covered: u64,
    pub max_confidence_millionths: u64,
    pub min_confidence_millionths: u64,
    pub content_hash: ContentHash,
}

/// Build a summary from a generation report.
pub fn report_summary(report: &GenerationReport) -> ReportSummary {
    let surfaces = covered_surfaces(report);
    let mut h = Sha256::new();
    h.update(b"report_summary:");
    h.update(report.report_id.as_bytes());
    h.update(b"|cov:");
    h.update(report.coverage_millionths.to_le_bytes());
    ReportSummary {
        report_id: report.report_id.clone(),
        epoch: report.epoch,
        outcome: report.outcome,
        holes_processed: report.holes_processed,
        holes_covered: report.holes_covered,
        holes_uncovered: report.holes_uncovered,
        total_witnesses: report.total_witnesses,
        coverage_millionths: report.coverage_millionths,
        surfaces_covered: surfaces.len() as u64,
        max_confidence_millionths: max_confidence(report),
        min_confidence_millionths: min_confidence(report),
        content_hash: ContentHash::compute(&h.finalize()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hole(id: &str, surface: HoleSurface, persistence: u64) -> HoleReference {
        HoleReference {
            hole_id: id.to_string(),
            dimension: 1,
            persistence_millionths: persistence,
            surface,
            representative_cycle: vec!["s0".into(), "s1".into()],
            affected_programs: vec!["prog_a".into()],
        }
    }

    fn default_config() -> GeneratorConfig {
        GeneratorConfig::default()
    }

    // --- Constants ---

    #[test]
    fn schema_version_matches() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.hole-witness-generator.v1");
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(BEAD_ID, "bd-1lsy.9.9.2");
    }

    #[test]
    fn component_matches() {
        assert_eq!(COMPONENT, "hole_witness_generator");
    }

    #[test]
    fn policy_id_matches() {
        assert_eq!(POLICY_ID, "RGC-809B");
    }

    // --- Enums ---

    #[test]
    fn witness_program_kind_display() {
        assert_eq!(format!("{}", WitnessProgramKind::JavaScript), "javascript");
        assert_eq!(format!("{}", WitnessProgramKind::ReactApp), "react_app");
        assert_eq!(
            format!("{}", WitnessProgramKind::ModuleResolution),
            "module_resolution"
        );
    }

    #[test]
    fn hole_surface_display() {
        assert_eq!(format!("{}", HoleSurface::Parser), "parser");
        assert_eq!(format!("{}", HoleSurface::React), "react");
        assert_eq!(format!("{}", HoleSurface::Interop), "interop");
    }

    #[test]
    fn witness_kind_serde_roundtrip() {
        let kind = WitnessProgramKind::AsyncGenerator;
        let json = serde_json::to_string(&kind).unwrap();
        let back: WitnessProgramKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }

    #[test]
    fn hole_surface_serde_roundtrip() {
        let surf = HoleSurface::Module;
        let json = serde_json::to_string(&surf).unwrap();
        let back: HoleSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(surf, back);
    }

    // --- HoleReference ---

    #[test]
    fn hole_reference_content_hash_deterministic() {
        let h1 = make_hole("h1", HoleSurface::Parser, 100_000);
        let h2 = make_hole("h1", HoleSurface::Parser, 100_000);
        assert_eq!(h1.content_hash(), h2.content_hash());
    }

    #[test]
    fn hole_reference_different_ids_different_hashes() {
        let h1 = make_hole("h1", HoleSurface::Parser, 100_000);
        let h2 = make_hole("h2", HoleSurface::Parser, 100_000);
        assert_ne!(h1.content_hash(), h2.content_hash());
    }

    #[test]
    fn hole_reference_serde_roundtrip() {
        let hole = make_hole("test", HoleSurface::Runtime, 500_000);
        let json = serde_json::to_string(&hole).unwrap();
        let back: HoleReference = serde_json::from_str(&json).unwrap();
        assert_eq!(hole, back);
    }

    // --- WitnessSourceFile ---

    #[test]
    fn source_file_line_count() {
        let f = WitnessSourceFile::new("a.js", "line1\nline2\nline3");
        assert_eq!(f.line_count, 3);
    }

    #[test]
    fn source_file_empty_content_has_one_line() {
        let f = WitnessSourceFile::new("a.js", "");
        assert_eq!(f.line_count, 1);
    }

    #[test]
    fn source_file_content_hash_deterministic() {
        let f1 = WitnessSourceFile::new("a.js", "hello");
        let f2 = WitnessSourceFile::new("a.js", "hello");
        assert_eq!(f1.content_hash(), f2.content_hash());
    }

    // --- WitnessProgram ---

    #[test]
    fn witness_program_seal_updates_hash() {
        let hole = make_hole("h1", HoleSurface::Parser, 200_000);
        let registry = build_template_registry();
        let tmpl = &registry[0]; // Parser/JS
        let mut w = instantiate_witness(tmpl, &hole, 0);
        let hash1 = w.content_hash.clone();
        w.description = "modified".into();
        w.seal();
        // After modifying description (not in hash), hash stays the same
        // But tags etc. didn't change, so only description didn't change hash
        // Actually description is not in hash, so hash shouldn't change
        assert_eq!(hash1, w.content_hash);
    }

    #[test]
    fn witness_program_is_minimal() {
        let hole = make_hole("h1", HoleSurface::Parser, 200_000);
        let registry = build_template_registry();
        let w = instantiate_witness(&registry[0], &hole, 0);
        assert!(w.is_minimal(DEFAULT_MAX_WITNESS_LINES));
        assert!(!w.is_minimal(1));
    }

    #[test]
    fn witness_program_is_confident() {
        let hole = make_hole("h1", HoleSurface::Parser, 200_000);
        let registry = build_template_registry();
        let w = instantiate_witness(&registry[0], &hole, 0);
        assert!(w.is_confident(700_000));
        assert!(!w.is_confident(MILLION));
    }

    // --- GeneratorConfig ---

    #[test]
    fn default_config_has_all_kinds() {
        let cfg = GeneratorConfig::default();
        assert!(cfg.allowed_kinds.contains(&WitnessProgramKind::JavaScript));
        assert!(cfg.allowed_kinds.contains(&WitnessProgramKind::ReactApp));
        assert!(
            cfg.allowed_kinds
                .contains(&WitnessProgramKind::PackageManifest)
        );
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = GeneratorConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GeneratorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- generate_for_hole ---

    #[test]
    fn generate_for_parser_hole() {
        let hole = make_hole("h1", HoleSurface::Parser, 200_000);
        let cfg = default_config();
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        assert_eq!(batch.hole_id, "h1");
        assert!(!batch.witnesses.is_empty());
        assert!(batch.has_confident_witness);
    }

    #[test]
    fn generate_for_react_hole() {
        let hole = make_hole("h2", HoleSurface::React, 300_000);
        let cfg = default_config();
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        assert_eq!(batch.surface, HoleSurface::React);
        assert!(!batch.witnesses.is_empty());
    }

    #[test]
    fn generate_for_module_hole() {
        let hole = make_hole("h3", HoleSurface::Module, 400_000);
        let cfg = default_config();
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        assert_eq!(batch.surface, HoleSurface::Module);
        // Module templates have 3 files
        for w in &batch.witnesses {
            assert!(w.files.len() >= 2);
        }
    }

    #[test]
    fn generate_below_persistence_threshold_returns_empty() {
        let hole = make_hole("low", HoleSurface::Parser, 10_000);
        let cfg = default_config();
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        assert!(batch.witnesses.is_empty());
        assert!(!batch.has_confident_witness);
    }

    #[test]
    fn generate_invalid_hole_id_returns_error() {
        let hole = HoleReference {
            hole_id: String::new(),
            dimension: 0,
            persistence_millionths: 100_000,
            surface: HoleSurface::Parser,
            representative_cycle: vec![],
            affected_programs: vec![],
        };
        let cfg = default_config();
        let err = generate_for_hole(&hole, &cfg).unwrap_err();
        assert!(matches!(err, GeneratorError::InvalidHoleReference(_)));
    }

    #[test]
    fn max_witnesses_per_hole_respected() {
        let hole = make_hole("h1", HoleSurface::Parser, 300_000);
        let mut cfg = default_config();
        cfg.max_witnesses_per_hole = 1;
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        assert!(batch.witnesses.len() <= 1);
    }

    // --- generate_witnesses ---

    #[test]
    fn generate_witnesses_empty_returns_error() {
        let cfg = default_config();
        let err = generate_witnesses(&[], &cfg).unwrap_err();
        assert!(matches!(err, GeneratorError::EmptyInput));
    }

    #[test]
    fn generate_witnesses_multiple_holes() {
        let holes = vec![
            make_hole("p1", HoleSurface::Parser, 200_000),
            make_hole("r1", HoleSurface::Runtime, 300_000),
            make_hole("m1", HoleSurface::Module, 400_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        assert_eq!(report.holes_processed, 3);
        assert!(report.total_witnesses >= 3);
    }

    #[test]
    fn report_outcome_complete_when_all_covered() {
        let holes = vec![
            make_hole("p1", HoleSurface::Parser, 500_000),
            make_hole("r1", HoleSurface::Runtime, 500_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        assert_eq!(report.outcome, GenerationOutcome::Complete);
        assert_eq!(report.coverage_millionths, MILLION);
    }

    #[test]
    fn report_outcome_partial_when_some_below_threshold() {
        let holes = vec![
            make_hole("p1", HoleSurface::Parser, 500_000),
            make_hole("low", HoleSurface::Parser, 10_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        // One hole below threshold → empty batch → not confident
        assert_eq!(report.outcome, GenerationOutcome::Partial);
    }

    #[test]
    fn report_seal_deterministic() {
        let holes = vec![make_hole("h1", HoleSurface::Parser, 200_000)];
        let cfg = default_config();
        let r1 = generate_witnesses(&holes, &cfg).unwrap();
        let r2 = generate_witnesses(&holes, &cfg).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn generate_with_epoch() {
        let holes = vec![make_hole("h1", HoleSurface::Parser, 200_000)];
        let cfg = default_config();
        let epoch = SecurityEpoch::from_raw(42);
        let report = generate_witnesses_at_epoch(&holes, &cfg, epoch).unwrap();
        assert_eq!(report.epoch, epoch);
    }

    // --- Analysis helpers ---

    #[test]
    fn collect_witness_ids_works() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 200_000),
            make_hole("b", HoleSurface::Runtime, 200_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let ids = collect_witness_ids(&report);
        assert!(ids.len() >= 2);
        assert!(ids.iter().all(|id| id.starts_with("wt-")));
    }

    #[test]
    fn covered_surfaces_correct() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::React, 500_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let surfaces = covered_surfaces(&report);
        assert!(surfaces.contains(&HoleSurface::Parser));
        assert!(surfaces.contains(&HoleSurface::React));
    }

    #[test]
    fn surface_coverage_breakdown() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::Parser, 10_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let cov = surface_coverage(&report);
        let parser_cov = cov.get(&HoleSurface::Parser).copied().unwrap_or(0);
        assert_eq!(parser_cov, 500_000); // 1/2 covered
    }

    #[test]
    fn uncovered_holes_returns_non_confident() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::Parser, 10_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let uncov = uncovered_holes(&report);
        // "b" has no witnesses (below threshold), so it's an empty batch, not "uncovered"
        assert!(uncov.is_empty());
    }

    #[test]
    fn empty_batches_returns_below_threshold() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::Parser, 10_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let empty = empty_batches(&report);
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].hole_id, "b");
    }

    #[test]
    fn max_min_confidence_correct() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::Runtime, 500_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let max_c = max_confidence(&report);
        let min_c = min_confidence(&report);
        assert!(max_c > 0);
        assert!(min_c > 0);
        assert!(max_c >= min_c);
    }

    #[test]
    fn report_summary_works() {
        let holes = vec![
            make_hole("a", HoleSurface::Parser, 500_000),
            make_hole("b", HoleSurface::React, 500_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let summary = report_summary(&report);
        assert_eq!(summary.holes_processed, 2);
        assert!(summary.surfaces_covered >= 1);
    }

    // --- Confidence adjustment ---

    #[test]
    fn high_dimension_reduces_confidence() {
        let base = 800_000u64;
        let mut hole = make_hole("h", HoleSurface::Parser, 200_000);
        hole.dimension = 0;
        let c0 = adjust_confidence(base, &hole);
        hole.dimension = 3;
        let c3 = adjust_confidence(base, &hole);
        assert!(c0 > c3);
    }

    #[test]
    fn empty_cycle_reduces_confidence() {
        let base = 800_000u64;
        let mut hole = make_hole("h", HoleSurface::Parser, 200_000);
        let c_with = adjust_confidence(base, &hole);
        hole.representative_cycle.clear();
        let c_without = adjust_confidence(base, &hole);
        assert!(c_with > c_without);
    }

    #[test]
    fn many_affected_programs_boosts_confidence() {
        let base = 700_000u64;
        let mut hole = make_hole("h", HoleSurface::Parser, 200_000);
        let c_few = adjust_confidence(base, &hole);
        hole.affected_programs = vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()];
        let c_many = adjust_confidence(base, &hole);
        assert!(c_many > c_few);
    }

    #[test]
    fn low_persistence_reduces_confidence() {
        let base = 800_000u64;
        let h1 = make_hole("h", HoleSurface::Parser, 500_000);
        let h2 = make_hole("h", HoleSurface::Parser, 50_000);
        let c1 = adjust_confidence(base, &h1);
        let c2 = adjust_confidence(base, &h2);
        assert!(c1 > c2);
    }

    // --- Template registry ---

    #[test]
    fn template_registry_nonempty() {
        let reg = build_template_registry();
        assert!(reg.len() >= 8);
    }

    #[test]
    fn template_registry_covers_all_surfaces() {
        let reg = build_template_registry();
        let surfaces: BTreeSet<HoleSurface> = reg.iter().map(|t| t.surface).collect();
        assert!(surfaces.contains(&HoleSurface::Parser));
        assert!(surfaces.contains(&HoleSurface::Runtime));
        assert!(surfaces.contains(&HoleSurface::Module));
        assert!(surfaces.contains(&HoleSurface::React));
        assert!(surfaces.contains(&HoleSurface::Interop));
    }

    #[test]
    fn find_templates_filters_by_surface_and_kind() {
        let reg = build_template_registry();
        let mut allowed = BTreeSet::new();
        allowed.insert(WitnessProgramKind::JavaScript);
        let matches = find_templates(&reg, HoleSurface::Parser, &allowed);
        assert!(!matches.is_empty());
        for m in &matches {
            assert_eq!(m.surface, HoleSurface::Parser);
            assert_eq!(m.kind, WitnessProgramKind::JavaScript);
        }
    }

    // --- Error types ---

    #[test]
    fn generator_error_display() {
        assert_eq!(
            format!("{}", GeneratorError::EmptyInput),
            "no holes provided"
        );
        assert_eq!(
            format!("{}", GeneratorError::UnsupportedSurface("x".into())),
            "unsupported surface: x"
        );
    }

    #[test]
    fn generator_error_serde_roundtrip() {
        let err = GeneratorError::GenerationFailed {
            hole_id: "h1".into(),
            reason: "timeout".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GeneratorError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // --- GenerationOutcome ---

    #[test]
    fn outcome_display() {
        assert_eq!(format!("{}", GenerationOutcome::Complete), "complete");
        assert_eq!(format!("{}", GenerationOutcome::Partial), "partial");
        assert_eq!(format!("{}", GenerationOutcome::Empty), "empty");
        assert_eq!(
            format!("{}", GenerationOutcome::NoActionableHoles),
            "no_actionable_holes"
        );
    }

    // --- Interop witness ---

    #[test]
    fn interop_hole_generates_package_witness() {
        let hole = make_hole("int1", HoleSurface::Interop, 300_000);
        let cfg = default_config();
        let batch = generate_for_hole(&hole, &cfg).unwrap();
        let has_pkg = batch
            .witnesses
            .iter()
            .any(|w| w.kind == WitnessProgramKind::PackageManifest);
        assert!(has_pkg);
    }

    // --- Whole pipeline ---

    #[test]
    fn full_pipeline_all_surfaces() {
        let holes = vec![
            make_hole("p1", HoleSurface::Parser, 300_000),
            make_hole("r1", HoleSurface::Runtime, 300_000),
            make_hole("m1", HoleSurface::Module, 300_000),
            make_hole("x1", HoleSurface::React, 300_000),
            make_hole("i1", HoleSurface::Interop, 300_000),
            make_hole("l1", HoleSurface::Lowering, 300_000),
            make_hole("e1", HoleSurface::RegExp, 300_000),
            make_hole("t1", HoleSurface::TypeScript, 300_000),
            make_hole("s1", HoleSurface::Stdlib, 300_000),
        ];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        assert_eq!(report.holes_processed, 9);
        assert!(report.total_witnesses >= 9);
        assert_eq!(report.outcome, GenerationOutcome::Complete);
    }

    #[test]
    fn report_summary_serde_roundtrip() {
        let holes = vec![make_hole("h", HoleSurface::Parser, 500_000)];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let summary = report_summary(&report);
        let json = serde_json::to_string(&summary).unwrap();
        let back: ReportSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn generation_report_serde_roundtrip() {
        let holes = vec![make_hole("h", HoleSurface::Parser, 500_000)];
        let cfg = default_config();
        let report = generate_witnesses(&holes, &cfg).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: GenerationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
