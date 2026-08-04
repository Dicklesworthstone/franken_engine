//! Negative tests for cosmetic red-team variants counted as non-novel.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use frankenengine_engine::novelty_scoring_contract::{
    CandidateKind, MILLIONTHS, NoveltyCandidate, NoveltyVerdict, ScoringConfig,
    SemanticNoveltyVerdict, classify_semantic_novelty, score_batch,
};
use serde_json::json;

const BEAD_ID: &str = "bd-cixqu.21.5";
const EVENT_SCHEMA: &str = "franken-engine.red-team-cosmetic-variant-rejection.v1";

struct Scenario {
    id: &'static str,
    source: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "ambient_authority_via_globalthis",
        source: include_str!("red_team_scenarios/ambient_authority_via_globalthis.js"),
    },
    Scenario {
        id: "capability_shadowed_import",
        source: include_str!("red_team_scenarios/capability_shadowed_import.js"),
    },
    Scenario {
        id: "computed_member_capability_evasion",
        source: include_str!("red_team_scenarios/computed_member_capability_evasion.js"),
    },
    Scenario {
        id: "declassification_without_receipt",
        source: include_str!("red_team_scenarios/declassification_without_receipt.js"),
    },
    Scenario {
        id: "dynamic_import_capability_evasion",
        source: include_str!("red_team_scenarios/dynamic_import_capability_evasion.js"),
    },
    Scenario {
        id: "environment_variable_exfiltration",
        source: include_str!("red_team_scenarios/environment_variable_exfiltration.js"),
    },
    Scenario {
        id: "eval_capability_evasion",
        source: include_str!("red_team_scenarios/eval_capability_evasion.js"),
    },
    Scenario {
        id: "function_constructor_evasion",
        source: include_str!("red_team_scenarios/function_constructor_evasion.js"),
    },
    Scenario {
        id: "process_privilege_surface_probe",
        source: include_str!("red_team_scenarios/process_privilege_surface_probe.js"),
    },
    Scenario {
        id: "prototype_pollution_capability_escape",
        source: include_str!("red_team_scenarios/prototype_pollution_capability_escape.js"),
    },
    Scenario {
        id: "proxy_trap_authority_smuggling",
        source: include_str!("red_team_scenarios/proxy_trap_authority_smuggling.js"),
    },
    Scenario {
        id: "reflect_apply_authority_smuggling",
        source: include_str!("red_team_scenarios/reflect_apply_authority_smuggling.js"),
    },
    Scenario {
        id: "shell_command_injection_package_script",
        source: include_str!("red_team_scenarios/shell_command_injection_package_script.js"),
    },
    Scenario {
        id: "supply_chain_backdoor_execution",
        source: include_str!("red_team_scenarios/supply_chain_backdoor_execution.js"),
    },
    Scenario {
        id: "typed_effect_laundering_downcast",
        source: include_str!("red_team_scenarios/typed_effect_laundering_downcast.js"),
    },
    Scenario {
        id: "with_block_scope_smuggling",
        source: include_str!("red_team_scenarios/with_block_scope_smuggling.js"),
    },
];

fn scenario_fixture_ids_from_disk() -> Vec<String> {
    let scenario_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/red_team_scenarios");
    let mut ids = std::fs::read_dir(&scenario_dir)
        .unwrap_or_else(|err| {
            panic!(
                "red_team_cosmetic_variant_rejection could not read {scenario_dir:?}: {err}"
            )
        })
        .filter_map(|entry| {
            let path = entry
                .unwrap_or_else(|err| {
                    panic!(
                        "red_team_cosmetic_variant_rejection could not read scenario entry: {err}"
                    )
                })
                .path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("js") {
                return None;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_else(|| {
                    panic!(
                        "red_team_cosmetic_variant_rejection scenario path has no UTF-8 stem: {path:?}"
                    )
                });
            Some(stem.to_owned())
        })
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

#[derive(Clone, Copy)]
enum CosmeticVariantKind {
    VariableRename,
    StatementReorder,
    NoopInsertion,
    WhitespaceCommentPerturbation,
}

impl CosmeticVariantKind {
    const ALL: &[Self] = &[
        Self::VariableRename,
        Self::StatementReorder,
        Self::NoopInsertion,
        Self::WhitespaceCommentPerturbation,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::VariableRename => "variable_rename",
            Self::StatementReorder => "statement_reorder",
            Self::NoopInsertion => "noop_insertion",
            Self::WhitespaceCommentPerturbation => "whitespace_comment_perturbation",
        }
    }

    fn accepts_non_distinct_verdict(self, verdict: SemanticNoveltyVerdict) -> bool {
        match self {
            Self::VariableRename => matches!(
                verdict,
                SemanticNoveltyVerdict::Duplicate | SemanticNoveltyVerdict::NearDuplicate
            ),
            Self::StatementReorder | Self::NoopInsertion | Self::WhitespaceCommentPerturbation => {
                verdict == SemanticNoveltyVerdict::Duplicate
            }
        }
    }
}

fn red_team_cosmetic_variant_rejection_candidate(id: String, source: &str) -> NoveltyCandidate {
    NoveltyCandidate::new(
        id,
        CandidateKind::Program,
        (source.len() as u64).saturating_mul(8),
        red_team_cosmetic_variant_rejection_features(source),
        source.as_bytes(),
    )
}

fn red_team_cosmetic_variant_rejection_features(source: &str) -> Vec<u64> {
    let normalized = strip_comments_preserving_strings(source).to_ascii_lowercase();
    [
        &["frankenhostcall", "capability", "permission"][..],
        &["eval", "function constructor", "new function"][..],
        &["process", "env", "environment"][..],
        &["import", "require", "package", "script"][..],
        &["prototype", "__proto__", "proxy", "reflect"][..],
        &["globalthis", "constructor", "computed", "member"][..],
        &["declass", "receipt", "effect", "typed", "downcast"][..],
        &["filesystem", "shell", "command", "write", "exfil"][..],
    ]
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

fn strip_comments_preserving_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' || c == '`' {
            copy_quoted(&chars, &mut i, &mut out);
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.push('\n');
            continue;
        }
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(' ');
            continue;
        }

        out.push(c);
        i += 1;
    }

    out
}

fn cosmetic_variant_source(kind: CosmeticVariantKind, source: &str) -> String {
    match kind {
        CosmeticVariantKind::VariableRename => rename_identifiers_preserving_strings(source),
        CosmeticVariantKind::StatementReorder => format!(
            "/* {BEAD_ID} reordered independent no-op statements */\n\
             const __bd_cixqu_21_5_noop_b = 2;\n\
             const __bd_cixqu_21_5_noop_a = 1;\n\
             {source}\n\
             void __bd_cixqu_21_5_noop_a;\n\
             void __bd_cixqu_21_5_noop_b;\n"
        ),
        CosmeticVariantKind::NoopInsertion => {
            format!("/* {BEAD_ID} no-op insertion */\nvoid 0;\n{source}\n;void 0;\n")
        }
        CosmeticVariantKind::WhitespaceCommentPerturbation => source
            .lines()
            .enumerate()
            .map(|(line_idx, line)| {
                format!(
                    "    /* {BEAD_ID} cosmetic whitespace line {line_idx} */    {}\n",
                    line.trim()
                )
            })
            .collect(),
    }
}

fn rename_identifiers_preserving_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len() + 64);
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    let mut i = 0usize;

    out.push_str("/* bd-cixqu.21.5 deterministic variable rename */\n");

    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' || c == '`' {
            copy_quoted(&chars, &mut i, &mut out);
            continue;
        }

        if is_identifier_start(c) {
            let start = i;
            i += 1;
            while i < chars.len() && is_identifier_continue(chars[i]) {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            if should_rename_identifier(&ident)
                && !identifier_is_property_or_key_context(&chars, start, i)
            {
                let next = renames.len() + 1;
                let renamed = renames
                    .entry(ident)
                    .or_insert_with(|| format!("bd_cixqu_21_5_name_{next}"));
                out.push_str(renamed);
            } else {
                out.push_str(&ident);
            }
            continue;
        }

        out.push(c);
        i += 1;
    }

    out
}

fn identifier_is_property_or_key_context(chars: &[char], start: usize, end: usize) -> bool {
    if previous_non_whitespace(chars, start).is_some_and(|c| c == '.') {
        return true;
    }

    if next_non_whitespace(chars, end).is_some_and(|c| c == ':') {
        return true;
    }

    let previous = previous_non_whitespace(chars, start);
    let next = next_non_whitespace(chars, end);
    matches!(previous, Some('{') | Some(',')) && matches!(next, Some('}') | Some(',') | Some('('))
}

fn previous_non_whitespace(chars: &[char], start: usize) -> Option<char> {
    chars
        .get(..start)?
        .iter()
        .rev()
        .find(|c| !c.is_whitespace())
        .copied()
}

fn next_non_whitespace(chars: &[char], end: usize) -> Option<char> {
    chars
        .get(end..)?
        .iter()
        .find(|c| !c.is_whitespace())
        .copied()
}

fn copy_quoted(chars: &[char], i: &mut usize, out: &mut String) {
    let quote = chars[*i];
    out.push(quote);
    *i += 1;
    while *i < chars.len() {
        let c = chars[*i];
        out.push(c);
        *i += 1;
        if c == '\\' && *i < chars.len() {
            out.push(chars[*i]);
            *i += 1;
            continue;
        }
        if c == quote {
            break;
        }
    }
}

fn is_identifier_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

fn is_identifier_continue(c: char) -> bool {
    is_identifier_start(c) || c.is_ascii_digit()
}

fn should_rename_identifier(ident: &str) -> bool {
    !matches!(
        ident,
        "async"
            | "await"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "export"
            | "extends"
            | "finally"
            | "for"
            | "from"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "let"
            | "new"
            | "return"
            | "static"
            | "switch"
            | "throw"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "yield"
            | "frankenHostCall"
            | "frankenhostcall"
            | "globalThis"
            | "globalthis"
            | "process"
            | "console"
            | "Reflect"
            | "reflect"
            | "Proxy"
            | "proxy"
            | "Object"
            | "Function"
            | "__proto__"
            | "capability"
            | "command"
            | "computed"
            | "constructor"
            | "declass"
            | "downcast"
            | "effect"
            | "env"
            | "environment"
            | "eval"
            | "exfil"
            | "filesystem"
            | "member"
            | "package"
            | "permission"
            | "prototype"
            | "require"
            | "receipt"
            | "script"
            | "shell"
            | "typed"
            | "write"
    )
}

#[test]
fn red_team_cosmetic_variant_rejection_embeds_all_js_scenarios() {
    let mut embedded = SCENARIOS
        .iter()
        .map(|scenario| scenario.id.to_owned())
        .collect::<Vec<_>>();
    let unique = embedded.iter().collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        embedded.len(),
        "red_team_cosmetic_variant_rejection scenario IDs must be unique"
    );

    embedded.sort_unstable();
    assert_eq!(
        embedded,
        scenario_fixture_ids_from_disk(),
        "red_team_cosmetic_variant_rejection must cover every red_team_scenarios/*.js fixture"
    );
}

#[test]
fn red_team_cosmetic_variant_rejection_alpha_rename_preserves_property_names() {
    let source =
        "const localSecret = { readFile: host.fs.readFile }; localSecret.readFile(payload);";
    let renamed = rename_identifiers_preserving_strings(source);

    assert!(renamed.contains("readFile:"));
    assert!(renamed.contains(".fs.readFile"));
    assert!(renamed.contains(".readFile("));
    assert!(renamed.contains("bd_cixqu_21_5_name_"));
    assert!(!renamed.contains("localSecret.readFile"));
}

#[test]
fn red_team_cosmetic_variant_rejection_rejects_generated_variants() {
    let cfg = ScoringConfig::default_config();
    let mut events = Vec::new();

    for scenario in SCENARIOS {
        let existing = red_team_cosmetic_variant_rejection_candidate(
            format!("corpus:{}", scenario.id),
            scenario.source,
        );

        for variant_kind in CosmeticVariantKind::ALL {
            let variant_source = cosmetic_variant_source(*variant_kind, scenario.source);
            let variant = red_team_cosmetic_variant_rejection_candidate(
                format!("candidate:{}:{}", scenario.id, variant_kind.as_str()),
                &variant_source,
            );

            assert_ne!(
                existing.source_hash,
                variant.source_hash,
                "red_team_cosmetic_variant_rejection source bytes should differ for {} {}",
                scenario.id,
                variant_kind.as_str()
            );

            let report = classify_semantic_novelty(&variant, std::slice::from_ref(&existing));
            let nearest = report
                .nearest
                .as_ref()
                .expect("red_team_cosmetic_variant_rejection nearest match");

            assert!(
                variant_kind.accepts_non_distinct_verdict(report.verdict),
                "red_team_cosmetic_variant_rejection expected non-distinct cosmetic verdict for {} {}, got {}",
                scenario.id,
                variant_kind.as_str(),
                report.verdict
            );
            assert!(!report.counts_as_distinct());
            assert_eq!(nearest.existing_candidate_id, existing.candidate_id);
            assert!(!nearest.source_hash_match);
            let required_similarity = match variant_kind {
                CosmeticVariantKind::VariableRename => report.near_duplicate_threshold_millionths,
                CosmeticVariantKind::StatementReorder
                | CosmeticVariantKind::NoopInsertion
                | CosmeticVariantKind::WhitespaceCommentPerturbation => {
                    report.duplicate_threshold_millionths
                }
            };
            assert!(
                nearest.similarity_millionths >= required_similarity,
                "red_team_cosmetic_variant_rejection similarity below non-distinct threshold for {} {}",
                scenario.id,
                variant_kind.as_str()
            );

            let batch = score_batch(&[existing.clone(), variant.clone()], &cfg);
            let variant_report = &batch.semantic_reports[1];
            assert!(
                variant_kind.accepts_non_distinct_verdict(variant_report.verdict),
                "red_team_cosmetic_variant_rejection expected non-distinct batch verdict for {} {}, got {}",
                scenario.id,
                variant_kind.as_str(),
                variant_report.verdict
            );
            let variant_certificate = batch
                .certificates
                .iter()
                .find(|cert| cert.candidate_id == variant.candidate_id)
                .expect("red_team_cosmetic_variant_rejection variant certificate");
            assert_eq!(variant_certificate.verdict, NoveltyVerdict::Redundant);
            assert_eq!(variant_certificate.score.total_score_millionths, 0);
            assert!(!variant_certificate.score.is_novel);

            events.push(json!({
                "schema_version": EVENT_SCHEMA,
                "bead_id": BEAD_ID,
                "event_type": "cosmetic_variant_rejected",
                "scenario_id": scenario.id,
                "variant_kind": variant_kind.as_str(),
                "candidate_id": variant.candidate_id.as_str(),
                "existing_candidate_id": existing.candidate_id.as_str(),
                "semantic_verdict": report.verdict.as_str(),
                "counts_as_distinct": report.counts_as_distinct(),
                "similarity_millionths": nearest.similarity_millionths,
                "source_hash_match": nearest.source_hash_match,
            }));
        }
    }

    assert_eq!(
        events.len(),
        SCENARIOS.len() * CosmeticVariantKind::ALL.len()
    );
    assert!(
        events.len() >= 30,
        "red_team_cosmetic_variant_rejection must satisfy bd-cixqu.45 integration case count"
    );
    let jsonl = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("red_team_cosmetic_variant_rejection events serialize")
        .join("\n");
    assert_eq!(jsonl.lines().count(), events.len());
    assert!(jsonl.contains("\"event_type\":\"cosmetic_variant_rejected\""));
}

#[test]
fn red_team_cosmetic_variant_rejection_allows_genuine_new_attack() {
    let corpus: Vec<NoveltyCandidate> = SCENARIOS
        .iter()
        .map(|scenario| {
            red_team_cosmetic_variant_rejection_candidate(
                format!("corpus:{}", scenario.id),
                scenario.source,
            )
        })
        .collect();
    let genuine_new_attack = NoveltyCandidate::new(
        "candidate:handcrafted-wasm-side-channel".into(),
        CandidateKind::ModuleGraph,
        80_000,
        vec![0, 0, 0, 0, 0, 0, 0, MILLIONTHS],
        br#"
        export async function attack(host) {
            const memory = await host.mapSharedMemory("timer");
            return memory.measureCacheProbe("tenant-secret-page");
        }
        "#,
    );

    let report = classify_semantic_novelty(&genuine_new_attack, &corpus);

    assert_eq!(report.verdict, SemanticNoveltyVerdict::Novel);
    assert!(report.counts_as_distinct());
    assert!(
        report
            .nearest
            .as_ref()
            .is_none_or(|nearest| nearest.similarity_millionths
                < report.near_duplicate_threshold_millionths),
        "red_team_cosmetic_variant_rejection genuine attack should stay below near-duplicate threshold"
    );
}
