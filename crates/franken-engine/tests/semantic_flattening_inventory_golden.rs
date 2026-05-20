#![forbid(unsafe_code)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_flattening_inventory::{
    BoundaryPoint, FlatteningClassification, FlatteningInventory, FlatteningOccurrence,
    FlatteningSeverity, FlatteningSummary, SemanticDomain, TranslationKind,
};
use serde::{Deserialize, Serialize};

const EXPECTED: &str = include_str!("golden_vectors/semantic_flattening_inventory_hashes_v1.json");
const FIXTURE_SCHEMA_VERSION: &str = "franken-engine.semantic-flattening-inventory-hashes.v1";
const GOLDEN_EPOCH: u64 = 13;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SemanticFlatteningGoldenSet {
    fixture_schema_version: String,
    cases: Vec<SemanticFlatteningGoldenCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SemanticFlatteningGoldenCase {
    case_id: String,
    expectation: String,
    assessed_epoch: u64,
    inventory_hash: String,
    summary: FlatteningSummary,
    occurrences: Vec<SemanticFlatteningGoldenOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SemanticFlatteningGoldenOccurrence {
    id: String,
    domain: SemanticDomain,
    boundary: BoundaryPoint,
    translation_kind: TranslationKind,
    classification: FlatteningClassification,
    severity: FlatteningSeverity,
    description: String,
    remediation: String,
    remediation_bead: String,
    content_hash: String,
}

impl From<&FlatteningOccurrence> for SemanticFlatteningGoldenOccurrence {
    fn from(occurrence: &FlatteningOccurrence) -> Self {
        Self {
            id: occurrence.id.clone(),
            domain: occurrence.domain,
            boundary: occurrence.boundary.clone(),
            translation_kind: occurrence.translation_kind,
            classification: occurrence.classification,
            severity: occurrence.severity,
            description: occurrence.description.clone(),
            remediation: occurrence.remediation.clone(),
            remediation_bead: occurrence.remediation_bead.clone(),
            content_hash: occurrence.content_hash.to_hex(),
        }
    }
}

fn boundary(
    source_module: &str,
    target_module: &str,
    api_surface: &str,
    line_hint: Option<u32>,
) -> BoundaryPoint {
    BoundaryPoint {
        source_module: source_module.to_string(),
        target_module: target_module.to_string(),
        api_surface: api_surface.to_string(),
        line_hint,
    }
}

#[allow(clippy::too_many_arguments)]
fn occurrence(
    id: &str,
    domain: SemanticDomain,
    boundary: BoundaryPoint,
    translation_kind: TranslationKind,
    classification: FlatteningClassification,
    severity: FlatteningSeverity,
    description: &str,
    remediation: &str,
    remediation_bead: &str,
) -> FlatteningOccurrence {
    FlatteningOccurrence::new(
        id.to_string(),
        domain,
        boundary,
        translation_kind,
        classification,
        severity,
        description.to_string(),
        remediation.to_string(),
        remediation_bead.to_string(),
    )
}

fn golden_case(
    case_id: &str,
    expectation: &str,
    occurrence: FlatteningOccurrence,
) -> SemanticFlatteningGoldenCase {
    let mut inventory = FlatteningInventory::new(SecurityEpoch::from_raw(GOLDEN_EPOCH));
    inventory.add(occurrence.clone());

    SemanticFlatteningGoldenCase {
        case_id: case_id.to_string(),
        expectation: expectation.to_string(),
        assessed_epoch: GOLDEN_EPOCH,
        inventory_hash: inventory.content_hash().to_hex(),
        summary: inventory.summary(),
        occurrences: vec![SemanticFlatteningGoldenOccurrence::from(&occurrence)],
    }
}

fn golden_set() -> SemanticFlatteningGoldenSet {
    SemanticFlatteningGoldenSet {
        fixture_schema_version: FIXTURE_SCHEMA_VERSION.to_string(),
        cases: vec![
            golden_case(
                "intentional_preserved_policy_id",
                "documented policy identifier pass-through remains stable",
                occurrence(
                    "sf-intentional-policy-id",
                    SemanticDomain::PolicyId,
                    boundary(
                        "policy_controller",
                        "audit_ledger",
                        "record_policy_identifier",
                        Some(120),
                    ),
                    TranslationKind::Preserved,
                    FlatteningClassification::Intentional,
                    FlatteningSeverity::Info,
                    "Policy identifiers are forwarded unchanged into audit evidence.",
                    "Keep the boundary documented as intentional pass-through.",
                    "bd-xrkpf",
                ),
            ),
            golden_case(
                "acceptable_edge_diagnostics_translated",
                "operator diagnostics translation stays reviewable",
                occurrence(
                    "sf-acceptable-diagnostics",
                    SemanticDomain::Diagnostics,
                    boundary(
                        "parser_diagnostics",
                        "operator_cli",
                        "render_diagnostic",
                        Some(214),
                    ),
                    TranslationKind::Translated,
                    FlatteningClassification::AcceptableEdge,
                    FlatteningSeverity::Low,
                    "Structured parser diagnostics are rendered into stable operator text.",
                    "Retain source diagnostic identifiers when the CLI renderer grows detail.",
                    "bd-xrkpf",
                ),
            ),
            golden_case(
                "capability_widening_must_fix",
                "capability widening continues to hash as a release-blocking finding",
                occurrence(
                    "sf-capability-widening",
                    SemanticDomain::Capability,
                    boundary(
                        "extension_manifest",
                        "capability_grant_store",
                        "materialize_grant",
                        Some(338),
                    ),
                    TranslationKind::Widened,
                    FlatteningClassification::MustFix,
                    FlatteningSeverity::Critical,
                    "Manifest capability scope expands while entering the grant store.",
                    "Reject widened grants unless an explicit authority edge proves the expansion.",
                    "bd-capability-widening",
                ),
            ),
            golden_case(
                "budget_narrowing_must_fix",
                "budget narrowing keeps a distinct content hash from widening",
                occurrence(
                    "sf-budget-narrowing",
                    SemanticDomain::Budget,
                    boundary(
                        "budget_planner",
                        "execution_scheduler",
                        "schedule_with_budget",
                        Some(512),
                    ),
                    TranslationKind::Narrowed,
                    FlatteningClassification::MustFix,
                    FlatteningSeverity::High,
                    "Tiered CPU and memory budgets collapse into a single scheduler quota.",
                    "Carry the tier breakdown through scheduling receipts.",
                    "bd-budget-narrowing",
                ),
            ),
            golden_case(
                "critical_outcome_dropped",
                "critical outcome loss stays frozen as a distinct regression vector",
                occurrence(
                    "sf-critical-outcome-dropped",
                    SemanticDomain::Outcome,
                    boundary(
                        "safe_mode_controller",
                        "release_gate",
                        "record_execution_outcome",
                        Some(733),
                    ),
                    TranslationKind::Dropped,
                    FlatteningClassification::MustFix,
                    FlatteningSeverity::Critical,
                    "Partial-failure outcome detail is dropped before release-gate evidence.",
                    "Persist partial-failure outcome detail in release-gate artifacts.",
                    "bd-critical-outcome-dropped",
                ),
            ),
        ],
    }
}

fn rehydrate_occurrence(occurrence: &SemanticFlatteningGoldenOccurrence) -> FlatteningOccurrence {
    FlatteningOccurrence::new(
        occurrence.id.clone(),
        occurrence.domain,
        occurrence.boundary.clone(),
        occurrence.translation_kind,
        occurrence.classification,
        occurrence.severity,
        occurrence.description.clone(),
        occurrence.remediation.clone(),
        occurrence.remediation_bead.clone(),
    )
}

#[test]
fn semantic_flattening_inventory_hashes_match_golden() {
    let expected = golden_set();
    let actual_json = serde_json::to_string_pretty(&expected).expect("serialize golden set") + "\n";

    if actual_json != EXPECTED {
        eprintln!("{actual_json}");
    }
    assert_eq!(actual_json, EXPECTED);

    let decoded: SemanticFlatteningGoldenSet =
        serde_json::from_str(EXPECTED).expect("golden set should decode");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.cases.len(), 5);

    for case in decoded.cases {
        let mut inventory = FlatteningInventory::new(SecurityEpoch::from_raw(case.assessed_epoch));
        for golden_occurrence in &case.occurrences {
            let occurrence = rehydrate_occurrence(golden_occurrence);
            assert_eq!(
                occurrence.content_hash.to_hex(),
                golden_occurrence.content_hash,
                "occurrence hash drifted for {}",
                golden_occurrence.id
            );
            inventory.add(occurrence);
        }

        assert_eq!(inventory.summary(), case.summary);
        assert_eq!(
            inventory.content_hash().to_hex(),
            case.inventory_hash,
            "inventory hash drifted for {}",
            case.case_id
        );
    }
}
