#![forbid(unsafe_code)]

//! Conformance harness for ES2020 module import/export grammar (bd-h5er9).
//!
//! This matrix pins the module-goal parser surface that feeds lowering and
//! runtime module work: default, named, side-effect, namespace, declaration
//! exports, re-exports, and fail-closed script-goal / syntax boundaries.
//!
//! Schema: `franken-engine.module-import-export-grammar-conformance.v1`
//! Bead: bd-h5er9

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::{ExportKind, ImportClause, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::parser::ParseErrorCode;
use frankenengine_engine::parser_api_stability::{parse_module, parse_script};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.module-import-export-grammar-conformance.v1";
const BEAD_ID: &str = "bd-h5er9";

const KNOWN_MODULE_GRAMMAR_WAIVERS: &[&str] = &["ES2020-16.2.3.2-export-star-as-namespace"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModuleSurface {
    ImportSideEffect,
    ImportDefault,
    ImportNamed,
    ImportNamespace,
    ImportDefaultNamespace,
    ExportDefault,
    ExportDeclaration,
    ReExport,
    InvalidGoal,
    InvalidSyntax,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequirementLevel {
    Must,
    Should,
}

#[derive(Debug, Clone)]
struct Waiver {
    id: &'static str,
    reason: &'static str,
    follow_up: &'static str,
}

#[derive(Debug, Clone)]
struct ModuleGrammarCase {
    id: &'static str,
    requirement_id: &'static str,
    description: &'static str,
    es2020_section: &'static str,
    requirement_level: RequirementLevel,
    surface: ModuleSurface,
    source: &'static str,
    expected: ExpectedOutcome,
    waiver: Option<Waiver>,
}

#[derive(Debug, Clone)]
enum ExpectedOutcome {
    AcceptModule {
        body_len: usize,
        import_count: usize,
        export_count: usize,
        checks: Vec<AstCheck>,
    },
    Reject {
        goal: ParseGoal,
        code: ParseErrorCode,
    },
}

#[derive(Debug, Clone)]
enum AstCheck {
    SideEffectImport {
        source: &'static str,
    },
    DefaultImport {
        local: &'static str,
        source: &'static str,
    },
    NamedImport {
        import_name: &'static str,
        local_name: &'static str,
        source: &'static str,
    },
    NamespaceImport {
        local: &'static str,
        source: &'static str,
    },
    DefaultAndNamespaceImport {
        default: &'static str,
        namespace: &'static str,
        source: &'static str,
    },
    DefaultExport,
    NamedExportClause {
        clause: &'static str,
    },
    ExportedDeclaration {
        binding: &'static str,
        clause: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModuleCaseStatus {
    Pass,
    Fail,
    Waived,
    WaiverDrift,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ModuleGrammarStatistics {
    total_tests: u32,
    passes: u32,
    fails: u32,
    waived: u32,
    waiver_drifts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModuleCaseReport {
    requirement_id: String,
    requirement_level: RequirementLevel,
    surface: ModuleSurface,
    status: ModuleCaseStatus,
    waiver_id: Option<String>,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModuleGrammarReport {
    schema_version: String,
    bead_id: String,
    case_results: BTreeMap<String, ModuleCaseReport>,
    statistics: ModuleGrammarStatistics,
}

fn module_grammar_cases() -> Vec<ModuleGrammarCase> {
    vec![
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-side-effect",
            requirement_id: "MIE-MUST-001",
            description: "Side-effect-only import creates an ImportDeclaration with no bindings",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ImportSideEffect,
            source: r#"import "./setup.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 1,
                export_count: 0,
                checks: vec![AstCheck::SideEffectImport {
                    source: "./setup.js",
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-default",
            requirement_id: "MIE-MUST-002",
            description: "Default import binds the requested local name",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ImportDefault,
            source: r#"import thing from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 1,
                export_count: 0,
                checks: vec![AstCheck::DefaultImport {
                    local: "thing",
                    source: "./dep.js",
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-named-alias",
            requirement_id: "MIE-MUST-003",
            description: "Named import records imported and local alias names",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ImportNamed,
            source: r#"import { value as localValue, other } from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 1,
                export_count: 0,
                checks: vec![
                    AstCheck::NamedImport {
                        import_name: "value",
                        local_name: "localValue",
                        source: "./dep.js",
                    },
                    AstCheck::NamedImport {
                        import_name: "other",
                        local_name: "other",
                        source: "./dep.js",
                    },
                ],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-namespace",
            requirement_id: "MIE-MUST-004",
            description: "Namespace import binds exactly the requested namespace object name",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ImportNamespace,
            source: r#"import * as ns from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 1,
                export_count: 0,
                checks: vec![AstCheck::NamespaceImport {
                    local: "ns",
                    source: "./dep.js",
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-default-and-namespace",
            requirement_id: "MIE-MUST-005",
            description: "Default plus namespace import preserves both local bindings",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ImportDefaultNamespace,
            source: r#"import thing, * as ns from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 1,
                export_count: 0,
                checks: vec![AstCheck::DefaultAndNamespaceImport {
                    default: "thing",
                    namespace: "ns",
                    source: "./dep.js",
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.3.4-export-default-expression",
            requirement_id: "MIE-MUST-006",
            description: "Default export expression is represented as ExportKind::Default",
            es2020_section: "16.2.3.4",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ExportDefault,
            source: "export default 42;",
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 0,
                export_count: 1,
                checks: vec![AstCheck::DefaultExport],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.3.4-export-const-declaration",
            requirement_id: "MIE-MUST-007",
            description: "Exported lexical declaration emits the declaration and a named export",
            es2020_section: "16.2.3.4",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ExportDeclaration,
            source: "export const value = 1;",
            expected: ExpectedOutcome::AcceptModule {
                body_len: 2,
                import_count: 0,
                export_count: 1,
                checks: vec![AstCheck::ExportedDeclaration {
                    binding: "value",
                    clause: "{ value }",
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.3.4-export-named-from",
            requirement_id: "MIE-MUST-008",
            description: "Named re-export records the export list and quoted source module",
            es2020_section: "16.2.3.4",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::ReExport,
            source: r#"export { value as renamed } from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 0,
                export_count: 1,
                checks: vec![AstCheck::NamedExportClause {
                    clause: r#"{ value as renamed } from "./dep.js""#,
                }],
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-in-script-rejected",
            requirement_id: "MIE-MUST-009",
            description: "Script-goal parse rejects top-level import fail-closed",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::InvalidGoal,
            source: r#"import thing from "./dep.js";"#,
            expected: ExpectedOutcome::Reject {
                goal: ParseGoal::Script,
                code: ParseErrorCode::InvalidGoal,
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.3.4-export-in-script-rejected",
            requirement_id: "MIE-MUST-010",
            description: "Script-goal parse rejects top-level export fail-closed",
            es2020_section: "16.2.3.4",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::InvalidGoal,
            source: "export const value = 1;",
            expected: ExpectedOutcome::Reject {
                goal: ParseGoal::Script,
                code: ParseErrorCode::InvalidGoal,
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.2.2-import-namespace-missing-as-rejected",
            requirement_id: "MIE-MUST-011",
            description: "Namespace import without `as` alias is rejected",
            es2020_section: "16.2.2.2",
            requirement_level: RequirementLevel::Must,
            surface: ModuleSurface::InvalidSyntax,
            source: r#"import * ns from "./dep.js";"#,
            expected: ExpectedOutcome::Reject {
                goal: ParseGoal::Module,
                code: ParseErrorCode::UnsupportedSyntax,
            },
            waiver: None,
        },
        ModuleGrammarCase {
            id: "ES2020-16.2.3.2-export-star-as-namespace",
            requirement_id: "MIE-SHOULD-012",
            description: "Namespace re-export should parse as an export from a source module",
            es2020_section: "16.2.3.2",
            requirement_level: RequirementLevel::Should,
            surface: ModuleSurface::ReExport,
            source: r#"export * as ns from "./dep.js";"#,
            expected: ExpectedOutcome::AcceptModule {
                body_len: 1,
                import_count: 0,
                export_count: 1,
                checks: Vec::new(),
            },
            waiver: Some(Waiver {
                id: "bd-h5er9-waiver-export-star-as-namespace",
                reason: "current AST only models default and named-clause exports",
                follow_up: "add ExportKind support for ES2020 namespace re-export",
            }),
        },
    ]
}

fn run_conformance_suite() -> ModuleGrammarReport {
    let mut case_results = BTreeMap::new();
    let mut statistics = ModuleGrammarStatistics::default();

    for case in module_grammar_cases() {
        let raw = execute_case(&case);
        let (status, detail) = classify_case_result(&case, raw);
        match status {
            ModuleCaseStatus::Pass => statistics.passes += 1,
            ModuleCaseStatus::Fail => statistics.fails += 1,
            ModuleCaseStatus::Waived => statistics.waived += 1,
            ModuleCaseStatus::WaiverDrift => statistics.waiver_drifts += 1,
        }

        case_results.insert(
            case.id.to_string(),
            ModuleCaseReport {
                requirement_id: case.requirement_id.to_string(),
                requirement_level: case.requirement_level,
                surface: case.surface,
                status,
                waiver_id: case.waiver.as_ref().map(|waiver| waiver.id.to_string()),
                detail,
            },
        );
    }

    statistics.total_tests = u32::try_from(case_results.len()).unwrap_or(u32::MAX);

    ModuleGrammarReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        case_results,
        statistics,
    }
}

fn classify_case_result(
    case: &ModuleGrammarCase,
    raw: Result<(), String>,
) -> (ModuleCaseStatus, String) {
    match (raw, &case.waiver) {
        (Ok(()), None) => (ModuleCaseStatus::Pass, "matched expectation".to_string()),
        (Ok(()), Some(waiver)) => (
            ModuleCaseStatus::WaiverDrift,
            format!(
                "waiver {} should be removed; accepted after prior gap: {}",
                waiver.id, waiver.reason
            ),
        ),
        (Err(detail), None) => (ModuleCaseStatus::Fail, detail),
        (Err(detail), Some(waiver)) => (
            ModuleCaseStatus::Waived,
            format!("{}; waived by {} ({})", detail, waiver.id, waiver.follow_up),
        ),
    }
}

fn execute_case(case: &ModuleGrammarCase) -> Result<(), String> {
    match &case.expected {
        ExpectedOutcome::AcceptModule {
            body_len,
            import_count,
            export_count,
            checks,
        } => {
            let tree = parse_module(case.source).map_err(|err| {
                format!(
                    "expected module parse success, got {:?}: {}",
                    err.code, err.message
                )
            })?;
            let mut failures = Vec::new();
            if tree.goal != ParseGoal::Module {
                failures.push(format!("expected module goal, got {:?}", tree.goal));
            }
            if tree.body.len() != *body_len {
                failures.push(format!(
                    "expected {body_len} statements, got {}",
                    tree.body.len()
                ));
            }
            let actual_imports = tree
                .body
                .iter()
                .filter(|statement| matches!(statement, Statement::Import(_)))
                .count();
            let actual_exports = tree
                .body
                .iter()
                .filter(|statement| matches!(statement, Statement::Export(_)))
                .count();
            if actual_imports != *import_count {
                failures.push(format!(
                    "expected {import_count} imports, got {actual_imports}"
                ));
            }
            if actual_exports != *export_count {
                failures.push(format!(
                    "expected {export_count} exports, got {actual_exports}"
                ));
            }
            for check in checks {
                if let Err(detail) = check.assert_against(&tree) {
                    failures.push(detail);
                }
            }

            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        }
        ExpectedOutcome::Reject { goal, code } => {
            let result = match goal {
                ParseGoal::Script => parse_script(case.source),
                ParseGoal::Module => parse_module(case.source),
            };
            match result {
                Ok(tree) => Err(format!(
                    "expected {:?} rejection {:?}, accepted {} statements",
                    goal,
                    code,
                    tree.body.len()
                )),
                Err(err) if err.code == *code => Ok(()),
                Err(err) => Err(format!(
                    "expected {:?} rejection {:?}, got {:?}: {}",
                    goal, code, err.code, err.message
                )),
            }
        }
    }
}

impl AstCheck {
    fn assert_against(&self, tree: &SyntaxTree) -> Result<(), String> {
        match self {
            Self::SideEffectImport { source } => {
                if imports(tree).any(|import| {
                    matches!(&import.clause, ImportClause::SideEffect)
                        && import.source.as_str() == *source
                }) {
                    Ok(())
                } else {
                    Err(format!("missing side-effect import from {source}"))
                }
            }
            Self::DefaultImport { local, source } => {
                if imports(tree).any(|import| {
                    matches!(&import.clause, ImportClause::Default { local: actual } if actual.as_str() == *local)
                        && import.binding.as_deref() == Some(*local)
                        && import.clause.binding_names() == vec![*local]
                        && import.source.as_str() == *source
                }) {
                    Ok(())
                } else {
                    Err(format!("missing default import {local} from {source}"))
                }
            }
            Self::NamedImport {
                import_name,
                local_name,
                source,
            } => {
                if imports(tree).any(|import| {
                    import.source.as_str() == *source
                        && matches!(&import.clause, ImportClause::Named { specifiers } if specifiers.iter().any(|specifier| specifier.import_name.as_str() == *import_name && specifier.local_name.as_str() == *local_name))
                }) {
                    Ok(())
                } else {
                    Err(format!(
                        "missing named import {import_name} as {local_name} from {source}"
                    ))
                }
            }
            Self::NamespaceImport { local, source } => {
                if imports(tree).any(|import| {
                    matches!(&import.clause, ImportClause::Namespace { local: actual } if actual.as_str() == *local)
                        && import.binding.as_deref() == Some(*local)
                        && import.clause.binding_names() == vec![*local]
                        && import.source.as_str() == *source
                }) {
                    Ok(())
                } else {
                    Err(format!("missing namespace import * as {local} from {source}"))
                }
            }
            Self::DefaultAndNamespaceImport {
                default,
                namespace,
                source,
            } => {
                if imports(tree).any(|import| {
                    matches!(
                        &import.clause,
                        ImportClause::DefaultAndNamespace {
                            default: actual_default,
                            namespace: actual_namespace,
                        } if actual_default.as_str() == *default && actual_namespace.as_str() == *namespace
                    ) && import.binding.as_deref() == Some(*default)
                        && import.clause.binding_names() == vec![*default, *namespace]
                        && import.source.as_str() == *source
                }) {
                    Ok(())
                } else {
                    Err(format!(
                        "missing default+namespace import {default}, * as {namespace} from {source}"
                    ))
                }
            }
            Self::DefaultExport => {
                if exports(tree).any(|export| matches!(&export.kind, ExportKind::Default(_))) {
                    Ok(())
                } else {
                    Err("missing default export".to_string())
                }
            }
            Self::NamedExportClause { clause } => {
                if exports(tree).any(|export| {
                    matches!(&export.kind, ExportKind::NamedClause(actual) if actual == clause)
                }) {
                    Ok(())
                } else {
                    Err(format!("missing named export clause {clause}"))
                }
            }
            Self::ExportedDeclaration { binding, clause } => {
                let has_binding = tree.body.iter().any(|statement| {
                    matches!(
                        statement,
                        Statement::VariableDeclaration(declaration)
                            if declaration
                                .declarations
                                .iter()
                                .any(|declarator| declarator.name() == Some(*binding))
                    )
                });
                let has_export = exports(tree).any(|export| {
                    matches!(&export.kind, ExportKind::NamedClause(actual) if actual == clause)
                });
                if has_binding && has_export {
                    Ok(())
                } else {
                    Err(format!(
                        "missing exported declaration binding={binding} clause={clause}"
                    ))
                }
            }
        }
    }
}

fn imports(
    tree: &SyntaxTree,
) -> impl Iterator<Item = &frankenengine_engine::ast::ImportDeclaration> {
    tree.body.iter().filter_map(|statement| match statement {
        Statement::Import(import) => Some(import),
        _ => None,
    })
}

fn exports(
    tree: &SyntaxTree,
) -> impl Iterator<Item = &frankenengine_engine::ast::ExportDeclaration> {
    tree.body.iter().filter_map(|statement| match statement {
        Statement::Export(export) => Some(export),
        _ => None,
    })
}

#[test]
fn module_grammar_cases_have_unique_requirement_ids_and_descriptions() {
    let cases = module_grammar_cases();
    let mut case_ids = BTreeSet::new();
    let mut requirement_ids = BTreeSet::new();

    for case in &cases {
        assert!(!case.id.is_empty(), "case id must be non-empty");
        assert!(
            !case.requirement_id.is_empty(),
            "requirement id must be non-empty"
        );
        assert!(
            !case.description.is_empty(),
            "description must be non-empty for {}",
            case.id
        );
        assert!(
            !case.es2020_section.is_empty(),
            "ES2020 section must be non-empty for {}",
            case.id
        );
        assert!(!case.source.is_empty(), "source must be non-empty");
        assert!(
            case_ids.insert(case.id),
            "duplicate module grammar case id {}",
            case.id
        );
        assert!(
            requirement_ids.insert(case.requirement_id),
            "duplicate requirement id {}",
            case.requirement_id
        );
    }

    assert!(
        (8..=12).contains(&cases.len()),
        "matrix must define 8-12 import/export cases, found {}",
        cases.len()
    );
}

#[test]
fn module_grammar_matrix_covers_import_export_namespace_axes() {
    let surfaces: BTreeSet<ModuleSurface> = module_grammar_cases()
        .into_iter()
        .map(|case| case.surface)
        .collect();

    for required in [
        ModuleSurface::ImportSideEffect,
        ModuleSurface::ImportDefault,
        ModuleSurface::ImportNamed,
        ModuleSurface::ImportNamespace,
        ModuleSurface::ImportDefaultNamespace,
        ModuleSurface::ExportDefault,
        ModuleSurface::ExportDeclaration,
        ModuleSurface::ReExport,
        ModuleSurface::InvalidGoal,
        ModuleSurface::InvalidSyntax,
    ] {
        assert!(
            surfaces.contains(&required),
            "matrix missing required surface {required:?}"
        );
    }
}

#[test]
fn module_grammar_report_round_trips_through_serde() {
    let report = run_conformance_suite();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(
        report.statistics.total_tests,
        report.statistics.passes
            + report.statistics.fails
            + report.statistics.waived
            + report.statistics.waiver_drifts,
        "case-result counts must sum to total_tests"
    );

    let json = serde_json::to_string(&report).expect("report should serialize");
    let round_trip: ModuleGrammarReport =
        serde_json::from_str(&json).expect("report should deserialize");
    assert_eq!(round_trip.schema_version, report.schema_version);
    assert_eq!(round_trip.bead_id, report.bead_id);
    assert_eq!(
        round_trip.statistics.total_tests,
        report.statistics.total_tests
    );
    assert_eq!(round_trip.case_results.len(), report.case_results.len());
}

#[test]
fn module_grammar_full_matrix_has_no_unwaived_failures() {
    let report = run_conformance_suite();
    let hard_failures: BTreeMap<&str, &ModuleCaseReport> = report
        .case_results
        .iter()
        .filter(|(_, result)| {
            matches!(
                result.status,
                ModuleCaseStatus::Fail | ModuleCaseStatus::WaiverDrift
            )
        })
        .map(|(id, result)| (id.as_str(), result))
        .collect();
    assert!(
        hard_failures.is_empty(),
        "module import/export conformance failures drifted from waiver set:\n{hard_failures:#?}"
    );

    let observed_waivers: BTreeSet<&str> = report
        .case_results
        .iter()
        .filter(|(_, result)| result.status == ModuleCaseStatus::Waived)
        .map(|(id, _)| id.as_str())
        .collect();
    let expected_waivers: BTreeSet<&str> = KNOWN_MODULE_GRAMMAR_WAIVERS.iter().copied().collect();
    assert_eq!(
        observed_waivers, expected_waivers,
        "module import/export waiver set drifted. If a gap closed, remove the waiver; if a new gap opened, file a follow-up bead."
    );
}
