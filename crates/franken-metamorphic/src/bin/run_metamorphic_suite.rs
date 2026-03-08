use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_metamorphic::build_enabled_relations;
use frankenengine_metamorphic::catalog::RelationCatalog;
use frankenengine_metamorphic::relation::MetamorphicRelation;
use frankenengine_metamorphic::relations::CatalogBackedRelation;
use frankenengine_metamorphic::runner::{
    MinimizerConfig, RunContext, campaign_triage_report_for_suite, evidence_entries_for_suite,
    generator_choice_stream_schema_for_suite, hdd_reducer_report_for_suite,
    minimized_property_counterexamples_for_suite, minimized_structured_repros_for_suite,
    property_generator_catalog_for_suite, reduction_stability_matrix_for_suite,
    relation_log_events_for_suite, repro_governance_actions_from_triage, run_suite,
    seed_manifest_for_suite, seed_transcript_entries_for_suite, shrinker_verdict_report_for_suite,
    structured_reduction_operator_catalog_for_suite, write_campaign_triage_report_json,
    write_evidence_jsonl, write_generator_choice_stream_schema_json, write_hdd_reducer_report_json,
    write_minimized_property_counterexamples_jsonl, write_minimized_structured_repros_jsonl,
    write_property_generator_catalog_json, write_reduction_stability_matrix_json,
    write_repro_governance_actions_json, write_seed_manifest_json, write_seed_transcript_jsonl,
    write_shrinker_verdict_report_json, write_structured_reduction_operator_catalog_json,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut pairs_override = None::<u32>;
    let mut seed = 1u64;
    let mut trace_id = String::from("trace-metamorphic-default");
    let mut decision_id = String::from("decision-metamorphic-default");
    let mut policy_id = String::from("policy-metamorphic-v1");
    let mut evidence_path = PathBuf::from("artifacts/metamorphic/metamorphic_evidence.jsonl");
    let mut events_path = PathBuf::from("artifacts/metamorphic/relation_events.jsonl");
    let mut seed_transcript_path = PathBuf::from("artifacts/metamorphic/seed_transcript.jsonl");
    let mut seed_manifest_path = PathBuf::from("artifacts/metamorphic/seed_manifest.json");
    let mut property_generator_catalog_path =
        PathBuf::from("artifacts/metamorphic/property_generator_catalog.json");
    let mut generator_choice_stream_schema_path =
        PathBuf::from("artifacts/metamorphic/generator_choice_stream_schema.json");
    let mut shrinker_verdict_report_path =
        PathBuf::from("artifacts/metamorphic/shrinker_verdict_report.json");
    let mut minimized_counterexamples_path =
        PathBuf::from("artifacts/metamorphic/minimized_property_counterexamples.jsonl");
    let mut hdd_reducer_report_path =
        PathBuf::from("artifacts/metamorphic/hdd_reducer_report.json");
    let mut structured_reduction_operator_catalog_path =
        PathBuf::from("artifacts/metamorphic/structured_reduction_operator_catalog.json");
    let mut minimized_structured_repros_path =
        PathBuf::from("artifacts/metamorphic/minimized_structured_repros.jsonl");
    let mut reduction_stability_matrix_path =
        PathBuf::from("artifacts/metamorphic/reduction_stability_matrix.json");
    let mut triage_report_path = PathBuf::from("artifacts/metamorphic/triage_report.json");
    let mut governance_actions_path =
        PathBuf::from("artifacts/metamorphic/repro_governance_actions.json");
    let mut failures_dir = PathBuf::from("artifacts/metamorphic/failures");
    let mut replay_command = String::from("./scripts/e2e/metamorphic_suite_replay.sh ci");
    let mut relation_filters = Vec::<String>::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pairs" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --pairs".into());
                };
                pairs_override = Some(value.parse::<u32>()?);
            }
            "--seed" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --seed".into());
                };
                seed = value.parse::<u64>()?;
            }
            "--trace-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --trace-id".into());
                };
                trace_id = value;
            }
            "--decision-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --decision-id".into());
                };
                decision_id = value;
            }
            "--policy-id" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --policy-id".into());
                };
                policy_id = value;
            }
            "--evidence" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --evidence".into());
                };
                evidence_path = PathBuf::from(value);
            }
            "--events" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --events".into());
                };
                events_path = PathBuf::from(value);
            }
            "--seed-transcript" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --seed-transcript".into());
                };
                seed_transcript_path = PathBuf::from(value);
            }
            "--seed-manifest" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --seed-manifest".into());
                };
                seed_manifest_path = PathBuf::from(value);
            }
            "--property-generator-catalog" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --property-generator-catalog".into());
                };
                property_generator_catalog_path = PathBuf::from(value);
            }
            "--generator-choice-stream-schema" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --generator-choice-stream-schema".into());
                };
                generator_choice_stream_schema_path = PathBuf::from(value);
            }
            "--shrinker-verdict-report" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --shrinker-verdict-report".into());
                };
                shrinker_verdict_report_path = PathBuf::from(value);
            }
            "--minimized-counterexamples" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --minimized-counterexamples".into());
                };
                minimized_counterexamples_path = PathBuf::from(value);
            }
            "--hdd-reducer-report" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --hdd-reducer-report".into());
                };
                hdd_reducer_report_path = PathBuf::from(value);
            }
            "--structured-reduction-operator-catalog" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --structured-reduction-operator-catalog".into());
                };
                structured_reduction_operator_catalog_path = PathBuf::from(value);
            }
            "--minimized-structured-repros" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --minimized-structured-repros".into());
                };
                minimized_structured_repros_path = PathBuf::from(value);
            }
            "--reduction-stability-matrix" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --reduction-stability-matrix".into());
                };
                reduction_stability_matrix_path = PathBuf::from(value);
            }
            "--triage-report" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --triage-report".into());
                };
                triage_report_path = PathBuf::from(value);
            }
            "--replay-command" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --replay-command".into());
                };
                replay_command = value;
            }
            "--governance-actions" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --governance-actions".into());
                };
                governance_actions_path = PathBuf::from(value);
            }
            "--failures-dir" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --failures-dir".into());
                };
                failures_dir = PathBuf::from(value);
            }
            "--relation" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --relation".into());
                };
                relation_filters.push(value);
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    let catalog = RelationCatalog::load_default()?;
    let catalog_hash = catalog.content_hash();

    let all_relations = build_enabled_relations(&catalog);
    let selected_relations = select_relations(&all_relations, &relation_filters)?;

    if selected_relations.is_empty() {
        return Err("no relations selected for execution".into());
    }

    if let Some(parent) = evidence_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = events_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = seed_transcript_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = seed_manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = property_generator_catalog_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = generator_choice_stream_schema_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = shrinker_verdict_report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = minimized_counterexamples_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = hdd_reducer_report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = structured_reduction_operator_catalog_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = minimized_structured_repros_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = reduction_stability_matrix_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = triage_report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = governance_actions_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(&failures_dir)?;

    let context = RunContext::new(
        trace_id,
        decision_id,
        policy_id,
        "metamorphic_suite",
        catalog_hash,
        seed,
    );

    let relation_refs: Vec<&dyn MetamorphicRelation> = selected_relations
        .iter()
        .map(|relation| relation as &dyn MetamorphicRelation)
        .collect();

    let suite = run_suite(
        &relation_refs,
        &context,
        pairs_override,
        Some(&failures_dir),
        MinimizerConfig::default(),
    )?;

    let evidence_entries = evidence_entries_for_suite(&suite);
    write_evidence_jsonl(&evidence_path, &evidence_entries)?;

    let events = relation_log_events_for_suite(&suite);
    write_events_jsonl(&events_path, &events)?;
    let seed_transcript = seed_transcript_entries_for_suite(&suite);
    write_seed_transcript_jsonl(&seed_transcript_path, &seed_transcript)?;
    let seed_manifest = seed_manifest_for_suite(&suite);
    write_seed_manifest_json(&seed_manifest_path, &seed_manifest)?;
    let property_generator_catalog = property_generator_catalog_for_suite(&suite);
    write_property_generator_catalog_json(
        &property_generator_catalog_path,
        &property_generator_catalog,
    )?;
    let generator_choice_stream_schema = generator_choice_stream_schema_for_suite(&suite);
    write_generator_choice_stream_schema_json(
        &generator_choice_stream_schema_path,
        &generator_choice_stream_schema,
    )?;
    let shrinker_verdict_report = shrinker_verdict_report_for_suite(&suite);
    write_shrinker_verdict_report_json(&shrinker_verdict_report_path, &shrinker_verdict_report)?;
    let minimized_counterexamples = minimized_property_counterexamples_for_suite(&suite);
    write_minimized_property_counterexamples_jsonl(
        &minimized_counterexamples_path,
        &minimized_counterexamples,
    )?;
    let hdd_reducer_report = hdd_reducer_report_for_suite(&suite);
    write_hdd_reducer_report_json(&hdd_reducer_report_path, &hdd_reducer_report)?;
    let structured_reduction_operator_catalog =
        structured_reduction_operator_catalog_for_suite(&suite);
    write_structured_reduction_operator_catalog_json(
        &structured_reduction_operator_catalog_path,
        &structured_reduction_operator_catalog,
    )?;
    let minimized_structured_repros = minimized_structured_repros_for_suite(&suite);
    write_minimized_structured_repros_jsonl(
        &minimized_structured_repros_path,
        &minimized_structured_repros,
    )?;
    let reduction_stability_matrix = reduction_stability_matrix_for_suite(&suite);
    write_reduction_stability_matrix_json(
        &reduction_stability_matrix_path,
        &reduction_stability_matrix,
    )?;
    let triage_report = campaign_triage_report_for_suite(&suite, &replay_command);
    write_campaign_triage_report_json(&triage_report_path, &triage_report)?;
    let governance_actions = repro_governance_actions_from_triage(&triage_report);
    write_repro_governance_actions_json(&governance_actions_path, &governance_actions)?;

    println!(
        "metamorphic suite relations={} total_pairs={} violations={} evidence={} events={} seed_transcript={} seed_manifest={} property_generator_catalog={} generator_choice_stream_schema={} shrinker_verdict_report={} minimized_property_counterexamples={} hdd_reducer_report={} structured_reduction_operator_catalog={} minimized_structured_repros={} reduction_stability_matrix={} triage_report={} governance_actions={} failures_dir={}",
        suite.relation_executions.len(),
        suite.total_pairs,
        suite.total_violations,
        evidence_path.display(),
        events_path.display(),
        seed_transcript_path.display(),
        seed_manifest_path.display(),
        property_generator_catalog_path.display(),
        generator_choice_stream_schema_path.display(),
        shrinker_verdict_report_path.display(),
        minimized_counterexamples_path.display(),
        hdd_reducer_report_path.display(),
        structured_reduction_operator_catalog_path.display(),
        minimized_structured_repros_path.display(),
        reduction_stability_matrix_path.display(),
        triage_report_path.display(),
        governance_actions_path.display(),
        failures_dir.display()
    );

    if suite.total_violations > 0 {
        return Err(format!(
            "metamorphic violations detected: {}",
            suite.total_violations
        )
        .into());
    }

    Ok(())
}

fn write_events_jsonl(
    events_path: &std::path::Path,
    events: &[frankenengine_metamorphic::runner::RelationLogEvent],
) -> std::io::Result<()> {
    let mut payload = String::new();
    for event in events {
        payload
            .push_str(&serde_json::to_string(event).expect("event serialization should succeed"));
        payload.push('\n');
    }

    fs::write(events_path, payload)
}

fn select_relations(
    all_relations: &[CatalogBackedRelation],
    relation_filters: &[String],
) -> Result<Vec<CatalogBackedRelation>, String> {
    if relation_filters.is_empty() {
        return Ok(all_relations.to_vec());
    }

    let mut selected = Vec::new();
    let mut unknown = Vec::new();
    let mut seen = BTreeSet::new();

    for relation_filter in relation_filters {
        if !seen.insert(relation_filter.clone()) {
            continue;
        }

        match all_relations
            .iter()
            .find(|relation| relation.spec().id.as_str() == relation_filter.as_str())
        {
            Some(relation) => selected.push(relation.clone()),
            None => unknown.push(relation_filter.clone()),
        }
    }

    if !unknown.is_empty() {
        let available = all_relations
            .iter()
            .map(|relation| relation.spec().id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "unknown relation filter(s): {}. available enabled relations: {available}",
            unknown.join(", ")
        ));
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use frankenengine_metamorphic::build_enabled_relations;
    use frankenengine_metamorphic::catalog::RelationCatalog;
    use frankenengine_metamorphic::relation::MetamorphicRelation;

    use super::select_relations;

    #[test]
    fn select_relations_returns_all_when_filters_are_empty() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let selected = select_relations(&all_relations, &[]).expect("selection should succeed");
        assert_eq!(selected.len(), all_relations.len());
    }

    #[test]
    fn select_relations_rejects_unknown_filter_even_if_some_valid() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let filters = vec![
            "parser_whitespace_invariance".to_string(),
            "nonexistent_relation".to_string(),
        ];

        let error = select_relations(&all_relations, &filters).expect_err("selection should fail");
        assert!(error.contains("unknown relation filter(s): nonexistent_relation"));
        assert!(error.contains("available enabled relations:"));
    }

    #[test]
    fn select_relations_deduplicates_filters_preserving_first_seen_order() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let all_relations = build_enabled_relations(&catalog);
        let filters = vec![
            "execution_gc_timing_independence".to_string(),
            "execution_gc_timing_independence".to_string(),
            "parser_comment_invariance".to_string(),
        ];

        let selected = select_relations(&all_relations, &filters).expect("selection should pass");
        let selected_ids = selected
            .iter()
            .map(|relation| relation.spec().id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            selected_ids,
            vec![
                "execution_gc_timing_independence",
                "parser_comment_invariance"
            ]
        );
    }
}
