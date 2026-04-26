#!/usr/bin/env rust-script
//! Module dependency analyzer for franken-engine
//!
//! This script analyzes the dependency graph of all modules in the franken-engine crate
//! and classifies them based on reachability from entry points.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleClassification {
    CoreReachable,     // Reachable from execution_orchestrator.rs and core runtime
    GovernanceReachable, // Reachable from governance/control plane modules
    GateReachable,     // Reachable from gate/verification modules
    Island,            // Not reachable from any entry point
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub file_path: String,
    pub dependencies: BTreeSet<String>,
    pub classification: ModuleClassification,
    pub reachable_from: BTreeSet<String>, // Entry points that can reach this module
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleAnalysis {
    pub modules: BTreeMap<String, ModuleInfo>,
    pub entry_points: BTreeSet<String>,
    pub summary: ModuleSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleSummary {
    pub total_modules: usize,
    pub core_reachable: usize,
    pub governance_reachable: usize,
    pub gate_reachable: usize,
    pub island_modules: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let src_path = Path::new("crates/franken-engine/src");

    // Step 1: Collect all modules
    let modules = collect_modules(src_path)?;
    println!("Found {} modules", modules.len());

    // Step 2: Parse dependencies for each module
    let mut module_deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (module_name, file_path) in &modules {
        let deps = parse_module_dependencies(file_path)?;
        module_deps.insert(module_name.clone(), deps);
    }

    // Step 3: Define entry points
    let entry_points = get_entry_points(&modules);
    println!("Entry points: {:?}", entry_points);

    // Step 4: Build dependency graph and classify modules
    let mut analysis = ModuleAnalysis {
        modules: BTreeMap::new(),
        entry_points: entry_points.clone(),
        summary: ModuleSummary {
            total_modules: modules.len(),
            core_reachable: 0,
            governance_reachable: 0,
            gate_reachable: 0,
            island_modules: 0,
        },
    };

    // Step 5: Compute reachability from each entry point
    let mut reachability: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry_point in &entry_points {
        let reachable = compute_reachable_modules(entry_point, &module_deps);
        reachability.insert(entry_point.clone(), reachable);
    }

    // Step 6: Classify each module
    for (module_name, file_path) in &modules {
        let mut reachable_from = BTreeSet::new();

        for (entry_point, reachable_modules) in &reachability {
            if reachable_modules.contains(module_name) {
                reachable_from.insert(entry_point.clone());
            }
        }

        let classification = classify_module(module_name, &reachable_from);

        let module_info = ModuleInfo {
            name: module_name.clone(),
            file_path: file_path.display().to_string(),
            dependencies: module_deps.get(module_name).cloned().unwrap_or_default(),
            classification: classification.clone(),
            reachable_from,
        };

        // Update summary
        match classification {
            ModuleClassification::CoreReachable => analysis.summary.core_reachable += 1,
            ModuleClassification::GovernanceReachable => analysis.summary.governance_reachable += 1,
            ModuleClassification::GateReachable => analysis.summary.gate_reachable += 1,
            ModuleClassification::Island => analysis.summary.island_modules += 1,
        }

        analysis.modules.insert(module_name.clone(), module_info);
    }

    // Step 7: Output results
    let output_file = "docs/architecture/module_classification.json";
    let json = serde_json::to_string_pretty(&analysis)?;
    fs::write(output_file, json)?;

    println!("\nModule Classification Summary:");
    println!("Total modules: {}", analysis.summary.total_modules);
    println!("Core reachable: {}", analysis.summary.core_reachable);
    println!("Governance reachable: {}", analysis.summary.governance_reachable);
    println!("Gate reachable: {}", analysis.summary.gate_reachable);
    println!("Island modules: {}", analysis.summary.island_modules);

    // Show some examples of each category
    println!("\nExamples by category:");
    for (category, modules) in [
        ("Core reachable", ModuleClassification::CoreReachable),
        ("Governance reachable", ModuleClassification::GovernanceReachable),
        ("Gate reachable", ModuleClassification::GateReachable),
        ("Island", ModuleClassification::Island),
    ] {
        let examples: Vec<_> = analysis.modules.values()
            .filter(|m| m.classification == modules)
            .take(5)
            .map(|m| &m.name)
            .collect();
        println!("{}: {:?}", category, examples);
    }

    println!("\nResults written to {}", output_file);

    Ok(())
}

fn collect_modules(src_path: &Path) -> Result<BTreeMap<String, PathBuf>, std::io::Error> {
    let mut modules = BTreeMap::new();

    for entry in fs::read_dir(src_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().map_or(false, |ext| ext == "rs") {
            if let Some(stem) = path.file_stem() {
                if let Some(module_name) = stem.to_str() {
                    modules.insert(module_name.to_string(), path);
                }
            }
        }
    }

    // Also check bin directory for binary targets
    let bin_path = src_path.join("bin");
    if bin_path.exists() {
        for entry in fs::read_dir(bin_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "rs") {
                if let Some(stem) = path.file_stem() {
                    if let Some(module_name) = stem.to_str() {
                        modules.insert(format!("bin_{}", module_name), path);
                    }
                }
            }
        }
    }

    Ok(modules)
}

fn parse_module_dependencies(file_path: &Path) -> Result<BTreeSet<String>, std::io::Error> {
    let content = fs::read_to_string(file_path)?;
    let mut deps = BTreeSet::new();

    // Match use statements that reference crate modules
    let use_regex = Regex::new(r"use\s+(?:crate::)?([a-zA-Z_][a-zA-Z0-9_]*)")
        .expect("Invalid regex");

    // Match mod statements
    let mod_regex = Regex::new(r"mod\s+([a-zA-Z_][a-zA-Z0-9_]*)")
        .expect("Invalid regex");

    for cap in use_regex.captures_iter(&content) {
        if let Some(module) = cap.get(1) {
            deps.insert(module.as_str().to_string());
        }
    }

    for cap in mod_regex.captures_iter(&content) {
        if let Some(module) = cap.get(1) {
            deps.insert(module.as_str().to_string());
        }
    }

    Ok(deps)
}

fn get_entry_points(modules: &BTreeMap<String, PathBuf>) -> BTreeSet<String> {
    let mut entry_points = BTreeSet::new();

    // Primary entry points
    entry_points.insert("execution_orchestrator".to_string());
    entry_points.insert("lib".to_string()); // lib.rs public API

    // Binary targets are also entry points
    for module_name in modules.keys() {
        if module_name.starts_with("bin_") {
            entry_points.insert(module_name.clone());
        }
    }

    entry_points
}

fn compute_reachable_modules(
    entry_point: &str,
    module_deps: &BTreeMap<String, BTreeSet<String>>
) -> BTreeSet<String> {
    let mut visited = BTreeSet::new();
    let mut to_visit = vec![entry_point.to_string()];

    while let Some(current) = to_visit.pop() {
        if visited.contains(&current) {
            continue;
        }

        visited.insert(current.clone());

        if let Some(deps) = module_deps.get(&current) {
            for dep in deps {
                if !visited.contains(dep) {
                    to_visit.push(dep.clone());
                }
            }
        }
    }

    visited
}

fn classify_module(module_name: &str, reachable_from: &BTreeSet<String>) -> ModuleClassification {
    if reachable_from.is_empty() {
        return ModuleClassification::Island;
    }

    // Core reachable: reachable from execution_orchestrator or lib
    if reachable_from.contains("execution_orchestrator") || reachable_from.contains("lib") {
        return ModuleClassification::CoreReachable;
    }

    // Check if module or its entry points suggest governance/control plane
    let governance_indicators = [
        "control_plane", "governance", "policy", "scorecard", "audit",
        "compliance", "security", "attestation", "witness"
    ];

    let gate_indicators = [
        "gate", "verification", "conformance", "test", "benchmark",
        "harness", "validator", "checker"
    ];

    let module_lower = module_name.to_lowercase();

    for indicator in &governance_indicators {
        if module_lower.contains(indicator) ||
           reachable_from.iter().any(|ep| ep.to_lowercase().contains(indicator)) {
            return ModuleClassification::GovernanceReachable;
        }
    }

    for indicator in &gate_indicators {
        if module_lower.contains(indicator) ||
           reachable_from.iter().any(|ep| ep.to_lowercase().contains(indicator)) {
            return ModuleClassification::GateReachable;
        }
    }

    // Default to governance reachable if reachable from somewhere
    ModuleClassification::GovernanceReachable
}
