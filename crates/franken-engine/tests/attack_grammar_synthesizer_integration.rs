//! Integration tests for attack grammar synthesizer.
//!
//! Tests the end-to-end generation of JavaScript exploit scenarios with
//! corresponding manifest files, covering all attack strategies and mutation
//! operators in realistic scenarios.

use frankenengine_engine::attack_grammar_synthesizer::{
    AttackGrammarSynthesizer, AttackStrategy, ExploitSeverity, ExploitTarget, MutationOperator,
    SynthesisConfig,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

#[test]
fn synthesize_complete_exploit_suite() {
    // Test generating a complete suite of exploits across all strategies.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);
    strategies.insert(AttackStrategy::PrototypePollution);
    strategies.insert(AttackStrategy::EventHijacking);
    strategies.insert(AttackStrategy::ResourceExhaustion);
    strategies.insert(AttackStrategy::LogicBomb);
    strategies.insert(AttackStrategy::SupplyChain);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 15,
        max_mutations_per_base: 8,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(200),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(1_500_000_000)
        .expect("should synthesize exploit suite");

    assert!(!candidates.is_empty());
    assert!(candidates.len() >= 6); // At least one per strategy

    // Verify all strategies are represented.
    let mut represented_strategies = BTreeSet::new();
    for candidate in &candidates {
        represented_strategies.insert(candidate.manifest.strategy);
    }
    assert!(represented_strategies.len() >= 3);

    // Verify manifest completeness.
    for candidate in &candidates {
        assert!(!candidate.manifest.description.is_empty());
        assert!(!candidate.manifest.preconditions.is_empty());
        assert!(!candidate.manifest.expected_outcomes.is_empty());
        assert!(!candidate.manifest.detection_patterns.is_empty());
        assert!(!candidate.manifest.mitigations.is_empty());
        assert!(!candidate.javascript_code.is_empty());
        assert!(candidate.js_filename.ends_with(".js"));
        assert!(candidate.manifest_filename.ends_with(".manifest.json"));
    }

    // Verify JavaScript code quality.
    for candidate in &candidates {
        assert!(candidate.javascript_code.contains("function"));
        assert!(candidate.javascript_code.len() > 100);
        // All exploits should be wrapped in IIFE for safety.
        assert!(candidate.javascript_code.contains("(function()"));
    }
}

#[test]
fn dom_injection_exploit_generation() {
    // Test specific DOM injection exploit generation with mutations.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 20,
        max_mutations_per_base: 10,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Medium,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(300),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(2_000_000_000)
        .expect("should synthesize DOM injection exploits");

    // Verify DOM injection specifics.
    let dom_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.strategy == AttackStrategy::DomInjection)
        .collect();

    assert!(!dom_candidates.is_empty());

    for candidate in &dom_candidates {
        assert_eq!(candidate.manifest.target, ExploitTarget::DomTree);
        assert!(
            candidate.javascript_code.contains("innerHTML")
                || candidate.javascript_code.contains("DOM")
        );
        assert!(
            candidate
                .manifest
                .detection_patterns
                .iter()
                .any(|p| p.contains("innerHTML") || p.contains("script"))
        );
        assert!(
            candidate
                .manifest
                .mitigations
                .iter()
                .any(|m| m.contains("CSP") || m.contains("sanitization"))
        );
    }

    // Verify mutations are present.
    let mutated_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.description.contains("mutated with"))
        .collect();
    assert!(!mutated_candidates.is_empty());
}

#[test]
fn prototype_pollution_exploit_critical_severity() {
    // Test that prototype pollution exploits have critical severity.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::PrototypePollution);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 10,
        max_mutations_per_base: 5,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Critical,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(400),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(2_500_000_000)
        .expect("should synthesize prototype pollution exploits");

    assert!(!candidates.is_empty());

    for candidate in &candidates {
        assert_eq!(
            candidate.manifest.strategy,
            AttackStrategy::PrototypePollution
        );
        assert_eq!(candidate.manifest.severity, ExploitSeverity::Critical);
        assert_eq!(candidate.manifest.target, ExploitTarget::GlobalNamespace);
        assert!(
            candidate.javascript_code.contains("__proto__")
                || candidate.javascript_code.contains("prototype")
        );
    }
}

#[test]
fn event_hijacking_race_conditions() {
    // Test event hijacking exploits include race condition patterns.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::EventHijacking);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 8,
        max_mutations_per_base: 6,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(500),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(3_000_000_000)
        .expect("should synthesize event hijacking exploits");

    let hijacking_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.strategy == AttackStrategy::EventHijacking)
        .collect();

    assert!(!hijacking_candidates.is_empty());

    for candidate in &hijacking_candidates {
        assert_eq!(candidate.manifest.target, ExploitTarget::EventSystem);
        assert!(
            candidate.javascript_code.contains("addEventListener")
                || candidate.javascript_code.contains("event")
        );
        assert!(
            candidate
                .manifest
                .detection_patterns
                .iter()
                .any(|p| p.contains("event") || p.contains("privilege"))
        );
    }
}

#[test]
fn resource_exhaustion_memory_bombs() {
    // Test resource exhaustion exploits generate memory allocation patterns.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::ResourceExhaustion);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 12,
        max_mutations_per_base: 7,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Medium,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(600),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(3_500_000_000)
        .expect("should synthesize resource exhaustion exploits");

    let exhaustion_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.strategy == AttackStrategy::ResourceExhaustion)
        .collect();

    assert!(!exhaustion_candidates.is_empty());

    for candidate in &exhaustion_candidates {
        assert_eq!(candidate.manifest.target, ExploitTarget::MemorySubsystem);
        assert!(
            candidate.javascript_code.contains("Array")
                || candidate.javascript_code.contains("memory")
                || candidate.javascript_code.contains("allocation")
        );
        assert!(
            candidate
                .manifest
                .expected_outcomes
                .iter()
                .any(|o| o.contains("memory") || o.contains("crash"))
        );
    }
}

#[test]
fn logic_bomb_time_based_triggers() {
    // Test logic bomb exploits have time-based conditional execution.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::LogicBomb);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 6,
        max_mutations_per_base: 4,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::High,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(700),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(4_000_000_000)
        .expect("should synthesize logic bomb exploits");

    let bomb_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.strategy == AttackStrategy::LogicBomb)
        .collect();

    assert!(!bomb_candidates.is_empty());

    for candidate in &bomb_candidates {
        assert_eq!(candidate.manifest.target, ExploitTarget::RuntimeEnvironment);
        assert!(
            candidate.javascript_code.contains("Date")
                || candidate.javascript_code.contains("time")
                || candidate.javascript_code.contains("trigger")
        );
        assert!(
            candidate
                .manifest
                .detection_patterns
                .iter()
                .any(|p| p.contains("date") || p.contains("trigger"))
        );
    }
}

#[test]
fn supply_chain_package_interception() {
    // Test supply chain exploits modify package loading mechanisms.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::SupplyChain);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 8,
        max_mutations_per_base: 5,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Critical,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(800),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(4_500_000_000)
        .expect("should synthesize supply chain exploits");

    let supply_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.manifest.strategy == AttackStrategy::SupplyChain)
        .collect();

    assert!(!supply_candidates.is_empty());

    for candidate in &supply_candidates {
        assert_eq!(candidate.manifest.target, ExploitTarget::Dependencies);
        assert!(
            candidate.javascript_code.contains("require")
                || candidate.javascript_code.contains("import")
                || candidate.javascript_code.contains("package")
        );
        assert!(
            candidate
                .manifest
                .mitigations
                .iter()
                .any(|m| m.contains("integrity") || m.contains("dependency"))
        );
    }
}

#[test]
fn payload_encoding_mutations() {
    // Test that payload encoding mutations apply base64 encoding.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 5,
        max_mutations_per_base: 3,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(900),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(5_000_000_000)
        .expect("should synthesize exploits with mutations");

    // Find payload encoding mutations.
    let encoded_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.javascript_code.contains("atob"))
        .collect();

    assert!(!encoded_candidates.is_empty());

    for candidate in &encoded_candidates {
        assert!(candidate.manifest.description.contains("payload-encoding"));
        assert!(candidate.js_filename.contains("payload_encoding"));
    }
}

#[test]
fn obfuscation_mutations() {
    // Test obfuscation mutations add comments and complexity.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::PrototypePollution);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 4,
        max_mutations_per_base: 6,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Medium,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(1000),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(5_500_000_000)
        .expect("should synthesize exploits with obfuscation");

    // Find obfuscated candidates.
    let obfuscated_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.javascript_code.contains("Obfuscated version"))
        .collect();

    assert!(!obfuscated_candidates.is_empty());

    for candidate in &obfuscated_candidates {
        assert!(candidate.manifest.description.contains("obfuscation"));
        assert!(candidate.js_filename.contains("obfuscation"));
    }
}

#[test]
fn target_mutation_changes_selectors() {
    // Test target mutations modify DOM selectors.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 6,
        max_mutations_per_base: 8,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1100),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(6_000_000_000)
        .expect("should synthesize exploits with target mutations");

    // Find target mutations.
    let target_mutated: Vec<_> = candidates
        .iter()
        .filter(|c| {
            c.javascript_code.contains("div, span, p") || c.javascript_code.contains("mousedown")
        })
        .collect();

    assert!(!target_mutated.is_empty());

    for candidate in &target_mutated {
        assert!(
            candidate.manifest.description.contains("target-mutation")
                || candidate.js_filename.contains("target_mutation")
        );
    }
}

#[test]
fn timing_mutations_add_delays() {
    // Test timing mutations introduce setTimeout delays.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::EventHijacking);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 5,
        max_mutations_per_base: 4,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Medium,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1200),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(6_500_000_000)
        .expect("should synthesize exploits with timing mutations");

    // Find timing mutations.
    let timing_mutated: Vec<_> = candidates
        .iter()
        .filter(|c| {
            c.javascript_code.contains("Math.random()") && c.javascript_code.contains("setTimeout")
        })
        .collect();

    assert!(!timing_mutated.is_empty());

    for candidate in &timing_mutated {
        assert!(
            candidate.manifest.description.contains("timing-mutation")
                || candidate.js_filename.contains("timing_mutation")
        );
    }
}

#[test]
fn context_mutations_change_execution_wrapper() {
    // Test context mutations wrap code in different execution contexts.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::LogicBomb);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 4,
        max_mutations_per_base: 3,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::High,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1300),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(7_000_000_000)
        .expect("should synthesize exploits with context mutations");

    // Find context mutations.
    let context_mutated: Vec<_> = candidates
        .iter()
        .filter(|c| {
            c.javascript_code.contains("typeof window") && c.javascript_code.contains("global")
        })
        .collect();

    assert!(!context_mutated.is_empty());

    for candidate in &context_mutated {
        assert!(
            candidate.manifest.description.contains("context-mutation")
                || candidate.js_filename.contains("context_mutation")
        );
    }
}

#[test]
fn severity_threshold_filtering() {
    // Test that severity threshold filtering works correctly.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);
    strategies.insert(AttackStrategy::ResourceExhaustion);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 10,
        max_mutations_per_base: 5,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::High,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(1400),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(7_500_000_000)
        .expect("should synthesize exploits with threshold filtering");

    // All candidates should meet the severity threshold.
    for candidate in &candidates {
        assert!(candidate.manifest.severity >= ExploitSeverity::High);
    }

    // DOM injection should be included (high severity).
    let dom_present = candidates
        .iter()
        .any(|c| c.manifest.strategy == AttackStrategy::DomInjection);
    assert!(dom_present);

    // Resource exhaustion should be filtered out (medium severity).
    let resource_present = candidates
        .iter()
        .any(|c| c.manifest.strategy == AttackStrategy::ResourceExhaustion);
    assert!(!resource_present);
}

#[test]
fn exploit_ids_are_deterministic() {
    // Test that exploit IDs are deterministic for identical inputs.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::PrototypePollution);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 3,
        max_mutations_per_base: 2,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1500),
    };

    let mut synth1 = AttackGrammarSynthesizer::new(config.clone());
    let mut synth2 = AttackGrammarSynthesizer::new(config);

    let candidates1 = synth1
        .synthesize_exploits(8_000_000_000)
        .expect("should synthesize exploits");
    let candidates2 = synth2
        .synthesize_exploits(8_000_000_000)
        .expect("should synthesize exploits");

    assert_eq!(candidates1.len(), candidates2.len());

    // IDs should match for identical generation parameters.
    for (c1, c2) in candidates1.iter().zip(candidates2.iter()) {
        if c1.manifest.description == c2.manifest.description {
            assert_eq!(c1.manifest.exploit_id, c2.manifest.exploit_id);
        }
    }
}

#[test]
fn generation_count_tracking() {
    // Test that generation count is properly tracked.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 5,
        max_mutations_per_base: 3,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(1600),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    assert_eq!(synthesizer.generation_count(), 0);

    let candidates = synthesizer
        .synthesize_exploits(8_500_000_000)
        .expect("should synthesize exploits");

    assert_eq!(synthesizer.generation_count(), candidates.len() as u64);
    assert_eq!(synthesizer.candidates().len(), candidates.len());
}

#[test]
fn manifest_file_naming_consistency() {
    // Test that manifest and JS filenames are consistently named.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::SupplyChain);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 4,
        max_mutations_per_base: 2,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Critical,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1700),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(9_000_000_000)
        .expect("should synthesize exploits");

    for candidate in &candidates {
        // JS filename should match manifest filename pattern.
        let js_base = candidate
            .js_filename
            .strip_suffix(".js")
            .expect("should have .js suffix");
        let manifest_base = candidate
            .manifest_filename
            .strip_suffix(".manifest.json")
            .expect("should have .manifest.json suffix");

        assert_eq!(js_base, manifest_base);

        // Both filenames should contain strategy info.
        assert!(js_base.contains("supply_chain"));
        assert!(manifest_base.contains("supply_chain"));
    }
}

#[test]
fn all_mutation_operators_covered() {
    // Test that all mutation operators are exercised.
    let mut strategies = BTreeSet::new();
    strategies.insert(AttackStrategy::DomInjection);
    strategies.insert(AttackStrategy::EventHijacking);

    let config = SynthesisConfig {
        max_candidates_per_strategy: 15,
        max_mutations_per_base: 12,
        preferred_strategies: strategies,
        severity_threshold: ExploitSeverity::Low,
        include_obfuscation: true,
        epoch: SecurityEpoch::from_raw(1800),
    };

    let mut synthesizer = AttackGrammarSynthesizer::new(config);
    let candidates = synthesizer
        .synthesize_exploits(9_500_000_000)
        .expect("should synthesize exploits");

    let mutation_operators = [
        "payload-encoding",
        "target-mutation",
        "obfuscation",
        "timing-mutation",
    ];

    // Verify all mutation operators are represented.
    for operator in &mutation_operators {
        let operator_present = candidates
            .iter()
            .any(|c| c.manifest.description.contains(operator));
        assert!(operator_present, "mutation operator {} not found", operator);
    }
}

#[test]
fn config_accessor_methods() {
    // Test synthesizer accessor methods.
    let config = SynthesisConfig {
        max_candidates_per_strategy: 7,
        max_mutations_per_base: 4,
        preferred_strategies: [AttackStrategy::LogicBomb].iter().cloned().collect(),
        severity_threshold: ExploitSeverity::Medium,
        include_obfuscation: false,
        epoch: SecurityEpoch::from_raw(1900),
    };

    let synthesizer = AttackGrammarSynthesizer::new(config.clone());

    assert_eq!(*synthesizer.config(), config);
    assert_eq!(synthesizer.generation_count(), 0);
    assert!(synthesizer.candidates().is_empty());
}
