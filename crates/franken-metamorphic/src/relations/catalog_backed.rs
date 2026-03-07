use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::relation::{
    ChoiceStream, Equivalence, GeneratedCase, GeneratedPair, GenerationChoice, MetamorphicRelation,
    PropertyContract, RelationSpec, default_generator_id,
};

const IDENTIFIERS: [&str; 12] = [
    "alpha", "beta", "gamma", "delta", "theta", "sigma", "omega", "kappa", "lambda", "net", "fs",
    "clock",
];

#[derive(Debug, Clone)]
pub struct CatalogBackedRelation {
    spec: RelationSpec,
}

impl CatalogBackedRelation {
    pub fn new(spec: RelationSpec) -> Self {
        Self { spec }
    }

    fn relation_id(&self) -> &str {
        self.spec.id.as_str()
    }

    fn parse_or_diverge(source: &str, side: &str) -> Result<Program, Equivalence> {
        parse_program(source).map_err(|error| Equivalence::Diverged {
            detail: format!("{side} parse failure: {error}"),
        })
    }

    fn lower_or_diverge(source: &str, side: &str) -> Result<IrLowering, Equivalence> {
        lower_program(source).map_err(|error| Equivalence::Diverged {
            detail: format!("{side} lowering failure: {error}"),
        })
    }

    fn execution_or_diverge(
        source: &str,
        side: &str,
        options: ExecOptions,
    ) -> Result<ExecutionResult, Equivalence> {
        let program = Self::parse_or_diverge(source, side)?;
        execute_program(&program, options).map_err(|error| Equivalence::Diverged {
            detail: format!("{side} execution failure: {error}"),
        })
    }

    fn parser_oracle(&self, pair: &GeneratedPair) -> Equivalence {
        let input_program = match Self::parse_or_diverge(&pair.input_source, "input") {
            Ok(program) => program,
            Err(error) => return error,
        };
        let variant_program = match Self::parse_or_diverge(&pair.variant_source, "variant") {
            Ok(program) => program,
            Err(error) => return error,
        };

        let input_signature = canonical_program_signature(&input_program);
        let variant_signature = canonical_program_signature(&variant_program);

        if input_signature == variant_signature {
            Equivalence::Equivalent
        } else {
            Equivalence::Diverged {
                detail: format!(
                    "parser semantic signatures differ: input={input_signature} variant={variant_signature}"
                ),
            }
        }
    }

    fn ir_oracle(&self, pair: &GeneratedPair) -> Equivalence {
        let left = match Self::lower_or_diverge(&pair.input_source, "input") {
            Ok(lowering) => lowering,
            Err(error) => return error,
        };
        let right = match Self::lower_or_diverge(&pair.variant_source, "variant") {
            Ok(lowering) => lowering,
            Err(error) => return error,
        };

        match self.relation_id() {
            "ir_lowering_determinism" => {
                if left.ir0 == right.ir0
                    && left.ir1 == right.ir1
                    && left.ir2 == right.ir2
                    && left.ir3 == right.ir3
                    && left.ir4 == right.ir4
                {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "lowering artifacts diverged: left_ir4={} right_ir4={}",
                            left.ir4, right.ir4
                        ),
                    }
                }
            }
            "ir_optimization_idempotence" => {
                let left_idempotent = left.optimized_once == left.optimized_twice;
                let right_idempotent = right.optimized_once == right.optimized_twice;
                if left_idempotent && right_idempotent {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "optimization is not idempotent: left={} right={}",
                            left_idempotent, right_idempotent
                        ),
                    }
                }
            }
            "ir_capability_preservation" => {
                let left_ok = is_subset(&left.capabilities_ir2, &left.capabilities_ir3)
                    && is_subset(&left.capabilities_ir3, &left.capabilities_ir4);
                let right_ok = is_subset(&right.capabilities_ir2, &right.capabilities_ir3)
                    && is_subset(&right.capabilities_ir3, &right.capabilities_ir4);
                if left_ok && right_ok {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "capability closure violated: left_ok={} right_ok={}",
                            left_ok, right_ok
                        ),
                    }
                }
            }
            "ir_dead_code_insertion_invariance" => {
                if left.observable_signature == right.observable_signature {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "dead-code insertion changed observable output: input={} variant={}",
                            left.observable_signature, right.observable_signature
                        ),
                    }
                }
            }
            "ir_constant_folding_equivalence" => {
                if left.observable_signature == right.observable_signature
                    && left.optimized_once == right.optimized_once
                {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "constant folding equivalence violated: left={} right={}",
                            left.observable_signature, right.observable_signature
                        ),
                    }
                }
            }
            other => Equivalence::Diverged {
                detail: format!("unknown ir relation id: {other}"),
            },
        }
    }

    fn execution_oracle(&self, pair: &GeneratedPair) -> Equivalence {
        match self.relation_id() {
            "execution_evaluation_order_determinism" => {
                let first = match Self::execution_or_diverge(
                    &pair.input_source,
                    "input",
                    ExecOptions::default(),
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let second = match Self::execution_or_diverge(
                    &pair.input_source,
                    "input_replay",
                    ExecOptions::default(),
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let variant = match Self::execution_or_diverge(
                    &pair.variant_source,
                    "variant",
                    ExecOptions::default(),
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };

                if first == second && first == variant {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "evaluation order instability: first={:?} second={:?} variant={:?}",
                            first.side_effect_trace,
                            second.side_effect_trace,
                            variant.side_effect_trace
                        ),
                    }
                }
            }
            "execution_gc_timing_independence" => {
                let fast = ExecOptions {
                    gc_schedule: 1,
                    ..ExecOptions::default()
                };
                let slow = ExecOptions {
                    gc_schedule: 17,
                    ..ExecOptions::default()
                };

                let left = match Self::execution_or_diverge(&pair.input_source, "input", fast) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let right = match Self::execution_or_diverge(&pair.input_source, "input_gc", slow) {
                    Ok(result) => result,
                    Err(error) => return error,
                };

                if left.observable_signature() == right.observable_signature() {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "gc timing affected observable output: left={} right={}",
                            left.observable_signature(),
                            right.observable_signature()
                        ),
                    }
                }
            }
            "execution_stack_depth_independence" => {
                let shallow = ExecOptions {
                    stack_limit: 100,
                    ..ExecOptions::default()
                };
                let deep = ExecOptions {
                    stack_limit: 10_000,
                    ..ExecOptions::default()
                };

                let left = match Self::execution_or_diverge(&pair.input_source, "input", shallow) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let right = match Self::execution_or_diverge(&pair.input_source, "input_deep", deep)
                {
                    Ok(result) => result,
                    Err(error) => return error,
                };

                if left.observable_signature() == right.observable_signature() {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "stack depth changed observable output: left={} right={}",
                            left.observable_signature(),
                            right.observable_signature()
                        ),
                    }
                }
            }
            "execution_prototype_chain_equivalence" => {
                let left = match Self::execution_or_diverge(
                    &pair.input_source,
                    "input",
                    ExecOptions::default(),
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let right = match Self::execution_or_diverge(
                    &pair.variant_source,
                    "variant",
                    ExecOptions::default(),
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };

                if left.observable_signature() == right.observable_signature() {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "prototype resolution diverged: left={} right={}",
                            left.observable_signature(),
                            right.observable_signature()
                        ),
                    }
                }
            }
            "execution_promise_resolution_order_stability" => {
                let single = ExecOptions {
                    promise_batch: 1,
                    ..ExecOptions::default()
                };
                let batched = ExecOptions {
                    promise_batch: 3,
                    ..ExecOptions::default()
                };

                let left = match Self::execution_or_diverge(&pair.input_source, "input", single) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                let right = match Self::execution_or_diverge(
                    &pair.input_source,
                    "input_batched",
                    batched,
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };

                if left.observable_signature() == right.observable_signature() {
                    Equivalence::Equivalent
                } else {
                    Equivalence::Diverged {
                        detail: format!(
                            "promise resolution order changed: left={:?} right={:?}",
                            left.side_effect_trace, right.side_effect_trace
                        ),
                    }
                }
            }
            other => Equivalence::Diverged {
                detail: format!("unknown execution relation id: {other}"),
            },
        }
    }
}

impl MetamorphicRelation for CatalogBackedRelation {
    fn spec(&self) -> &RelationSpec {
        &self.spec
    }

    fn generate_pair(&self, seed: u64) -> GeneratedPair {
        generate_case_for_relation(self.relation_id(), seed).pair
    }

    fn generate_case(&self, seed: u64) -> GeneratedCase {
        generate_case_for_relation(self.relation_id(), seed)
    }

    fn replay_case(&self, choice_stream: &ChoiceStream) -> Option<GeneratedCase> {
        replay_case_for_relation(choice_stream)
    }

    fn shrink_strategy(&self) -> &'static str {
        "recorded_choice_stream_then_ddmin"
    }

    fn oracle(&self, pair: &GeneratedPair) -> Equivalence {
        match self.spec.subsystem {
            crate::relation::Subsystem::Parser => self.parser_oracle(pair),
            crate::relation::Subsystem::Ir => self.ir_oracle(pair),
            crate::relation::Subsystem::Execution => self.execution_oracle(pair),
        }
    }

    fn validate_program(&self, source: &str) -> bool {
        parse_program(source).is_ok()
    }
}

fn generate_case_for_relation(relation_id: &str, seed: u64) -> GeneratedCase {
    let mut machine = GeneratorMachine::record(relation_id, seed);
    let pair = generate_pair_for_relation(relation_id, &mut machine).unwrap_or(GeneratedPair {
        input_source: "return 0;".to_string(),
        variant_source: "return 0;".to_string(),
    });
    let generator_id = machine.generator_id().to_string();
    let choice_stream = machine.finish_recording();
    let property_contract = property_contract_for_pair(relation_id, &generator_id, &pair);

    GeneratedCase {
        relation_id: relation_id.to_string(),
        generator_id,
        seed,
        pair,
        choice_stream,
        property_contract,
    }
}

fn replay_case_for_relation(choice_stream: &ChoiceStream) -> Option<GeneratedCase> {
    if choice_stream.generator_id != default_generator_id(&choice_stream.relation_id) {
        return None;
    }

    let mut machine = GeneratorMachine::replay(choice_stream);
    let pair = generate_pair_for_relation(choice_stream.relation_id.as_str(), &mut machine)?;
    if !machine.replay_finished() {
        return None;
    }

    let property_contract = property_contract_for_pair(
        &choice_stream.relation_id,
        &choice_stream.generator_id,
        &pair,
    );

    Some(GeneratedCase {
        relation_id: choice_stream.relation_id.clone(),
        generator_id: choice_stream.generator_id.clone(),
        seed: choice_stream.seed,
        pair,
        choice_stream: choice_stream.clone(),
        property_contract,
    })
}

fn property_contract_for_pair(
    relation_id: &str,
    generator_id: &str,
    pair: &GeneratedPair,
) -> PropertyContract {
    PropertyContract {
        schema_version: "franken-engine.metamorphic.property-contract.v1".to_string(),
        relation_id: relation_id.to_string(),
        generator_id: generator_id.to_string(),
        expected_equivalence: "equivalent".to_string(),
        validates_input: parse_program(&pair.input_source).is_ok(),
        validates_variant: parse_program(&pair.variant_source).is_ok(),
        replay_supported: true,
        shrink_strategy: "recorded_choice_stream_then_ddmin".to_string(),
    }
}

fn generate_pair_for_relation(
    relation_id: &str,
    machine: &mut GeneratorMachine<'_>,
) -> Option<GeneratedPair> {
    match relation_id {
        "parser_whitespace_invariance" => {
            let base = generate_arithmetic_program(machine, "parser_whitespace_invariance.base")?;
            let variant = inject_whitespace(&base, machine, "parser_whitespace_invariance")?;
            Some(GeneratedPair {
                input_source: base,
                variant_source: variant,
            })
        }
        "parser_comment_invariance" => {
            let base = generate_arithmetic_program(machine, "parser_comment_invariance.base")?;
            let variant = inject_comments(&base, machine, "parser_comment_invariance")?;
            Some(GeneratedPair {
                input_source: base,
                variant_source: variant,
            })
        }
        "parser_parenthesization_invariance" => {
            let name = pick_identifier(machine, "parser_parenthesization_invariance.name")?;
            let a = machine.int_inclusive("parser_parenthesization_invariance.a", 2, 8)?;
            let b = machine.int_inclusive("parser_parenthesization_invariance.b", 3, 9)?;
            Some(GeneratedPair {
                input_source: format!("let {name} = {a} + {b}; return {name};"),
                variant_source: format!("let {name} = (({a})) + (({b})); return ({name});"),
            })
        }
        "parser_asi_equivalence" => {
            let name = pick_identifier(machine, "parser_asi_equivalence.name")?;
            let value = machine.int_inclusive("parser_asi_equivalence.value", 1, 9)?;
            Some(GeneratedPair {
                input_source: format!("let {name} = {value} + 1\nemit({name})\nreturn {name}\n"),
                variant_source: format!("let {name} = {value} + 1; emit({name}); return {name};"),
            })
        }
        "parser_unicode_escape_equivalence" => {
            let plain = pick_identifier(machine, "parser_unicode_escape_equivalence.plain")?;
            let escaped = escape_identifier(plain);
            Some(GeneratedPair {
                input_source: format!("let {plain} = 4 + 5; return {plain};"),
                variant_source: format!("let {escaped} = 4 + 5; return {escaped};"),
            })
        }
        "parser_source_position_independence" => {
            let base =
                generate_arithmetic_program(machine, "parser_source_position_independence.base")?;
            let variant = format!("\n\n\n    {base}");
            Some(GeneratedPair {
                input_source: base,
                variant_source: variant,
            })
        }
        "ir_lowering_determinism" => {
            let base = generate_arithmetic_program(machine, "ir_lowering_determinism.base")?;
            let variant = inject_whitespace(&base, machine, "ir_lowering_determinism")?;
            Some(GeneratedPair {
                input_source: base.clone(),
                variant_source: variant,
            })
        }
        "ir_optimization_idempotence" => {
            let name = pick_identifier(machine, "ir_optimization_idempotence.name")?;
            Some(GeneratedPair {
                input_source: format!("let {name} = 1 + 2 + 0; return {name};"),
                variant_source: format!("let {name} = ((1 + 2)) + 0; return ({name});"),
            })
        }
        "ir_capability_preservation" => {
            let name = pick_identifier(machine, "ir_capability_preservation.name")?;
            let second = pick_identifier(machine, "ir_capability_preservation.second")?;
            Some(GeneratedPair {
                input_source: format!(
                    "cap(net); cap(fs); let {name} = 2 + 3; let {second} = {name} * 2; return {second};"
                ),
                variant_source: format!(
                    "cap(net); cap(fs);\nlet {name} = 2 + 3;\nlet {second} = ({name}) * 2;\nreturn {second};"
                ),
            })
        }
        "ir_dead_code_insertion_invariance" => {
            let base =
                generate_arithmetic_program(machine, "ir_dead_code_insertion_invariance.base")?;
            Some(GeneratedPair {
                input_source: base.clone(),
                variant_source: format!("if(false){{emit(999);}} {base}"),
            })
        }
        "ir_constant_folding_equivalence" => {
            let name = pick_identifier(machine, "ir_constant_folding_equivalence.name")?;
            Some(GeneratedPair {
                input_source: format!("let {name} = 2 + 3 * 4; return {name};"),
                variant_source: format!("let {name} = 14; return {name};"),
            })
        }
        "execution_evaluation_order_determinism" => Some(GeneratedPair {
            input_source: "emit(\"alpha\"); emit(\"beta\"); return 1;".to_string(),
            variant_source: "emit(\"alpha\"); emit(\"beta\"); return 1;".to_string(),
        }),
        "execution_gc_timing_independence" => {
            let base =
                generate_arithmetic_program(machine, "execution_gc_timing_independence.base")?;
            Some(GeneratedPair {
                input_source: base.clone(),
                variant_source: base,
            })
        }
        "execution_stack_depth_independence" => {
            let depth = machine.int_inclusive("execution_stack_depth_independence.depth", 5, 24)?;
            Some(GeneratedPair {
                input_source: format!("recurse({depth}); return {depth};"),
                variant_source: format!("recurse({depth}); return {depth};"),
            })
        }
        "execution_prototype_chain_equivalence" => {
            let base =
                machine.int_inclusive("execution_prototype_chain_equivalence.base", 10, 29)?;
            let derived =
                machine.int_inclusive("execution_prototype_chain_equivalence.derived", 50, 69)?;
            Some(GeneratedPair {
                input_source: format!(
                    "proto(base={base},derived={derived},key=base); return {base};"
                ),
                variant_source: format!(
                    "proto(base={base},derived={derived},key=base,mirror=true); return {base};"
                ),
            })
        }
        "execution_promise_resolution_order_stability" => Some(GeneratedPair {
            input_source: "promise(alpha,beta,gamma,delta); return 0;".to_string(),
            variant_source: "promise(alpha,beta,gamma,delta); return 0;".to_string(),
        }),
        _ => Some(GeneratedPair {
            input_source: "return 0;".to_string(),
            variant_source: "return 0;".to_string(),
        }),
    }
}

fn generate_arithmetic_program(machine: &mut GeneratorMachine<'_>, prefix: &str) -> Option<String> {
    let left = pick_identifier(machine, &format!("{prefix}.left"))?;
    let right = pick_identifier(machine, &format!("{prefix}.right"))?;
    let first = machine.int_inclusive(&format!("{prefix}.first"), 1, 11)?;
    let second = machine.int_inclusive(&format!("{prefix}.second"), 1, 11)?;
    let multiplier = machine.int_inclusive(&format!("{prefix}.multiplier"), 2, 6)?;

    Some(format!(
        "let {left} = {first} + {second}; let {right} = {left} * {multiplier}; emit({right}); return {right};"
    ))
}

fn inject_whitespace(
    source: &str,
    machine: &mut GeneratorMachine<'_>,
    prefix: &str,
) -> Option<String> {
    let mut out = String::new();
    let mut punctuation_index = 0usize;
    for ch in source.chars() {
        match ch {
            ';' | ',' | '=' | '+' | '*' | '(' | ')' | '{' | '}' => {
                let left_spaces = machine.usize_inclusive(
                    &format!("{prefix}.punctuation.{punctuation_index}.left_spaces"),
                    1,
                    3,
                    "spacing_width",
                )?;
                let right_spaces = machine.usize_inclusive(
                    &format!("{prefix}.punctuation.{punctuation_index}.right_spaces"),
                    1,
                    3,
                    "spacing_width",
                )?;
                out.push_str(&" ".repeat(left_spaces));
                out.push(ch);
                out.push_str(&" ".repeat(right_spaces));
                punctuation_index = punctuation_index.saturating_add(1);
            }
            _ => out.push(ch),
        }
    }

    Some(format!("  {}  ", out))
}

fn inject_comments(
    source: &str,
    machine: &mut GeneratorMachine<'_>,
    prefix: &str,
) -> Option<String> {
    let marker = machine.usize_inclusive(&format!("{prefix}.comment_marker"), 0, 999, "marker")?;
    Some(
        source
            .split(';')
            .filter(|segment| !segment.trim().is_empty())
            .map(|segment| format!("/*meta-{marker}*/ {} // meta-{marker}\n", segment.trim()))
            .collect::<Vec<_>>()
            .join("; ")
            + ";",
    )
}

fn escape_identifier(identifier: &str) -> String {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return identifier.to_string();
    };

    format!("\\u{:04x}{}", first as u32, chars.collect::<String>())
}

fn pick_identifier(machine: &mut GeneratorMachine<'_>, label: &str) -> Option<&'static str> {
    let idx = machine.usize_inclusive(label, 0, IDENTIFIERS.len() - 1, "identifier_index")?;
    Some(IDENTIFIERS[idx])
}

#[derive(Debug, Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[derive(Debug, Clone)]
enum GeneratorMode<'a> {
    Record {
        rng: DeterministicRng,
    },
    Replay {
        choices: &'a [GenerationChoice],
        cursor: usize,
    },
}

#[derive(Debug, Clone)]
struct GeneratorMachine<'a> {
    relation_id: &'a str,
    generator_id: String,
    seed: u64,
    mode: GeneratorMode<'a>,
    recorded_choices: Vec<GenerationChoice>,
}

impl<'a> GeneratorMachine<'a> {
    fn record(relation_id: &'a str, seed: u64) -> Self {
        Self {
            relation_id,
            generator_id: default_generator_id(relation_id),
            seed,
            mode: GeneratorMode::Record {
                rng: DeterministicRng::new(seed),
            },
            recorded_choices: Vec::new(),
        }
    }

    fn replay(choice_stream: &'a ChoiceStream) -> Self {
        Self {
            relation_id: choice_stream.relation_id.as_str(),
            generator_id: choice_stream.generator_id.clone(),
            seed: choice_stream.seed,
            mode: GeneratorMode::Replay {
                choices: &choice_stream.choices,
                cursor: 0,
            },
            recorded_choices: Vec::new(),
        }
    }

    fn generator_id(&self) -> &str {
        self.generator_id.as_str()
    }

    fn finish_recording(self) -> ChoiceStream {
        ChoiceStream {
            schema_version: "franken-engine.metamorphic.choice-stream.v1".to_string(),
            relation_id: self.relation_id.to_string(),
            generator_id: self.generator_id,
            seed: self.seed,
            choices: self.recorded_choices,
        }
    }

    fn replay_finished(&self) -> bool {
        match &self.mode {
            GeneratorMode::Record { .. } => true,
            GeneratorMode::Replay { choices, cursor } => *cursor == choices.len(),
        }
    }

    fn int_inclusive(&mut self, label: &str, min: i64, max: i64) -> Option<i64> {
        let value = self.choose(label, "integer_range", min as u64, max as u64)?;
        Some(value as i64)
    }

    fn usize_inclusive(
        &mut self,
        label: &str,
        min: usize,
        max: usize,
        strategy: &str,
    ) -> Option<usize> {
        let value = self.choose(label, strategy, min as u64, max as u64)?;
        Some(value as usize)
    }

    fn choose(
        &mut self,
        label: &str,
        strategy: &str,
        min_value: u64,
        max_value: u64,
    ) -> Option<u64> {
        if min_value > max_value {
            return None;
        }

        match &mut self.mode {
            GeneratorMode::Record { rng } => {
                let span = max_value.saturating_sub(min_value).saturating_add(1);
                let raw = rng.next_u64();
                let value = min_value.saturating_add(raw % span);
                self.recorded_choices.push(GenerationChoice {
                    index: self.recorded_choices.len() as u32,
                    label: label.to_string(),
                    strategy: strategy.to_string(),
                    min_value,
                    max_value,
                    value,
                });
                Some(value)
            }
            GeneratorMode::Replay { choices, cursor } => {
                let choice = choices.get(*cursor)?;
                if choice.label != label
                    || choice.strategy != strategy
                    || choice.min_value != min_value
                    || choice.max_value != max_value
                    || choice.value < min_value
                    || choice.value > max_value
                {
                    return None;
                }
                *cursor += 1;
                Some(choice.value)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Program {
    statements: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Statement {
    Let {
        name: String,
        expr: Expression,
    },
    Emit {
        expr: Expression,
    },
    Return {
        expr: Expression,
    },
    IfFalse {
        body: Vec<Statement>,
    },
    Capability {
        capability: String,
    },
    Recurse {
        depth: u32,
    },
    Proto {
        base: i64,
        derived: i64,
        key: String,
    },
    Promise {
        labels: Vec<String>,
    },
    Expr {
        expr: Expression,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Expression {
    Int {
        value: i64,
    },
    Str {
        value: String,
    },
    Ident {
        name: String,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BinaryOp {
    Add,
    Sub,
    Mul,
}

fn parse_program(source: &str) -> Result<Program, String> {
    let tokens = tokenize(source)?;
    let mut parser = Parser::new(tokens);
    parser.parse_program()
}

fn tokenize(source: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }

        if ch == '/' && index + 1 < chars.len() {
            let next = chars[index + 1];
            if next == '/' {
                index += 2;
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
                continue;
            }

            if next == '*' {
                index += 2;
                let mut terminated = false;
                while index + 1 < chars.len() {
                    if chars[index] == '*' && chars[index + 1] == '/' {
                        terminated = true;
                        index += 2;
                        break;
                    }
                    index += 1;
                }
                if !terminated {
                    return Err("unterminated block comment".to_string());
                }
                continue;
            }
        }

        if ch == '\'' || ch == '"' {
            let quote = ch;
            index += 1;
            let mut literal = String::new();
            while index < chars.len() {
                let current = chars[index];
                if current == '\\' {
                    if index + 1 >= chars.len() {
                        return Err("unterminated escape sequence in string literal".to_string());
                    }
                    literal.push(chars[index + 1]);
                    index += 2;
                    continue;
                }

                if current == quote {
                    index += 1;
                    break;
                }

                literal.push(current);
                index += 1;
            }

            tokens.push(format!("str:{literal}"));
            continue;
        }

        if ch.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < chars.len() && chars[index].is_ascii_digit() {
                index += 1;
            }
            tokens.push(chars[start..index].iter().collect::<String>());
            continue;
        }

        if is_identifier_start(ch)
            || (ch == '\\' && index + 1 < chars.len() && chars[index + 1] == 'u')
        {
            let mut ident = String::new();

            while index < chars.len() {
                if is_identifier_continue(chars[index]) {
                    ident.push(chars[index]);
                    index += 1;
                    continue;
                }

                if chars[index] == '\\' && index + 1 < chars.len() && chars[index + 1] == 'u' {
                    let (decoded, consumed) = decode_unicode_escape(&chars, index)?;
                    ident.push(decoded);
                    index += consumed;
                    continue;
                }

                break;
            }

            if ident.is_empty() {
                return Err("identifier tokenization produced empty identifier".to_string());
            }

            tokens.push(ident);
            continue;
        }

        if matches!(
            ch,
            ';' | '(' | ')' | '{' | '}' | '=' | ',' | '+' | '-' | '*'
        ) {
            tokens.push(ch.to_string());
            index += 1;
            continue;
        }

        return Err(format!("unexpected token character: {ch:?}"));
    }

    Ok(tokens)
}

fn decode_unicode_escape(chars: &[char], start: usize) -> Result<(char, usize), String> {
    if start + 5 >= chars.len() {
        return Err("incomplete unicode escape".to_string());
    }

    if chars[start] != '\\' || chars[start + 1] != 'u' {
        return Err("unicode escape must start with \\u".to_string());
    }

    let hex: String = chars[start + 2..start + 6].iter().collect();
    let value = u32::from_str_radix(&hex, 16)
        .map_err(|_| format!("invalid unicode escape digits: {hex}"))?;
    let decoded = char::from_u32(value).ok_or_else(|| format!("invalid unicode scalar: {hex}"))?;

    Ok((decoded, 6))
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_' || ch == '$'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

#[derive(Debug)]
struct Parser {
    tokens: Vec<String>,
    cursor: usize,
}

impl Parser {
    fn new(tokens: Vec<String>) -> Self {
        Self { tokens, cursor: 0 }
    }

    fn parse_program(&mut self) -> Result<Program, String> {
        let mut statements = Vec::new();

        while self.peek().is_some() {
            if self.consume_if(";") {
                continue;
            }
            statements.push(self.parse_statement()?);
            let _ = self.consume_if(";");
        }

        if statements.is_empty() {
            return Err("program contains no statements".to_string());
        }

        Ok(Program { statements })
    }

    fn parse_statement(&mut self) -> Result<Statement, String> {
        let Some(token) = self.peek() else {
            return Err("unexpected end of input".to_string());
        };

        match token {
            "let" => self.parse_let_statement(),
            "emit" => self.parse_emit_statement(),
            "return" => self.parse_return_statement(),
            "if" => self.parse_if_false_statement(),
            "cap" => self.parse_capability_statement(),
            "recurse" => self.parse_recurse_statement(),
            "proto" => self.parse_proto_statement(),
            "promise" => self.parse_promise_statement(),
            _ => {
                let expr = self.parse_expression()?;
                Ok(Statement::Expr { expr })
            }
        }
    }

    fn parse_let_statement(&mut self) -> Result<Statement, String> {
        self.expect("let")?;
        let name = self.expect_identifier()?;
        self.expect("=")?;
        let expr = self.parse_expression()?;
        Ok(Statement::Let { name, expr })
    }

    fn parse_emit_statement(&mut self) -> Result<Statement, String> {
        self.expect("emit")?;
        self.expect("(")?;
        let expr = self.parse_expression()?;
        self.expect(")")?;
        Ok(Statement::Emit { expr })
    }

    fn parse_return_statement(&mut self) -> Result<Statement, String> {
        self.expect("return")?;
        let expr = self.parse_expression()?;
        Ok(Statement::Return { expr })
    }

    fn parse_if_false_statement(&mut self) -> Result<Statement, String> {
        self.expect("if")?;
        self.expect("(")?;
        self.expect("false")?;
        self.expect(")")?;
        self.expect("{")?;

        let mut body = Vec::new();
        while !self.consume_if("}") {
            if self.peek().is_none() {
                return Err("unterminated if(false) block".to_string());
            }
            if self.consume_if(";") {
                continue;
            }
            body.push(self.parse_statement()?);
            let _ = self.consume_if(";");
        }

        Ok(Statement::IfFalse { body })
    }

    fn parse_capability_statement(&mut self) -> Result<Statement, String> {
        self.expect("cap")?;
        self.expect("(")?;
        let capability = self.expect_identifier()?;
        self.expect(")")?;
        Ok(Statement::Capability { capability })
    }

    fn parse_recurse_statement(&mut self) -> Result<Statement, String> {
        self.expect("recurse")?;
        self.expect("(")?;
        let depth = self.expect_u32()?;
        self.expect(")")?;
        Ok(Statement::Recurse { depth })
    }

    fn parse_proto_statement(&mut self) -> Result<Statement, String> {
        self.expect("proto")?;
        self.expect("(")?;

        let mut base = None::<i64>;
        let mut derived = None::<i64>;
        let mut key = None::<String>;

        loop {
            if self.consume_if(")") {
                break;
            }

            let field = self.expect_identifier()?;
            self.expect("=")?;

            match field.as_str() {
                "base" => {
                    base = Some(self.expect_i64()?);
                }
                "derived" => {
                    derived = Some(self.expect_i64()?);
                }
                "key" => {
                    key = Some(self.expect_identifier()?);
                }
                _ => {
                    let _ = self.expect_identifier_or_literal()?;
                }
            }

            if self.consume_if(",") {
                continue;
            }

            self.expect(")")?;
            break;
        }

        Ok(Statement::Proto {
            base: base.ok_or_else(|| "proto statement missing base field".to_string())?,
            derived: derived.ok_or_else(|| "proto statement missing derived field".to_string())?,
            key: key.ok_or_else(|| "proto statement missing key field".to_string())?,
        })
    }

    fn parse_promise_statement(&mut self) -> Result<Statement, String> {
        self.expect("promise")?;
        self.expect("(")?;
        let mut labels = Vec::new();

        loop {
            if self.consume_if(")") {
                break;
            }

            labels.push(self.expect_identifier()?);

            if self.consume_if(",") {
                continue;
            }

            self.expect(")")?;
            break;
        }

        if labels.is_empty() {
            return Err("promise statement requires at least one label".to_string());
        }

        Ok(Statement::Promise { labels })
    }

    fn parse_expression(&mut self) -> Result<Expression, String> {
        self.parse_additive_expression()
    }

    fn parse_additive_expression(&mut self) -> Result<Expression, String> {
        let mut lhs = self.parse_multiplicative_expression()?;

        while let Some(token) = self.peek() {
            let op = match token {
                "+" => BinaryOp::Add,
                "-" => BinaryOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_multiplicative_expression()?;
            lhs = Expression::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }

        Ok(lhs)
    }

    fn parse_multiplicative_expression(&mut self) -> Result<Expression, String> {
        let mut lhs = self.parse_primary_expression()?;

        while let Some(token) = self.peek() {
            let op = match token {
                "*" => BinaryOp::Mul,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_primary_expression()?;
            lhs = Expression::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }

        Ok(lhs)
    }

    fn parse_primary_expression(&mut self) -> Result<Expression, String> {
        let Some(token) = self.peek().map(ToOwned::to_owned) else {
            return Err("unexpected end of expression".to_string());
        };

        if token == "(" {
            self.bump();
            let expr = self.parse_expression()?;
            self.expect(")")?;
            return Ok(expr);
        }

        if let Ok(value) = token.parse::<i64>() {
            self.bump();
            return Ok(Expression::Int { value });
        }

        if let Some(string) = token.strip_prefix("str:") {
            self.bump();
            return Ok(Expression::Str {
                value: string.to_string(),
            });
        }

        if is_keyword(&token) {
            return Err(format!("unexpected keyword in expression: {token}"));
        }

        let ident = self.expect_identifier()?;
        Ok(Expression::Ident { name: ident })
    }

    fn expect(&mut self, expected: &str) -> Result<(), String> {
        match self.bump() {
            Some(token) if token == expected => Ok(()),
            Some(token) => Err(format!("expected token {expected}, found {token}")),
            None => Err(format!("expected token {expected}, found end of input")),
        }
    }

    fn expect_identifier(&mut self) -> Result<String, String> {
        let Some(token) = self.bump() else {
            return Err("expected identifier, found end of input".to_string());
        };

        if token.starts_with("str:") {
            return Err(format!("expected identifier, found string literal {token}"));
        }

        if token.parse::<i64>().is_ok() {
            return Err(format!(
                "expected identifier, found numeric literal {token}"
            ));
        }

        if matches!(
            token.as_str(),
            ";" | "(" | ")" | "{" | "}" | "=" | "," | "+" | "-" | "*"
        ) {
            return Err(format!("expected identifier, found symbol {token}"));
        }

        Ok(token)
    }

    fn expect_identifier_or_literal(&mut self) -> Result<String, String> {
        let Some(token) = self.bump() else {
            return Err("expected identifier or literal, found end of input".to_string());
        };

        if token == "(" {
            let expr = self.parse_expression()?;
            self.expect(")")?;
            return Ok(serialize_expression(&expr));
        }

        Ok(token)
    }

    fn expect_u32(&mut self) -> Result<u32, String> {
        let token = self
            .bump()
            .ok_or_else(|| "expected u32 literal, found end of input".to_string())?;
        token
            .parse::<u32>()
            .map_err(|_| format!("expected u32 literal, found {token}"))
    }

    fn expect_i64(&mut self) -> Result<i64, String> {
        let token = self
            .bump()
            .ok_or_else(|| "expected i64 literal, found end of input".to_string())?;
        token
            .parse::<i64>()
            .map_err(|_| format!("expected i64 literal, found {token}"))
    }

    fn consume_if(&mut self, token: &str) -> bool {
        if self.peek().is_some_and(|candidate| candidate == token) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.cursor).map(String::as_str)
    }

    fn bump(&mut self) -> Option<String> {
        let token = self.tokens.get(self.cursor).cloned();
        if token.is_some() {
            self.cursor += 1;
        }
        token
    }
}

fn is_keyword(token: &str) -> bool {
    matches!(
        token,
        "let" | "emit" | "return" | "if" | "false" | "cap" | "recurse" | "proto" | "promise"
    )
}

fn serialize_expression(expr: &Expression) -> String {
    serde_json::to_string(expr).expect("expression serialization should succeed")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Int(i64),
    Str(String),
}

impl Value {
    fn into_string(self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Str(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExecutionResult {
    return_value: String,
    side_effect_trace: Vec<String>,
}

impl ExecutionResult {
    fn observable_signature(&self) -> String {
        serde_json::to_string(self).expect("execution result serialization should succeed")
    }
}

#[derive(Debug, Clone, Copy)]
struct ExecOptions {
    gc_schedule: u32,
    stack_limit: usize,
    promise_batch: usize,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            gc_schedule: 0,
            stack_limit: 10_000,
            promise_batch: 1,
        }
    }
}

fn execute_program(program: &Program, options: ExecOptions) -> Result<ExecutionResult, String> {
    let mut env = HashMap::<String, Value>::new();
    let mut side_effect_trace = Vec::<String>::new();
    let mut return_value = Value::Int(0);

    for statement in &program.statements {
        execute_statement(
            statement,
            &mut env,
            &mut side_effect_trace,
            &mut return_value,
            options,
        )?;
    }

    let _ = options.gc_schedule;

    Ok(ExecutionResult {
        return_value: return_value.into_string(),
        side_effect_trace,
    })
}

fn execute_statement(
    statement: &Statement,
    env: &mut HashMap<String, Value>,
    side_effect_trace: &mut Vec<String>,
    return_value: &mut Value,
    options: ExecOptions,
) -> Result<(), String> {
    match statement {
        Statement::Let { name, expr } => {
            let value = eval_expression(expr, env)?;
            env.insert(name.clone(), value);
            Ok(())
        }
        Statement::Emit { expr } => {
            let value = eval_expression(expr, env)?;
            side_effect_trace.push(format!("emit:{}", value.into_string()));
            Ok(())
        }
        Statement::Return { expr } => {
            *return_value = eval_expression(expr, env)?;
            Ok(())
        }
        Statement::IfFalse { .. } => Ok(()),
        Statement::Capability { capability } => {
            side_effect_trace.push(format!("cap:{capability}"));
            Ok(())
        }
        Statement::Recurse { depth } => {
            let depth_usize = *depth as usize;
            if depth_usize > options.stack_limit {
                return Err(format!(
                    "stack limit exceeded for recurse depth {depth_usize} > {}",
                    options.stack_limit
                ));
            }
            env.insert(
                "__last_recurse_depth".to_string(),
                Value::Int(*depth as i64),
            );
            Ok(())
        }
        Statement::Proto { base, derived, key } => {
            let resolved = match key.as_str() {
                "base" => *base,
                _ => *derived,
            };
            side_effect_trace.push(format!("proto:{resolved}"));
            env.insert("__proto_result".to_string(), Value::Int(resolved));
            Ok(())
        }
        Statement::Promise { labels } => {
            let batch = options.promise_batch.max(1);
            for chunk in labels.chunks(batch) {
                for label in chunk {
                    side_effect_trace.push(format!("promise:{label}"));
                }
            }
            Ok(())
        }
        Statement::Expr { expr } => {
            let _ = eval_expression(expr, env)?;
            Ok(())
        }
    }
}

fn eval_expression(expr: &Expression, env: &HashMap<String, Value>) -> Result<Value, String> {
    match expr {
        Expression::Int { value } => Ok(Value::Int(*value)),
        Expression::Str { value } => Ok(Value::Str(value.clone())),
        Expression::Ident { name } => env
            .get(name)
            .cloned()
            .ok_or_else(|| format!("unknown identifier: {name}")),
        Expression::Binary { op, lhs, rhs } => {
            let left = eval_expression(lhs, env)?;
            let right = eval_expression(rhs, env)?;
            eval_binary(*op, left, right)
        }
    }
}

fn eval_binary(op: BinaryOp, left: Value, right: Value) -> Result<Value, String> {
    match (op, left, right) {
        (BinaryOp::Add, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a + b)),
        (BinaryOp::Sub, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a - b)),
        (BinaryOp::Mul, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a * b)),
        (BinaryOp::Add, Value::Str(a), Value::Str(b)) => Ok(Value::Str(format!("{a}{b}"))),
        (operation, lhs, rhs) => Err(format!(
            "unsupported binary operation {operation:?} for operands {lhs:?} and {rhs:?}"
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IrLowering {
    ir0: String,
    ir1: String,
    ir2: String,
    ir3: String,
    ir4: String,
    optimized_once: String,
    optimized_twice: String,
    capabilities_ir2: BTreeSet<String>,
    capabilities_ir3: BTreeSet<String>,
    capabilities_ir4: BTreeSet<String>,
    observable_signature: String,
}

fn lower_program(source: &str) -> Result<IrLowering, String> {
    let parsed = parse_program(source)?;
    let ir0 = canonical_program_signature(&parsed);

    let optimized_program = optimize_program(&parsed);
    let optimized_program_twice = optimize_program(&optimized_program);
    let optimized_once = canonical_program_signature(&optimized_program);
    let optimized_twice = canonical_program_signature(&optimized_program_twice);

    let execution = execute_program(&optimized_program, ExecOptions::default())?;
    let observable_signature = execution.observable_signature();

    let capabilities_ir2 = derive_capabilities(&parsed);
    let mut capabilities_ir3 = capabilities_ir2.clone();
    capabilities_ir3.insert("runtime_core".to_string());

    let mut capabilities_ir4 = capabilities_ir3.clone();
    capabilities_ir4.insert("scheduler".to_string());

    let ir1 = stable_hash(&optimized_once);
    let ir2 = stable_hash(&format!("{ir1}|{:?}", capabilities_ir2));
    let ir3 = stable_hash(&format!("{ir2}|{:?}", capabilities_ir3));
    let ir4 = stable_hash(&format!(
        "{ir3}|{observable_signature}|{:?}",
        capabilities_ir4
    ));

    Ok(IrLowering {
        ir0,
        ir1,
        ir2,
        ir3,
        ir4,
        optimized_once,
        optimized_twice,
        capabilities_ir2,
        capabilities_ir3,
        capabilities_ir4,
        observable_signature,
    })
}

fn optimize_program(program: &Program) -> Program {
    let mut statements = Vec::new();

    for statement in &program.statements {
        match statement {
            Statement::IfFalse { .. } => {
                continue;
            }
            Statement::Let { name, expr } => statements.push(Statement::Let {
                name: name.clone(),
                expr: fold_expression(expr),
            }),
            Statement::Emit { expr } => statements.push(Statement::Emit {
                expr: fold_expression(expr),
            }),
            Statement::Return { expr } => statements.push(Statement::Return {
                expr: fold_expression(expr),
            }),
            Statement::Expr { expr } => statements.push(Statement::Expr {
                expr: fold_expression(expr),
            }),
            _ => statements.push(statement.clone()),
        }
    }

    Program { statements }
}

fn fold_expression(expr: &Expression) -> Expression {
    match expr {
        Expression::Binary { op, lhs, rhs } => {
            let lhs_folded = fold_expression(lhs);
            let rhs_folded = fold_expression(rhs);

            if let (Expression::Int { value: left }, Expression::Int { value: right }) =
                (&lhs_folded, &rhs_folded)
            {
                return match op {
                    BinaryOp::Add => Expression::Int {
                        value: left + right,
                    },
                    BinaryOp::Sub => Expression::Int {
                        value: left - right,
                    },
                    BinaryOp::Mul => Expression::Int {
                        value: left * right,
                    },
                };
            }

            if *op == BinaryOp::Add {
                if rhs_folded == (Expression::Int { value: 0 }) {
                    return lhs_folded;
                }
                if lhs_folded == (Expression::Int { value: 0 }) {
                    return rhs_folded;
                }
            }

            Expression::Binary {
                op: *op,
                lhs: Box::new(lhs_folded),
                rhs: Box::new(rhs_folded),
            }
        }
        _ => expr.clone(),
    }
}

fn derive_capabilities(program: &Program) -> BTreeSet<String> {
    let mut capabilities = BTreeSet::new();

    for statement in &program.statements {
        if let Statement::Capability { capability } = statement {
            capabilities.insert(capability.clone());
        }
    }

    capabilities
}

fn canonical_program_signature(program: &Program) -> String {
    serde_json::to_string(program).expect("program serialization should succeed")
}

fn stable_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn is_subset(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().all(|item| right.contains(item))
}

#[cfg(test)]
mod tests {
    use crate::relation::{Equivalence, MetamorphicRelation, OracleKind, RelationSpec, Subsystem};

    use super::{CatalogBackedRelation, parse_program, stable_hash};

    fn relation(id: &str, subsystem: Subsystem, oracle: OracleKind) -> CatalogBackedRelation {
        CatalogBackedRelation::new(RelationSpec {
            id: id.to_string(),
            subsystem,
            description: "test relation".to_string(),
            oracle,
            budget_pairs: 100,
            enabled: true,
        })
    }

    #[test]
    fn tokenizer_decodes_unicode_identifier_escapes() {
        let parsed = parse_program("let \\u0061lpha = 1 + 2; return \\u0061lpha;")
            .expect("unicode identifier program should parse");
        let serialized = serde_json::to_string(&parsed).expect("serialization should work");
        assert!(serialized.contains("alpha"));
    }

    #[test]
    fn parser_relation_is_deterministic_for_seed() {
        let relation = relation(
            "parser_whitespace_invariance",
            Subsystem::Parser,
            OracleKind::AstEquality,
        );

        let left = relation.generate_pair(42);
        let right = relation.generate_pair(42);
        assert_eq!(left, right);
    }

    #[test]
    fn parser_relation_accepts_equivalent_pair() {
        let relation = relation(
            "parser_comment_invariance",
            Subsystem::Parser,
            OracleKind::AstEquality,
        );

        let pair = relation.generate_pair(9);
        assert!(relation.oracle(&pair).is_equivalent());
    }

    #[test]
    fn ir_constant_folding_relation_accepts_equivalence() {
        let relation = relation(
            "ir_constant_folding_equivalence",
            Subsystem::Ir,
            OracleKind::CanonicalOutputEquality,
        );
        let pair = relation.generate_pair(1);
        assert!(relation.oracle(&pair).is_equivalent());
    }

    #[test]
    fn execution_promise_relation_keeps_order_stable() {
        let relation = relation(
            "execution_promise_resolution_order_stability",
            Subsystem::Execution,
            OracleKind::SideEffectTraceEquality,
        );
        let pair = relation.generate_pair(0);
        assert!(relation.oracle(&pair).is_equivalent());
    }

    #[test]
    fn divergent_programs_are_reported() {
        let relation = relation(
            "parser_whitespace_invariance",
            Subsystem::Parser,
            OracleKind::AstEquality,
        );

        let outcome = relation.oracle(&crate::relation::GeneratedPair {
            input_source: "let alpha = 1 + 2; return alpha;".to_string(),
            variant_source: "let alpha = 1 + 3; return alpha;".to_string(),
        });

        assert!(matches!(outcome, Equivalence::Diverged { .. }));
    }

    #[test]
    fn stable_hash_is_deterministic() {
        assert_eq!(stable_hash("abc"), stable_hash("abc"));
    }
}
