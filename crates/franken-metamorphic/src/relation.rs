use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    Parser,
    Ir,
    Execution,
}

impl Subsystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Ir => "ir",
            Self::Execution => "execution",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    AstEquality,
    IrEquality,
    CanonicalOutputEquality,
    SideEffectTraceEquality,
}

impl OracleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AstEquality => "ast_equality",
            Self::IrEquality => "ir_equality",
            Self::CanonicalOutputEquality => "canonical_output_equality",
            Self::SideEffectTraceEquality => "side_effect_trace_equality",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSpec {
    pub id: String,
    pub subsystem: Subsystem,
    pub description: String,
    pub oracle: OracleKind,
    pub budget_pairs: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedPair {
    pub input_source: String,
    pub variant_source: String,
}

impl GeneratedPair {
    pub fn size_metric(&self) -> usize {
        self.input_source
            .len()
            .saturating_add(self.variant_source.len())
    }

    pub fn ast_node_metric(&self) -> usize {
        let left = self
            .input_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count();
        let right = self
            .variant_source
            .split_whitespace()
            .filter(|token| !token.is_empty())
            .count();
        left.saturating_add(right)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationChoice {
    pub index: u32,
    pub label: String,
    pub strategy: String,
    pub min_value: u64,
    pub max_value: u64,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceStream {
    pub schema_version: String,
    pub relation_id: String,
    pub generator_id: String,
    pub seed: u64,
    pub choices: Vec<GenerationChoice>,
}

impl ChoiceStream {
    pub fn empty(relation_id: &str, generator_id: &str, seed: u64) -> Self {
        Self {
            schema_version: "franken-engine.metamorphic.choice-stream.v1".to_string(),
            relation_id: relation_id.to_string(),
            generator_id: generator_id.to_string(),
            seed,
            choices: Vec::new(),
        }
    }

    pub fn choice_count(&self) -> usize {
        self.choices.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyContract {
    pub schema_version: String,
    pub relation_id: String,
    pub generator_id: String,
    pub expected_equivalence: String,
    pub validates_input: bool,
    pub validates_variant: bool,
    pub replay_supported: bool,
    pub shrink_strategy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedCase {
    pub relation_id: String,
    pub generator_id: String,
    pub seed: u64,
    pub pair: GeneratedPair,
    pub choice_stream: ChoiceStream,
    pub property_contract: PropertyContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Equivalence {
    Equivalent,
    Diverged { detail: String },
}

impl Equivalence {
    pub fn is_equivalent(&self) -> bool {
        matches!(self, Self::Equivalent)
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Equivalent => None,
            Self::Diverged { detail } => Some(detail.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRunOutcome {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub relation_id: String,
    pub subsystem: Subsystem,
    pub oracle: OracleKind,
    pub generator_id: String,
    pub seed: u64,
    pub pair: GeneratedPair,
    pub choice_stream: ChoiceStream,
    pub property_contract: PropertyContract,
    pub equivalence: Equivalence,
}

pub fn default_generator_id(relation_id: &str) -> String {
    format!("{relation_id}.property-generator.v1")
}

pub trait MetamorphicRelation {
    fn spec(&self) -> &RelationSpec;

    fn generate_pair(&self, seed: u64) -> GeneratedPair;

    fn generator_id(&self) -> String {
        default_generator_id(&self.spec().id)
    }

    fn shrink_strategy(&self) -> &'static str {
        "choice_stream_replay_then_ddmin"
    }

    fn generate_case(&self, seed: u64) -> GeneratedCase {
        let pair = self.generate_pair(seed);
        let generator_id = self.generator_id();
        let choice_stream = ChoiceStream::empty(&self.spec().id, &generator_id, seed);
        let property_contract = PropertyContract {
            schema_version: "franken-engine.metamorphic.property-contract.v1".to_string(),
            relation_id: self.spec().id.clone(),
            generator_id: generator_id.clone(),
            expected_equivalence: "equivalent".to_string(),
            validates_input: self.validate_program(&pair.input_source),
            validates_variant: self.validate_program(&pair.variant_source),
            replay_supported: true,
            shrink_strategy: self.shrink_strategy().to_string(),
        };

        GeneratedCase {
            relation_id: self.spec().id.clone(),
            generator_id,
            seed,
            pair,
            choice_stream,
            property_contract,
        }
    }

    fn replay_case(&self, choice_stream: &ChoiceStream) -> Option<GeneratedCase> {
        if choice_stream.relation_id != self.spec().id {
            return None;
        }
        if choice_stream.generator_id != self.generator_id() {
            return None;
        }

        Some(self.generate_case(choice_stream.seed))
    }

    fn oracle(&self, pair: &GeneratedPair) -> Equivalence;

    fn validate_program(&self, source: &str) -> bool;

    fn run_once(
        &self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        component: &str,
        seed: u64,
    ) -> RelationRunOutcome {
        let generated_case = self.generate_case(seed);
        let pair = generated_case.pair.clone();
        let equivalence = self.oracle(&pair);
        let outcome = if equivalence.is_equivalent() {
            "pass"
        } else {
            "fail"
        };

        RelationRunOutcome {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: component.to_string(),
            event: "pair_evaluated".to_string(),
            outcome: outcome.to_string(),
            error_code: if equivalence.is_equivalent() {
                None
            } else {
                Some("FE-META-0001".to_string())
            },
            relation_id: self.spec().id.clone(),
            subsystem: self.spec().subsystem,
            oracle: self.spec().oracle,
            generator_id: generated_case.generator_id,
            seed,
            pair,
            choice_stream: generated_case.choice_stream,
            property_contract: generated_case.property_contract,
            equivalence,
        }
    }
}
