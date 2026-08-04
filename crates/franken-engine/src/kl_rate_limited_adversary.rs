#![forbid(unsafe_code)]

//! KL-rate-limited adversary budget model - Track KK.1 (bd-cixqu.37.1).
//!
//! The model treats adversarial attack generation as spending a finite
//! KL-divergence budget.  Each attack class receives an explicit allocation,
//! observed attack attempts deplete that allocation and the global budget, and
//! saturation is reached once the remaining global budget falls at or below the
//! configured threshold.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};

pub const SCHEMA_VERSION: &str = "franken-engine.kl-rate-limited-adversary.v1";
pub const BEAD_ID: &str = "bd-cixqu.37.1";
pub const COMPONENT: &str = "kl_rate_limited_adversary";
pub const DEFAULT_INITIAL_BUDGET_MICROLN: u64 = 1_000_000;
pub const DEFAULT_SATURATION_THRESHOLD_MICROLN: u64 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackClass {
    PromptInjection,
    CapabilityProbe,
    PrototypePollution,
    SupplyChainBackdoor,
    AmbientAuthority,
    TypedEffectLaundering,
}

impl AttackClass {
    pub const ALL: &[Self] = &[
        Self::PromptInjection,
        Self::CapabilityProbe,
        Self::PrototypePollution,
        Self::SupplyChainBackdoor,
        Self::AmbientAuthority,
        Self::TypedEffectLaundering,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptInjection => "prompt_injection",
            Self::CapabilityProbe => "capability_probe",
            Self::PrototypePollution => "prototype_pollution",
            Self::SupplyChainBackdoor => "supply_chain_backdoor",
            Self::AmbientAuthority => "ambient_authority",
            Self::TypedEffectLaundering => "typed_effect_laundering",
        }
    }
}

impl fmt::Display for AttackClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetOperation {
    Allocation,
    Depletion,
    SaturationCheck,
}

impl BudgetOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allocation => "allocation",
            Self::Depletion => "depletion",
            Self::SaturationCheck => "saturation_check",
        }
    }
}

impl fmt::Display for BudgetOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KLBudgetParameterization {
    pub schema_version: String,
    pub parameterization_id: String,
    pub initial_budget_microln: u64,
    pub saturation_threshold_microln: u64,
    pub depletion_rates_microln: BTreeMap<AttackClass, u64>,
}

impl KLBudgetParameterization {
    pub fn try_new(
        parameterization_id: impl Into<String>,
        initial_budget_microln: u64,
        saturation_threshold_microln: u64,
        depletion_rates_microln: BTreeMap<AttackClass, u64>,
    ) -> Result<Self, KLBudgetError> {
        let parameterization_id = parameterization_id.into();
        if parameterization_id.trim().is_empty() {
            return Err(KLBudgetError::EmptyParameterizationId);
        }
        validate_budget_shape(initial_budget_microln, saturation_threshold_microln)?;
        for attack_class in AttackClass::ALL {
            match depletion_rates_microln.get(attack_class) {
                Some(0) => {
                    return Err(KLBudgetError::ZeroDepletionRate {
                        attack_class: *attack_class,
                    });
                }
                Some(_) => {}
                None => {
                    return Err(KLBudgetError::MissingDepletionRate {
                        attack_class: *attack_class,
                    });
                }
            }
        }

        Ok(Self {
            schema_version: SCHEMA_VERSION.to_string(),
            parameterization_id,
            initial_budget_microln,
            saturation_threshold_microln,
            depletion_rates_microln,
        })
    }

    pub fn default_v1() -> Self {
        let mut rates = BTreeMap::new();
        rates.insert(AttackClass::PromptInjection, 80_000);
        rates.insert(AttackClass::CapabilityProbe, 120_000);
        rates.insert(AttackClass::PrototypePollution, 150_000);
        rates.insert(AttackClass::SupplyChainBackdoor, 220_000);
        rates.insert(AttackClass::AmbientAuthority, 100_000);
        rates.insert(AttackClass::TypedEffectLaundering, 130_000);
        Self::try_new(
            "kl-rate-limited-adversary-v1",
            DEFAULT_INITIAL_BUDGET_MICROLN,
            DEFAULT_SATURATION_THRESHOLD_MICROLN,
            rates,
        )
        .expect("default KL budget parameterization is valid")
    }

    pub fn allocate_all(&self, budget_id: impl Into<String>) -> Result<KLBudget, KLBudgetError> {
        let mut budget = KLBudget::try_new(
            budget_id,
            self.initial_budget_microln,
            self.saturation_threshold_microln,
        )?;
        for (attack_class, rate) in &self.depletion_rates_microln {
            budget.allocate(*attack_class, *rate)?;
        }
        Ok(budget)
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.parameterization_id);
        append_u64(&mut buf, self.initial_budget_microln);
        append_u64(&mut buf, self.saturation_threshold_microln);
        append_u64(&mut buf, self.depletion_rates_microln.len() as u64);
        for (attack_class, rate) in &self.depletion_rates_microln {
            append_str(&mut buf, attack_class.as_str());
            append_u64(&mut buf, *rate);
        }
        ContentHash::compute(&buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KLBudget {
    pub schema_version: String,
    pub budget_id: String,
    pub initial_budget_microln: u64,
    pub remaining_budget_microln: u64,
    pub saturation_threshold_microln: u64,
    pub allocations_microln: BTreeMap<AttackClass, u64>,
    pub spent_microln: BTreeMap<AttackClass, u64>,
}

impl KLBudget {
    pub fn try_new(
        budget_id: impl Into<String>,
        initial_budget_microln: u64,
        saturation_threshold_microln: u64,
    ) -> Result<Self, KLBudgetError> {
        let budget_id = budget_id.into();
        if budget_id.trim().is_empty() {
            return Err(KLBudgetError::EmptyBudgetId);
        }
        validate_budget_shape(initial_budget_microln, saturation_threshold_microln)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.to_string(),
            budget_id,
            initial_budget_microln,
            remaining_budget_microln: initial_budget_microln,
            saturation_threshold_microln,
            allocations_microln: BTreeMap::new(),
            spent_microln: BTreeMap::new(),
        })
    }

    pub fn allocate(
        &mut self,
        attack_class: AttackClass,
        amount_microln: u64,
    ) -> Result<(), KLBudgetError> {
        if amount_microln == 0 {
            return Err(KLBudgetError::ZeroAllocation { attack_class });
        }
        let current = self
            .allocations_microln
            .get(&attack_class)
            .copied()
            .unwrap_or(0);
        let next = checked_add(current, amount_microln)?;
        let total_without_current = self.allocated_total_microln().saturating_sub(current);
        let total_next = checked_add(total_without_current, next)?;
        if total_next > self.initial_budget_microln {
            return Err(KLBudgetError::AllocationExceedsBudget {
                requested_total_microln: total_next,
                initial_budget_microln: self.initial_budget_microln,
            });
        }
        self.allocations_microln.insert(attack_class, next);
        self.spent_microln.entry(attack_class).or_insert(0);
        Ok(())
    }

    pub fn deplete(
        &mut self,
        attack_class: AttackClass,
        requested_depletion_microln: u64,
        event_index: u64,
    ) -> Result<SaturationReceipt, KLBudgetError> {
        if requested_depletion_microln == 0 {
            return Err(KLBudgetError::ZeroDepletion { attack_class });
        }
        let allocated = self
            .allocations_microln
            .get(&attack_class)
            .copied()
            .ok_or(KLBudgetError::UnallocatedAttackClass { attack_class })?;
        let spent_before = self.spent_for(attack_class);
        let class_remaining = allocated.saturating_sub(spent_before);
        let remaining_before = self.remaining_budget_microln;
        let applied_depletion_microln = requested_depletion_microln
            .min(class_remaining)
            .min(remaining_before);
        let remaining_after = remaining_before.saturating_sub(applied_depletion_microln);
        let spent_after = checked_add(spent_before, applied_depletion_microln)?;

        self.remaining_budget_microln = remaining_after;
        self.spent_microln.insert(attack_class, spent_after);

        Ok(SaturationReceipt::new(SaturationReceiptInput {
            budget_id: self.budget_id.clone(),
            operation: BudgetOperation::Depletion,
            attack_class: Some(attack_class),
            event_index,
            requested_depletion_microln,
            applied_depletion_microln,
            remaining_before_microln: remaining_before,
            remaining_after_microln: remaining_after,
            saturation_threshold_microln: self.saturation_threshold_microln,
            class_allocation_before_microln: allocated,
            class_spent_before_microln: spent_before,
            class_spent_after_microln: spent_after,
        }))
    }

    pub fn saturation_check(&self, event_index: u64) -> SaturationReceipt {
        SaturationReceipt::new(SaturationReceiptInput {
            budget_id: self.budget_id.clone(),
            operation: BudgetOperation::SaturationCheck,
            attack_class: None,
            event_index,
            requested_depletion_microln: 0,
            applied_depletion_microln: 0,
            remaining_before_microln: self.remaining_budget_microln,
            remaining_after_microln: self.remaining_budget_microln,
            saturation_threshold_microln: self.saturation_threshold_microln,
            class_allocation_before_microln: 0,
            class_spent_before_microln: 0,
            class_spent_after_microln: 0,
        })
    }

    pub fn is_saturated(&self) -> bool {
        self.remaining_budget_microln <= self.saturation_threshold_microln
    }

    pub fn allocated_total_microln(&self) -> u64 {
        self.allocations_microln.values().copied().sum()
    }

    pub fn spent_total_microln(&self) -> u64 {
        self.spent_microln.values().copied().sum()
    }

    pub fn spent_for(&self, attack_class: AttackClass) -> u64 {
        self.spent_microln.get(&attack_class).copied().unwrap_or(0)
    }

    pub fn class_remaining_microln(&self, attack_class: AttackClass) -> u64 {
        self.allocations_microln
            .get(&attack_class)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.spent_for(attack_class))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationReceipt {
    pub schema_version: String,
    pub budget_id: String,
    pub operation: BudgetOperation,
    pub attack_class: Option<AttackClass>,
    pub event_index: u64,
    pub requested_depletion_microln: u64,
    pub applied_depletion_microln: u64,
    pub remaining_before_microln: u64,
    pub remaining_after_microln: u64,
    pub saturation_threshold_microln: u64,
    pub saturated: bool,
    pub truncated_by_class_allocation: bool,
    pub truncated_by_global_budget: bool,
    pub class_allocation_before_microln: u64,
    pub class_spent_before_microln: u64,
    pub class_spent_after_microln: u64,
    pub content_hash: ContentHash,
    pub signature: AuthenticityHash,
}

impl SaturationReceipt {
    fn new(input: SaturationReceiptInput) -> Self {
        let saturated = input.remaining_after_microln <= input.saturation_threshold_microln;
        let truncated_by_class_allocation = input.requested_depletion_microln
            > input.applied_depletion_microln
            && input.class_spent_after_microln == input.class_allocation_before_microln;
        let truncated_by_global_budget = input.requested_depletion_microln
            > input.applied_depletion_microln
            && input.remaining_after_microln == 0;
        let mut receipt = Self {
            schema_version: SCHEMA_VERSION.to_string(),
            budget_id: input.budget_id,
            operation: input.operation,
            attack_class: input.attack_class,
            event_index: input.event_index,
            requested_depletion_microln: input.requested_depletion_microln,
            applied_depletion_microln: input.applied_depletion_microln,
            remaining_before_microln: input.remaining_before_microln,
            remaining_after_microln: input.remaining_after_microln,
            saturation_threshold_microln: input.saturation_threshold_microln,
            saturated,
            truncated_by_class_allocation,
            truncated_by_global_budget,
            class_allocation_before_microln: input.class_allocation_before_microln,
            class_spent_before_microln: input.class_spent_before_microln,
            class_spent_after_microln: input.class_spent_after_microln,
            content_hash: ContentHash::compute(&[]),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        };
        receipt.content_hash = receipt.expected_content_hash();
        receipt
    }

    pub fn sign(mut self, key: &[u8]) -> Self {
        self.signature = AuthenticityHash::compute_keyed(key, &self.signing_preimage());
        self
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        if !self.has_valid_content_hash() {
            return false;
        }
        let expected = AuthenticityHash::compute_keyed(key, &self.signing_preimage());
        self.signature.constant_time_eq(&expected)
    }

    pub fn has_valid_content_hash(&self) -> bool {
        self.content_hash
            .constant_time_eq(&self.expected_content_hash())
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, "kl-rate-limited-adversary.signature.v1");
        buf.extend_from_slice(self.content_hash.as_bytes());
        append_u64(&mut buf, self.event_index);
        append_str(&mut buf, &self.budget_id);
        buf
    }

    pub fn structured_log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("schema_version".to_string(), self.schema_version.clone());
        fields.insert("component".to_string(), COMPONENT.to_string());
        fields.insert("budget_id".to_string(), self.budget_id.clone());
        fields.insert("operation".to_string(), self.operation.as_str().to_string());
        fields.insert(
            "attack_class".to_string(),
            self.attack_class
                .map(|attack_class| attack_class.as_str().to_string())
                .unwrap_or_else(|| "none".to_string()),
        );
        fields.insert("event_index".to_string(), self.event_index.to_string());
        fields.insert(
            "remaining_after_microln".to_string(),
            self.remaining_after_microln.to_string(),
        );
        fields.insert("saturated".to_string(), self.saturated.to_string());
        fields.insert("content_hash".to_string(), self.content_hash.to_hex());
        fields
    }

    fn expected_content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.budget_id);
        append_str(&mut buf, self.operation.as_str());
        match self.attack_class {
            Some(attack_class) => {
                append_u64(&mut buf, 1);
                append_str(&mut buf, attack_class.as_str());
            }
            None => append_u64(&mut buf, 0),
        }
        append_u64(&mut buf, self.event_index);
        append_u64(&mut buf, self.requested_depletion_microln);
        append_u64(&mut buf, self.applied_depletion_microln);
        append_u64(&mut buf, self.remaining_before_microln);
        append_u64(&mut buf, self.remaining_after_microln);
        append_u64(&mut buf, self.saturation_threshold_microln);
        append_bool(&mut buf, self.saturated);
        append_bool(&mut buf, self.truncated_by_class_allocation);
        append_bool(&mut buf, self.truncated_by_global_budget);
        append_u64(&mut buf, self.class_allocation_before_microln);
        append_u64(&mut buf, self.class_spent_before_microln);
        append_u64(&mut buf, self.class_spent_after_microln);
        ContentHash::compute(&buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SaturationReceiptInput {
    budget_id: String,
    operation: BudgetOperation,
    attack_class: Option<AttackClass>,
    event_index: u64,
    requested_depletion_microln: u64,
    applied_depletion_microln: u64,
    remaining_before_microln: u64,
    remaining_after_microln: u64,
    saturation_threshold_microln: u64,
    class_allocation_before_microln: u64,
    class_spent_before_microln: u64,
    class_spent_after_microln: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KLBudgetError {
    EmptyBudgetId,
    EmptyParameterizationId,
    ZeroInitialBudget,
    SaturationThresholdExceedsInitial {
        initial_budget_microln: u64,
        saturation_threshold_microln: u64,
    },
    ZeroAllocation {
        attack_class: AttackClass,
    },
    AllocationExceedsBudget {
        requested_total_microln: u64,
        initial_budget_microln: u64,
    },
    ZeroDepletion {
        attack_class: AttackClass,
    },
    UnallocatedAttackClass {
        attack_class: AttackClass,
    },
    MissingDepletionRate {
        attack_class: AttackClass,
    },
    ZeroDepletionRate {
        attack_class: AttackClass,
    },
    ArithmeticOverflow,
}

impl fmt::Display for KLBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBudgetId => f.write_str("KL budget id must not be empty"),
            Self::EmptyParameterizationId => {
                f.write_str("KL budget parameterization id must not be empty")
            }
            Self::ZeroInitialBudget => f.write_str("initial KL budget must be greater than zero"),
            Self::SaturationThresholdExceedsInitial {
                initial_budget_microln,
                saturation_threshold_microln,
            } => write!(
                f,
                "saturation threshold {saturation_threshold_microln} exceeds initial budget {initial_budget_microln}"
            ),
            Self::ZeroAllocation { attack_class } => {
                write!(f, "zero allocation for attack class {attack_class}")
            }
            Self::AllocationExceedsBudget {
                requested_total_microln,
                initial_budget_microln,
            } => write!(
                f,
                "allocation total {requested_total_microln} exceeds initial budget {initial_budget_microln}"
            ),
            Self::ZeroDepletion { attack_class } => {
                write!(f, "zero depletion for attack class {attack_class}")
            }
            Self::UnallocatedAttackClass { attack_class } => {
                write!(f, "attack class {attack_class} has no KL budget allocation")
            }
            Self::MissingDepletionRate { attack_class } => {
                write!(f, "missing depletion rate for attack class {attack_class}")
            }
            Self::ZeroDepletionRate { attack_class } => {
                write!(f, "zero depletion rate for attack class {attack_class}")
            }
            Self::ArithmeticOverflow => f.write_str("KL budget arithmetic overflow"),
        }
    }
}

impl std::error::Error for KLBudgetError {}

fn validate_budget_shape(
    initial_budget_microln: u64,
    saturation_threshold_microln: u64,
) -> Result<(), KLBudgetError> {
    if initial_budget_microln == 0 {
        return Err(KLBudgetError::ZeroInitialBudget);
    }
    if saturation_threshold_microln > initial_budget_microln {
        return Err(KLBudgetError::SaturationThresholdExceedsInitial {
            initial_budget_microln,
            saturation_threshold_microln,
        });
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, KLBudgetError> {
    left.checked_add(right)
        .ok_or(KLBudgetError::ArithmeticOverflow)
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn append_str(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> KLBudget {
        let mut budget = KLBudget::try_new("test-budget", 1_000, 100).unwrap();
        budget.allocate(AttackClass::PromptInjection, 400).unwrap();
        budget.allocate(AttackClass::CapabilityProbe, 300).unwrap();
        budget
    }

    fn key() -> &'static [u8] {
        b"kl-rate-limited-adversary-test-key"
    }

    #[test]
    fn attack_class_strings_are_stable() {
        assert_eq!(AttackClass::PromptInjection.as_str(), "prompt_injection");
        assert_eq!(AttackClass::ALL.len(), 6);
    }

    #[test]
    fn budget_operation_strings_are_stable() {
        assert_eq!(BudgetOperation::Depletion.as_str(), "depletion");
        assert_eq!(
            BudgetOperation::SaturationCheck.as_str(),
            "saturation_check"
        );
    }

    #[test]
    fn budget_rejects_empty_id() {
        assert_eq!(
            KLBudget::try_new(" ", 1, 0).unwrap_err(),
            KLBudgetError::EmptyBudgetId
        );
    }

    #[test]
    fn budget_rejects_zero_initial_budget() {
        assert_eq!(
            KLBudget::try_new("b", 0, 0).unwrap_err(),
            KLBudgetError::ZeroInitialBudget
        );
    }

    #[test]
    fn budget_rejects_threshold_above_initial() {
        assert!(matches!(
            KLBudget::try_new("b", 10, 11),
            Err(KLBudgetError::SaturationThresholdExceedsInitial { .. })
        ));
    }

    #[test]
    fn allocation_records_class_budget() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        budget.allocate(AttackClass::AmbientAuthority, 25).unwrap();
        assert_eq!(
            budget.class_remaining_microln(AttackClass::AmbientAuthority),
            25
        );
    }

    #[test]
    fn allocation_accumulates_same_class() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        budget.allocate(AttackClass::AmbientAuthority, 25).unwrap();
        budget.allocate(AttackClass::AmbientAuthority, 15).unwrap();
        assert_eq!(
            budget.class_remaining_microln(AttackClass::AmbientAuthority),
            40
        );
    }

    #[test]
    fn allocation_rejects_zero() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        assert_eq!(
            budget
                .allocate(AttackClass::AmbientAuthority, 0)
                .unwrap_err(),
            KLBudgetError::ZeroAllocation {
                attack_class: AttackClass::AmbientAuthority
            }
        );
    }

    #[test]
    fn allocation_rejects_total_above_initial() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        budget.allocate(AttackClass::AmbientAuthority, 80).unwrap();
        assert!(matches!(
            budget.allocate(AttackClass::CapabilityProbe, 21),
            Err(KLBudgetError::AllocationExceedsBudget { .. })
        ));
    }

    #[test]
    fn depletion_reduces_global_and_class_budget() {
        let mut budget = budget();
        let receipt = budget.deplete(AttackClass::PromptInjection, 75, 1).unwrap();
        assert_eq!(receipt.applied_depletion_microln, 75);
        assert_eq!(budget.remaining_budget_microln, 925);
        assert_eq!(budget.spent_for(AttackClass::PromptInjection), 75);
    }

    #[test]
    fn depletion_rejects_zero_request() {
        let mut budget = budget();
        assert_eq!(
            budget
                .deplete(AttackClass::PromptInjection, 0, 1)
                .unwrap_err(),
            KLBudgetError::ZeroDepletion {
                attack_class: AttackClass::PromptInjection
            }
        );
    }

    #[test]
    fn depletion_rejects_unallocated_attack_class() {
        let mut budget = budget();
        assert_eq!(
            budget
                .deplete(AttackClass::PrototypePollution, 10, 1)
                .unwrap_err(),
            KLBudgetError::UnallocatedAttackClass {
                attack_class: AttackClass::PrototypePollution
            }
        );
    }

    #[test]
    fn depletion_clamps_to_class_allocation() {
        let mut budget = budget();
        let receipt = budget
            .deplete(AttackClass::CapabilityProbe, 500, 1)
            .unwrap();
        assert_eq!(receipt.applied_depletion_microln, 300);
        assert!(receipt.truncated_by_class_allocation);
        assert_eq!(
            budget.class_remaining_microln(AttackClass::CapabilityProbe),
            0
        );
    }

    #[test]
    fn depletion_clamps_to_global_remaining() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        budget.allocate(AttackClass::CapabilityProbe, 100).unwrap();
        let receipt = budget
            .deplete(AttackClass::CapabilityProbe, 150, 1)
            .unwrap();
        assert_eq!(receipt.applied_depletion_microln, 100);
        assert!(receipt.truncated_by_global_budget);
        assert_eq!(budget.remaining_budget_microln, 0);
    }

    #[test]
    fn saturation_threshold_is_inclusive() {
        let mut budget = KLBudget::try_new("b", 100, 10).unwrap();
        budget.allocate(AttackClass::PromptInjection, 90).unwrap();
        budget.deplete(AttackClass::PromptInjection, 90, 1).unwrap();
        assert!(budget.is_saturated());
    }

    #[test]
    fn saturation_check_does_not_mutate_budget() {
        let budget = budget();
        let receipt = budget.saturation_check(9);
        assert_eq!(receipt.operation, BudgetOperation::SaturationCheck);
        assert_eq!(
            receipt.remaining_before_microln,
            budget.remaining_budget_microln
        );
        assert_eq!(
            receipt.remaining_after_microln,
            budget.remaining_budget_microln
        );
    }

    #[test]
    fn receipt_hash_is_deterministic() {
        let mut budget_a = budget();
        let mut budget_b = budget();
        let a = budget_a
            .deplete(AttackClass::PromptInjection, 50, 7)
            .unwrap();
        let b = budget_b
            .deplete(AttackClass::PromptInjection, 50, 7)
            .unwrap();
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn receipt_hash_changes_with_remaining_budget() {
        let mut budget = budget();
        let a = budget.deplete(AttackClass::PromptInjection, 50, 7).unwrap();
        let b = budget.deplete(AttackClass::PromptInjection, 50, 8).unwrap();
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn signed_receipt_verifies() {
        let mut budget = budget();
        let receipt = budget
            .deplete(AttackClass::PromptInjection, 50, 7)
            .unwrap()
            .sign(key());
        assert!(receipt.verify_signature(key()));
    }

    #[test]
    fn signature_rejects_wrong_key() {
        let mut budget = budget();
        let receipt = budget
            .deplete(AttackClass::PromptInjection, 50, 7)
            .unwrap()
            .sign(key());
        assert!(!receipt.verify_signature(b"wrong-key"));
    }

    #[test]
    fn signature_rejects_tampered_body() {
        let mut budget = budget();
        let mut receipt = budget
            .deplete(AttackClass::PromptInjection, 50, 7)
            .unwrap()
            .sign(key());
        receipt.remaining_after_microln += 1;
        assert!(!receipt.verify_signature(key()));
    }

    #[test]
    fn structured_log_fields_include_required_keys() {
        let mut budget = budget();
        let receipt = budget.deplete(AttackClass::PromptInjection, 50, 7).unwrap();
        let fields = receipt.structured_log_fields();
        assert_eq!(fields["component"], COMPONENT);
        assert_eq!(fields["operation"], "depletion");
        assert_eq!(fields["attack_class"], "prompt_injection");
    }

    #[test]
    fn default_parameterization_is_valid() {
        let parameterization = KLBudgetParameterization::default_v1();
        assert_eq!(
            parameterization.depletion_rates_microln.len(),
            AttackClass::ALL.len()
        );
        assert_ne!(parameterization.content_hash(), ContentHash::compute(&[]));
    }

    #[test]
    fn parameterization_rejects_missing_rates() {
        let err = KLBudgetParameterization::try_new("p", 100, 10, BTreeMap::new()).unwrap_err();
        assert!(matches!(err, KLBudgetError::MissingDepletionRate { .. }));
    }

    #[test]
    fn parameterization_allocates_all_rates() {
        let parameterization = KLBudgetParameterization::default_v1();
        let budget = parameterization.allocate_all("b").unwrap();
        assert_eq!(budget.allocations_microln.len(), AttackClass::ALL.len());
        assert_eq!(budget.allocated_total_microln(), 800_000);
    }
}
