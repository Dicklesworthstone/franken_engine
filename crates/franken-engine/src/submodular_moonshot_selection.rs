//! Submodular moonshot selection formulation - Track LL.1 (bd-cixqu.38.1).
//!
//! Defines the portfolio objective used by the LL governor:
//!
//! `f(S) = base_eiv(S) + covered_dependency_unlock_value(S)`
//!
//! where `base_eiv` is modular over selected moonshots and dependency unlock
//! value is weighted coverage over unlock atoms. Weighted coverage is monotone
//! submodular: selecting another moonshot can only add atoms not already
//! covered, so marginal gain decreases as the selected set grows. The effort
//! knapsack is tracked separately as a hard fixed-point-millionths budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::expected_info_value_scoring::EivScore;
use crate::hash_tiers::ContentHash;

/// One moonshot candidate in the Track LL objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotSelectionOption {
    /// Stable moonshot id.
    pub moonshot_id: String,
    /// Per-moonshot expected information value in millionths of a bit.
    pub base_eiv_millimillibits: i64,
    /// Effort cost under the knapsack, in fixed-point millionths.
    pub effort_millionths: u64,
    /// Dependency/capability atoms this moonshot covers if selected.
    pub unlock_atom_ids: BTreeSet<String>,
}

impl MoonshotSelectionOption {
    pub fn try_new(
        moonshot_id: impl Into<String>,
        base_eiv_millimillibits: i64,
        effort_millionths: u64,
        unlock_atom_ids: BTreeSet<String>,
    ) -> Result<Self, SubmodularSelectionError> {
        let moonshot_id = moonshot_id.into();
        if moonshot_id.trim().is_empty() {
            return Err(SubmodularSelectionError::EmptyMoonshotId);
        }
        if base_eiv_millimillibits < 0 {
            return Err(SubmodularSelectionError::NegativeInformationValue {
                id: moonshot_id,
                value_millimillibits: base_eiv_millimillibits,
            });
        }
        if effort_millionths == 0 {
            return Err(SubmodularSelectionError::ZeroEffort { id: moonshot_id });
        }
        Ok(Self {
            moonshot_id,
            base_eiv_millimillibits,
            effort_millionths,
            unlock_atom_ids,
        })
    }

    pub fn from_eiv_score(
        score: &EivScore,
        effort_millionths: u64,
        unlock_atom_ids: BTreeSet<String>,
    ) -> Result<Self, SubmodularSelectionError> {
        Self::try_new(
            score.moonshot_id.clone(),
            score.eiv_millimillibits,
            effort_millionths,
            unlock_atom_ids,
        )
    }
}

/// Weighted coverage atom for dependency-unlock value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyUnlockAtom {
    /// Stable dependency/capability atom id.
    pub atom_id: String,
    /// Expected information value contributed the first time this atom is covered.
    pub information_value_millimillibits: i64,
}

impl DependencyUnlockAtom {
    pub fn try_new(
        atom_id: impl Into<String>,
        information_value_millimillibits: i64,
    ) -> Result<Self, SubmodularSelectionError> {
        let atom_id = atom_id.into();
        if atom_id.trim().is_empty() {
            return Err(SubmodularSelectionError::EmptyUnlockAtomId);
        }
        if information_value_millimillibits < 0 {
            return Err(SubmodularSelectionError::NegativeInformationValue {
                id: atom_id,
                value_millimillibits: information_value_millimillibits,
            });
        }
        Ok(Self {
            atom_id,
            information_value_millimillibits,
        })
    }
}

/// Validated submodular selection instance plus effort knapsack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmodularMoonshotSelectionProblem {
    /// Hard effort budget in fixed-point millionths.
    pub effort_budget_millionths: u64,
    /// Candidate moonshots, keyed by stable id.
    pub options: BTreeMap<String, MoonshotSelectionOption>,
    /// Weighted dependency/capability atoms used by the coverage term.
    pub unlock_atoms: BTreeMap<String, DependencyUnlockAtom>,
}

impl SubmodularMoonshotSelectionProblem {
    pub fn try_from_parts(
        effort_budget_millionths: u64,
        options: Vec<MoonshotSelectionOption>,
        unlock_atoms: Vec<DependencyUnlockAtom>,
    ) -> Result<Self, SubmodularSelectionError> {
        let mut option_map = BTreeMap::new();
        for option in options {
            if option_map
                .insert(option.moonshot_id.clone(), option)
                .is_some()
            {
                return Err(SubmodularSelectionError::DuplicateMoonshotId);
            }
        }

        let mut unlock_atom_map = BTreeMap::new();
        for atom in unlock_atoms {
            if unlock_atom_map.insert(atom.atom_id.clone(), atom).is_some() {
                return Err(SubmodularSelectionError::DuplicateUnlockAtomId);
            }
        }

        let problem = Self {
            effort_budget_millionths,
            options: option_map,
            unlock_atoms: unlock_atom_map,
        };
        problem.validate()?;
        Ok(problem)
    }

    pub fn validate(&self) -> Result<(), SubmodularSelectionError> {
        for (moonshot_id, option) in &self.options {
            if moonshot_id != &option.moonshot_id {
                return Err(SubmodularSelectionError::MoonshotKeyMismatch {
                    key: moonshot_id.clone(),
                    option_id: option.moonshot_id.clone(),
                });
            }
            if option.base_eiv_millimillibits < 0 {
                return Err(SubmodularSelectionError::NegativeInformationValue {
                    id: option.moonshot_id.clone(),
                    value_millimillibits: option.base_eiv_millimillibits,
                });
            }
            if option.effort_millionths == 0 {
                return Err(SubmodularSelectionError::ZeroEffort {
                    id: option.moonshot_id.clone(),
                });
            }
            for atom_id in &option.unlock_atom_ids {
                if !self.unlock_atoms.contains_key(atom_id) {
                    return Err(SubmodularSelectionError::UnknownUnlockAtom {
                        moonshot_id: option.moonshot_id.clone(),
                        atom_id: atom_id.clone(),
                    });
                }
            }
        }

        for (atom_id, atom) in &self.unlock_atoms {
            if atom_id != &atom.atom_id {
                return Err(SubmodularSelectionError::UnlockAtomKeyMismatch {
                    key: atom_id.clone(),
                    atom_id: atom.atom_id.clone(),
                });
            }
            if atom.information_value_millimillibits < 0 {
                return Err(SubmodularSelectionError::NegativeInformationValue {
                    id: atom.atom_id.clone(),
                    value_millimillibits: atom.information_value_millimillibits,
                });
            }
        }

        Ok(())
    }

    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    pub fn unlock_atom_count(&self) -> usize {
        self.unlock_atoms.len()
    }

    pub fn is_knapsack_feasible(&self, selected_ids: &BTreeSet<String>) -> bool {
        match self.selected_effort(selected_ids) {
            Ok(effort) => effort <= self.effort_budget_millionths,
            Err(_) => false,
        }
    }

    pub fn evaluate_selection(
        &self,
        selected_ids: &BTreeSet<String>,
    ) -> Result<MoonshotSelectionEvaluation, SubmodularSelectionError> {
        self.validate_selection_ids(selected_ids)?;
        let selected_effort_millionths = self.selected_effort(selected_ids)?;
        if selected_effort_millionths > self.effort_budget_millionths {
            return Err(SubmodularSelectionError::BudgetExceeded {
                effort_budget_millionths: self.effort_budget_millionths,
                selected_effort_millionths,
            });
        }

        let mut base_eiv_millimillibits = 0_i64;
        let mut saturated_unlock_atom_ids = BTreeSet::new();
        for moonshot_id in selected_ids {
            let option = self
                .options
                .get(moonshot_id)
                .expect("selection ids validated before evaluation");
            base_eiv_millimillibits =
                checked_add_i64(base_eiv_millimillibits, option.base_eiv_millimillibits)?;
            saturated_unlock_atom_ids.extend(option.unlock_atom_ids.iter().cloned());
        }

        let dependency_unlock_eiv_millimillibits = self.unlock_value(&saturated_unlock_atom_ids)?;
        let total_expected_information_value_millimillibits = checked_add_i64(
            base_eiv_millimillibits,
            dependency_unlock_eiv_millimillibits,
        )?;

        Ok(MoonshotSelectionEvaluation {
            selected_ids: selected_ids.clone(),
            selected_effort_millionths,
            effort_budget_millionths: self.effort_budget_millionths,
            base_eiv_millimillibits,
            dependency_unlock_eiv_millimillibits,
            total_expected_information_value_millimillibits,
            saturated_unlock_atom_ids,
        })
    }

    pub fn marginal_gain(
        &self,
        current_selection: &BTreeSet<String>,
        candidate_id: &str,
    ) -> Result<MoonshotMarginalGain, SubmodularSelectionError> {
        let current = self.evaluate_selection(current_selection)?;
        let Some(candidate) = self.options.get(candidate_id) else {
            return Err(SubmodularSelectionError::UnknownMoonshotId {
                moonshot_id: candidate_id.to_string(),
            });
        };
        if current_selection.contains(candidate_id) {
            return Ok(MoonshotMarginalGain {
                candidate_id: candidate_id.to_string(),
                marginal_effort_millionths: 0,
                marginal_base_eiv_millimillibits: 0,
                marginal_dependency_unlock_eiv_millimillibits: 0,
                marginal_total_eiv_millimillibits: 0,
                newly_saturated_unlock_atom_ids: BTreeSet::new(),
                feasible_after_add: true,
            });
        }

        let selected_effort_after_add = current
            .selected_effort_millionths
            .checked_add(candidate.effort_millionths)
            .ok_or(SubmodularSelectionError::ArithmeticOverflow)?;
        let newly_saturated_unlock_atom_ids: BTreeSet<String> = candidate
            .unlock_atom_ids
            .difference(&current.saturated_unlock_atom_ids)
            .cloned()
            .collect();
        let marginal_dependency_unlock_eiv_millimillibits =
            self.unlock_value(&newly_saturated_unlock_atom_ids)?;
        let marginal_total_eiv_millimillibits = checked_add_i64(
            candidate.base_eiv_millimillibits,
            marginal_dependency_unlock_eiv_millimillibits,
        )?;

        Ok(MoonshotMarginalGain {
            candidate_id: candidate_id.to_string(),
            marginal_effort_millionths: candidate.effort_millionths,
            marginal_base_eiv_millimillibits: candidate.base_eiv_millimillibits,
            marginal_dependency_unlock_eiv_millimillibits,
            marginal_total_eiv_millimillibits,
            newly_saturated_unlock_atom_ids,
            feasible_after_add: selected_effort_after_add <= self.effort_budget_millionths,
        })
    }

    fn selected_effort(
        &self,
        selected_ids: &BTreeSet<String>,
    ) -> Result<u64, SubmodularSelectionError> {
        let mut effort = 0_u64;
        for moonshot_id in selected_ids {
            let option = self.options.get(moonshot_id).ok_or_else(|| {
                SubmodularSelectionError::UnknownMoonshotId {
                    moonshot_id: moonshot_id.clone(),
                }
            })?;
            effort = effort
                .checked_add(option.effort_millionths)
                .ok_or(SubmodularSelectionError::ArithmeticOverflow)?;
        }
        Ok(effort)
    }

    fn validate_selection_ids(
        &self,
        selected_ids: &BTreeSet<String>,
    ) -> Result<(), SubmodularSelectionError> {
        for moonshot_id in selected_ids {
            if !self.options.contains_key(moonshot_id) {
                return Err(SubmodularSelectionError::UnknownMoonshotId {
                    moonshot_id: moonshot_id.clone(),
                });
            }
        }
        Ok(())
    }

    fn unlock_value(
        &self,
        unlock_atom_ids: &BTreeSet<String>,
    ) -> Result<i64, SubmodularSelectionError> {
        let mut value = 0_i64;
        for atom_id in unlock_atom_ids {
            let atom = self.unlock_atoms.get(atom_id).ok_or_else(|| {
                SubmodularSelectionError::UnknownUnlockAtom {
                    moonshot_id: String::new(),
                    atom_id: atom_id.clone(),
                }
            })?;
            value = checked_add_i64(value, atom.information_value_millimillibits)?;
        }
        Ok(value)
    }
}

/// Deterministic evaluation of one selected set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotSelectionEvaluation {
    pub selected_ids: BTreeSet<String>,
    pub selected_effort_millionths: u64,
    pub effort_budget_millionths: u64,
    pub base_eiv_millimillibits: i64,
    pub dependency_unlock_eiv_millimillibits: i64,
    pub total_expected_information_value_millimillibits: i64,
    pub saturated_unlock_atom_ids: BTreeSet<String>,
}

impl MoonshotSelectionEvaluation {
    pub fn budget_remaining_millionths(&self) -> u64 {
        self.effort_budget_millionths
            .saturating_sub(self.selected_effort_millionths)
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"submodular_moonshot_selection_evaluation_v1");
        bytes.push(0);
        bytes.extend_from_slice(&self.selected_effort_millionths.to_be_bytes());
        bytes.extend_from_slice(&self.effort_budget_millionths.to_be_bytes());
        bytes.extend_from_slice(&self.base_eiv_millimillibits.to_be_bytes());
        bytes.extend_from_slice(&self.dependency_unlock_eiv_millimillibits.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .total_expected_information_value_millimillibits
                .to_be_bytes(),
        );
        write_string_set(&mut bytes, &self.selected_ids);
        write_string_set(&mut bytes, &self.saturated_unlock_atom_ids);
        ContentHash::compute(&bytes)
    }
}

/// Marginal contribution of adding one candidate to a feasible selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotMarginalGain {
    pub candidate_id: String,
    pub marginal_effort_millionths: u64,
    pub marginal_base_eiv_millimillibits: i64,
    pub marginal_dependency_unlock_eiv_millimillibits: i64,
    pub marginal_total_eiv_millimillibits: i64,
    pub newly_saturated_unlock_atom_ids: BTreeSet<String>,
    pub feasible_after_add: bool,
}

/// Validation/evaluation errors for the LL.1 formulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmodularSelectionError {
    EmptyMoonshotId,
    EmptyUnlockAtomId,
    DuplicateMoonshotId,
    DuplicateUnlockAtomId,
    UnknownMoonshotId {
        moonshot_id: String,
    },
    UnknownUnlockAtom {
        moonshot_id: String,
        atom_id: String,
    },
    MoonshotKeyMismatch {
        key: String,
        option_id: String,
    },
    UnlockAtomKeyMismatch {
        key: String,
        atom_id: String,
    },
    NegativeInformationValue {
        id: String,
        value_millimillibits: i64,
    },
    ZeroEffort {
        id: String,
    },
    BudgetExceeded {
        effort_budget_millionths: u64,
        selected_effort_millionths: u64,
    },
    ArithmeticOverflow,
}

impl fmt::Display for SubmodularSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMoonshotId => f.write_str("moonshot id must not be empty"),
            Self::EmptyUnlockAtomId => f.write_str("unlock atom id must not be empty"),
            Self::DuplicateMoonshotId => f.write_str("duplicate moonshot id"),
            Self::DuplicateUnlockAtomId => f.write_str("duplicate unlock atom id"),
            Self::UnknownMoonshotId { moonshot_id } => {
                write!(f, "unknown moonshot id {moonshot_id}")
            }
            Self::UnknownUnlockAtom {
                moonshot_id,
                atom_id,
            } => {
                if moonshot_id.is_empty() {
                    write!(f, "unknown unlock atom {atom_id}")
                } else {
                    write!(
                        f,
                        "moonshot {moonshot_id} references unknown unlock atom {atom_id}"
                    )
                }
            }
            Self::MoonshotKeyMismatch { key, option_id } => {
                write!(
                    f,
                    "moonshot map key {key} does not match option id {option_id}"
                )
            }
            Self::UnlockAtomKeyMismatch { key, atom_id } => {
                write!(
                    f,
                    "unlock atom map key {key} does not match atom id {atom_id}"
                )
            }
            Self::NegativeInformationValue {
                id,
                value_millimillibits,
            } => write!(
                f,
                "negative information value for {id}: {value_millimillibits}"
            ),
            Self::ZeroEffort { id } => write!(f, "moonshot {id} has zero effort"),
            Self::BudgetExceeded {
                effort_budget_millionths,
                selected_effort_millionths,
            } => write!(
                f,
                "selected effort {selected_effort_millionths} exceeds budget {effort_budget_millionths}"
            ),
            Self::ArithmeticOverflow => f.write_str("submodular selection arithmetic overflowed"),
        }
    }
}

impl std::error::Error for SubmodularSelectionError {}

fn checked_add_i64(left: i64, right: i64) -> Result<i64, SubmodularSelectionError> {
    left.checked_add(right)
        .ok_or(SubmodularSelectionError::ArithmeticOverflow)
}

fn write_string_set(bytes: &mut Vec<u8>, values: &BTreeSet<String>) {
    bytes.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        let raw = value.as_bytes();
        bytes.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        bytes.extend_from_slice(raw);
    }
    bytes.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expected_info_value_scoring::PriorEvidence;
    use crate::security_epoch::SecurityEpoch;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn option(id: &str, eiv: i64, effort: u64, unlocks: &[&str]) -> MoonshotSelectionOption {
        MoonshotSelectionOption::try_new(id, eiv, effort, set(unlocks)).unwrap()
    }

    fn atom(id: &str, value: i64) -> DependencyUnlockAtom {
        DependencyUnlockAtom::try_new(id, value).unwrap()
    }

    fn problem() -> SubmodularMoonshotSelectionProblem {
        SubmodularMoonshotSelectionProblem::try_from_parts(
            3_000_000,
            vec![
                option("parser-frontier", 500_000, 1_000_000, &["ast", "oracle"]),
                option("ifc-proof", 400_000, 1_500_000, &["ifc", "oracle"]),
                option("fleet-report", 200_000, 2_000_000, &["reporting"]),
            ],
            vec![
                atom("ast", 150_000),
                atom("oracle", 300_000),
                atom("ifc", 250_000),
                atom("reporting", 100_000),
            ],
        )
        .unwrap()
    }

    #[test]
    fn validates_problem_parts_into_canonical_maps() {
        let p = problem();
        assert_eq!(p.option_count(), 3);
        assert_eq!(p.unlock_atom_count(), 4);
        assert_eq!(
            p.options.keys().cloned().collect::<Vec<_>>(),
            vec!["fleet-report", "ifc-proof", "parser-frontier"]
        );
    }

    #[test]
    fn evaluates_weighted_coverage_once_per_unlock_atom() {
        let p = problem();
        let selected = set(&["parser-frontier", "ifc-proof"]);
        let eval = p.evaluate_selection(&selected).unwrap();
        assert_eq!(eval.selected_effort_millionths, 2_500_000);
        assert_eq!(eval.base_eiv_millimillibits, 900_000);
        assert_eq!(eval.dependency_unlock_eiv_millimillibits, 700_000);
        assert_eq!(
            eval.total_expected_information_value_millimillibits,
            1_600_000
        );
        assert_eq!(
            eval.saturated_unlock_atom_ids,
            set(&["ast", "ifc", "oracle"])
        );
    }

    #[test]
    fn overlapping_unlock_atom_has_diminishing_marginal_gain() {
        let p = problem();
        let empty = BTreeSet::new();
        let with_parser = set(&["parser-frontier"]);
        let gain_from_empty = p.marginal_gain(&empty, "ifc-proof").unwrap();
        let gain_after_parser = p.marginal_gain(&with_parser, "ifc-proof").unwrap();

        assert_eq!(
            gain_from_empty.marginal_dependency_unlock_eiv_millimillibits,
            550_000
        );
        assert_eq!(
            gain_after_parser.marginal_dependency_unlock_eiv_millimillibits,
            250_000
        );
        assert!(
            gain_from_empty.marginal_total_eiv_millimillibits
                >= gain_after_parser.marginal_total_eiv_millimillibits
        );
    }

    #[test]
    fn marginal_gain_reports_feasibility_under_knapsack() {
        let p = problem();
        let selected = set(&["parser-frontier", "ifc-proof"]);
        let gain = p.marginal_gain(&selected, "fleet-report").unwrap();
        assert_eq!(gain.marginal_effort_millionths, 2_000_000);
        assert!(!gain.feasible_after_add);
        assert_eq!(gain.newly_saturated_unlock_atom_ids, set(&["reporting"]));
    }

    #[test]
    fn repeated_candidate_has_zero_marginal_gain() {
        let p = problem();
        let selected = set(&["parser-frontier"]);
        let gain = p.marginal_gain(&selected, "parser-frontier").unwrap();
        assert_eq!(gain.marginal_total_eiv_millimillibits, 0);
        assert_eq!(gain.marginal_effort_millionths, 0);
        assert!(gain.feasible_after_add);
        assert!(gain.newly_saturated_unlock_atom_ids.is_empty());
    }

    #[test]
    fn budget_excess_rejects_selection_evaluation() {
        let p = problem();
        let selected = set(&["ifc-proof", "fleet-report"]);
        let err = p.evaluate_selection(&selected).unwrap_err();
        assert_eq!(
            err,
            SubmodularSelectionError::BudgetExceeded {
                effort_budget_millionths: 3_000_000,
                selected_effort_millionths: 3_500_000
            }
        );
        assert!(!p.is_knapsack_feasible(&selected));
    }

    #[test]
    fn zero_budget_allows_empty_selection_only() {
        let p = SubmodularMoonshotSelectionProblem::try_from_parts(
            0,
            vec![option("a", 100_000, 1, &[])],
            vec![],
        )
        .unwrap();
        assert!(p.evaluate_selection(&BTreeSet::new()).is_ok());
        assert!(matches!(
            p.evaluate_selection(&set(&["a"])),
            Err(SubmodularSelectionError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn unknown_moonshot_is_rejected() {
        let p = problem();
        let err = p.evaluate_selection(&set(&["missing"])).unwrap_err();
        assert_eq!(
            err,
            SubmodularSelectionError::UnknownMoonshotId {
                moonshot_id: "missing".to_string()
            }
        );
    }

    #[test]
    fn unknown_unlock_atom_is_rejected() {
        let err = SubmodularMoonshotSelectionProblem::try_from_parts(
            1_000_000,
            vec![option("a", 100_000, 1, &["missing"])],
            vec![],
        )
        .unwrap_err();
        assert_eq!(
            err,
            SubmodularSelectionError::UnknownUnlockAtom {
                moonshot_id: "a".to_string(),
                atom_id: "missing".to_string()
            }
        );
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let err = SubmodularMoonshotSelectionProblem::try_from_parts(
            1_000_000,
            vec![option("a", 100_000, 1, &[]), option("a", 200_000, 1, &[])],
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, SubmodularSelectionError::DuplicateMoonshotId);

        let err = SubmodularMoonshotSelectionProblem::try_from_parts(
            1_000_000,
            vec![],
            vec![atom("x", 1), atom("x", 2)],
        )
        .unwrap_err();
        assert_eq!(err, SubmodularSelectionError::DuplicateUnlockAtomId);
    }

    #[test]
    fn invalid_option_inputs_fail_closed() {
        assert_eq!(
            MoonshotSelectionOption::try_new(" ", 1, 1, BTreeSet::new()).unwrap_err(),
            SubmodularSelectionError::EmptyMoonshotId
        );
        assert_eq!(
            MoonshotSelectionOption::try_new("a", -1, 1, BTreeSet::new()).unwrap_err(),
            SubmodularSelectionError::NegativeInformationValue {
                id: "a".to_string(),
                value_millimillibits: -1
            }
        );
        assert_eq!(
            MoonshotSelectionOption::try_new("a", 1, 0, BTreeSet::new()).unwrap_err(),
            SubmodularSelectionError::ZeroEffort {
                id: "a".to_string()
            }
        );
    }

    #[test]
    fn invalid_unlock_atom_inputs_fail_closed() {
        assert_eq!(
            DependencyUnlockAtom::try_new(" ", 1).unwrap_err(),
            SubmodularSelectionError::EmptyUnlockAtomId
        );
        assert_eq!(
            DependencyUnlockAtom::try_new("x", -1).unwrap_err(),
            SubmodularSelectionError::NegativeInformationValue {
                id: "x".to_string(),
                value_millimillibits: -1
            }
        );
    }

    #[test]
    fn evaluation_hash_is_deterministic_and_selection_sensitive() {
        let p = problem();
        let a = p.evaluate_selection(&set(&["parser-frontier"])).unwrap();
        let b = p.evaluate_selection(&set(&["parser-frontier"])).unwrap();
        let c = p.evaluate_selection(&set(&["ifc-proof"])).unwrap();
        assert_eq!(a.content_hash(), b.content_hash());
        assert_ne!(a.content_hash(), c.content_hash());
    }

    #[test]
    fn selection_order_does_not_change_evaluation() {
        let p = problem();
        let mut left = BTreeSet::new();
        left.insert("parser-frontier".to_string());
        left.insert("ifc-proof".to_string());

        let mut right = BTreeSet::new();
        right.insert("ifc-proof".to_string());
        right.insert("parser-frontier".to_string());

        assert_eq!(
            p.evaluate_selection(&left).unwrap(),
            p.evaluate_selection(&right).unwrap()
        );
    }

    #[test]
    fn can_construct_option_from_eiv_score() {
        let score = EivScore::compute(
            "from-score",
            PriorEvidence::uniform(),
            42,
            SecurityEpoch::from_raw(7),
        );
        let option =
            MoonshotSelectionOption::from_eiv_score(&score, 1_000_000, set(&["atom"])).unwrap();
        assert_eq!(option.moonshot_id, "from-score");
        assert_eq!(option.base_eiv_millimillibits, score.eiv_millimillibits);
        assert_eq!(option.effort_millionths, 1_000_000);
        assert_eq!(option.unlock_atom_ids, set(&["atom"]));
    }

    #[test]
    fn marginal_gain_exposes_new_unlock_atoms_only() {
        let p = problem();
        let selected = set(&["parser-frontier"]);
        let gain = p.marginal_gain(&selected, "ifc-proof").unwrap();
        assert_eq!(gain.newly_saturated_unlock_atom_ids, set(&["ifc"]));
        assert_eq!(gain.marginal_base_eiv_millimillibits, 400_000);
        assert_eq!(gain.marginal_total_eiv_millimillibits, 650_000);
    }
}
