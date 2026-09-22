//! Checked fixed-point inputs for policy decisions.
//!
//! A missing cost is not a free action. Validate the distribution before doing
//! arithmetic and require an explicit loss for every state with positive mass.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{LossMatrix, PolicyControllerError, Posterior};

const PROBABILITY_SCALE: i128 = 1_000_000;

/// Why a posterior and loss model cannot support an auditable decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionInputError {
    InvalidPosterior { reason: String },
    NoLossEntries,
    MissingLossEntry { state: String, action: String },
    ExpectedLossOutOfRange { action: String },
}

impl fmt::Display for DecisionInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPosterior { reason } => write!(f, "invalid posterior: {reason}"),
            Self::NoLossEntries => write!(f, "loss matrix is empty"),
            Self::MissingLossEntry { state, action } => {
                write!(f, "missing loss for state '{state}' and action '{action}'")
            }
            Self::ExpectedLossOutOfRange { action } => {
                write!(f, "expected loss for action '{action}' is out of range")
            }
        }
    }
}

impl std::error::Error for DecisionInputError {}

impl From<DecisionInputError> for PolicyControllerError {
    fn from(error: DecisionInputError) -> Self {
        match error {
            DecisionInputError::NoLossEntries => Self::NoLossEntries,
            error => Self::EvidenceEmissionFailed {
                // Keep the existing serialized controller/error-code boundary:
                // invalid model inputs cannot support valid decision evidence.
                reason: format!("invalid decision inputs: {error}"),
            },
        }
    }
}

impl Posterior {
    /// Normalize nonnegative integer weights into exactly one million units.
    ///
    /// This is an explicit conversion for observation counts or relative
    /// weights; decisions never silently normalize malformed posteriors.
    /// Fractional units go to the largest remainders, with ties resolved by
    /// state name. Zero-weight states remain zero. Positive weights smaller
    /// than the millionth-unit resolution may round to zero.
    pub fn from_weights(weights: BTreeMap<String, i64>) -> Result<Self, DecisionInputError> {
        let mut total = 0_i128;
        for (state, &weight) in &weights {
            if weight < 0 {
                return Err(DecisionInputError::InvalidPosterior {
                    reason: format!("negative weight for state '{state}'"),
                });
            }
            total = total.checked_add(i128::from(weight)).ok_or_else(|| {
                DecisionInputError::InvalidPosterior {
                    reason: "total weight exceeds i128 range".to_string(),
                }
            })?;
        }
        if total == 0 {
            return Err(DecisionInputError::InvalidPosterior {
                reason: "weights must contain positive mass".to_string(),
            });
        }

        let mut allocated = 0_i128;
        let mut shares = Vec::with_capacity(weights.len());
        for (state, weight) in weights {
            // i64 weights times one million fit in i128, even when their sum
            // exceeds i64. Each quotient is bounded by one million.
            let numerator = i128::from(weight) * PROBABILITY_SCALE;
            let units = numerator / total;
            let probability =
                i64::try_from(units).map_err(|_| DecisionInputError::InvalidPosterior {
                    reason: "normalized weight exceeds probability range".to_string(),
                })?;
            allocated += units;
            shares.push((state, probability, numerator % total));
        }
        shares.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
        let remaining = usize::try_from(PROBABILITY_SCALE - allocated).map_err(|_| {
            DecisionInputError::InvalidPosterior {
                reason: "normalization remainder exceeds allocation range".to_string(),
            }
        })?;
        // The sum of fractional remainders is an integer strictly below the
        // number of nonzero remainders, so zero-weight states get no extras.
        for (_, probability, _) in shares.iter_mut().take(remaining) {
            *probability += 1;
        }
        let posterior = Self::new(
            shares
                .into_iter()
                .map(|(state, probability, _)| (state, probability))
                .collect(),
        );
        posterior.validate()?;
        Ok(posterior)
    }
}

pub(super) fn validate_posterior(posterior: &Posterior) -> Result<(), DecisionInputError> {
    let mut total = 0_i128;
    for (state, &probability) in &posterior.probabilities {
        if !(0..=1_000_000).contains(&probability) {
            return Err(DecisionInputError::InvalidPosterior {
                reason: format!("probability for state '{state}' is outside 0..=1000000"),
            });
        }
        total += i128::from(probability);
        if total > PROBABILITY_SCALE {
            return Err(DecisionInputError::InvalidPosterior {
                reason: "probability mass exceeds 1000000".to_string(),
            });
        }
    }
    if total != PROBABILITY_SCALE {
        return Err(DecisionInputError::InvalidPosterior {
            reason: format!("probability mass is {total}, expected 1000000"),
        });
    }
    Ok(())
}

pub(super) fn expected_loss(
    matrix: &LossMatrix,
    action: &str,
    posterior: &Posterior,
) -> Result<i64, DecisionInputError> {
    validate_posterior(posterior)?;
    if matrix.is_empty() {
        return Err(DecisionInputError::NoLossEntries);
    }

    let mut numerator = 0_i128;
    for (state, &probability) in &posterior.probabilities {
        // Zero-mass states contribute nothing and need no cost entry.
        if probability == 0 {
            continue;
        }
        let loss =
            matrix
                .get(state, action)
                .ok_or_else(|| DecisionInputError::MissingLossEntry {
                    state: state.clone(),
                    action: action.to_string(),
                })?;
        // Validation bounds total probability mass to 1M. Even at either i64
        // loss endpoint, the entire numerator fits in i128. Round only once:
        // rounding each state's contribution can change the winning action.
        numerator += i128::from(probability) * i128::from(loss);
    }
    i64::try_from(numerator / PROBABILITY_SCALE).map_err(|_| {
        DecisionInputError::ExpectedLossOutOfRange {
            action: action.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posterior(entries: &[(&str, i64)]) -> Posterior {
        Posterior::new(
            entries
                .iter()
                .map(|(state, probability)| ((*state).to_string(), *probability))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn from_weights(entries: &[(&str, i64)]) -> Result<Posterior, DecisionInputError> {
        Posterior::from_weights(
            entries
                .iter()
                .map(|(state, weight)| ((*state).to_string(), *weight))
                .collect(),
        )
    }

    #[test]
    fn malformed_distributions_are_rejected_before_arithmetic() {
        let cases: &[&[(&str, i64)]] = &[
            &[],
            &[("a", 0)],
            &[("a", 999_999)],
            &[("a", 1_000_001)],
            &[("a", 600_000), ("b", 600_000)],
            &[("a", -1), ("b", 1_000_001)],
            &[("a", i64::MIN), ("b", i64::MAX)],
        ];
        for case in cases {
            let distribution = posterior(case);
            assert!(
                matches!(
                    validate_posterior(&distribution),
                    Err(DecisionInputError::InvalidPosterior { .. })
                ),
                "accepted malformed distribution: {case:?}"
            );
            assert!(matches!(
                expected_loss(&LossMatrix::new(), "allow", &distribution),
                Err(DecisionInputError::InvalidPosterior { .. })
            ));
        }
    }

    #[test]
    fn empty_matrix_is_not_a_zero_cost_model() {
        assert_eq!(
            expected_loss(&LossMatrix::new(), "allow", &posterior(&[("a", 1_000_000)])),
            Err(DecisionInputError::NoLossEntries)
        );
    }

    #[test]
    fn missing_positive_mass_cost_is_rejected() {
        let mut matrix = LossMatrix::new();
        matrix.set("benign", "allow", 0);
        assert_eq!(
            expected_loss(
                &matrix,
                "allow",
                &posterior(&[("benign", 900_000), ("malicious", 100_000)])
            ),
            Err(DecisionInputError::MissingLossEntry {
                state: "malicious".to_string(),
                action: "allow".to_string(),
            })
        );
    }

    #[test]
    fn missing_action_cannot_win_by_defaulting_to_zero() {
        let mut matrix = LossMatrix::new();
        matrix.set("a", "deny", 100);
        assert_eq!(
            expected_loss(&matrix, "allow", &posterior(&[("a", 1_000_000)])),
            Err(DecisionInputError::MissingLossEntry {
                state: "a".to_string(),
                action: "allow".to_string(),
            })
        );
    }

    #[test]
    fn zero_mass_states_need_no_loss_entry() {
        let mut matrix = LossMatrix::new();
        matrix.set("present", "allow", 42);
        assert_eq!(
            expected_loss(
                &matrix,
                "allow",
                &posterior(&[("absent", 0), ("present", 1_000_000)])
            ),
            Ok(42)
        );
    }

    #[test]
    fn explicit_zero_loss_remains_valid() {
        let mut matrix = LossMatrix::new();
        matrix.set("a", "allow", 0);
        assert_eq!(
            expected_loss(&matrix, "allow", &posterior(&[("a", 1_000_000)])),
            Ok(0)
        );
    }

    #[test]
    fn negative_losses_remain_supported() {
        let mut matrix = LossMatrix::new();
        matrix.set("a", "allow", -500_000);
        assert_eq!(
            expected_loss(&matrix, "allow", &posterior(&[("a", 1_000_000)])),
            Ok(-500_000)
        );
    }

    #[test]
    fn fractional_contributions_are_summed_before_rounding() {
        let distribution = posterior(&[("a", 600_000), ("b", 400_000)]);
        let mut matrix = LossMatrix::new();
        matrix.set("a", "allow", 1);
        matrix.set("b", "allow", 1);
        assert_eq!(expected_loss(&matrix, "allow", &distribution), Ok(1));
    }

    #[test]
    fn signed_contributions_are_rounded_together_toward_zero() {
        let distribution = posterior(&[("a", 400_000), ("b", 600_000)]);
        let mut matrix = LossMatrix::new();
        matrix.set("a", "allow", -2);
        matrix.set("b", "allow", 2);
        assert_eq!(expected_loss(&matrix, "allow", &distribution), Ok(0));
    }

    #[test]
    fn full_i64_loss_range_is_preserved() {
        let distribution = posterior(&[("a", 333_333), ("b", 333_333), ("c", 333_334)]);
        for endpoint in [i64::MIN, i64::MAX] {
            let mut matrix = LossMatrix::new();
            for state in ["a", "b", "c"] {
                matrix.set(state, "allow", endpoint);
            }
            assert_eq!(expected_loss(&matrix, "allow", &distribution), Ok(endpoint));
        }
    }

    #[test]
    fn extreme_opposing_losses_do_not_overflow() {
        let mut matrix = LossMatrix::new();
        matrix.set("a", "allow", i64::MIN);
        matrix.set("b", "allow", i64::MAX);
        assert_eq!(
            expected_loss(
                &matrix,
                "allow",
                &posterior(&[("a", 500_000), ("b", 500_000)])
            ),
            Ok(0)
        );
    }

    #[test]
    fn input_errors_round_trip_and_preserve_controller_error_boundary() {
        for error in [
            DecisionInputError::InvalidPosterior {
                reason: "mass".into(),
            },
            DecisionInputError::NoLossEntries,
            DecisionInputError::MissingLossEntry {
                state: "s".into(),
                action: "a".into(),
            },
            DecisionInputError::ExpectedLossOutOfRange { action: "a".into() },
        ] {
            let json = serde_json::to_string(&error).expect("serialize input error");
            assert_eq!(
                serde_json::from_str::<DecisionInputError>(&json).unwrap(),
                error
            );
            assert!(!error.to_string().is_empty());
            let controller_error = PolicyControllerError::from(error.clone());
            if error == DecisionInputError::NoLossEntries {
                assert_eq!(controller_error, PolicyControllerError::NoLossEntries);
            } else {
                assert!(matches!(
                    controller_error,
                    PolicyControllerError::EvidenceEmissionFailed { .. }
                ));
            }
        }
    }

    #[test]
    fn equal_weights_distribute_remainder_by_state_name() {
        let normalized = from_weights(&[("c", 1), ("b", 1), ("a", 1)]).unwrap();
        assert_eq!(
            normalized,
            posterior(&[("a", 333_334), ("b", 333_333), ("c", 333_333)])
        );
        assert_eq!(normalized.validate(), Ok(()));
    }

    #[test]
    fn largest_remainder_takes_precedence_over_state_name() {
        let normalized = from_weights(&[("a", 1), ("b", 1), ("z", 4)]).unwrap();
        assert_eq!(
            normalized,
            posterior(&[("a", 166_667), ("b", 166_667), ("z", 666_666)])
        );
        let normalized = from_weights(&[("a", 1), ("z", 2)]).unwrap();
        assert_eq!(normalized, posterior(&[("a", 333_333), ("z", 666_667)]));
    }

    #[test]
    fn zero_weights_never_receive_rounding_mass() {
        let normalized = from_weights(&[("zero", 0), ("a", 1), ("b", 1), ("c", 1)]).unwrap();
        assert_eq!(normalized.probability("zero"), 0);
        assert_eq!(normalized.states().count(), 4);
        assert_eq!(normalized.validate(), Ok(()));
    }

    #[test]
    fn large_weights_and_totals_do_not_overflow() {
        let normalized =
            from_weights(&[("a", i64::MAX), ("b", i64::MAX), ("c", i64::MAX)]).unwrap();
        assert_eq!(
            normalized,
            posterior(&[("a", 333_334), ("b", 333_333), ("c", 333_333)])
        );
        let normalized = from_weights(&[("a", i64::MAX), ("tiny", 1)]).unwrap();
        assert_eq!(normalized, posterior(&[("a", 1_000_000), ("tiny", 0)]));
    }

    #[test]
    fn invalid_weights_are_rejected_without_inventing_a_distribution() {
        let cases: &[&[(&str, i64)]] = &[
            &[],
            &[("a", 0)],
            &[("a", 0), ("b", 0)],
            &[("a", -1), ("b", 10)],
            &[("a", i64::MIN), ("b", i64::MAX)],
        ];
        for case in cases {
            assert!(matches!(
                from_weights(case),
                Err(DecisionInputError::InvalidPosterior { .. })
            ));
        }
    }

    #[test]
    fn normalization_is_scale_invariant_and_preserves_valid_posteriors() {
        assert_eq!(
            from_weights(&[("a", 1), ("b", 2), ("c", 7)]),
            from_weights(&[("a", 100), ("b", 200), ("c", 700)])
        );
        let original = posterior(&[("a", 123_456), ("b", 876_544), ("c", 0)]);
        assert_eq!(
            Posterior::from_weights(original.probabilities.clone()).unwrap(),
            original
        );
        assert_eq!(
            from_weights(&[("only", 7)]).unwrap(),
            posterior(&[("only", 1_000_000)])
        );
    }

    #[test]
    fn normalization_conserves_mass_across_varying_state_counts() {
        for count in 1..=100 {
            let weights: BTreeMap<String, i64> = (0..count)
                .map(|i| (format!("state-{i:03}"), i64::from(i + 1)))
                .collect();
            let normalized = Posterior::from_weights(weights.clone()).unwrap();
            assert_eq!(normalized.validate(), Ok(()));
            let total: i128 = weights.values().map(|weight| i128::from(*weight)).sum();
            for (state, weight) in weights {
                let ideal_numerator = i128::from(weight) * PROBABILITY_SCALE;
                let actual_numerator = i128::from(normalized.probability(&state)) * total;
                assert!((ideal_numerator - actual_numerator).abs() < total);
            }
        }
    }
}
