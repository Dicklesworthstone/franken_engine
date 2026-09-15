//! Checked fixed-point inputs for policy decisions.
//!
//! A missing cost is not a free action. Validate the distribution before doing
//! arithmetic and require an explicit loss for every state with positive mass.

use super::{LossMatrix, PolicyControllerError, Posterior};

const PROBABILITY_SCALE: i128 = 1_000_000;

pub(super) fn validate_posterior(posterior: &Posterior) -> Result<(), PolicyControllerError> {
    let mut total = 0_i128;
    for (state, &probability) in &posterior.probabilities {
        if !(0..=1_000_000).contains(&probability) {
            return Err(PolicyControllerError::InvalidPosterior {
                reason: format!("probability for state '{state}' is outside 0..=1000000"),
            });
        }
        total += i128::from(probability);
        if total > PROBABILITY_SCALE {
            return Err(PolicyControllerError::InvalidPosterior {
                reason: "probability mass exceeds 1000000".to_string(),
            });
        }
    }
    if total != PROBABILITY_SCALE {
        return Err(PolicyControllerError::InvalidPosterior {
            reason: format!("probability mass is {total}, expected 1000000"),
        });
    }
    Ok(())
}

pub(super) fn expected_loss(
    matrix: &LossMatrix,
    action: &str,
    posterior: &Posterior,
) -> Result<i64, PolicyControllerError> {
    validate_posterior(posterior)?;
    if matrix.is_empty() {
        return Err(PolicyControllerError::NoLossEntries);
    }

    let mut numerator = 0_i128;
    for (state, &probability) in &posterior.probabilities {
        // Zero-mass states contribute nothing and need no cost entry.
        if probability == 0 {
            continue;
        }
        let loss = matrix.get(state, action).ok_or_else(|| {
            PolicyControllerError::MissingLossEntry {
                state: state.clone(),
                action: action.to_string(),
            }
        })?;
        // Validation bounds total probability mass to 1M. Even at either i64
        // loss endpoint, the entire numerator fits in i128. Round only once:
        // rounding each state's contribution can change the winning action.
        numerator += i128::from(probability) * i128::from(loss);
    }
    i64::try_from(numerator / PROBABILITY_SCALE).map_err(|_| {
        PolicyControllerError::ExpectedLossOutOfRange {
            action: action.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn posterior(entries: &[(&str, i64)]) -> Posterior {
        Posterior::new(
            entries
                .iter()
                .map(|(state, probability)| ((*state).to_string(), *probability))
                .collect::<BTreeMap<_, _>>(),
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
                    Err(PolicyControllerError::InvalidPosterior { .. })
                ),
                "accepted malformed distribution: {case:?}"
            );
            assert!(matches!(
                expected_loss(&LossMatrix::new(), "allow", &distribution),
                Err(PolicyControllerError::InvalidPosterior { .. })
            ));
        }
    }

    #[test]
    fn empty_matrix_is_not_a_zero_cost_model() {
        assert_eq!(
            expected_loss(&LossMatrix::new(), "allow", &posterior(&[("a", 1_000_000)])),
            Err(PolicyControllerError::NoLossEntries)
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
            Err(PolicyControllerError::MissingLossEntry {
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
            Err(PolicyControllerError::MissingLossEntry {
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
            expected_loss(&matrix, "allow", &posterior(&[("a", 500_000), ("b", 500_000)])),
            Ok(0)
        );
    }
}
