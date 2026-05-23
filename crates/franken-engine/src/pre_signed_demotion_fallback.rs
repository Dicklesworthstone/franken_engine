// Pre-Signed Demotion Fallback — bd-cixqu.22.3.
//
// Track V.3 contract. Before applying a promotion (a `ReplacementReceipt`),
// the operator signs the demotion receipt that would fire if the
// promotion misbehaves, and STORES it. If the promotion later
// misbehaves, the demotion path is just *publishing the pre-signed
// receipt* — no operator round-trip needed.
//
// The point of this module is to make "promotion-without-pre-signed-
// fallback" structurally impossible: V.5 (bd-cixqu.22.5) is the
// negative test that the promotion path REFUSES to proceed if the
// store has no sealed fallback for the candidate. This module
// implements the store + sealing contract so V.5 has something
// concrete to gate against.
//
// Design notes:
//
//   * The pre-signed receipt is an opaque blob from this module's
//     perspective. We don't redefine `DemotionReceipt` — we hold its
//     `receipt_id` + a content-addressed digest of the canonical
//     receipt bytes. Wiring to `demotion_rollback::DemotionReceipt`
//     lives at the call site, not here.
//   * The fallback's lifecycle is:
//       Sealed (just signed, promotion not yet applied) →
//       Active (promotion is live; fallback can be activated on trigger) →
//       Activated (the demotion has been published) OR Voided (the
//         promotion completed successfully; no fallback needed).
//     Once Activated or Voided the fallback is terminal.
//   * The store rejects sealing two fallbacks for the same
//     `promotion_id` so the negative-test invariant ("exactly one
//     sealed fallback per promotion") is enforced at the API.
//
// Non-goals:
//
//   * The promotion-side wiring (the code that REFUSES to promote
//     without a sealed fallback) lives in V.4 / V.5 follow-ups.
//   * The actual signature / canonical encoding of the underlying
//     demotion receipt is handled by `demotion_rollback.rs`; we just
//     hold the digests.

use crate::demotion_rollback::DemotionReceipt;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::VerificationKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// PromotionId — the join key
// ---------------------------------------------------------------------------

/// Stable identifier for the promotion being protected. The store
/// keys fallbacks on this id; downstream wiring uses it to look up
/// "has THIS promotion been pre-signed against demotion yet?".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PromotionId(String);

impl PromotionId {
    /// Build a `PromotionId`. Rejects empty strings.
    pub fn try_new(value: impl Into<String>) -> Result<Self, FallbackError> {
        let value: String = value.into();
        if value.is_empty() {
            return Err(FallbackError::EmptyPromotionId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PromotionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Trigger conditions — what would activate the fallback
// ---------------------------------------------------------------------------

/// What kind of trigger condition can fire the pre-signed demotion.
/// The exact predicate is enforced by the demotion-policy machinery in
/// `demotion_rollback.rs`; this enum tags the rationale for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemotionTrigger {
    /// The promoted cell's digest no longer matches expectations.
    DigestDrift,
    /// A monitoring signal crossed a severity threshold.
    SeverityThresholdCrossed,
    /// The gatekeeper / decision verdict rejected the promotion.
    GatekeeperRejection,
    /// Manual operator decision (with rationale captured elsewhere).
    ManualOperator,
}

// ---------------------------------------------------------------------------
// FallbackStatus — lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle of a pre-signed demotion fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FallbackStatus {
    /// Just sealed; the underlying promotion has NOT yet been applied.
    Sealed,
    /// Promotion has been applied; the fallback is armed and can be
    /// activated by a trigger.
    Active,
    /// Trigger fired and the demotion receipt has been published.
    Activated {
        activated_at_ns: u64,
        trigger: DemotionTrigger,
    },
    /// Promotion completed successfully; the fallback is no longer
    /// needed and is voided for the audit ledger.
    Voided { voided_at_ns: u64, reason: String },
}

impl FallbackStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Activated { .. } | Self::Voided { .. })
    }

    pub fn is_armable(&self) -> bool {
        matches!(self, Self::Sealed)
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

// ---------------------------------------------------------------------------
// PreSignedDemotionFallback — the receipt-and-status record
// ---------------------------------------------------------------------------

/// A pre-signed demotion fallback record. Holds the digests of the
/// underlying signed demotion receipt + the lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreSignedDemotionFallback {
    /// Promotion this fallback protects.
    pub promotion_id: PromotionId,
    /// Content-addressed digest of the canonical signed demotion-
    /// receipt bytes. Two fallbacks signed against the same
    /// promotion would produce different digests; this is how we
    /// detect tampering between sealing and activation.
    pub receipt_digest: ContentHash,
    /// Time the fallback was sealed (nanoseconds, monotonic).
    pub sealed_at_ns: u64,
    /// Security epoch at sealing time.
    pub epoch: SecurityEpoch,
    /// Permitted trigger kinds (the fallback can fire on any of these).
    pub permitted_triggers: Vec<DemotionTrigger>,
    /// Lifecycle status.
    pub status: FallbackStatus,
}

impl PreSignedDemotionFallback {
    pub fn new(
        promotion_id: PromotionId,
        receipt_digest: ContentHash,
        sealed_at_ns: u64,
        epoch: SecurityEpoch,
        permitted_triggers: Vec<DemotionTrigger>,
    ) -> Self {
        Self {
            promotion_id,
            receipt_digest,
            sealed_at_ns,
            epoch,
            permitted_triggers,
            status: FallbackStatus::Sealed,
        }
    }

    /// Whether the supplied trigger is one this fallback was sealed to
    /// honor.
    pub fn permits(&self, trigger: &DemotionTrigger) -> bool {
        self.permitted_triggers.iter().any(|t| t == trigger)
    }
}

// ---------------------------------------------------------------------------
// PreSignedFallbackStore — the sealed-receipt store
// ---------------------------------------------------------------------------

/// Append-style store of pre-signed demotion fallbacks. Keyed on
/// `PromotionId`. Exactly one fallback may be sealed per promotion;
/// trying to seal a second one is `FallbackError::AlreadySealed`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreSignedFallbackStore {
    fallbacks: BTreeMap<PromotionId, PreSignedDemotionFallback>,
}

impl PreSignedFallbackStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }

    pub fn get(&self, promotion_id: &PromotionId) -> Option<&PreSignedDemotionFallback> {
        self.fallbacks.get(promotion_id)
    }

    /// Whether a sealed fallback exists for the given promotion. The
    /// downstream V.5 negative test asks exactly this question before
    /// allowing a promotion to proceed.
    pub fn has_sealed_fallback_for(&self, promotion_id: &PromotionId) -> bool {
        matches!(
            self.fallbacks.get(promotion_id).map(|f| &f.status),
            Some(FallbackStatus::Sealed),
        )
    }

    /// Seal a fallback before applying the corresponding promotion.
    /// Rejects a second seal for the same `promotion_id`.
    pub fn seal(&mut self, fallback: PreSignedDemotionFallback) -> Result<(), FallbackError> {
        if !matches!(fallback.status, FallbackStatus::Sealed) {
            return Err(FallbackError::InitialStatusNotSealed);
        }
        if fallback.permitted_triggers.is_empty() {
            return Err(FallbackError::NoPermittedTriggers);
        }
        if self.fallbacks.contains_key(&fallback.promotion_id) {
            return Err(FallbackError::AlreadySealed {
                promotion_id: fallback.promotion_id.clone(),
            });
        }
        self.fallbacks
            .insert(fallback.promotion_id.clone(), fallback);
        Ok(())
    }

    /// Verify and seal the pre-signed demotion receipt for a promotion.
    ///
    /// This is the V.5 call-shape: the operator-signed demotion receipt
    /// must verify under the expected operator key before the promotion
    /// path can observe a sealed fallback.
    pub fn seal_verified_demotion_receipt(
        &mut self,
        promotion_id: PromotionId,
        demotion_receipt: &DemotionReceipt,
        expected_operator_key: &VerificationKey,
        sealed_at_ns: u64,
        epoch: SecurityEpoch,
        permitted_triggers: Vec<DemotionTrigger>,
    ) -> Result<(), FallbackError> {
        demotion_receipt
            .verify_signature(expected_operator_key)
            .map_err(|_| FallbackError::InvalidDemotionReceiptSignature {
                promotion_id: promotion_id.clone(),
            })?;
        self.seal(PreSignedDemotionFallback::new(
            promotion_id,
            demotion_receipt.content_hash(),
            sealed_at_ns,
            epoch,
            permitted_triggers,
        ))
    }

    /// Mark the promotion as APPLIED. Transitions Sealed -> Active.
    pub fn mark_promotion_applied(
        &mut self,
        promotion_id: &PromotionId,
    ) -> Result<(), FallbackError> {
        let fallback =
            self.fallbacks
                .get_mut(promotion_id)
                .ok_or_else(|| FallbackError::NotFound {
                    promotion_id: promotion_id.clone(),
                })?;
        match fallback.status {
            FallbackStatus::Sealed => {
                fallback.status = FallbackStatus::Active;
                Ok(())
            }
            FallbackStatus::Active => Err(FallbackError::AlreadyActive {
                promotion_id: promotion_id.clone(),
            }),
            FallbackStatus::Activated { .. } | FallbackStatus::Voided { .. } => {
                Err(FallbackError::TerminalStatus {
                    promotion_id: promotion_id.clone(),
                })
            }
        }
    }

    /// Activate the fallback because a trigger fired. Transitions
    /// Active -> Activated. Refuses to activate from any other state.
    pub fn activate(
        &mut self,
        promotion_id: &PromotionId,
        trigger: DemotionTrigger,
        now_ns: u64,
    ) -> Result<&PreSignedDemotionFallback, FallbackError> {
        let fallback =
            self.fallbacks
                .get_mut(promotion_id)
                .ok_or_else(|| FallbackError::NotFound {
                    promotion_id: promotion_id.clone(),
                })?;
        match fallback.status {
            FallbackStatus::Active => {
                if !fallback.permits(&trigger) {
                    return Err(FallbackError::TriggerNotPermitted {
                        promotion_id: promotion_id.clone(),
                    });
                }
                fallback.status = FallbackStatus::Activated {
                    activated_at_ns: now_ns,
                    trigger,
                };
                Ok(&*fallback)
            }
            FallbackStatus::Sealed => Err(FallbackError::ActivationBeforeArmed {
                promotion_id: promotion_id.clone(),
            }),
            FallbackStatus::Activated { .. } | FallbackStatus::Voided { .. } => {
                Err(FallbackError::TerminalStatus {
                    promotion_id: promotion_id.clone(),
                })
            }
        }
    }

    /// Void the fallback because the promotion completed cleanly.
    /// Transitions Active -> Voided.
    pub fn void(
        &mut self,
        promotion_id: &PromotionId,
        reason: impl Into<String>,
        now_ns: u64,
    ) -> Result<(), FallbackError> {
        let fallback =
            self.fallbacks
                .get_mut(promotion_id)
                .ok_or_else(|| FallbackError::NotFound {
                    promotion_id: promotion_id.clone(),
                })?;
        match fallback.status {
            FallbackStatus::Active => {
                fallback.status = FallbackStatus::Voided {
                    voided_at_ns: now_ns,
                    reason: reason.into(),
                };
                Ok(())
            }
            FallbackStatus::Sealed => Err(FallbackError::VoidBeforeArmed {
                promotion_id: promotion_id.clone(),
            }),
            FallbackStatus::Activated { .. } | FallbackStatus::Voided { .. } => {
                Err(FallbackError::TerminalStatus {
                    promotion_id: promotion_id.clone(),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackError {
    EmptyPromotionId,
    InitialStatusNotSealed,
    NoPermittedTriggers,
    AlreadySealed { promotion_id: PromotionId },
    NotFound { promotion_id: PromotionId },
    AlreadyActive { promotion_id: PromotionId },
    TerminalStatus { promotion_id: PromotionId },
    ActivationBeforeArmed { promotion_id: PromotionId },
    VoidBeforeArmed { promotion_id: PromotionId },
    TriggerNotPermitted { promotion_id: PromotionId },
    InvalidDemotionReceiptSignature { promotion_id: PromotionId },
}

impl fmt::Display for FallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPromotionId => f.write_str("promotion id must be non-empty"),
            Self::InitialStatusNotSealed => {
                f.write_str("sealed fallbacks must start in Sealed status")
            }
            Self::NoPermittedTriggers => {
                f.write_str("fallback must permit at least one demotion trigger")
            }
            Self::AlreadySealed { promotion_id } => {
                write!(f, "fallback already sealed for promotion {promotion_id}")
            }
            Self::NotFound { promotion_id } => {
                write!(f, "no fallback recorded for promotion {promotion_id}")
            }
            Self::AlreadyActive { promotion_id } => {
                write!(f, "promotion {promotion_id} is already marked active")
            }
            Self::TerminalStatus { promotion_id } => write!(
                f,
                "fallback for promotion {promotion_id} is in a terminal status",
            ),
            Self::ActivationBeforeArmed { promotion_id } => write!(
                f,
                "cannot activate fallback for promotion {promotion_id} before it is marked applied",
            ),
            Self::VoidBeforeArmed { promotion_id } => write!(
                f,
                "cannot void fallback for promotion {promotion_id} before it is marked applied",
            ),
            Self::TriggerNotPermitted { promotion_id } => write!(
                f,
                "supplied trigger is not in the permitted set for promotion {promotion_id}",
            ),
            Self::InvalidDemotionReceiptSignature { promotion_id } => write!(
                f,
                "demotion receipt signature is invalid for promotion {promotion_id}",
            ),
        }
    }
}

impl std::error::Error for FallbackError {}

// ---------------------------------------------------------------------------
// Tests — sealing semantics + lifecycle invariants
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(s: &str) -> PromotionId {
        PromotionId::try_new(s).unwrap()
    }

    fn digest(s: &str) -> ContentHash {
        ContentHash::compute(s.as_bytes())
    }

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn fallback(p: &str) -> PreSignedDemotionFallback {
        PreSignedDemotionFallback::new(
            pid(p),
            digest(p),
            100,
            epoch(),
            vec![
                DemotionTrigger::DigestDrift,
                DemotionTrigger::GatekeeperRejection,
            ],
        )
    }

    // ----- PromotionId -----

    #[test]
    fn promotion_id_rejects_empty() {
        assert_eq!(
            PromotionId::try_new("").unwrap_err(),
            FallbackError::EmptyPromotionId
        );
    }

    #[test]
    fn promotion_id_round_trips() {
        let p = pid("promo-42");
        assert_eq!(p.as_str(), "promo-42");
        assert_eq!(format!("{p}"), "promo-42");
    }

    // ----- Status -----

    #[test]
    fn status_terminal_classification() {
        assert!(!FallbackStatus::Sealed.is_terminal());
        assert!(!FallbackStatus::Active.is_terminal());
        assert!(
            FallbackStatus::Activated {
                activated_at_ns: 1,
                trigger: DemotionTrigger::DigestDrift,
            }
            .is_terminal()
        );
        assert!(
            FallbackStatus::Voided {
                voided_at_ns: 1,
                reason: "ok".into(),
            }
            .is_terminal()
        );
    }

    #[test]
    fn status_armable_only_in_sealed() {
        assert!(FallbackStatus::Sealed.is_armable());
        assert!(!FallbackStatus::Active.is_armable());
    }

    // ----- Fallback construction -----

    #[test]
    fn new_fallback_starts_sealed() {
        let f = fallback("p1");
        assert_eq!(f.status, FallbackStatus::Sealed);
        assert_eq!(f.sealed_at_ns, 100);
        assert_eq!(f.permitted_triggers.len(), 2);
    }

    #[test]
    fn permits_only_listed_triggers() {
        let f = fallback("p1");
        assert!(f.permits(&DemotionTrigger::DigestDrift));
        assert!(f.permits(&DemotionTrigger::GatekeeperRejection));
        assert!(!f.permits(&DemotionTrigger::ManualOperator));
        assert!(!f.permits(&DemotionTrigger::SeverityThresholdCrossed));
    }

    // ----- Store seal -----

    #[test]
    fn fresh_store_is_empty() {
        let s = PreSignedFallbackStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn seal_inserts_fallback() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.has_sealed_fallback_for(&pid("p1")));
    }

    #[test]
    fn seal_rejects_second_attempt_for_same_promotion() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        let err = s.seal(fallback("p1")).unwrap_err();
        match err {
            FallbackError::AlreadySealed { promotion_id } => {
                assert_eq!(promotion_id, pid("p1"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn seal_rejects_empty_trigger_list() {
        let mut s = PreSignedFallbackStore::new();
        let mut f = fallback("p1");
        f.permitted_triggers.clear();
        let err = s.seal(f).unwrap_err();
        assert_eq!(err, FallbackError::NoPermittedTriggers);
    }

    #[test]
    fn seal_rejects_pre_active_fallback() {
        let mut s = PreSignedFallbackStore::new();
        let mut f = fallback("p1");
        f.status = FallbackStatus::Active;
        let err = s.seal(f).unwrap_err();
        assert_eq!(err, FallbackError::InitialStatusNotSealed);
    }

    // ----- Promotion-applied transition -----

    #[test]
    fn mark_applied_transitions_sealed_to_active() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        let f = s.get(&pid("p1")).unwrap();
        assert!(f.status.is_active());
        // has_sealed_fallback_for no longer returns true once active.
        assert!(!s.has_sealed_fallback_for(&pid("p1")));
    }

    #[test]
    fn mark_applied_idempotency_is_rejected() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        let err = s.mark_promotion_applied(&pid("p1")).unwrap_err();
        assert!(matches!(err, FallbackError::AlreadyActive { .. }));
    }

    #[test]
    fn mark_applied_on_missing_promotion() {
        let mut s = PreSignedFallbackStore::new();
        let err = s.mark_promotion_applied(&pid("nope")).unwrap_err();
        assert!(matches!(err, FallbackError::NotFound { .. }));
    }

    // ----- Activate -----

    #[test]
    fn activate_after_armed_transitions_to_activated() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        let f = s
            .activate(&pid("p1"), DemotionTrigger::DigestDrift, 500)
            .unwrap()
            .clone();
        match f.status {
            FallbackStatus::Activated {
                activated_at_ns,
                trigger,
            } => {
                assert_eq!(activated_at_ns, 500);
                assert_eq!(trigger, DemotionTrigger::DigestDrift);
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    #[test]
    fn activate_before_armed_is_rejected() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        let err = s
            .activate(&pid("p1"), DemotionTrigger::DigestDrift, 500)
            .unwrap_err();
        assert!(matches!(err, FallbackError::ActivationBeforeArmed { .. }));
    }

    #[test]
    fn activate_rejects_disallowed_trigger() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        let err = s
            .activate(&pid("p1"), DemotionTrigger::ManualOperator, 500)
            .unwrap_err();
        assert!(matches!(err, FallbackError::TriggerNotPermitted { .. }));
    }

    #[test]
    fn activate_after_terminal_is_rejected() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        s.activate(&pid("p1"), DemotionTrigger::DigestDrift, 500)
            .unwrap();
        let err = s
            .activate(&pid("p1"), DemotionTrigger::DigestDrift, 600)
            .unwrap_err();
        assert!(matches!(err, FallbackError::TerminalStatus { .. }));
    }

    // ----- Void -----

    #[test]
    fn void_after_armed_transitions_to_voided() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        s.void(&pid("p1"), "promotion completed", 700).unwrap();
        let f = s.get(&pid("p1")).unwrap();
        match &f.status {
            FallbackStatus::Voided {
                voided_at_ns,
                reason,
            } => {
                assert_eq!(*voided_at_ns, 700);
                assert_eq!(reason, "promotion completed");
            }
            other => panic!("unexpected status: {:?}", other),
        }
    }

    #[test]
    fn void_before_armed_is_rejected() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        let err = s.void(&pid("p1"), "should fail", 700).unwrap_err();
        assert!(matches!(err, FallbackError::VoidBeforeArmed { .. }));
    }

    #[test]
    fn void_after_terminal_is_rejected() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        s.void(&pid("p1"), "ok", 700).unwrap();
        let err = s.void(&pid("p1"), "again", 800).unwrap_err();
        assert!(matches!(err, FallbackError::TerminalStatus { .. }));
    }

    // ----- has_sealed_fallback_for (the V.5 negative-test predicate) -----

    #[test]
    fn has_sealed_fallback_for_returns_true_only_in_sealed() {
        let mut s = PreSignedFallbackStore::new();
        assert!(!s.has_sealed_fallback_for(&pid("p1"))); // not yet sealed
        s.seal(fallback("p1")).unwrap();
        assert!(s.has_sealed_fallback_for(&pid("p1"))); // sealed
        s.mark_promotion_applied(&pid("p1")).unwrap();
        assert!(!s.has_sealed_fallback_for(&pid("p1"))); // active
    }

    // ----- Multi-promotion store -----

    #[test]
    fn multi_promotion_store_keeps_independent_lifecycles() {
        let mut s = PreSignedFallbackStore::new();
        s.seal(fallback("p1")).unwrap();
        s.seal(fallback("p2")).unwrap();
        s.mark_promotion_applied(&pid("p1")).unwrap();
        s.activate(&pid("p1"), DemotionTrigger::DigestDrift, 500)
            .unwrap();
        // p2 untouched.
        assert_eq!(s.get(&pid("p2")).unwrap().status, FallbackStatus::Sealed);
        // p1 terminal.
        assert!(s.get(&pid("p1")).unwrap().status.is_terminal());
    }

    // ----- Serde -----

    #[test]
    fn fallback_serde_round_trip() {
        let original = fallback("p-serde");
        let json = serde_json::to_string(&original).unwrap();
        let restored: PreSignedDemotionFallback = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn store_serde_round_trip() {
        let mut original = PreSignedFallbackStore::new();
        original.seal(fallback("p1")).unwrap();
        original.seal(fallback("p2")).unwrap();
        original.mark_promotion_applied(&pid("p1")).unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let restored: PreSignedFallbackStore = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    // ----- Error display -----

    #[test]
    fn error_display_includes_promotion_id() {
        let s = format!(
            "{}",
            FallbackError::AlreadySealed {
                promotion_id: pid("p-99"),
            }
        );
        assert!(s.contains("p-99"));
    }
}
