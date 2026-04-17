//! Mandatory revocation enforcement interceptors.
//!
//! Three enforcement points that must be passed before any:
//! 1. **Token acceptance** — checks `is_revoked(token.jti)` and transitive
//!    issuer-key revocation.
//! 2. **High-risk operation execution** — checks revocation status of the
//!    requesting principal's current key attestation.
//! 3. **Extension activation** — checks `is_revoked(extension_id)` and
//!    `is_revoked(extension_signing_key_id)`.
//!
//! All checks produce structured audit events. Revocation checks happen
//! *after* signature verification but *before* any state mutation.
//!
//! Plan references: Section 10.10 item 18, 9E.7.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::revocation_chain::{RevocationChain, RevocationTargetType};
use crate::signature_preimage::VerificationKey;

// ---------------------------------------------------------------------------
// Enforcement point identifiers
// ---------------------------------------------------------------------------

/// Which enforcement point triggered the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnforcementPoint {
    /// Token acceptance — before authorizing an action with a capability token.
    TokenAcceptance,
    /// High-risk operation — before executing policy changes, key ops, etc.
    HighRiskOperation,
    /// Extension activation — before loading/resuming an extension.
    ExtensionActivation,
}

impl fmt::Display for EnforcementPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenAcceptance => write!(f, "token_acceptance"),
            Self::HighRiskOperation => write!(f, "high_risk_operation"),
            Self::ExtensionActivation => write!(f, "extension_activation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RevocationDenial — hard denial with full context
// ---------------------------------------------------------------------------

/// A hard denial produced when a revoked object is encountered at an
/// enforcement point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationDenial {
    /// Type of the revoked target.
    pub target_type: RevocationTargetType,
    /// ID of the revoked target.
    pub target_id: EngineObjectId,
    /// Whether the denial was direct or transitive (e.g. issuer key revoked).
    pub transitive: bool,
    /// If transitive, the root revoked ID (e.g. the issuer key ID).
    pub transitive_root: Option<EngineObjectId>,
    /// The enforcement point where denial occurred.
    pub enforcement_point: EnforcementPoint,
}

impl fmt::Display for RevocationDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.transitive {
            write!(
                f,
                "revocation denial at {}: {} {} transitively revoked via {}",
                self.enforcement_point,
                self.target_type,
                self.target_id,
                self.transitive_root
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |r| r.to_string()),
            )
        } else {
            write!(
                f,
                "revocation denial at {}: {} {} directly revoked",
                self.enforcement_point, self.target_type, self.target_id,
            )
        }
    }
}

impl std::error::Error for RevocationDenial {}

// ---------------------------------------------------------------------------
// High-risk operation classification
// ---------------------------------------------------------------------------

/// Categories of operations considered high-risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HighRiskCategory {
    /// Policy change (create, update, delete).
    PolicyChange,
    /// Key operations (rotation, derivation, export).
    KeyOperation,
    /// Data export or declassification.
    DataExport,
    /// Cross-zone action.
    CrossZoneAction,
    /// Extension lifecycle change.
    ExtensionLifecycleChange,
}

impl fmt::Display for HighRiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyChange => write!(f, "policy_change"),
            Self::KeyOperation => write!(f, "key_operation"),
            Self::DataExport => write!(f, "data_export"),
            Self::CrossZoneAction => write!(f, "cross_zone_action"),
            Self::ExtensionLifecycleChange => write!(f, "extension_lifecycle_change"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Audit event emitted for every revocation check (pass or fail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCheckEvent {
    /// Which enforcement point.
    pub enforcement_point: EnforcementPoint,
    /// The target ID that was checked.
    pub target_id: EngineObjectId,
    /// Target type that was checked.
    pub target_type: RevocationTargetType,
    /// Whether the target was found to be revoked.
    pub is_revoked: bool,
    /// Whether this was a transitive check.
    pub transitive: bool,
    /// Trace ID for forensic linkage.
    pub trace_id: String,
    /// Timestamp of the check.
    pub checked_at: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Enforcement result
// ---------------------------------------------------------------------------

/// Result of a revocation enforcement check: either cleared or denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementResult {
    /// All checks passed — object is not revoked.
    Cleared {
        enforcement_point: EnforcementPoint,
        checks_performed: u32,
    },
    /// Revocation detected — hard denial.
    Denied(RevocationDenial),
}

impl EnforcementResult {
    /// Returns `Ok(())` if cleared, or `Err(RevocationDenial)` if denied.
    pub fn into_result(self) -> Result<(), RevocationDenial> {
        match self {
            Self::Cleared { .. } => Ok(()),
            Self::Denied(denial) => Err(denial),
        }
    }

    /// Whether the check passed.
    pub fn is_cleared(&self) -> bool {
        matches!(self, Self::Cleared { .. })
    }
}

// ---------------------------------------------------------------------------
// Helper: derive key ID from VerificationKey
// ---------------------------------------------------------------------------

/// Derive a stable EngineObjectId from a verification key, for revocation
/// lookup of keys.
pub fn key_id_from_verification_key(vk: &VerificationKey) -> EngineObjectId {
    let hash = ContentHash::compute(vk.as_bytes());
    EngineObjectId(*hash.as_bytes())
}

// ---------------------------------------------------------------------------
// RevocationEnforcer — the enforcement engine
// ---------------------------------------------------------------------------

/// Mandatory revocation enforcement engine.
///
/// Wraps a `RevocationChain` and provides the three enforcement interceptors.
/// Every check emits audit events regardless of outcome.
#[derive(Debug)]
pub struct RevocationEnforcer {
    /// The underlying revocation chain (shared reference via mutable borrow).
    chain: RevocationChain,
    /// Accumulated audit events.
    audit_log: Vec<RevocationCheckEvent>,
    /// Statistics by enforcement point.
    stats: BTreeMap<EnforcementPoint, EnforcementStats>,
    /// Current tick for timestamps.
    current_tick: u64,
}

/// Per-enforcement-point statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementStats {
    pub checks: u64,
    pub cleared: u64,
    pub denied: u64,
    pub transitive_denials: u64,
}

impl RevocationEnforcer {
    /// Create a new enforcer wrapping the given revocation chain.
    pub fn new(chain: RevocationChain, current_tick: u64) -> Self {
        Self {
            chain,
            audit_log: Vec::new(),
            stats: BTreeMap::new(),
            current_tick,
        }
    }

    /// Access the underlying revocation chain.
    pub fn chain(&self) -> &RevocationChain {
        &self.chain
    }

    /// Mutable access to the underlying revocation chain (e.g. for appends).
    pub fn chain_mut(&mut self) -> &mut RevocationChain {
        &mut self.chain
    }

    /// Update the current tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Drain accumulated audit events.
    pub fn drain_audit_log(&mut self) -> Vec<RevocationCheckEvent> {
        std::mem::take(&mut self.audit_log)
    }

    /// Get enforcement statistics.
    pub fn stats(&self) -> &BTreeMap<EnforcementPoint, EnforcementStats> {
        &self.stats
    }

    // -------------------------------------------------------------------
    // Enforcement point 1: Token acceptance
    // -------------------------------------------------------------------

    /// Check revocation status before accepting a capability token.
    ///
    /// Checks:
    /// 1. `is_revoked(token_jti)` — direct token revocation.
    /// 2. `is_revoked(issuer_key_id)` — transitive issuer key revocation.
    ///
    /// Must be called *after* signature verification.
    pub fn check_token_acceptance(
        &mut self,
        token_jti: &EngineObjectId,
        issuer_key: &VerificationKey,
        trace_id: &str,
    ) -> EnforcementResult {
        let point = EnforcementPoint::TokenAcceptance;

        // Check 1: direct token revocation.
        let token_revoked = self.chain.is_revoked(token_jti);
        self.emit_audit(
            point,
            token_jti,
            RevocationTargetType::Token,
            token_revoked,
            false,
            trace_id,
        );

        if token_revoked {
            self.record_denial(point, false);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Token,
                target_id: token_jti.clone(),
                transitive: false,
                transitive_root: None,
                enforcement_point: point,
            });
        }

        // Check 2: transitive issuer key revocation.
        let issuer_key_id = key_id_from_verification_key(issuer_key);
        let key_revoked = self.chain.is_revoked(&issuer_key_id);
        self.emit_audit(
            point,
            &issuer_key_id,
            RevocationTargetType::Key,
            key_revoked,
            true,
            trace_id,
        );

        if key_revoked {
            self.record_denial(point, true);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Token,
                target_id: token_jti.clone(),
                transitive: true,
                transitive_root: Some(issuer_key_id),
                enforcement_point: point,
            });
        }

        self.record_cleared(point, 2);
        EnforcementResult::Cleared {
            enforcement_point: point,
            checks_performed: 2,
        }
    }

    // -------------------------------------------------------------------
    // Enforcement point 2: High-risk operation
    // -------------------------------------------------------------------

    /// Check revocation status before executing a high-risk operation.
    ///
    /// Verifies the requesting principal's current key attestation has not
    /// been revoked.
    ///
    /// Must be called *after* signature verification.
    pub fn check_high_risk_operation(
        &mut self,
        attestation_id: &EngineObjectId,
        principal_key: &VerificationKey,
        _category: HighRiskCategory,
        trace_id: &str,
    ) -> EnforcementResult {
        let point = EnforcementPoint::HighRiskOperation;

        // Check 1: attestation revocation.
        let attestation_revoked = self.chain.is_revoked(attestation_id);
        self.emit_audit(
            point,
            attestation_id,
            RevocationTargetType::Attestation,
            attestation_revoked,
            false,
            trace_id,
        );

        if attestation_revoked {
            self.record_denial(point, false);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Attestation,
                target_id: attestation_id.clone(),
                transitive: false,
                transitive_root: None,
                enforcement_point: point,
            });
        }

        // Check 2: principal key revocation (transitive).
        let key_id = key_id_from_verification_key(principal_key);
        let key_revoked = self.chain.is_revoked(&key_id);
        self.emit_audit(
            point,
            &key_id,
            RevocationTargetType::Key,
            key_revoked,
            true,
            trace_id,
        );

        if key_revoked {
            self.record_denial(point, true);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Attestation,
                target_id: attestation_id.clone(),
                transitive: true,
                transitive_root: Some(key_id),
                enforcement_point: point,
            });
        }

        self.record_cleared(point, 2);
        EnforcementResult::Cleared {
            enforcement_point: point,
            checks_performed: 2,
        }
    }

    // -------------------------------------------------------------------
    // Enforcement point 3: Extension activation
    // -------------------------------------------------------------------

    /// Check revocation status before activating an extension.
    ///
    /// Checks:
    /// 1. `is_revoked(extension_id)` — direct extension revocation.
    /// 2. `is_revoked(extension_signing_key_id)` — signing key revocation.
    ///
    /// Must be called *after* signature verification.
    pub fn check_extension_activation(
        &mut self,
        extension_id: &EngineObjectId,
        signing_key: &VerificationKey,
        trace_id: &str,
    ) -> EnforcementResult {
        let point = EnforcementPoint::ExtensionActivation;

        // Check 1: direct extension revocation.
        let ext_revoked = self.chain.is_revoked(extension_id);
        self.emit_audit(
            point,
            extension_id,
            RevocationTargetType::Extension,
            ext_revoked,
            false,
            trace_id,
        );

        if ext_revoked {
            self.record_denial(point, false);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Extension,
                target_id: extension_id.clone(),
                transitive: false,
                transitive_root: None,
                enforcement_point: point,
            });
        }

        // Check 2: signing key revocation.
        let key_id = key_id_from_verification_key(signing_key);
        let key_revoked = self.chain.is_revoked(&key_id);
        self.emit_audit(
            point,
            &key_id,
            RevocationTargetType::Key,
            key_revoked,
            true,
            trace_id,
        );

        if key_revoked {
            self.record_denial(point, true);
            return EnforcementResult::Denied(RevocationDenial {
                target_type: RevocationTargetType::Extension,
                target_id: extension_id.clone(),
                transitive: true,
                transitive_root: Some(key_id),
                enforcement_point: point,
            });
        }

        self.record_cleared(point, 2);
        EnforcementResult::Cleared {
            enforcement_point: point,
            checks_performed: 2,
        }
    }

    // -------------------------------------------------------------------
    // Batch enforcement
    // -------------------------------------------------------------------

    /// Check multiple token JTIs in batch. Returns the first denial found,
    /// or cleared if all pass.
    pub fn check_token_batch(
        &mut self,
        tokens: &[(EngineObjectId, VerificationKey)],
        trace_id: &str,
    ) -> EnforcementResult {
        for (jti, issuer_key) in tokens {
            let result = self.check_token_acceptance(jti, issuer_key, trace_id);
            if let EnforcementResult::Denied(_) = &result {
                return result;
            }
        }
        EnforcementResult::Cleared {
            enforcement_point: EnforcementPoint::TokenAcceptance,
            checks_performed: tokens.len() as u32 * 2,
        }
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    fn emit_audit(
        &mut self,
        point: EnforcementPoint,
        target_id: &EngineObjectId,
        target_type: RevocationTargetType,
        is_revoked: bool,
        transitive: bool,
        trace_id: &str,
    ) {
        self.audit_log.push(RevocationCheckEvent {
            enforcement_point: point,
            target_id: target_id.clone(),
            target_type,
            is_revoked,
            transitive,
            trace_id: trace_id.to_string(),
            checked_at: DeterministicTimestamp(self.current_tick),
        });
    }

    fn record_denial(&mut self, point: EnforcementPoint, transitive: bool) {
        let stats = self.stats.entry(point).or_default();
        stats.checks = stats.checks.saturating_add(1);
        stats.denied = stats.denied.saturating_add(1);
        if transitive {
            stats.transitive_denials = stats.transitive_denials.saturating_add(1);
        }
    }

    fn record_cleared(&mut self, point: EnforcementPoint, checks: u32) {
        let stats = self.stats.entry(point).or_default();
        stats.checks = stats.checks.saturating_add(1);
        stats.cleared = stats.cleared.saturating_add(1);
        // checks is the number of sub-checks within this enforcement call
        let _ = checks;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_token::PrincipalId;
    use crate::engine_object_id::{self, ObjectDomain};
    use crate::revocation_chain::{Revocation, RevocationReason, revocation_schema_id};
    use crate::signature_preimage::{
        SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, sign_preimage,
    };

    const TEST_ZONE: &str = "test-zone";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ])
        .unwrap()
    }

    fn revocation_key() -> SigningKey {
        SigningKey::from_bytes([
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
            0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
            0xBD, 0xBE, 0xBF, 0xC0,
        ])
        .unwrap()
    }

    fn make_revocation(
        target_type: RevocationTargetType,
        reason: RevocationReason,
        target_bytes: [u8; 32],
    ) -> Revocation {
        let sk = revocation_key();
        let principal = PrincipalId::from_verification_key(&sk.verification_key());
        let target_id = EngineObjectId(target_bytes);
        let revocation_id = engine_object_id::derive_id(
            ObjectDomain::Revocation,
            TEST_ZONE,
            &revocation_schema_id(),
            target_bytes.as_slice(),
        )
        .unwrap();

        let mut rev = Revocation {
            revocation_id,
            target_type,
            target_id,
            reason,
            issued_by: principal,
            issued_at: DeterministicTimestamp(1000),
            zone: TEST_ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        let preimage = rev.preimage_bytes();
        let sig = sign_preimage(&sk, &preimage).unwrap();
        rev.signature = sig;
        rev
    }

    fn make_enforcer() -> RevocationEnforcer {
        let chain = RevocationChain::new(TEST_ZONE);
        RevocationEnforcer::new(chain, 5000)
    }

    fn revoke_target(
        enforcer: &mut RevocationEnforcer,
        target_type: RevocationTargetType,
        target_bytes: [u8; 32],
    ) {
        let rev = make_revocation(target_type, RevocationReason::Compromised, target_bytes);
        let sk = test_signing_key();
        enforcer.chain_mut().append(rev, &sk, "t-revoke").unwrap();
    }

    // ---------------------------------------------------------------
    // Token acceptance — non-revoked
    // ---------------------------------------------------------------

    #[test]
    fn token_acceptance_cleared_for_valid_token() {
        let mut enforcer = make_enforcer();
        let token_jti = EngineObjectId([1; 32]);
        let issuer_key = VerificationKey::from_bytes([2; 32]).unwrap();

        let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-1");
        assert!(result.is_cleared());
    }

    #[test]
    fn token_acceptance_cleared_emits_two_audit_events() {
        let mut enforcer = make_enforcer();
        let token_jti = EngineObjectId([1; 32]);
        let issuer_key = VerificationKey::from_bytes([2; 32]).unwrap();

        enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-audit");
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 2);
        assert!(!events[0].is_revoked);
        assert!(!events[1].is_revoked);
    }

    // ---------------------------------------------------------------
    // Token acceptance — direct revocation
    // ---------------------------------------------------------------

    #[test]
    fn token_acceptance_denied_for_revoked_jti() {
        let mut enforcer = make_enforcer();
        let token_jti = EngineObjectId([10; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);

        let issuer_key = VerificationKey::from_bytes([2; 32]).unwrap();
        let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-revoked");

        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_type, RevocationTargetType::Token);
                assert_eq!(denial.target_id, token_jti);
                assert!(!denial.transitive);
                assert!(denial.transitive_root.is_none());
                assert_eq!(denial.enforcement_point, EnforcementPoint::TokenAcceptance);
            }
            _ => panic!("expected denial"),
        }
    }

    #[test]
    fn token_acceptance_denied_jti_emits_one_audit_event() {
        let mut enforcer = make_enforcer();
        let token_jti = EngineObjectId([10; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
        enforcer.drain_audit_log();

        let issuer_key = VerificationKey::from_bytes([2; 32]).unwrap();
        enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-denied");
        let events = enforcer.drain_audit_log();
        // Only one audit event: the direct token check (stops before issuer check)
        assert_eq!(events.len(), 1);
        assert!(events[0].is_revoked);
        assert!(!events[0].transitive);
    }

    // ---------------------------------------------------------------
    // Token acceptance — transitive issuer key revocation
    // ---------------------------------------------------------------

    #[test]
    fn token_acceptance_denied_for_revoked_issuer_key() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([20; 32]).unwrap();
        let issuer_key_id = key_id_from_verification_key(&issuer_key);

        // Revoke the issuer's key.
        revoke_target(
            &mut enforcer,
            RevocationTargetType::Key,
            *issuer_key_id.as_bytes(),
        );
        enforcer.drain_audit_log();

        let token_jti = EngineObjectId([30; 32]); // token itself not revoked
        let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-transitive");

        match result {
            EnforcementResult::Denied(denial) => {
                assert!(denial.transitive);
                assert_eq!(denial.transitive_root, Some(issuer_key_id));
                assert_eq!(denial.target_type, RevocationTargetType::Token);
            }
            _ => panic!("expected transitive denial"),
        }
    }

    #[test]
    fn transitive_denial_emits_two_audit_events() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([20; 32]).unwrap();
        let issuer_key_id = key_id_from_verification_key(&issuer_key);
        revoke_target(
            &mut enforcer,
            RevocationTargetType::Key,
            *issuer_key_id.as_bytes(),
        );
        enforcer.drain_audit_log();

        let token_jti = EngineObjectId([30; 32]);
        enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-trans-audit");
        let events = enforcer.drain_audit_log();
        // Two events: direct check (pass) + transitive check (fail)
        assert_eq!(events.len(), 2);
        assert!(!events[0].is_revoked); // direct token check passes
        assert!(events[1].is_revoked); // transitive key check fails
        assert!(events[1].transitive);
    }

    // ---------------------------------------------------------------
    // High-risk operation — non-revoked
    // ---------------------------------------------------------------

    #[test]
    fn high_risk_cleared_for_valid_attestation() {
        let mut enforcer = make_enforcer();
        let attestation_id = EngineObjectId([40; 32]);
        let principal_key = VerificationKey::from_bytes([41; 32]).unwrap();

        let result = enforcer.check_high_risk_operation(
            &attestation_id,
            &principal_key,
            HighRiskCategory::PolicyChange,
            "t-hr-ok",
        );
        assert!(result.is_cleared());
    }

    // ---------------------------------------------------------------
    // High-risk operation — attestation revoked
    // ---------------------------------------------------------------

    #[test]
    fn high_risk_denied_for_revoked_attestation() {
        let mut enforcer = make_enforcer();
        let attestation_id = EngineObjectId([50; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, [50; 32]);

        let principal_key = VerificationKey::from_bytes([51; 32]).unwrap();
        let result = enforcer.check_high_risk_operation(
            &attestation_id,
            &principal_key,
            HighRiskCategory::KeyOperation,
            "t-hr-denied",
        );

        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_type, RevocationTargetType::Attestation);
                assert_eq!(
                    denial.enforcement_point,
                    EnforcementPoint::HighRiskOperation
                );
                assert!(!denial.transitive);
            }
            _ => panic!("expected denial"),
        }
    }

    // ---------------------------------------------------------------
    // High-risk operation — principal key revoked (transitive)
    // ---------------------------------------------------------------

    #[test]
    fn high_risk_denied_for_revoked_principal_key() {
        let mut enforcer = make_enforcer();
        let principal_key = VerificationKey::from_bytes([60; 32]).unwrap();
        let key_id = key_id_from_verification_key(&principal_key);

        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

        let attestation_id = EngineObjectId([61; 32]); // attestation not directly revoked
        let result = enforcer.check_high_risk_operation(
            &attestation_id,
            &principal_key,
            HighRiskCategory::DataExport,
            "t-hr-trans",
        );

        match result {
            EnforcementResult::Denied(denial) => {
                assert!(denial.transitive);
                assert_eq!(denial.transitive_root, Some(key_id));
                assert_eq!(denial.target_type, RevocationTargetType::Attestation);
            }
            _ => panic!("expected transitive denial"),
        }
    }

    // ---------------------------------------------------------------
    // Extension activation — non-revoked
    // ---------------------------------------------------------------

    #[test]
    fn extension_activation_cleared_for_valid_extension() {
        let mut enforcer = make_enforcer();
        let ext_id = EngineObjectId([70; 32]);
        let signing_key = VerificationKey::from_bytes([71; 32]).unwrap();

        let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-ok");
        assert!(result.is_cleared());
    }

    // ---------------------------------------------------------------
    // Extension activation — direct revocation
    // ---------------------------------------------------------------

    #[test]
    fn extension_activation_denied_for_revoked_extension() {
        let mut enforcer = make_enforcer();
        let ext_id = EngineObjectId([80; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Extension, [80; 32]);

        let signing_key = VerificationKey::from_bytes([81; 32]).unwrap();
        let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-denied");

        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_type, RevocationTargetType::Extension);
                assert_eq!(denial.target_id, ext_id);
                assert!(!denial.transitive);
                assert_eq!(
                    denial.enforcement_point,
                    EnforcementPoint::ExtensionActivation
                );
            }
            _ => panic!("expected denial"),
        }
    }

    // ---------------------------------------------------------------
    // Extension activation — signing key revoked (transitive)
    // ---------------------------------------------------------------

    #[test]
    fn extension_activation_denied_for_revoked_signing_key() {
        let mut enforcer = make_enforcer();
        let signing_key = VerificationKey::from_bytes([90; 32]).unwrap();
        let key_id = key_id_from_verification_key(&signing_key);

        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

        let ext_id = EngineObjectId([91; 32]);
        let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-trans");

        match result {
            EnforcementResult::Denied(denial) => {
                assert!(denial.transitive);
                assert_eq!(denial.transitive_root, Some(key_id));
            }
            _ => panic!("expected transitive denial"),
        }
    }

    // ---------------------------------------------------------------
    // into_result conversion
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_result_into_result_cleared() {
        let result = EnforcementResult::Cleared {
            enforcement_point: EnforcementPoint::TokenAcceptance,
            checks_performed: 2,
        };
        assert!(result.into_result().is_ok());
    }

    #[test]
    fn enforcement_result_into_result_denied() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let result = EnforcementResult::Denied(denial.clone());
        let err = result.into_result().unwrap_err();
        assert_eq!(err, denial);
    }

    // ---------------------------------------------------------------
    // Audit events — all enforcement points emit
    // ---------------------------------------------------------------

    #[test]
    fn all_enforcement_points_emit_audit() {
        let mut enforcer = make_enforcer();

        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-a",
        );
        enforcer.check_high_risk_operation(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            HighRiskCategory::PolicyChange,
            "t-b",
        );
        enforcer.check_extension_activation(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-c",
        );

        let events = enforcer.drain_audit_log();
        // 2 checks per enforcement point = 6 events
        assert_eq!(events.len(), 6);

        let token_events: Vec<_> = events
            .iter()
            .filter(|e| e.enforcement_point == EnforcementPoint::TokenAcceptance)
            .collect();
        assert_eq!(token_events.len(), 2);

        let hr_events: Vec<_> = events
            .iter()
            .filter(|e| e.enforcement_point == EnforcementPoint::HighRiskOperation)
            .collect();
        assert_eq!(hr_events.len(), 2);

        let ext_events: Vec<_> = events
            .iter()
            .filter(|e| e.enforcement_point == EnforcementPoint::ExtensionActivation)
            .collect();
        assert_eq!(ext_events.len(), 2);
    }

    // ---------------------------------------------------------------
    // Statistics tracking
    // ---------------------------------------------------------------

    #[test]
    fn stats_track_cleared_and_denied() {
        let mut enforcer = make_enforcer();

        // 2 cleared token checks
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-s1",
        );
        enforcer.check_token_acceptance(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            "t-s2",
        );

        // 1 denied token check (direct)
        revoke_target(&mut enforcer, RevocationTargetType::Token, [5; 32]);
        enforcer.check_token_acceptance(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-s3",
        );

        let stats = enforcer.stats();
        let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
        assert_eq!(token_stats.checks, 3);
        assert_eq!(token_stats.cleared, 2);
        assert_eq!(token_stats.denied, 1);
        assert_eq!(token_stats.transitive_denials, 0);
    }

    #[test]
    fn stats_track_transitive_denials() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([20; 32]).unwrap();
        let key_id = key_id_from_verification_key(&issuer_key);

        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

        enforcer.check_token_acceptance(&EngineObjectId([21; 32]), &issuer_key, "t-ts");

        let stats = enforcer.stats();
        let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
        assert_eq!(token_stats.transitive_denials, 1);
    }

    // ---------------------------------------------------------------
    // Batch token check
    // ---------------------------------------------------------------

    #[test]
    fn batch_check_all_valid() {
        let mut enforcer = make_enforcer();
        let tokens = vec![
            (
                EngineObjectId([1; 32]),
                VerificationKey::from_bytes([2; 32]).unwrap(),
            ),
            (
                EngineObjectId([3; 32]),
                VerificationKey::from_bytes([4; 32]).unwrap(),
            ),
            (
                EngineObjectId([5; 32]),
                VerificationKey::from_bytes([6; 32]).unwrap(),
            ),
        ];

        let result = enforcer.check_token_batch(&tokens, "t-batch-ok");
        assert!(result.is_cleared());
        if let EnforcementResult::Cleared {
            checks_performed, ..
        } = result
        {
            assert_eq!(checks_performed, 6);
        }
    }

    #[test]
    fn batch_check_stops_at_first_denial() {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Token, [3; 32]);

        let tokens = vec![
            (
                EngineObjectId([1; 32]),
                VerificationKey::from_bytes([2; 32]).unwrap(),
            ),
            (
                EngineObjectId([3; 32]),
                VerificationKey::from_bytes([4; 32]).unwrap(),
            ), // revoked
            (
                EngineObjectId([5; 32]),
                VerificationKey::from_bytes([6; 32]).unwrap(),
            ),
        ];

        let result = enforcer.check_token_batch(&tokens, "t-batch-deny");
        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_id, EngineObjectId([3; 32]));
            }
            _ => panic!("expected denial"),
        }
    }

    // ---------------------------------------------------------------
    // key_id_from_verification_key determinism
    // ---------------------------------------------------------------

    #[test]
    fn key_id_derivation_is_deterministic() {
        let vk = VerificationKey::from_bytes([42; 32]).unwrap();
        let id1 = key_id_from_verification_key(&vk);
        let id2 = key_id_from_verification_key(&vk);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let vk1 = VerificationKey::from_bytes([1; 32]).unwrap();
        let vk2 = VerificationKey::from_bytes([2; 32]).unwrap();
        assert_ne!(
            key_id_from_verification_key(&vk1),
            key_id_from_verification_key(&vk2),
        );
    }

    // ---------------------------------------------------------------
    // Display implementations
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_point_display() {
        assert_eq!(
            EnforcementPoint::TokenAcceptance.to_string(),
            "token_acceptance"
        );
        assert_eq!(
            EnforcementPoint::HighRiskOperation.to_string(),
            "high_risk_operation"
        );
        assert_eq!(
            EnforcementPoint::ExtensionActivation.to_string(),
            "extension_activation"
        );
    }

    #[test]
    fn high_risk_category_display() {
        assert_eq!(HighRiskCategory::PolicyChange.to_string(), "policy_change");
        assert_eq!(HighRiskCategory::KeyOperation.to_string(), "key_operation");
        assert_eq!(HighRiskCategory::DataExport.to_string(), "data_export");
        assert_eq!(
            HighRiskCategory::CrossZoneAction.to_string(),
            "cross_zone_action"
        );
        assert_eq!(
            HighRiskCategory::ExtensionLifecycleChange.to_string(),
            "extension_lifecycle_change"
        );
    }

    #[test]
    fn revocation_denial_display_direct() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let display = denial.to_string();
        assert!(display.contains("directly revoked"));
        assert!(display.contains("token_acceptance"));
    }

    #[test]
    fn revocation_denial_display_transitive() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Extension,
            target_id: EngineObjectId([2; 32]),
            transitive: true,
            transitive_root: Some(EngineObjectId([3; 32])),
            enforcement_point: EnforcementPoint::ExtensionActivation,
        };
        let display = denial.to_string();
        assert!(display.contains("transitively revoked"));
        assert!(display.contains("extension_activation"));
    }

    // ---------------------------------------------------------------
    // Serialization round-trips
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_point_serialization() {
        let points = [
            EnforcementPoint::TokenAcceptance,
            EnforcementPoint::HighRiskOperation,
            EnforcementPoint::ExtensionActivation,
        ];
        for p in &points {
            let json = serde_json::to_string(p).unwrap();
            let restored: EnforcementPoint = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, restored);
        }
    }

    #[test]
    fn high_risk_category_serialization() {
        let cats = [
            HighRiskCategory::PolicyChange,
            HighRiskCategory::KeyOperation,
            HighRiskCategory::DataExport,
            HighRiskCategory::CrossZoneAction,
            HighRiskCategory::ExtensionLifecycleChange,
        ];
        for c in &cats {
            let json = serde_json::to_string(c).unwrap();
            let restored: HighRiskCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, restored);
        }
    }

    #[test]
    fn revocation_denial_serialization() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: true,
            transitive_root: Some(EngineObjectId([2; 32])),
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let json = serde_json::to_string(&denial).unwrap();
        let restored: RevocationDenial = serde_json::from_str(&json).unwrap();
        assert_eq!(denial, restored);
    }

    #[test]
    fn enforcement_result_serialization() {
        let cleared = EnforcementResult::Cleared {
            enforcement_point: EnforcementPoint::TokenAcceptance,
            checks_performed: 2,
        };
        let json = serde_json::to_string(&cleared).unwrap();
        let restored: EnforcementResult = serde_json::from_str(&json).unwrap();
        assert_eq!(cleared, restored);

        let denial = RevocationDenial {
            target_type: RevocationTargetType::Extension,
            target_id: EngineObjectId([3; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::ExtensionActivation,
        };
        let denied = EnforcementResult::Denied(denial);
        let json2 = serde_json::to_string(&denied).unwrap();
        let restored2: EnforcementResult = serde_json::from_str(&json2).unwrap();
        assert_eq!(denied, restored2);
    }

    #[test]
    fn check_event_serialization() {
        let event = RevocationCheckEvent {
            enforcement_point: EnforcementPoint::HighRiskOperation,
            target_id: EngineObjectId([5; 32]),
            target_type: RevocationTargetType::Attestation,
            is_revoked: true,
            transitive: false,
            trace_id: "t-ser".to_string(),
            checked_at: DeterministicTimestamp(5000),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: RevocationCheckEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // ---------------------------------------------------------------
    // EnforcementStats serialization
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_stats_serialization() {
        let stats = EnforcementStats {
            checks: 10,
            cleared: 8,
            denied: 2,
            transitive_denials: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let restored: EnforcementStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, restored);
    }

    // ---------------------------------------------------------------
    // Multiple revocations in same chain
    // ---------------------------------------------------------------

    #[test]
    fn multiple_revocations_all_enforced() {
        let mut enforcer = make_enforcer();

        // Revoke a token, an attestation, and an extension
        revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, [20; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Extension, [30; 32]);

        // Token check
        let r1 = enforcer.check_token_acceptance(
            &EngineObjectId([10; 32]),
            &VerificationKey::from_bytes([11; 32]).unwrap(),
            "t-multi-1",
        );
        assert!(matches!(r1, EnforcementResult::Denied(_)));

        // High-risk check
        let r2 = enforcer.check_high_risk_operation(
            &EngineObjectId([20; 32]),
            &VerificationKey::from_bytes([21; 32]).unwrap(),
            HighRiskCategory::PolicyChange,
            "t-multi-2",
        );
        assert!(matches!(r2, EnforcementResult::Denied(_)));

        // Extension check
        let r3 = enforcer.check_extension_activation(
            &EngineObjectId([30; 32]),
            &VerificationKey::from_bytes([31; 32]).unwrap(),
            "t-multi-3",
        );
        assert!(matches!(r3, EnforcementResult::Denied(_)));
    }

    // ---------------------------------------------------------------
    // Check ordering: same token, revoked then unrevoked via different chain
    // ---------------------------------------------------------------

    #[test]
    fn non_revoked_token_always_clears() {
        let mut enforcer = make_enforcer();

        // Revoke something else, not our token
        revoke_target(&mut enforcer, RevocationTargetType::Token, [99; 32]);

        let token_jti = EngineObjectId([1; 32]);
        let issuer_key = VerificationKey::from_bytes([2; 32]).unwrap();

        let result = enforcer.check_token_acceptance(&token_jti, &issuer_key, "t-clear");
        assert!(result.is_cleared());
    }

    // ---------------------------------------------------------------
    // Tick updates affect audit timestamps
    // ---------------------------------------------------------------

    #[test]
    fn set_tick_updates_audit_timestamps() {
        let mut enforcer = make_enforcer();

        enforcer.set_tick(1000);
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-tick-1",
        );

        enforcer.set_tick(2000);
        enforcer.check_token_acceptance(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            "t-tick-2",
        );

        let events = enforcer.drain_audit_log();
        assert_eq!(events[0].checked_at, DeterministicTimestamp(1000));
        assert_eq!(events[1].checked_at, DeterministicTimestamp(1000));
        assert_eq!(events[2].checked_at, DeterministicTimestamp(2000));
        assert_eq!(events[3].checked_at, DeterministicTimestamp(2000));
    }

    // ---------------------------------------------------------------
    // Determinism: same inputs produce same results
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_is_deterministic() {
        let run_scenario = || {
            let mut enforcer = make_enforcer();
            revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
            enforcer.drain_audit_log();

            let r1 = enforcer.check_token_acceptance(
                &EngineObjectId([10; 32]),
                &VerificationKey::from_bytes([11; 32]).unwrap(),
                "t-det",
            );
            let r2 = enforcer.check_token_acceptance(
                &EngineObjectId([20; 32]),
                &VerificationKey::from_bytes([21; 32]).unwrap(),
                "t-det",
            );
            let events = enforcer.drain_audit_log();
            (r1, r2, events)
        };

        let (r1a, r2a, events_a) = run_scenario();
        let (r1b, r2b, events_b) = run_scenario();

        assert_eq!(r1a, r1b);
        assert_eq!(r2a, r2b);
        assert_eq!(events_a, events_b);
    }

    // ---------------------------------------------------------------
    // All high-risk categories accepted
    // ---------------------------------------------------------------

    #[test]
    fn all_high_risk_categories_accepted() {
        let mut enforcer = make_enforcer();
        let categories = [
            HighRiskCategory::PolicyChange,
            HighRiskCategory::KeyOperation,
            HighRiskCategory::DataExport,
            HighRiskCategory::CrossZoneAction,
            HighRiskCategory::ExtensionLifecycleChange,
        ];

        for (i, cat) in categories.iter().enumerate() {
            let result = enforcer.check_high_risk_operation(
                &EngineObjectId([(i as u8) + 100; 32]),
                &VerificationKey::from_bytes([(i as u8) + 200; 32]).unwrap(),
                *cat,
                &format!("t-cat-{i}"),
            );
            assert!(result.is_cleared(), "category {cat} should clear");
        }
    }

    // ---------------------------------------------------------------
    // Chain access
    // ---------------------------------------------------------------

    #[test]
    fn chain_accessor_returns_underlying_chain() {
        let enforcer = make_enforcer();
        assert!(enforcer.chain().is_empty());
        assert_eq!(enforcer.chain().zone(), TEST_ZONE);
    }

    #[test]
    fn chain_mut_allows_appending() {
        let mut enforcer = make_enforcer();
        let rev = make_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [1; 32],
        );
        let sk = test_signing_key();
        enforcer.chain_mut().append(rev, &sk, "t-mut").unwrap();
        assert_eq!(enforcer.chain().len(), 1);
    }

    // ---------------------------------------------------------------
    // Empty batch
    // ---------------------------------------------------------------

    #[test]
    fn batch_check_empty_clears() {
        let mut enforcer = make_enforcer();
        let result = enforcer.check_token_batch(&[], "t-empty-batch");
        assert!(result.is_cleared());
        if let EnforcementResult::Cleared {
            checks_performed, ..
        } = result
        {
            assert_eq!(checks_performed, 0);
        }
    }

    // ---------------------------------------------------------------
    // Stress: many tokens, one key revoked
    // ---------------------------------------------------------------

    #[test]
    fn many_tokens_one_key_revoked_all_denied() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([42; 32]).unwrap();
        let key_id = key_id_from_verification_key(&issuer_key);

        // Revoke the issuer key
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());

        // All tokens from this issuer should be transitively denied
        for i in 0..20u8 {
            let token_jti = EngineObjectId([i; 32]);
            let result =
                enforcer.check_token_acceptance(&token_jti, &issuer_key, &format!("t-many-{i}"));
            assert!(
                matches!(result, EnforcementResult::Denied(ref d) if d.transitive),
                "token {i} should be transitively denied"
            );
        }

        let stats = enforcer.stats();
        let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
        assert_eq!(token_stats.denied, 20);
        assert_eq!(token_stats.transitive_denials, 20);
    }

    // ---------------------------------------------------------------
    // Default for EnforcementStats
    // ---------------------------------------------------------------

    // -- Enrichment: Ord --

    #[test]
    fn enforcement_point_ordering() {
        assert!(EnforcementPoint::TokenAcceptance < EnforcementPoint::HighRiskOperation);
        assert!(EnforcementPoint::HighRiskOperation < EnforcementPoint::ExtensionActivation);
    }

    #[test]
    fn high_risk_category_ordering() {
        assert!(HighRiskCategory::PolicyChange < HighRiskCategory::KeyOperation);
        assert!(HighRiskCategory::KeyOperation < HighRiskCategory::DataExport);
        assert!(HighRiskCategory::DataExport < HighRiskCategory::CrossZoneAction);
        assert!(HighRiskCategory::CrossZoneAction < HighRiskCategory::ExtensionLifecycleChange);
    }

    #[test]
    fn enforcement_stats_default() {
        let stats = EnforcementStats::default();
        assert_eq!(stats.checks, 0);
        assert_eq!(stats.cleared, 0);
        assert_eq!(stats.denied, 0);
        assert_eq!(stats.transitive_denials, 0);
    }

    // ---------------------------------------------------------------
    // Enrichment: high-risk audit event counts
    // ---------------------------------------------------------------

    #[test]
    fn high_risk_denied_attestation_emits_one_audit_event() {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, [50; 32]);
        enforcer.drain_audit_log();

        enforcer.check_high_risk_operation(
            &EngineObjectId([50; 32]),
            &VerificationKey::from_bytes([51; 32]).unwrap(),
            HighRiskCategory::KeyOperation,
            "t-hr-audit-1",
        );
        let events = enforcer.drain_audit_log();
        // Direct attestation revocation short-circuits before key check
        assert_eq!(events.len(), 1);
        assert!(events[0].is_revoked);
        assert!(!events[0].transitive);
        assert_eq!(events[0].target_type, RevocationTargetType::Attestation);
    }

    #[test]
    fn high_risk_transitive_emits_two_audit_events() {
        let mut enforcer = make_enforcer();
        let principal_key = VerificationKey::from_bytes([60; 32]).unwrap();
        let key_id = key_id_from_verification_key(&principal_key);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        enforcer.check_high_risk_operation(
            &EngineObjectId([61; 32]),
            &principal_key,
            HighRiskCategory::DataExport,
            "t-hr-audit-2",
        );
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 2);
        assert!(!events[0].is_revoked); // attestation check passes
        assert!(events[1].is_revoked); // key check fails
        assert!(events[1].transitive);
    }

    // ---------------------------------------------------------------
    // Enrichment: extension audit event counts
    // ---------------------------------------------------------------

    #[test]
    fn extension_denied_emits_one_audit_event() {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Extension, [80; 32]);
        enforcer.drain_audit_log();

        enforcer.check_extension_activation(
            &EngineObjectId([80; 32]),
            &VerificationKey::from_bytes([81; 32]).unwrap(),
            "t-ext-audit-1",
        );
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_revoked);
        assert!(!events[0].transitive);
        assert_eq!(events[0].target_type, RevocationTargetType::Extension);
    }

    #[test]
    fn extension_transitive_emits_two_audit_events() {
        let mut enforcer = make_enforcer();
        let signing_key = VerificationKey::from_bytes([90; 32]).unwrap();
        let key_id = key_id_from_verification_key(&signing_key);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        enforcer.check_extension_activation(
            &EngineObjectId([91; 32]),
            &signing_key,
            "t-ext-audit-2",
        );
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 2);
        assert!(!events[0].is_revoked); // extension check passes
        assert!(events[1].is_revoked); // key check fails
        assert!(events[1].transitive);
    }

    // ---------------------------------------------------------------
    // Enrichment: batch edge cases
    // ---------------------------------------------------------------

    #[test]
    fn batch_single_token_cleared() {
        let mut enforcer = make_enforcer();
        let tokens = vec![(
            EngineObjectId([1; 32]),
            VerificationKey::from_bytes([2; 32]).unwrap(),
        )];
        let result = enforcer.check_token_batch(&tokens, "t-batch-single");
        assert!(result.is_cleared());
        if let EnforcementResult::Cleared {
            checks_performed, ..
        } = result
        {
            assert_eq!(checks_performed, 2);
        }
    }

    #[test]
    fn batch_first_token_revoked_stops_immediately() {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Token, [1; 32]);
        enforcer.drain_audit_log();

        let tokens = vec![
            (
                EngineObjectId([1; 32]),
                VerificationKey::from_bytes([2; 32]).unwrap(),
            ), // revoked
            (
                EngineObjectId([3; 32]),
                VerificationKey::from_bytes([4; 32]).unwrap(),
            ),
        ];

        let result = enforcer.check_token_batch(&tokens, "t-batch-first");
        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_id, EngineObjectId([1; 32]));
                assert!(!denial.transitive);
            }
            _ => panic!("expected denial on first token"),
        }
        // Only 1 audit event for the direct token check (short-circuits)
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn batch_last_token_revoked() {
        let mut enforcer = make_enforcer();
        revoke_target(&mut enforcer, RevocationTargetType::Token, [5; 32]);
        enforcer.drain_audit_log();

        let tokens = vec![
            (
                EngineObjectId([1; 32]),
                VerificationKey::from_bytes([2; 32]).unwrap(),
            ),
            (
                EngineObjectId([3; 32]),
                VerificationKey::from_bytes([4; 32]).unwrap(),
            ),
            (
                EngineObjectId([5; 32]),
                VerificationKey::from_bytes([6; 32]).unwrap(),
            ), // revoked
        ];

        let result = enforcer.check_token_batch(&tokens, "t-batch-last");
        match result {
            EnforcementResult::Denied(denial) => {
                assert_eq!(denial.target_id, EngineObjectId([5; 32]));
            }
            _ => panic!("expected denial on last token"),
        }
        // 2 events per cleared token (2 tokens cleared) + 1 for the revoked token = 5
        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn batch_transitive_key_denial() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([42; 32]).unwrap();
        let key_id = key_id_from_verification_key(&issuer_key);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        let tokens = vec![
            (EngineObjectId([1; 32]), issuer_key.clone()),
            (EngineObjectId([2; 32]), issuer_key),
        ];

        let result = enforcer.check_token_batch(&tokens, "t-batch-trans");
        match result {
            EnforcementResult::Denied(denial) => {
                assert!(denial.transitive);
                assert_eq!(denial.transitive_root, Some(key_id));
                assert_eq!(denial.target_id, EngineObjectId([1; 32]));
            }
            _ => panic!("expected transitive denial in batch"),
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: drain/log edge cases
    // ---------------------------------------------------------------

    #[test]
    fn drain_audit_log_returns_empty_on_second_call() {
        let mut enforcer = make_enforcer();
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-drain",
        );
        let first = enforcer.drain_audit_log();
        assert_eq!(first.len(), 2);
        let second = enforcer.drain_audit_log();
        assert!(second.is_empty());
    }

    #[test]
    fn audit_log_ordering_matches_call_order() {
        let mut enforcer = make_enforcer();
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "trace-A",
        );
        enforcer.check_high_risk_operation(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            HighRiskCategory::PolicyChange,
            "trace-B",
        );

        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].trace_id, "trace-A");
        assert_eq!(events[1].trace_id, "trace-A");
        assert_eq!(events[2].trace_id, "trace-B");
        assert_eq!(events[3].trace_id, "trace-B");
    }

    #[test]
    fn trace_id_preserved_in_audit_events() {
        let mut enforcer = make_enforcer();
        enforcer.check_extension_activation(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "unique-trace-xyz",
        );
        let events = enforcer.drain_audit_log();
        for ev in &events {
            assert_eq!(ev.trace_id, "unique-trace-xyz");
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: enforcement result is_cleared / into_result
    // ---------------------------------------------------------------

    #[test]
    fn enforcement_result_is_cleared_returns_false_for_denied() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let result = EnforcementResult::Denied(denial);
        assert!(!result.is_cleared());
    }

    // ---------------------------------------------------------------
    // Enrichment: RevocationDenial as Error trait
    // ---------------------------------------------------------------

    #[test]
    fn revocation_denial_implements_error_trait() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([1; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let err: &dyn std::error::Error = &denial;
        // Error::source defaults to None
        assert!(err.source().is_none());
        // to_string should work via Display
        let msg = err.to_string();
        assert!(msg.contains("directly revoked"));
    }

    // ---------------------------------------------------------------
    // Enrichment: stats across multiple enforcement points
    // ---------------------------------------------------------------

    #[test]
    fn stats_across_all_enforcement_points() {
        let mut enforcer = make_enforcer();

        // Token acceptance: 1 cleared
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-multi-stats-1",
        );

        // High-risk: 1 cleared
        enforcer.check_high_risk_operation(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            HighRiskCategory::PolicyChange,
            "t-multi-stats-2",
        );

        // Extension: 1 cleared
        enforcer.check_extension_activation(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-multi-stats-3",
        );

        let stats = enforcer.stats();
        assert_eq!(stats.len(), 3);
        for s in stats.values() {
            assert_eq!(s.checks, 1);
            assert_eq!(s.cleared, 1);
            assert_eq!(s.denied, 0);
        }
    }

    #[test]
    fn stats_empty_before_any_checks() {
        let enforcer = make_enforcer();
        assert!(enforcer.stats().is_empty());
    }

    // ---------------------------------------------------------------
    // Enrichment: set_tick progression
    // ---------------------------------------------------------------

    #[test]
    fn set_tick_progression_reflected_in_audit() {
        let mut enforcer = make_enforcer();

        enforcer.set_tick(100);
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-tick-a",
        );

        enforcer.set_tick(200);
        enforcer.check_token_acceptance(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            "t-tick-b",
        );

        enforcer.set_tick(300);
        enforcer.check_token_acceptance(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-tick-c",
        );

        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 6);
        assert_eq!(events[0].checked_at, DeterministicTimestamp(100));
        assert_eq!(events[1].checked_at, DeterministicTimestamp(100));
        assert_eq!(events[2].checked_at, DeterministicTimestamp(200));
        assert_eq!(events[3].checked_at, DeterministicTimestamp(200));
        assert_eq!(events[4].checked_at, DeterministicTimestamp(300));
        assert_eq!(events[5].checked_at, DeterministicTimestamp(300));
    }

    // ---------------------------------------------------------------
    // Enrichment: direct beats transitive (both revoked)
    // ---------------------------------------------------------------

    #[test]
    fn direct_denial_takes_precedence_when_both_token_and_key_revoked() {
        let mut enforcer = make_enforcer();
        let issuer_key = VerificationKey::from_bytes([20; 32]).unwrap();
        let key_id = key_id_from_verification_key(&issuer_key);

        // Revoke both the token and its issuer key
        revoke_target(&mut enforcer, RevocationTargetType::Token, [10; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        let result =
            enforcer.check_token_acceptance(&EngineObjectId([10; 32]), &issuer_key, "t-both");
        match result {
            EnforcementResult::Denied(denial) => {
                // Direct token denial takes precedence (checked first)
                assert!(!denial.transitive);
                assert!(denial.transitive_root.is_none());
                assert_eq!(denial.target_type, RevocationTargetType::Token);
            }
            _ => panic!("expected direct denial"),
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: Cleared checks_performed values
    // ---------------------------------------------------------------

    #[test]
    fn cleared_checks_performed_is_two_for_each_enforcement_point() {
        let mut enforcer = make_enforcer();

        let r1 = enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-cp-1",
        );
        let r2 = enforcer.check_high_risk_operation(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            HighRiskCategory::PolicyChange,
            "t-cp-2",
        );
        let r3 = enforcer.check_extension_activation(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-cp-3",
        );

        for (r, point) in [
            (r1, EnforcementPoint::TokenAcceptance),
            (r2, EnforcementPoint::HighRiskOperation),
            (r3, EnforcementPoint::ExtensionActivation),
        ] {
            if let EnforcementResult::Cleared {
                enforcement_point,
                checks_performed,
            } = r
            {
                assert_eq!(enforcement_point, point);
                assert_eq!(checks_performed, 2);
            } else {
                panic!("expected cleared");
            }
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: RevocationDenial Display for Attestation type
    // ---------------------------------------------------------------

    #[test]
    fn revocation_denial_display_attestation_type() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Attestation,
            target_id: EngineObjectId([44; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::HighRiskOperation,
        };
        let display = denial.to_string();
        assert!(display.contains("directly revoked"));
        assert!(display.contains("high_risk_operation"));
    }

    // ---------------------------------------------------------------
    // Enrichment: RevocationTargetType serde round-trip
    // ---------------------------------------------------------------

    #[test]
    fn revocation_target_type_serialization() {
        let types = [
            RevocationTargetType::Token,
            RevocationTargetType::Key,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let restored: RevocationTargetType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, restored);
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: Clone/Eq trait coverage
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_enforcement_point_clone_eq() {
        let a = EnforcementPoint::TokenAcceptance;
        let b = a;
        assert_eq!(a, b);
        let c = EnforcementPoint::HighRiskOperation;
        assert_ne!(a, c);
    }

    #[test]
    fn enrichment_high_risk_category_clone_eq() {
        let a = HighRiskCategory::DataExport;
        let b = a;
        assert_eq!(a, b);
        let c = HighRiskCategory::CrossZoneAction;
        assert_ne!(a, c);
    }

    #[test]
    fn enrichment_revocation_denial_clone_eq() {
        let a = RevocationDenial {
            target_type: RevocationTargetType::Key,
            target_id: EngineObjectId([7; 32]),
            transitive: true,
            transitive_root: Some(EngineObjectId([8; 32])),
            enforcement_point: EnforcementPoint::HighRiskOperation,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_enforcement_stats_clone_eq() {
        let a = EnforcementStats {
            checks: 5,
            cleared: 3,
            denied: 2,
            transitive_denials: 1,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ---------------------------------------------------------------
    // Enrichment: Hash trait coverage
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_enforcement_point_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(EnforcementPoint::TokenAcceptance);
        set.insert(EnforcementPoint::HighRiskOperation);
        set.insert(EnforcementPoint::ExtensionActivation);
        set.insert(EnforcementPoint::TokenAcceptance); // duplicate
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn enrichment_high_risk_category_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for cat in [
            HighRiskCategory::PolicyChange,
            HighRiskCategory::KeyOperation,
            HighRiskCategory::DataExport,
            HighRiskCategory::CrossZoneAction,
            HighRiskCategory::ExtensionLifecycleChange,
        ] {
            set.insert(cat);
        }
        assert_eq!(set.len(), 5);
    }

    // ---------------------------------------------------------------
    // Enrichment: JSON field presence checks
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_revocation_denial_json_field_names() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Extension,
            target_id: EngineObjectId([9; 32]),
            transitive: true,
            transitive_root: Some(EngineObjectId([10; 32])),
            enforcement_point: EnforcementPoint::ExtensionActivation,
        };
        let json = serde_json::to_string(&denial).unwrap();
        assert!(json.contains("\"target_type\""));
        assert!(json.contains("\"target_id\""));
        assert!(json.contains("\"transitive\""));
        assert!(json.contains("\"transitive_root\""));
        assert!(json.contains("\"enforcement_point\""));
    }

    #[test]
    fn enrichment_revocation_check_event_json_field_names() {
        let event = RevocationCheckEvent {
            enforcement_point: EnforcementPoint::TokenAcceptance,
            target_id: EngineObjectId([11; 32]),
            target_type: RevocationTargetType::Token,
            is_revoked: false,
            transitive: false,
            trace_id: "trace-field-check".to_string(),
            checked_at: DeterministicTimestamp(9999),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"enforcement_point\""));
        assert!(json.contains("\"target_id\""));
        assert!(json.contains("\"target_type\""));
        assert!(json.contains("\"is_revoked\""));
        assert!(json.contains("\"transitive\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"checked_at\""));
        assert!(json.contains("trace-field-check"));
    }

    #[test]
    fn enrichment_enforcement_stats_json_field_names() {
        let stats = EnforcementStats {
            checks: 42,
            cleared: 30,
            denied: 12,
            transitive_denials: 5,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"checks\":42"));
        assert!(json.contains("\"cleared\":30"));
        assert!(json.contains("\"denied\":12"));
        assert!(json.contains("\"transitive_denials\":5"));
    }

    // ---------------------------------------------------------------
    // Enrichment: Display format edge cases
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_revocation_denial_display_transitive_without_root() {
        // Transitive flag set but transitive_root is None => shows "unknown"
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Key,
            target_id: EngineObjectId([12; 32]),
            transitive: true,
            transitive_root: None,
            enforcement_point: EnforcementPoint::HighRiskOperation,
        };
        let display = denial.to_string();
        assert!(display.contains("transitively revoked via unknown"));
        assert!(display.contains("high_risk_operation"));
    }

    #[test]
    fn enrichment_revocation_denial_display_extension_direct() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Extension,
            target_id: EngineObjectId([13; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::ExtensionActivation,
        };
        let display = denial.to_string();
        assert!(display.contains("directly revoked"));
        assert!(display.contains("extension_activation"));
        assert!(display.contains("extension"));
    }

    // ---------------------------------------------------------------
    // Enrichment: RevocationDenial serde with null transitive_root
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_revocation_denial_serde_null_transitive_root() {
        let denial = RevocationDenial {
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([14; 32]),
            transitive: false,
            transitive_root: None,
            enforcement_point: EnforcementPoint::TokenAcceptance,
        };
        let json = serde_json::to_string(&denial).unwrap();
        assert!(json.contains("\"transitive_root\":null"));
        let restored: RevocationDenial = serde_json::from_str(&json).unwrap();
        assert_eq!(denial, restored);
        assert!(restored.transitive_root.is_none());
    }

    // ---------------------------------------------------------------
    // Enrichment: EnforcementResult serde with all variants
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_enforcement_result_cleared_all_points_serde() {
        for point in [
            EnforcementPoint::TokenAcceptance,
            EnforcementPoint::HighRiskOperation,
            EnforcementPoint::ExtensionActivation,
        ] {
            let result = EnforcementResult::Cleared {
                enforcement_point: point,
                checks_performed: 2,
            };
            let json = serde_json::to_string(&result).unwrap();
            let restored: EnforcementResult = serde_json::from_str(&json).unwrap();
            assert_eq!(result, restored);
            assert!(restored.is_cleared());
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: key_id_from_verification_key edge cases
    // ---------------------------------------------------------------

    #[test]
    #[ignore = "API drift: VerificationKey::from_bytes([0; 32]) now returns Err (all-zero rejected)"]
    fn enrichment_key_id_from_all_zeros() {
        unimplemented!("all-zero VerificationKey construction is now rejected");
    }

    #[test]
    #[ignore = "API drift: VerificationKey::from_bytes([0xFF; 32]) is not a valid Ed25519 point"]
    fn enrichment_key_id_from_all_ones() {
        unimplemented!("needs rewrite against valid Ed25519 byte patterns");
    }

    // ---------------------------------------------------------------
    // Enrichment: high-risk both attestation and key revoked
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_high_risk_direct_beats_transitive_when_both_revoked() {
        let mut enforcer = make_enforcer();
        let principal_key = VerificationKey::from_bytes([60; 32]).unwrap();
        let key_id = key_id_from_verification_key(&principal_key);
        let attestation_id = EngineObjectId([50; 32]);

        // Revoke both attestation and key
        revoke_target(&mut enforcer, RevocationTargetType::Attestation, [50; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        let result = enforcer.check_high_risk_operation(
            &attestation_id,
            &principal_key,
            HighRiskCategory::KeyOperation,
            "t-hr-both",
        );
        match result {
            EnforcementResult::Denied(denial) => {
                // Direct attestation denial checked first, takes precedence
                assert!(!denial.transitive);
                assert!(denial.transitive_root.is_none());
                assert_eq!(denial.target_type, RevocationTargetType::Attestation);
            }
            _ => panic!("expected direct denial"),
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: extension both extension and key revoked
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_extension_direct_beats_transitive_when_both_revoked() {
        let mut enforcer = make_enforcer();
        let signing_key = VerificationKey::from_bytes([90; 32]).unwrap();
        let key_id = key_id_from_verification_key(&signing_key);
        let ext_id = EngineObjectId([80; 32]);

        // Revoke both extension and signing key
        revoke_target(&mut enforcer, RevocationTargetType::Extension, [80; 32]);
        revoke_target(&mut enforcer, RevocationTargetType::Key, *key_id.as_bytes());
        enforcer.drain_audit_log();

        let result = enforcer.check_extension_activation(&ext_id, &signing_key, "t-ext-both");
        match result {
            EnforcementResult::Denied(denial) => {
                assert!(!denial.transitive);
                assert!(denial.transitive_root.is_none());
                assert_eq!(denial.target_type, RevocationTargetType::Extension);
            }
            _ => panic!("expected direct denial"),
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: stats accumulation across many operations
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_stats_accumulate_across_many_operations() {
        let mut enforcer = make_enforcer();

        // 5 cleared token checks
        for i in 0..5u8 {
            enforcer.check_token_acceptance(
                &EngineObjectId([i + 100; 32]),
                &VerificationKey::from_bytes([i + 200; 32]).unwrap(),
                &format!("t-acc-{i}"),
            );
        }

        // 3 denied token checks
        for i in 0..3u8 {
            let target = [i + 150; 32];
            revoke_target(&mut enforcer, RevocationTargetType::Token, target);
            enforcer.check_token_acceptance(
                &EngineObjectId(target),
                &VerificationKey::from_bytes([i + 210; 32]).unwrap(),
                &format!("t-deny-{i}"),
            );
        }

        let stats = enforcer.stats();
        let token_stats = &stats[&EnforcementPoint::TokenAcceptance];
        assert_eq!(token_stats.checks, 8);
        assert_eq!(token_stats.cleared, 5);
        assert_eq!(token_stats.denied, 3);
        assert_eq!(token_stats.transitive_denials, 0);
    }

    // ---------------------------------------------------------------
    // Enrichment: audit events carry correct target_type per point
    // ---------------------------------------------------------------

    #[test]
    fn enrichment_audit_events_carry_correct_target_types() {
        let mut enforcer = make_enforcer();

        // Token acceptance => target types Token + Key
        enforcer.check_token_acceptance(
            &EngineObjectId([1; 32]),
            &VerificationKey::from_bytes([2; 32]).unwrap(),
            "t-tt",
        );

        // High-risk => target types Attestation + Key
        enforcer.check_high_risk_operation(
            &EngineObjectId([3; 32]),
            &VerificationKey::from_bytes([4; 32]).unwrap(),
            HighRiskCategory::DataExport,
            "t-hr-tt",
        );

        // Extension => target types Extension + Key
        enforcer.check_extension_activation(
            &EngineObjectId([5; 32]),
            &VerificationKey::from_bytes([6; 32]).unwrap(),
            "t-ext-tt",
        );

        let events = enforcer.drain_audit_log();
        assert_eq!(events.len(), 6);

        // Token acceptance events
        assert_eq!(events[0].target_type, RevocationTargetType::Token);
        assert_eq!(events[1].target_type, RevocationTargetType::Key);

        // High-risk events
        assert_eq!(events[2].target_type, RevocationTargetType::Attestation);
        assert_eq!(events[3].target_type, RevocationTargetType::Key);

        // Extension events
        assert_eq!(events[4].target_type, RevocationTargetType::Extension);
        assert_eq!(events[5].target_type, RevocationTargetType::Key);
    }
}
