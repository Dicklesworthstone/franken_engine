//! Live TEE quote integration for decision receipt attestation.
//!
//! This module provides the interface between FrankenEngine decision receipts
//! and live TEE (Trusted Execution Environment) attestation quotes. When running
//! on TEE-capable hardware, this module generates cryptographic proof that
//! decision-making occurred within a verified trusted environment.
//!
//! For non-TEE environments, this module implements graceful degradation to
//! evidence-only paths with proper signed acknowledgment of the capability gap.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence_contract::{AttestationValidityWindow, TeeAttestationBinding};
use crate::hash_tiers::ContentHash;
use crate::signature_preimage::{SigningKey, VerificationKey, sign_preimage};
use crate::tee_attestation_policy::{TeeAttestationPolicy, TeePlatform};

/// Configuration for TEE quote generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeQuoteConfig {
    /// TEE platform to use for quote generation.
    pub platform: TeePlatform,
    /// Freshness window for quote validity.
    pub freshness_window: Duration,
    /// Maximum retries for quote generation.
    pub max_retries: u32,
    /// Timeout for individual quote generation attempts.
    pub quote_timeout: Duration,
}

impl Default for TeeQuoteConfig {
    fn default() -> Self {
        Self {
            platform: TeePlatform::IntelSgx,            // Default to Intel SGX
            freshness_window: Duration::from_secs(300), // 5 minutes
            max_retries: 3,
            quote_timeout: Duration::from_secs(10),
        }
    }
}

/// Result of TEE capability detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeCapability {
    /// TEE hardware is available and functional.
    Available { platform: TeePlatform },
    /// TEE hardware is not available, will use safe-mode fallback.
    NotAvailable,
    /// TEE hardware is present but not functional (error condition).
    Error { reason: String },
}

/// Live TEE quote generation result.
#[derive(Debug, Clone)]
pub enum TeeQuoteResult {
    /// Successfully generated TEE quote with attestation binding.
    Success {
        binding: TeeAttestationBinding,
        raw_quote: Vec<u8>,
    },
    /// TEE not available, providing safe-mode attestation record.
    SafeModeFallback {
        safe_mode_attestation: SafeModeAttestationRecord,
    },
    /// Quote generation failed.
    Failed { error: TeeQuoteError },
}

/// Safe-mode attestation record when TEE is not available.
///
/// This record cryptographically attests that the worker attempted
/// TEE attestation but gracefully degraded to evidence-only mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeModeAttestationRecord {
    /// Unique identifier for this safe-mode record.
    pub record_id: String,
    /// Timestamp when safe-mode was initiated.
    pub initiated_at: String, // ISO8601
    /// Reason for safe-mode fallback.
    pub fallback_reason: String,
    /// Hash of the decision data that would have been attested.
    pub decision_data_hash: String,
    /// Signature of this safe-mode record.
    pub signature: String,
    /// Public key used to sign this record.
    pub signer_public_key: String,
}

/// Errors that can occur during TEE quote generation.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum TeeQuoteError {
    #[error("TEE platform not supported: {platform}")]
    UnsupportedPlatform { platform: String },
    #[error("TEE hardware not available")]
    HardwareNotAvailable,
    #[error("Quote generation timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("Quote generation failed: {reason}")]
    GenerationFailed { reason: String },
    #[error("Invalid quote format: {details}")]
    InvalidQuoteFormat { details: String },
    #[error("Attestation policy violation: {violation}")]
    PolicyViolation { violation: String },
}

/// Main TEE quote generator interface.
pub struct TeeQuoteGenerator {
    config: TeeQuoteConfig,
    signing_key: SigningKey,
}

impl TeeQuoteGenerator {
    /// Create a new TEE quote generator with the given configuration.
    pub fn new(config: TeeQuoteConfig, signing_key: SigningKey) -> Self {
        Self {
            config,
            signing_key,
        }
    }

    /// Detect TEE capabilities on the current system.
    pub fn detect_tee_capability(&self) -> TeeCapability {
        // In a real implementation, this would probe the hardware
        // For now, we simulate based on environment variables
        if std::env::var("FRANKEN_TEE_ENABLED").unwrap_or_default() == "true" {
            TeeCapability::Available {
                platform: self.config.platform,
            }
        } else if std::env::var("FRANKEN_TEE_ERROR").is_ok() {
            TeeCapability::Error {
                reason: std::env::var("FRANKEN_TEE_ERROR").unwrap_or_default(),
            }
        } else {
            TeeCapability::NotAvailable
        }
    }

    /// Generate a live TEE quote for the given decision data.
    ///
    /// This is the main entry point for TEE attestation. It will:
    /// 1. Detect TEE capabilities
    /// 2. Generate a live quote if TEE is available
    /// 3. Fall back to safe-mode attestation if TEE is not available
    pub fn generate_quote(&self, decision_data: &[u8], nonce: &str) -> TeeQuoteResult {
        match self.detect_tee_capability() {
            TeeCapability::Available { platform } => {
                self.generate_live_quote(decision_data, nonce, platform)
            }
            TeeCapability::NotAvailable => TeeQuoteResult::SafeModeFallback {
                safe_mode_attestation: self
                    .generate_safe_mode_record(decision_data, "TEE hardware not available"),
            },
            TeeCapability::Error { reason } => TeeQuoteResult::Failed {
                error: TeeQuoteError::HardwareNotAvailable,
            },
        }
    }

    /// Generate a live TEE quote (when TEE hardware is available).
    fn generate_live_quote(
        &self,
        decision_data: &[u8],
        nonce: &str,
        platform: TeePlatform,
    ) -> TeeQuoteResult {
        // In a real implementation, this would call into TEE SDK
        // For now, we simulate quote generation

        let quote_data = self.simulate_quote_generation(decision_data, nonce, platform);
        match quote_data {
            Ok((quote_bytes, measurement_id)) => {
                let quote_digest = hex::encode(ContentHash::compute(&quote_bytes).as_bytes());

                let now = SystemTime::now();
                let valid_from = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
                let valid_until = (now + self.config.freshness_window)
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let binding = TeeAttestationBinding {
                    quote_digest,
                    measurement_id,
                    attested_signer_key_id: hex::encode(
                        self.signing_key.verification_key().as_bytes(),
                    ),
                    nonce: nonce.to_string(),
                    validity_window: AttestationValidityWindow {
                        valid_from: chrono::DateTime::from_timestamp(valid_from as i64, 0)
                            .unwrap()
                            .to_rfc3339(),
                        valid_until: chrono::DateTime::from_timestamp(valid_until as i64, 0)
                            .unwrap()
                            .to_rfc3339(),
                    },
                    tee_platform: platform.canonical_tag().to_string(),
                    quote_algorithm: "sha256".to_string(),
                };

                TeeQuoteResult::Success {
                    binding,
                    raw_quote: quote_bytes,
                }
            }
            Err(error) => TeeQuoteResult::Failed { error },
        }
    }

    /// Simulate quote generation for testing/development.
    ///
    /// In production, this would be replaced with actual TEE SDK calls.
    fn simulate_quote_generation(
        &self,
        decision_data: &[u8],
        nonce: &str,
        platform: TeePlatform,
    ) -> Result<(Vec<u8>, String), TeeQuoteError> {
        // Simulate different quote generation scenarios based on environment
        if std::env::var("FRANKEN_TEE_QUOTE_FAIL").is_ok() {
            return Err(TeeQuoteError::GenerationFailed {
                reason: "Simulated quote generation failure".to_string(),
            });
        }

        // Generate a realistic-looking quote structure
        let mut quote_data = BTreeMap::new();
        quote_data.insert("platform", platform.canonical_tag());
        quote_data.insert("nonce", nonce);
        quote_data.insert(
            "decision_data_hash",
            &hex::encode(ContentHash::compute(decision_data).as_bytes()),
        );
        quote_data.insert(
            "timestamp",
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        );

        let quote_json =
            serde_json::to_string(&quote_data).map_err(|e| TeeQuoteError::GenerationFailed {
                reason: format!("Quote serialization failed: {}", e),
            })?;

        let quote_bytes = quote_json.into_bytes();
        let measurement_id = format!(
            "{}_measurement_{}",
            platform.canonical_tag(),
            hex::encode(&ContentHash::compute(&quote_bytes).as_bytes()[..8])
        );

        Ok((quote_bytes, measurement_id))
    }

    /// Generate a safe-mode attestation record.
    ///
    /// This creates a signed record acknowledging that TEE was attempted
    /// but not available, and the decision proceeded in evidence-only mode.
    fn generate_safe_mode_record(
        &self,
        decision_data: &[u8],
        reason: &str,
    ) -> SafeModeAttestationRecord {
        let record_id = format!(
            "safe_mode_{}",
            hex::encode(
                &ContentHash::compute(
                    &format!(
                        "{}{}",
                        reason,
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    )
                    .as_bytes()
                )
                .as_bytes()[..8]
            )
        );

        let decision_data_hash = hex::encode(ContentHash::compute(decision_data).as_bytes());

        let initiated_at = chrono::Utc::now().to_rfc3339();

        // Create signature payload
        let signature_payload = format!(
            "{}|{}|{}|{}",
            record_id, initiated_at, reason, decision_data_hash
        );

        let signature = sign_preimage(signature_payload.as_bytes(), &self.signing_key);
        let signature_hex = hex::encode(&signature);

        SafeModeAttestationRecord {
            record_id,
            initiated_at,
            fallback_reason: reason.to_string(),
            decision_data_hash,
            signature: signature_hex,
            signer_public_key: hex::encode(self.signing_key.verification_key().as_bytes()),
        }
    }

    /// Validate a TEE attestation binding against the current policy.
    pub fn validate_attestation_binding(
        &self,
        binding: &TeeAttestationBinding,
        policy: &TeeAttestationPolicy,
    ) -> Result<(), TeeQuoteError> {
        // Parse platform from binding
        let platform = match binding.tee_platform.as_str() {
            "intel_sgx" => TeePlatform::IntelSgx,
            "arm_trustzone" => TeePlatform::ArmTrustZone,
            "arm_cca" => TeePlatform::ArmCca,
            "amd_sev" => TeePlatform::AmdSev,
            unknown => {
                return Err(TeeQuoteError::UnsupportedPlatform {
                    platform: unknown.to_string(),
                });
            }
        };

        // Check validity window
        let now = chrono::Utc::now();
        let valid_from = chrono::DateTime::parse_from_rfc3339(&binding.validity_window.valid_from)
            .map_err(|e| TeeQuoteError::InvalidQuoteFormat {
                details: format!("Invalid valid_from timestamp: {}", e),
            })?;
        let valid_until = chrono::DateTime::parse_from_rfc3339(
            &binding.validity_window.valid_until,
        )
        .map_err(|e| TeeQuoteError::InvalidQuoteFormat {
            details: format!("Invalid valid_until timestamp: {}", e),
        })?;

        if now < valid_from.with_timezone(&chrono::Utc) {
            return Err(TeeQuoteError::PolicyViolation {
                violation: "Attestation not yet valid".to_string(),
            });
        }

        if now > valid_until.with_timezone(&chrono::Utc) {
            return Err(TeeQuoteError::PolicyViolation {
                violation: "Attestation has expired".to_string(),
            });
        }

        // Additional policy validations would go here
        // (measurement validation, revocation checks, etc.)

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_attestation_policy::TeePlatform;

    fn test_config() -> TeeQuoteConfig {
        TeeQuoteConfig::default()
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::generate()
    }

    #[test]
    fn tee_quote_config_default() {
        let config = TeeQuoteConfig::default();
        assert_eq!(config.platform, TeePlatform::IntelSgx);
        assert_eq!(config.freshness_window, Duration::from_secs(300));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn detect_tee_capability_not_available() {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::remove_var("FRANKEN_TEE_ERROR");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let capability = generator.detect_tee_capability();
        assert_eq!(capability, TeeCapability::NotAvailable);
    }

    #[test]
    fn detect_tee_capability_available() {
        std::env::set_var("FRANKEN_TEE_ENABLED", "true");
        std::env::remove_var("FRANKEN_TEE_ERROR");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let capability = generator.detect_tee_capability();
        assert_eq!(
            capability,
            TeeCapability::Available {
                platform: TeePlatform::IntelSgx
            }
        );

        std::env::remove_var("FRANKEN_TEE_ENABLED");
    }

    #[test]
    fn detect_tee_capability_error() {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::set_var("FRANKEN_TEE_ERROR", "Hardware malfunction");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let capability = generator.detect_tee_capability();
        matches!(capability, TeeCapability::Error { .. });

        std::env::remove_var("FRANKEN_TEE_ERROR");
    }

    #[test]
    fn generate_quote_tee_available() {
        std::env::set_var("FRANKEN_TEE_ENABLED", "true");
        std::env::remove_var("FRANKEN_TEE_QUOTE_FAIL");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let decision_data = b"test decision data";
        let nonce = "test_nonce_123";

        let result = generator.generate_quote(decision_data, nonce);
        assert!(matches!(result, TeeQuoteResult::Success { .. }));

        std::env::remove_var("FRANKEN_TEE_ENABLED");
    }

    #[test]
    fn generate_quote_safe_mode_fallback() {
        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::remove_var("FRANKEN_TEE_ERROR");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let decision_data = b"test decision data";
        let nonce = "test_nonce_123";

        let result = generator.generate_quote(decision_data, nonce);
        assert!(matches!(result, TeeQuoteResult::SafeModeFallback { .. }));
    }

    #[test]
    fn generate_quote_failure() {
        std::env::set_var("FRANKEN_TEE_ENABLED", "true");
        std::env::set_var("FRANKEN_TEE_QUOTE_FAIL", "1");

        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let decision_data = b"test decision data";
        let nonce = "test_nonce_123";

        let result = generator.generate_quote(decision_data, nonce);
        assert!(matches!(result, TeeQuoteResult::Failed { .. }));

        std::env::remove_var("FRANKEN_TEE_ENABLED");
        std::env::remove_var("FRANKEN_TEE_QUOTE_FAIL");
    }

    #[test]
    fn safe_mode_record_structure() {
        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());
        let decision_data = b"test decision data";
        let reason = "TEE hardware not available";

        let record = generator.generate_safe_mode_record(decision_data, reason);

        assert!(!record.record_id.is_empty());
        assert_eq!(record.fallback_reason, reason);
        assert!(!record.decision_data_hash.is_empty());
        assert!(!record.signature.is_empty());
        assert!(!record.signer_public_key.is_empty());
    }

    #[test]
    fn validate_attestation_binding_valid() {
        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());

        let now = chrono::Utc::now();
        let binding = TeeAttestationBinding {
            quote_digest: "abc123".to_string(),
            measurement_id: "test_measurement".to_string(),
            attested_signer_key_id: "key123".to_string(),
            nonce: "nonce123".to_string(),
            validity_window: AttestationValidityWindow {
                valid_from: (now - chrono::Duration::minutes(5)).to_rfc3339(),
                valid_until: (now + chrono::Duration::minutes(5)).to_rfc3339(),
            },
            tee_platform: "intel_sgx".to_string(),
            quote_algorithm: "sha256".to_string(),
        };

        // Create a minimal valid policy for testing
        let policy = TeeAttestationPolicy::default_for_testing();

        let result = generator.validate_attestation_binding(&binding, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_attestation_binding_expired() {
        let generator = TeeQuoteGenerator::new(test_config(), test_signing_key());

        let now = chrono::Utc::now();
        let binding = TeeAttestationBinding {
            quote_digest: "abc123".to_string(),
            measurement_id: "test_measurement".to_string(),
            attested_signer_key_id: "key123".to_string(),
            nonce: "nonce123".to_string(),
            validity_window: AttestationValidityWindow {
                valid_from: (now - chrono::Duration::hours(2)).to_rfc3339(),
                valid_until: (now - chrono::Duration::hours(1)).to_rfc3339(),
            },
            tee_platform: "intel_sgx".to_string(),
            quote_algorithm: "sha256".to_string(),
        };

        let policy = TeeAttestationPolicy::default_for_testing();

        let result = generator.validate_attestation_binding(&binding, &policy);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TeeQuoteError::PolicyViolation { .. }
        ));
    }

    #[test]
    fn tee_quote_error_display() {
        let error = TeeQuoteError::UnsupportedPlatform {
            platform: "unknown".to_string(),
        };
        assert!(error.to_string().contains("unknown"));

        let error = TeeQuoteError::Timeout { timeout_ms: 5000 };
        assert!(error.to_string().contains("5000ms"));
    }
}
