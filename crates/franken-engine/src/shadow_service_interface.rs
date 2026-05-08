//! Shadow daemon service interface for fastapi_rust integration.
//!
//! This module defines the HTTP service contract for exposing shadow daemon
//! status via fastapi_rust, preserving advisory-only semantics.

#![forbid(unsafe_code)]

use crate::shadow_handoff_contracts::{
    DaemonHealth, PanelBundleBuilder, ShadowStatusPanelBundle, serialize_panel_bundle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::security_epoch::SecurityEpoch;

/// Service configuration for shadow daemon HTTP interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowServiceConfig {
    pub host: String,
    pub port: u16,
    pub enable_cors: bool,
    pub max_response_size_bytes: usize,
    pub rate_limit_per_minute: u32,
}

impl Default for ShadowServiceConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            enable_cors: true,
            max_response_size_bytes: 1024 * 1024, // 1MB
            rate_limit_per_minute: 60,
        }
    }
}

/// Valid panel types for filtering
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PanelType {
    #[serde(rename = "shadow_status")]
    ShadowStatus,
    #[serde(rename = "source_freshness")]
    SourceFreshness,
    #[serde(rename = "degraded_gates")]
    DegradedGates,
    #[serde(rename = "replay_drift")]
    ReplayDrift,
    #[serde(rename = "recommended_actions")]
    RecommendedActions,
}

/// Request for panel filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredPanelsRequest {
    pub panels: BTreeSet<PanelType>,
}

/// Response for filtered panel data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteredPanelsResponse {
    pub shadow_status: Option<crate::shadow_handoff_contracts::ShadowStatusPanel>,
    pub source_freshness: Option<crate::shadow_handoff_contracts::SourceFreshnessPanel>,
    pub degraded_gates: Option<crate::shadow_handoff_contracts::DegradedGatesPanel>,
    pub replay_drift: Option<crate::shadow_handoff_contracts::ReplayDriftPanel>,
    pub recommended_actions: Option<crate::shadow_handoff_contracts::RecommendedActionsPanel>,
    pub generated_at: SecurityEpoch,
}

/// Action preview request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPreviewRequest {
    pub action_id: String,
}

/// Action preview response (advisory-only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPreviewResponse {
    pub action_id: String,
    pub command_preview: String,
    pub safety_check: String,
    pub advisory_notice: String,
    pub execution_context: String,
}

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
    pub shadow_daemon_connected: bool,
    pub last_panel_update: Option<SecurityEpoch>,
}

/// Error response for service endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceErrorResponse {
    pub error: String,
    pub code: String,
    pub timestamp: SecurityEpoch,
    pub advisory: Option<String>,
}

/// Shadow daemon service interface trait
pub trait ShadowServiceInterface {
    /// Get complete panel bundle
    fn get_panel_bundle(&self) -> Result<ShadowStatusPanelBundle, ServiceError>;

    /// Get filtered subset of panels
    fn get_filtered_panels(
        &self,
        request: FilteredPanelsRequest,
    ) -> Result<FilteredPanelsResponse, ServiceError>;

    /// Preview action command (advisory-only)
    fn preview_action(
        &self,
        request: ActionPreviewRequest,
    ) -> Result<ActionPreviewResponse, ServiceError>;

    /// Get service health status
    fn get_health(&self) -> Result<ServiceHealthResponse, ServiceError>;
}

/// Service error types
#[derive(Debug, Clone)]
pub enum ServiceError {
    DaemonUnavailable,
    InvalidRequest { field: String, reason: String },
    ActionNotFound { action_id: String },
    ResponseTooLarge { size_bytes: usize },
    InternalError { detail: String },
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::DaemonUnavailable => write!(f, "Shadow daemon unavailable"),
            ServiceError::InvalidRequest { field, reason } => {
                write!(f, "Invalid request field '{}': {}", field, reason)
            }
            ServiceError::ActionNotFound { action_id } => {
                write!(f, "Action '{}' not found", action_id)
            }
            ServiceError::ResponseTooLarge { size_bytes } => {
                write!(f, "Response too large: {} bytes", size_bytes)
            }
            ServiceError::InternalError { detail } => write!(f, "Internal error: {}", detail),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Default implementation of shadow service interface
pub struct DefaultShadowService {
    config: ShadowServiceConfig,
}

impl DefaultShadowService {
    pub fn new(config: ShadowServiceConfig) -> Self {
        Self { config }
    }

    /// Create an explicit unavailable bundle until real daemon evidence is attached.
    fn create_unavailable_panel_bundle(&self) -> ShadowStatusPanelBundle {
        PanelBundleBuilder::new()
            .with_daemon_health(DaemonHealth::Offline)
            .build()
    }
}

impl ShadowServiceInterface for DefaultShadowService {
    fn get_panel_bundle(&self) -> Result<ShadowStatusPanelBundle, ServiceError> {
        let bundle = self.create_unavailable_panel_bundle();

        // Check response size
        let serialized =
            serialize_panel_bundle(&bundle).map_err(|e| ServiceError::InternalError {
                detail: e.to_string(),
            })?;

        if serialized.len() > self.config.max_response_size_bytes {
            return Err(ServiceError::ResponseTooLarge {
                size_bytes: serialized.len(),
            });
        }

        Ok(bundle)
    }

    fn get_filtered_panels(
        &self,
        request: FilteredPanelsRequest,
    ) -> Result<FilteredPanelsResponse, ServiceError> {
        let bundle = self.create_unavailable_panel_bundle();

        let response = FilteredPanelsResponse {
            shadow_status: if request.panels.contains(&PanelType::ShadowStatus) {
                Some(bundle.shadow_status)
            } else {
                None
            },
            source_freshness: if request.panels.contains(&PanelType::SourceFreshness) {
                Some(bundle.source_freshness)
            } else {
                None
            },
            degraded_gates: if request.panels.contains(&PanelType::DegradedGates) {
                Some(bundle.degraded_gates)
            } else {
                None
            },
            replay_drift: if request.panels.contains(&PanelType::ReplayDrift) {
                Some(bundle.replay_drift)
            } else {
                None
            },
            recommended_actions: if request.panels.contains(&PanelType::RecommendedActions) {
                Some(bundle.recommended_actions)
            } else {
                None
            },
            generated_at: bundle.generated_at,
        };

        Ok(response)
    }

    fn preview_action(
        &self,
        request: ActionPreviewRequest,
    ) -> Result<ActionPreviewResponse, ServiceError> {
        let bundle = self.create_unavailable_panel_bundle();

        // Find the action
        let action = bundle
            .recommended_actions
            .actions
            .iter()
            .find(|a| a.action_id == request.action_id)
            .ok_or_else(|| ServiceError::ActionNotFound {
                action_id: request.action_id.clone(),
            })?;

        Ok(ActionPreviewResponse {
            action_id: request.action_id,
            command_preview: action.command_preview.clone(),
            safety_check: "advisory_only".to_string(),
            advisory_notice: "This command is for preview only. Copy and execute manually in appropriate context.".to_string(),
            execution_context: "Requires shadow-daemon access with appropriate permissions".to_string(),
        })
    }

    fn get_health(&self) -> Result<ServiceHealthResponse, ServiceError> {
        Ok(ServiceHealthResponse {
            status: "unavailable".to_string(),
            uptime_seconds: 0,
            version: crate::shadow_handoff_contracts::HANDOFF_CONTRACT_VERSION.to_string(),
            shadow_daemon_connected: false,
            last_panel_update: None,
        })
    }
}

/// Create service error response
pub fn create_error_response(error: ServiceError) -> ServiceErrorResponse {
    let (code, advisory) = match &error {
        ServiceError::DaemonUnavailable => {
            ("daemon_unavailable", Some("Check shadow daemon status"))
        }
        ServiceError::InvalidRequest { .. } => {
            ("invalid_request", Some("Verify request format and fields"))
        }
        ServiceError::ActionNotFound { .. } => (
            "action_not_found",
            Some("Use GET /shadow/status to see available actions"),
        ),
        ServiceError::ResponseTooLarge { .. } => (
            "response_too_large",
            Some("Use filtered panels to reduce response size"),
        ),
        ServiceError::InternalError { .. } => {
            ("internal_error", Some("Contact system administrator"))
        }
    };

    ServiceErrorResponse {
        error: error.to_string(),
        code: code.to_string(),
        timestamp: SecurityEpoch::GENESIS,
        advisory: advisory.map(String::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_service_config() {
        let config = ShadowServiceConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert!(config.enable_cors);
        assert_eq!(config.max_response_size_bytes, 1024 * 1024);
        assert_eq!(config.rate_limit_per_minute, 60);
    }

    #[test]
    fn test_panel_bundle_generation() {
        let config = ShadowServiceConfig::default();
        let service = DefaultShadowService::new(config);

        let bundle = service
            .get_panel_bundle()
            .expect("Should generate panel bundle");

        assert!(matches!(
            bundle.shadow_status.daemon_health,
            DaemonHealth::Offline
        ));
        assert_eq!(bundle.shadow_status.active_journals, 0);
        assert_eq!(bundle.shadow_status.last_decision_timestamp, None);
        assert_eq!(bundle.source_freshness.sources.len(), 0);
        assert_eq!(bundle.source_freshness.stale_source_count, 0);
        assert_eq!(bundle.degraded_gates.gates.len(), 0);
        assert_eq!(bundle.degraded_gates.degraded_count, 0);
        assert_eq!(bundle.replay_drift.drift_entries.len(), 0);
        assert_eq!(bundle.replay_drift.total_drift_count, 0);
        assert_eq!(bundle.recommended_actions.actions.len(), 0);
        assert_eq!(bundle.recommended_actions.priority_action_count, 0);
    }

    #[test]
    fn test_filtered_panels() {
        let config = ShadowServiceConfig::default();
        let service = DefaultShadowService::new(config);

        let mut panels = BTreeSet::new();
        panels.insert(PanelType::ShadowStatus);
        panels.insert(PanelType::RecommendedActions);

        let request = FilteredPanelsRequest { panels };
        let response = service
            .get_filtered_panels(request)
            .expect("Should filter panels");

        assert!(response.shadow_status.is_some());
        assert!(response.source_freshness.is_none());
        assert!(response.degraded_gates.is_none());
        assert!(response.replay_drift.is_none());
        assert!(response.recommended_actions.is_some());
    }

    #[test]
    fn test_action_preview() {
        let config = ShadowServiceConfig::default();
        let service = DefaultShadowService::new(config);

        let request = ActionPreviewRequest {
            action_id: "refresh-stale-sources".to_string(),
        };
        assert!(matches!(
            service.preview_action(request),
            Err(ServiceError::ActionNotFound { .. })
        ));
    }

    #[test]
    fn test_action_not_found() {
        let config = ShadowServiceConfig::default();
        let service = DefaultShadowService::new(config);

        let request = ActionPreviewRequest {
            action_id: "nonexistent-action".to_string(),
        };
        let result = service.preview_action(request);

        assert!(matches!(result, Err(ServiceError::ActionNotFound { .. })));
    }

    #[test]
    fn test_service_health() {
        let config = ShadowServiceConfig::default();
        let service = DefaultShadowService::new(config);

        let health = service.get_health().expect("Should get health status");

        assert_eq!(health.status, "unavailable");
        assert!(!health.shadow_daemon_connected);
        assert_eq!(health.uptime_seconds, 0);
        assert!(health.last_panel_update.is_none());
        assert_eq!(
            health.version,
            crate::shadow_handoff_contracts::HANDOFF_CONTRACT_VERSION
        );
    }

    #[test]
    fn test_error_response_creation() {
        let error = ServiceError::DaemonUnavailable;
        let response = create_error_response(error);

        assert_eq!(response.code, "daemon_unavailable");
        assert!(response.advisory.is_some());
        assert_eq!(response.advisory.unwrap(), "Check shadow daemon status");
    }
}
