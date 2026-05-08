# Shadow Daemon Handoff Contracts

This document defines the handoff contracts for shadow daemon operator UI/service consumers.

## Overview

The shadow daemon emits handoff artifacts for external consumption by operator UI and service interfaces. All contracts preserve **advisory-only semantics** - controls may stage or display commands but must not mutate br/Agent Mail/rch/git directly.

## FrankenTUI Panel Bundle Contract

### Panel Bundle Schema

The shadow daemon emits a `ShadowStatusPanelBundle` for consumption by frankentui-compatible terminals:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowStatusPanelBundle {
    pub shadow_status: ShadowStatusPanel,
    pub source_freshness: SourceFreshnessPanel,
    pub degraded_gates: DegradedGatesPanel,
    pub replay_drift: ReplayDriftPanel,
    pub recommended_actions: RecommendedActionsPanel,
    pub generated_at: SystemTime,
    pub bundle_version: String,
}
```

### Individual Panel Schemas

#### Shadow Status Panel
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowStatusPanel {
    pub title: String,
    pub daemon_health: DaemonHealth,
    pub active_journals: u32,
    pub last_decision_timestamp: Option<SystemTime>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonHealth {
    Healthy,
    Degraded { reason: String },
    Offline,
    Unknown,
}
```

#### Source Freshness Panel
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFreshnessPanel {
    pub title: String,
    pub sources: Vec<SourceFreshnessEntry>,
    pub stale_source_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFreshnessEntry {
    pub source_id: String,
    pub last_update: SystemTime,
    pub staleness_seconds: u64,
    pub threshold_seconds: u64,
    pub is_stale: bool,
}
```

#### Degraded Gates Panel
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedGatesPanel {
    pub title: String,
    pub gates: Vec<DegradedGateEntry>,
    pub degraded_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedGateEntry {
    pub gate_id: String,
    pub degradation_reason: String,
    pub degraded_since: SystemTime,
    pub severity: GateDegradationSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateDegradationSeverity {
    Warning,
    Critical,
    Blocking,
}
```

#### Replay Drift Panel
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDriftPanel {
    pub title: String,
    pub drift_entries: Vec<ReplayDriftEntry>,
    pub total_drift_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDriftEntry {
    pub journal_id: String,
    pub drift_type: String,
    pub detected_at: SystemTime,
    pub severity: DriftSeverity,
    pub expected_migration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftSeverity {
    Minor,
    Major,
    Critical,
}
```

#### Recommended Actions Panel
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedActionsPanel {
    pub title: String,
    pub actions: Vec<RecommendedAction>,
    pub priority_action_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_id: String,
    pub description: String,
    pub command_preview: String, // Advisory-only, never executed directly
    pub priority: ActionPriority,
    pub estimated_duration: Option<u64>, // seconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionPriority {
    Low,
    Medium,
    High,
    Urgent,
}
```

## FastAPI Rust Service Contract

### HTTP Endpoints

If HTTP/service surface is needed, these endpoints are defined through fastapi_rust reuse:

#### GET /shadow/status
Returns current shadow daemon status
- **Response**: `ShadowStatusPanelBundle`
- **Content-Type**: `application/json`

#### GET /shadow/panels
Returns individual panel data
- **Query params**: `?panels=shadow_status,source_freshness,degraded_gates,replay_drift,recommended_actions`
- **Response**: Filtered subset of `ShadowStatusPanelBundle`

#### POST /shadow/actions/preview
Preview recommended action commands (advisory-only)
- **Request**: `{ "action_id": "string" }`
- **Response**: `{ "command_preview": "string", "safety_check": "advisory_only" }`

## Accessibility and Scannability

### High-Volume Swarm Operations

For high-volume swarm operations, all panels must support:

1. **Scannable Headers**: Clear, consistent panel titles with status indicators
2. **Color-Coded Severity**: Consistent color scheme across all panels
3. **Condensed Mode**: Optional compact display for dashboard views
4. **Keyboard Navigation**: Tab/arrow key navigation between panels
5. **Screen Reader Support**: Semantic markup for accessibility tools

### Rendering States

#### Missing Source Rendering
When source data is unavailable:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingSourcePanel {
    pub title: String,
    pub message: String,
    pub last_successful_fetch: Option<SystemTime>,
    pub retry_in_seconds: Option<u64>,
}
```

#### No-Mutation Command Surfaces
All command surfaces must include safety barriers:
- Commands are displayed as preview text only
- "Copy to clipboard" buttons for manual execution
- Clear warnings that direct execution is disabled
- Advisory notices about proper execution context

## Implementation Notes

- All timestamps use `SystemTime` for consistency
- Panel bundles are versioned for backward compatibility
- Advisory-only semantics prevent accidental automation
- Missing data gracefully degrades to placeholder content
- All panels support both full and condensed display modes