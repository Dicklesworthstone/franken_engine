//! Trust-zone taxonomy with deterministic capability ceilings and inheritance.
//!
//! Trust zones partition runtime authority into explicit domains:
//! `Owner`, `Private`, `Team`, and `Community`.
//!
//! Each zone has:
//! - a deterministic `zone_id` (`EngineObjectId`)
//! - a declared ceiling (`CapabilitySet`)
//! - an effective ceiling (intersection of parent effective + declared)
//!
//! Plan references: Section 10.10 item 20, 9E.8.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityProfile, RuntimeCapability};
use crate::engine_object_id::{EngineObjectId, IdError, ObjectDomain, SchemaId, derive_id};

const ZONE_SCHEMA: &[u8] = b"frankenengine.trust-zone.v1";
const FE_ZONE_CEILING_EXCEEDED: &str = "FE-6001";
const FE_ZONE_POLICY_GATE_DENIED: &str = "FE-6002";

/// Canonical trust-zone classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustZoneClass {
    Owner,
    Private,
    Team,
    Community,
}

impl TrustZoneClass {
    pub const ORDERED: [Self; 4] = [Self::Owner, Self::Private, Self::Team, Self::Community];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Private => "private",
            Self::Team => "team",
            Self::Community => "community",
        }
    }

    pub fn default_ceiling(self) -> BTreeSet<RuntimeCapability> {
        use RuntimeCapability::*;

        match self {
            Self::Owner => CapabilityProfile::full().capabilities().clone(),
            Self::Private => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                PolicyRead,
                PolicyWrite,
                EvidenceEmit,
                DecisionInvoke,
                NetworkEgress,
                LeaseManagement,
                IdempotencyDerive,
                ExtensionLifecycle,
                HeapAllocate,
                FsRead,
            ]),
            Self::Team => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                EvidenceEmit,
                DecisionInvoke,
                ExtensionLifecycle,
                HeapAllocate,
                FsRead,
            ]),
            Self::Community => BTreeSet::from([
                VmDispatch,
                GcInvoke,
                IrLowering,
                ExtensionLifecycle,
                HeapAllocate,
            ]),
        }
    }
}

impl fmt::Display for TrustZoneClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persisted trust-zone metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustZone {
    pub zone_id: EngineObjectId,
    pub zone_name: String,
    pub class: TrustZoneClass,
    pub parent_zone: Option<EngineObjectId>,
    pub policy_version: u64,
    pub created_by: String,
    pub declared_ceiling: BTreeSet<RuntimeCapability>,
    pub effective_ceiling: BTreeSet<RuntimeCapability>,
}

impl TrustZone {
    fn from_request(
        request: ZoneCreateRequest,
        parent: Option<&TrustZone>,
    ) -> Result<Self, TrustZoneError> {
        let ZoneCreateRequest {
            zone_name,
            class,
            parent_zone_name: _,
            declared_ceiling,
            policy_version,
            created_by,
        } = request;

        let resolved_declared = declared_ceiling.unwrap_or_else(|| class.default_ceiling());
        let (parent_zone, parent_effective) = match parent {
            Some(parent_zone) => (
                Some(parent_zone.zone_id.clone()),
                parent_zone.effective_ceiling.clone(),
            ),
            None => (None, BTreeSet::new()),
        };

        let effective_ceiling = if parent.is_some() {
            resolved_declared
                .intersection(&parent_effective)
                .copied()
                .collect()
        } else {
            resolved_declared.clone()
        };

        if parent.is_some() && !effective_ceiling.is_subset(&parent_effective) {
            let exceeded = effective_ceiling
                .difference(&parent_effective)
                .copied()
                .collect();
            return Err(TrustZoneError::CeilingExceedsParent {
                zone_name,
                exceeded,
            });
        }

        let zone_id = derive_zone_id(&zone_name, class, parent_zone.as_ref(), policy_version)?;

        Ok(Self {
            zone_id,
            zone_name,
            class,
            parent_zone,
            policy_version,
            created_by,
            declared_ceiling: resolved_declared,
            effective_ceiling,
        })
    }

    pub fn allows(&self, requested: &BTreeSet<RuntimeCapability>) -> bool {
        requested.is_subset(&self.effective_ceiling)
    }
}

/// Request bundle for creating a trust zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneCreateRequest {
    pub zone_name: String,
    pub class: TrustZoneClass,
    pub parent_zone_name: Option<String>,
    pub declared_ceiling: Option<BTreeSet<RuntimeCapability>>,
    pub policy_version: u64,
    pub created_by: String,
}

impl ZoneCreateRequest {
    pub fn new(
        zone_name: impl Into<String>,
        class: TrustZoneClass,
        policy_version: u64,
        created_by: impl Into<String>,
    ) -> Self {
        Self {
            zone_name: zone_name.into(),
            class,
            parent_zone_name: None,
            declared_ceiling: None,
            policy_version,
            created_by: created_by.into(),
        }
    }

    pub fn with_parent(mut self, parent_zone_name: impl Into<String>) -> Self {
        self.parent_zone_name = Some(parent_zone_name.into());
        self
    }

    pub fn with_declared_ceiling(mut self, declared_ceiling: BTreeSet<RuntimeCapability>) -> Self {
        self.declared_ceiling = Some(declared_ceiling);
        self
    }
}

/// Structured event kind for trust-zone operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneEventType {
    Assignment,
    CeilingCheck,
    ZoneTransition,
}

/// Structured event outcome for trust-zone operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneEventOutcome {
    Pass,
    Assigned,
    Migrated,
    CeilingExceeded,
    Denied,
}

/// Structured trust-zone event with stable observability keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: ZoneEventType,
    pub outcome: ZoneEventOutcome,
    pub error_code: Option<String>,
    pub entity_id: Option<String>,
    pub zone_name: Option<String>,
    pub from_zone: Option<String>,
    pub to_zone: Option<String>,
}

impl ZoneEvent {
    fn base(trace_id: &str, event: ZoneEventType, outcome: ZoneEventOutcome) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            decision_id: None,
            policy_id: None,
            component: "trust_zone".to_string(),
            event,
            outcome,
            error_code: None,
            entity_id: None,
            zone_name: None,
            from_zone: None,
            to_zone: None,
        }
    }
}

/// Zone transition request with explicit policy gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneTransitionRequest {
    pub entity_id: String,
    pub to_zone_name: String,
    pub trace_id: String,
    pub policy_id: String,
    pub decision_id: String,
    pub policy_gate_approved: bool,
}

impl ZoneTransitionRequest {
    pub fn new(
        entity_id: impl Into<String>,
        to_zone_name: impl Into<String>,
        trace_id: impl Into<String>,
        policy_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_gate_approved: bool,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            to_zone_name: to_zone_name.into(),
            trace_id: trace_id.into(),
            policy_id: policy_id.into(),
            decision_id: decision_id.into(),
            policy_gate_approved,
        }
    }
}

/// Errors from trust-zone operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustZoneError {
    ZoneAlreadyExists {
        zone_name: String,
    },
    ParentZoneMissing {
        zone_name: String,
        parent_zone: String,
    },
    ZoneMissing {
        zone_name: String,
    },
    CeilingExceedsParent {
        zone_name: String,
        exceeded: BTreeSet<RuntimeCapability>,
    },
    CapabilityCeilingExceeded {
        zone_name: String,
        requested: BTreeSet<RuntimeCapability>,
        ceiling: BTreeSet<RuntimeCapability>,
    },
    PolicyGateDenied {
        entity_id: String,
        from_zone: String,
        to_zone: String,
    },
    IdDerivation(IdError),
}

impl fmt::Display for TrustZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZoneAlreadyExists { zone_name } => {
                write!(f, "zone already exists: {zone_name}")
            }
            Self::ParentZoneMissing {
                zone_name,
                parent_zone,
            } => write!(
                f,
                "cannot create zone '{zone_name}': missing parent zone '{parent_zone}'"
            ),
            Self::ZoneMissing { zone_name } => write!(f, "unknown zone: {zone_name}"),
            Self::CeilingExceedsParent {
                zone_name,
                exceeded,
            } => write!(
                f,
                "zone '{zone_name}' declared capabilities not permitted by parent: {:?}",
                exceeded
            ),
            Self::CapabilityCeilingExceeded {
                zone_name,
                requested,
                ceiling,
            } => write!(
                f,
                "zone '{zone_name}' capability ceiling exceeded: requested={:?}, ceiling={:?}",
                requested, ceiling
            ),
            Self::PolicyGateDenied {
                entity_id,
                from_zone,
                to_zone,
            } => write!(
                f,
                "policy gate denied transition for '{entity_id}' from '{from_zone}' to '{to_zone}'"
            ),
            Self::IdDerivation(err) => write!(f, "zone id derivation failed: {err}"),
        }
    }
}

impl std::error::Error for TrustZoneError {}

impl From<IdError> for TrustZoneError {
    fn from(value: IdError) -> Self {
        Self::IdDerivation(value)
    }
}

/// Mutable trust-zone hierarchy and assignment registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneHierarchy {
    zones: BTreeMap<String, TrustZone>,
    assignments: BTreeMap<String, String>,
    default_zone: String,
    events: Vec<ZoneEvent>,
}

impl ZoneHierarchy {
    pub fn new(default_zone: impl Into<String>) -> Self {
        Self {
            zones: BTreeMap::new(),
            assignments: BTreeMap::new(),
            default_zone: default_zone.into(),
            events: Vec::new(),
        }
    }

    pub fn standard(created_by: &str, policy_version: u64) -> Result<Self, TrustZoneError> {
        let mut hierarchy = Self::new("community");
        hierarchy.add_zone(ZoneCreateRequest::new(
            "owner",
            TrustZoneClass::Owner,
            policy_version,
            created_by,
        ))?;
        hierarchy.add_zone(
            ZoneCreateRequest::new(
                "private",
                TrustZoneClass::Private,
                policy_version,
                created_by,
            )
            .with_parent("owner"),
        )?;
        hierarchy.add_zone(
            ZoneCreateRequest::new("team", TrustZoneClass::Team, policy_version, created_by)
                .with_parent("private"),
        )?;
        hierarchy.add_zone(
            ZoneCreateRequest::new(
                "community",
                TrustZoneClass::Community,
                policy_version,
                created_by,
            )
            .with_parent("team"),
        )?;
        Ok(hierarchy)
    }

    pub fn add_zone(
        &mut self,
        request: ZoneCreateRequest,
    ) -> Result<EngineObjectId, TrustZoneError> {
        if self.zones.contains_key(&request.zone_name) {
            return Err(TrustZoneError::ZoneAlreadyExists {
                zone_name: request.zone_name,
            });
        }

        let parent = match request.parent_zone_name.as_ref() {
            Some(parent_zone_name) => Some(self.zones.get(parent_zone_name).ok_or_else(|| {
                TrustZoneError::ParentZoneMissing {
                    zone_name: request.zone_name.clone(),
                    parent_zone: parent_zone_name.clone(),
                }
            })?),
            None => None,
        };

        let zone_name = request.zone_name.clone();
        let zone = TrustZone::from_request(request, parent)?;
        let zone_id = zone.zone_id.clone();
        self.zones.insert(zone_name, zone);
        Ok(zone_id)
    }

    pub fn zone(&self, zone_name: &str) -> Option<&TrustZone> {
        self.zones.get(zone_name)
    }

    pub fn zone_for_entity(&self, entity_id: &str) -> Result<&TrustZone, TrustZoneError> {
        let zone_name = self
            .assignments
            .get(entity_id)
            .map_or(self.default_zone.as_str(), String::as_str);
        self.zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })
    }

    pub fn assign_entity(
        &mut self,
        entity_id: impl Into<String>,
        zone_name: &str,
        trace_id: &str,
    ) -> Result<(), TrustZoneError> {
        self.zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })?;
        let entity_id = entity_id.into();
        self.assignments
            .insert(entity_id.clone(), zone_name.to_string());

        let mut event = ZoneEvent::base(
            trace_id,
            ZoneEventType::Assignment,
            ZoneEventOutcome::Assigned,
        );
        event.entity_id = Some(entity_id);
        event.zone_name = Some(zone_name.to_string());
        self.events.push(event);
        Ok(())
    }

    pub fn enforce_ceiling(
        &mut self,
        zone_name: &str,
        requested: &BTreeSet<RuntimeCapability>,
        trace_id: &str,
    ) -> Result<(), TrustZoneError> {
        let zone = self
            .zone(zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })?;

        let allows = zone.allows(requested);
        let ceiling = zone.effective_ceiling.clone();

        if allows {
            let mut event = ZoneEvent::base(
                trace_id,
                ZoneEventType::CeilingCheck,
                ZoneEventOutcome::Pass,
            );
            event.zone_name = Some(zone_name.to_string());
            self.events.push(event);
            return Ok(());
        }

        let mut event = ZoneEvent::base(
            trace_id,
            ZoneEventType::CeilingCheck,
            ZoneEventOutcome::CeilingExceeded,
        );
        event.zone_name = Some(zone_name.to_string());
        event.error_code = Some(FE_ZONE_CEILING_EXCEEDED.to_string());
        self.events.push(event);

        Err(TrustZoneError::CapabilityCeilingExceeded {
            zone_name: zone_name.to_string(),
            requested: requested.clone(),
            ceiling,
        })
    }

    pub fn transition_entity(
        &mut self,
        request: ZoneTransitionRequest,
    ) -> Result<(), TrustZoneError> {
        self.zone(&request.to_zone_name)
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: request.to_zone_name.clone(),
            })?;

        let from_zone_name = self.zone_for_entity(&request.entity_id)?.zone_name.clone();
        if !request.policy_gate_approved {
            let mut event = ZoneEvent::base(
                &request.trace_id,
                ZoneEventType::ZoneTransition,
                ZoneEventOutcome::Denied,
            );
            event.policy_id = Some(request.policy_id);
            event.decision_id = Some(request.decision_id);
            event.entity_id = Some(request.entity_id.clone());
            event.from_zone = Some(from_zone_name.clone());
            event.to_zone = Some(request.to_zone_name.clone());
            event.error_code = Some(FE_ZONE_POLICY_GATE_DENIED.to_string());
            self.events.push(event);

            return Err(TrustZoneError::PolicyGateDenied {
                entity_id: request.entity_id,
                from_zone: from_zone_name,
                to_zone: request.to_zone_name,
            });
        }

        self.assignments
            .insert(request.entity_id.clone(), request.to_zone_name.clone());

        let mut event = ZoneEvent::base(
            &request.trace_id,
            ZoneEventType::ZoneTransition,
            ZoneEventOutcome::Migrated,
        );
        event.policy_id = Some(request.policy_id);
        event.decision_id = Some(request.decision_id);
        event.entity_id = Some(request.entity_id);
        event.from_zone = Some(from_zone_name);
        event.to_zone = Some(request.to_zone_name);
        self.events.push(event);
        Ok(())
    }

    pub fn compute_effective_ceiling(
        &self,
        zone_name: &str,
    ) -> Result<BTreeSet<RuntimeCapability>, TrustZoneError> {
        self.zone(zone_name)
            .map(|zone| zone.effective_ceiling.clone())
            .ok_or_else(|| TrustZoneError::ZoneMissing {
                zone_name: zone_name.to_string(),
            })
    }

    pub fn events(&self) -> &[ZoneEvent] {
        &self.events
    }

    pub fn drain_events(&mut self) -> Vec<ZoneEvent> {
        std::mem::take(&mut self.events)
    }
}

/// Derive any object id scoped to a specific trust zone.
pub fn derive_zone_scoped_object_id(
    zone: &TrustZone,
    domain: ObjectDomain,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<EngineObjectId, IdError> {
    derive_id(domain, &zone.zone_name, schema_id, canonical_bytes)
}

fn derive_zone_id(
    zone_name: &str,
    class: TrustZoneClass,
    parent_zone: Option<&EngineObjectId>,
    policy_version: u64,
) -> Result<EngineObjectId, IdError> {
    let schema = SchemaId::from_definition(ZONE_SCHEMA);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(class.as_str().as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&policy_version.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(zone_name.as_bytes());
    if let Some(parent) = parent_zone {
        canonical.extend_from_slice(parent.as_bytes());
    }
    derive_id(ObjectDomain::PolicyObject, zone_name, &schema, &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::ObjectDomain;

    fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
        caps.iter().copied().collect()
    }

    #[test]
    fn standard_hierarchy_has_expected_order_and_defaults() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        for class in TrustZoneClass::ORDERED {
            let zone_name = class.as_str();
            assert!(
                hierarchy.zone(zone_name).is_some(),
                "missing zone {zone_name}"
            );
        }
        assert_eq!(
            hierarchy
                .zone_for_entity("unknown-entity")
                .expect("default zone")
                .zone_name,
            "community"
        );
    }

    #[test]
    fn child_effective_ceiling_uses_intersection_with_parent() {
        let mut hierarchy = ZoneHierarchy::new("community");
        hierarchy
            .add_zone(ZoneCreateRequest::new(
                "owner",
                TrustZoneClass::Owner,
                7,
                "root",
            ))
            .expect("owner");
        hierarchy
            .add_zone(
                ZoneCreateRequest::new("private", TrustZoneClass::Private, 7, "root")
                    .with_parent("owner")
                    .with_declared_ceiling(capset(&[
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::NetworkEgress,
                    ])),
            )
            .expect("private");
        hierarchy
            .add_zone(
                ZoneCreateRequest::new("team", TrustZoneClass::Team, 7, "root")
                    .with_parent("private")
                    .with_declared_ceiling(capset(&[
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::FsWrite,
                    ])),
            )
            .expect("team");

        let team = hierarchy.zone("team").expect("team");
        assert_eq!(
            team.effective_ceiling,
            capset(&[RuntimeCapability::VmDispatch]),
        );
    }

    #[test]
    fn effective_ceiling_is_subset_of_parent_in_standard_hierarchy() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 9).expect("build hierarchy");
        let private = hierarchy.zone("private").expect("private");
        let team = hierarchy.zone("team").expect("team");
        let community = hierarchy.zone("community").expect("community");
        assert!(
            private
                .effective_ceiling
                .is_subset(&hierarchy.zone("owner").expect("owner").effective_ceiling)
        );
        assert!(team.effective_ceiling.is_subset(&private.effective_ceiling));
        assert!(
            community
                .effective_ceiling
                .is_subset(&team.effective_ceiling)
        );
    }

    #[test]
    fn add_zone_rejects_missing_parent() {
        let mut hierarchy = ZoneHierarchy::new("community");
        let err = hierarchy
            .add_zone(
                ZoneCreateRequest::new("team", TrustZoneClass::Team, 1, "root")
                    .with_parent("private"),
            )
            .expect_err("missing parent");
        assert!(matches!(err, TrustZoneError::ParentZoneMissing { .. }));
    }

    #[test]
    fn enforce_ceiling_rejects_requested_capability_outside_zone_ceiling() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        let requested = capset(&[
            RuntimeCapability::VmDispatch,
            RuntimeCapability::NetworkEgress,
        ]);

        let err = hierarchy
            .enforce_ceiling("community", &requested, "trace-zone-1")
            .expect_err("should reject network capability in community zone");

        match err {
            TrustZoneError::CapabilityCeilingExceeded { zone_name, .. } => {
                assert_eq!(zone_name, "community");
            }
            other => panic!("unexpected error: {other}"),
        }

        let event = hierarchy.events().last().expect("zone event");
        assert_eq!(event.error_code.as_deref(), Some(FE_ZONE_CEILING_EXCEEDED));
        assert_eq!(event.event, ZoneEventType::CeilingCheck);
        assert_eq!(event.outcome, ZoneEventOutcome::CeilingExceeded);
    }

    #[test]
    fn transition_requires_policy_gate() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        hierarchy
            .assign_entity("ext-alpha", "community", "trace-a")
            .expect("assign");

        let err = hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-alpha",
                "team",
                "trace-transition",
                "policy-zone",
                "decision-zone",
                false,
            ))
            .expect_err("must deny without policy gate");

        assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
        let event = hierarchy.events().last().expect("event");
        assert_eq!(event.event, ZoneEventType::ZoneTransition);
        assert_eq!(event.outcome, ZoneEventOutcome::Denied);
        assert_eq!(
            event.error_code.as_deref(),
            Some(FE_ZONE_POLICY_GATE_DENIED)
        );
    }

    #[test]
    fn transition_updates_assignment_when_policy_gate_is_approved() {
        let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("build hierarchy");
        hierarchy
            .assign_entity("ext-beta", "community", "trace-a")
            .expect("assign");

        hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-beta",
                "team",
                "trace-transition",
                "policy-zone",
                "decision-zone",
                true,
            ))
            .expect("transition");

        let zone = hierarchy.zone_for_entity("ext-beta").expect("zone");
        assert_eq!(zone.zone_name, "team");
        let event = hierarchy.events().last().expect("event");
        assert_eq!(event.outcome, ZoneEventOutcome::Migrated);
    }

    #[test]
    fn zone_scoped_object_id_changes_with_zone() {
        let hierarchy = ZoneHierarchy::standard("maintainer", 3).expect("build hierarchy");
        let team = hierarchy.zone("team").expect("team");
        let community = hierarchy.zone("community").expect("community");
        let schema = SchemaId::from_definition(b"zone-scoped-object-v1");
        let canonical_bytes = b"same-object";

        let team_id = derive_zone_scoped_object_id(
            team,
            ObjectDomain::EvidenceRecord,
            &schema,
            canonical_bytes,
        )
        .expect("team id");
        let community_id = derive_zone_scoped_object_id(
            community,
            ObjectDomain::EvidenceRecord,
            &schema,
            canonical_bytes,
        )
        .expect("community id");

        assert_ne!(team_id, community_id);
    }

    #[test]
    fn hierarchy_serialization_is_deterministic_for_same_inputs() {
        let a = ZoneHierarchy::standard("maintainer", 5).expect("hierarchy A");
        let b = ZoneHierarchy::standard("maintainer", 5).expect("hierarchy B");
        let json_a = serde_json::to_string(&a).expect("serde deserialization should succeed");
        let json_b = serde_json::to_string(&b).expect("serde deserialization should succeed");
        assert_eq!(json_a, json_b);
    }

    // ── TrustZoneClass ───────────────────────────────────────────────

    #[test]
    fn trust_zone_class_as_str() {
        assert_eq!(TrustZoneClass::Owner.as_str(), "owner");
        assert_eq!(TrustZoneClass::Private.as_str(), "private");
        assert_eq!(TrustZoneClass::Team.as_str(), "team");
        assert_eq!(TrustZoneClass::Community.as_str(), "community");
    }

    #[test]
    fn trust_zone_class_display() {
        assert_eq!(TrustZoneClass::Community.to_string(), "community");
    }

    #[test]
    fn trust_zone_class_ordering() {
        assert!(TrustZoneClass::Owner < TrustZoneClass::Community);
        assert!(TrustZoneClass::Private < TrustZoneClass::Team);
    }

    #[test]
    fn trust_zone_class_serde_roundtrip() {
        for class in TrustZoneClass::ORDERED {
            let json = serde_json::to_string(&class).expect("serde deserialization should succeed");
            let back: TrustZoneClass =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(back, class);
        }
    }

    #[test]
    fn trust_zone_class_snake_case_serde() {
        let json = serde_json::to_string(&TrustZoneClass::Community)
            .expect("serde deserialization should succeed");
        assert!(json.contains("community"));
    }

    #[test]
    fn trust_zone_class_ordered_constant() {
        assert_eq!(TrustZoneClass::ORDERED.len(), 4);
        assert_eq!(TrustZoneClass::ORDERED[0], TrustZoneClass::Owner);
        assert_eq!(TrustZoneClass::ORDERED[3], TrustZoneClass::Community);
    }

    #[test]
    fn default_ceiling_narrows_as_trust_decreases() {
        let owner_cap = TrustZoneClass::Owner.default_ceiling();
        let private_cap = TrustZoneClass::Private.default_ceiling();
        let team_cap = TrustZoneClass::Team.default_ceiling();
        let community_cap = TrustZoneClass::Community.default_ceiling();
        assert!(owner_cap.len() >= private_cap.len());
        assert!(private_cap.len() >= team_cap.len());
        assert!(team_cap.len() >= community_cap.len());
    }

    #[test]
    fn community_ceiling_is_subset_of_team() {
        let team_cap = TrustZoneClass::Team.default_ceiling();
        let community_cap = TrustZoneClass::Community.default_ceiling();
        assert!(community_cap.is_subset(&team_cap));
    }

    // ── TrustZoneError ───────────────────────────────────────────────

    #[test]
    fn error_display_zone_already_exists() {
        let err = TrustZoneError::ZoneAlreadyExists {
            zone_name: "team".into(),
        };
        assert!(err.to_string().contains("team"));
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn error_display_parent_missing() {
        let err = TrustZoneError::ParentZoneMissing {
            zone_name: "team".into(),
            parent_zone: "private".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("team"));
        assert!(msg.contains("private"));
    }

    #[test]
    fn error_display_zone_missing() {
        let err = TrustZoneError::ZoneMissing {
            zone_name: "nonexistent".into(),
        };
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn error_display_ceiling_exceeds_parent() {
        let err = TrustZoneError::CeilingExceedsParent {
            zone_name: "team".into(),
            exceeded: capset(&[RuntimeCapability::NetworkEgress]),
        };
        let msg = err.to_string();
        assert!(msg.contains("team"));
        assert!(msg.contains("NetworkEgress"));
    }

    #[test]
    fn error_display_capability_ceiling_exceeded() {
        let err = TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "community".into(),
            requested: capset(&[RuntimeCapability::FsWrite]),
            ceiling: capset(&[RuntimeCapability::VmDispatch]),
        };
        let msg = err.to_string();
        assert!(msg.contains("community"));
        assert!(msg.contains("ceiling exceeded"));
    }

    #[test]
    fn error_display_policy_gate_denied() {
        let err = TrustZoneError::PolicyGateDenied {
            entity_id: "ext-1".into(),
            from_zone: "community".into(),
            to_zone: "team".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ext-1"));
        assert!(msg.contains("community"));
        assert!(msg.contains("team"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = TrustZoneError::ZoneMissing {
            zone_name: "test".into(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let back: TrustZoneError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, err);
    }

    // ── ZoneAlreadyExists ────────────────────────────────────────────

    #[test]
    fn add_zone_rejects_duplicate_name() {
        let mut hierarchy = ZoneHierarchy::new("community");
        hierarchy
            .add_zone(ZoneCreateRequest::new(
                "owner",
                TrustZoneClass::Owner,
                1,
                "root",
            ))
            .expect("serde deserialization should succeed");
        let err = hierarchy
            .add_zone(ZoneCreateRequest::new(
                "owner",
                TrustZoneClass::Owner,
                1,
                "root",
            ))
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneAlreadyExists { .. }));
    }

    // ── enforce_ceiling pass path ────────────────────────────────────

    #[test]
    fn enforce_ceiling_passes_within_zone_capabilities() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let requested = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
        hierarchy
            .enforce_ceiling("community", &requested, "t")
            .expect("serde deserialization should succeed");
        let event = hierarchy
            .events()
            .last()
            .expect("serde deserialization should succeed");
        assert_eq!(event.outcome, ZoneEventOutcome::Pass);
    }

    // ── assign_entity errors ─────────────────────────────────────────

    #[test]
    fn assign_entity_to_missing_zone_fails() {
        let mut hierarchy = ZoneHierarchy::new("community");
        let err = hierarchy
            .assign_entity("ext-1", "nonexistent", "t")
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    }

    // ── zone_for_entity ──────────────────────────────────────────────

    #[test]
    fn zone_for_entity_returns_assigned_zone() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "team", "t")
            .expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone_for_entity("ext-1")
            .expect("serde deserialization should succeed");
        assert_eq!(zone.zone_name, "team");
    }

    #[test]
    fn zone_for_entity_returns_default_when_not_assigned() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone_for_entity("unassigned")
            .expect("serde deserialization should succeed");
        assert_eq!(zone.zone_name, "community");
    }

    // ── transition to missing zone ───────────────────────────────────

    #[test]
    fn transition_to_missing_zone_fails() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t")
            .expect("serde deserialization should succeed");
        let err = hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-1",
                "nonexistent",
                "t",
                "p",
                "d",
                true,
            ))
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    }

    // ── compute_effective_ceiling ─────────────────────────────────────

    #[test]
    fn compute_effective_ceiling_for_known_zone() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let ceiling = hierarchy
            .compute_effective_ceiling("team")
            .expect("serde deserialization should succeed");
        assert!(!ceiling.is_empty());
    }

    #[test]
    fn compute_effective_ceiling_for_missing_zone_fails() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let err = hierarchy
            .compute_effective_ceiling("nonexistent")
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    }

    // ── drain_events ─────────────────────────────────────────────────

    #[test]
    fn drain_events_empties_and_returns() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t")
            .expect("serde deserialization should succeed");
        let events = hierarchy.drain_events();
        assert!(!events.is_empty());
        assert!(hierarchy.events().is_empty());
    }

    // ── ZoneEventType / ZoneEventOutcome serde ───────────────────────

    #[test]
    fn zone_event_type_serde_roundtrip() {
        for event_type in [
            ZoneEventType::Assignment,
            ZoneEventType::CeilingCheck,
            ZoneEventType::ZoneTransition,
        ] {
            let json =
                serde_json::to_string(&event_type).expect("serde deserialization should succeed");
            let back: ZoneEventType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(back, event_type);
        }
    }

    #[test]
    fn zone_event_outcome_serde_roundtrip() {
        for outcome in [
            ZoneEventOutcome::Pass,
            ZoneEventOutcome::Assigned,
            ZoneEventOutcome::Migrated,
            ZoneEventOutcome::CeilingExceeded,
            ZoneEventOutcome::Denied,
        ] {
            let json =
                serde_json::to_string(&outcome).expect("serde deserialization should succeed");
            let back: ZoneEventOutcome =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(back, outcome);
        }
    }

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn zone_event_serde_roundtrip() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t")
            .expect("serde deserialization should succeed");
        for event in hierarchy.events() {
            let json = serde_json::to_string(event).expect("serde deserialization should succeed");
            let back: ZoneEvent =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(&back, event);
        }
    }

    #[test]
    fn zone_create_request_serde_roundtrip() {
        let req = ZoneCreateRequest::new("team", TrustZoneClass::Team, 5, "admin")
            .with_parent("private")
            .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch]));
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: ZoneCreateRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, req);
    }

    #[test]
    fn zone_transition_request_serde_roundtrip() {
        let req = ZoneTransitionRequest::new("ext-1", "team", "t", "p", "d", true);
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: ZoneTransitionRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, req);
    }

    #[test]
    fn trust_zone_serde_roundtrip() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("team")
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(zone).expect("serde deserialization should succeed");
        let back: TrustZone =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(&back, zone);
    }

    // ── zone_id determinism ──────────────────────────────────────────

    #[test]
    fn zone_id_deterministic_for_same_inputs() {
        let a = ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let b = ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        assert_eq!(
            a.zone("team")
                .expect("serde deserialization should succeed")
                .zone_id,
            b.zone("team")
                .expect("serde deserialization should succeed")
                .zone_id
        );
    }

    #[test]
    fn zone_id_changes_with_policy_version() {
        let a = ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let b = ZoneHierarchy::standard("m", 2).expect("serde deserialization should succeed");
        assert_ne!(
            a.zone("owner")
                .expect("serde deserialization should succeed")
                .zone_id,
            b.zone("owner")
                .expect("serde deserialization should succeed")
                .zone_id
        );
    }

    // ── TrustZone::allows ────────────────────────────────────────────

    #[test]
    fn trust_zone_allows_subset() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let owner = hierarchy
            .zone("owner")
            .expect("serde deserialization should succeed");
        assert!(owner.allows(&capset(&[RuntimeCapability::VmDispatch])));
    }

    #[test]
    fn trust_zone_allows_empty() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let community = hierarchy
            .zone("community")
            .expect("serde deserialization should succeed");
        assert!(community.allows(&BTreeSet::new()));
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn error_code_constants() {
        assert_eq!(FE_ZONE_CEILING_EXCEEDED, "FE-6001");
        assert_eq!(FE_ZONE_POLICY_GATE_DENIED, "FE-6002");
    }

    // ── derive_zone_scoped_object_id ─────────────────────────────────

    #[test]
    fn zone_scoped_id_deterministic() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("team")
            .expect("serde deserialization should succeed");
        let schema = SchemaId::from_definition(b"test-schema-v1");
        let a = derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, b"data")
            .expect("serde deserialization should succeed");
        let b = derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, b"data")
            .expect("serde deserialization should succeed");
        assert_eq!(a, b);
    }

    // ── ZoneCreateRequest builder ────────────────────────────────────

    #[test]
    fn zone_create_request_defaults() {
        let req = ZoneCreateRequest::new("test", TrustZoneClass::Team, 1, "admin");
        assert!(req.parent_zone_name.is_none());
        assert!(req.declared_ceiling.is_none());
        assert_eq!(req.zone_name, "test");
        assert_eq!(req.class, TrustZoneClass::Team);
        assert_eq!(req.policy_version, 1);
        assert_eq!(req.created_by, "admin");
    }

    // -- Enrichment: std::error --

    #[test]
    fn trust_zone_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(TrustZoneError::ZoneAlreadyExists {
                zone_name: "z1".into(),
            }),
            Box::new(TrustZoneError::ParentZoneMissing {
                zone_name: "z2".into(),
                parent_zone: "z-parent".into(),
            }),
            Box::new(TrustZoneError::ZoneMissing {
                zone_name: "z3".into(),
            }),
            Box::new(TrustZoneError::CapabilityCeilingExceeded {
                zone_name: "z5".into(),
                requested: std::collections::BTreeSet::from([RuntimeCapability::FsWrite]),
                ceiling: std::collections::BTreeSet::from([RuntimeCapability::FsRead]),
            }),
            Box::new(TrustZoneError::PolicyGateDenied {
                entity_id: "ext-1".into(),
                from_zone: "z-a".into(),
                to_zone: "z-b".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 tested variants produce distinct messages"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn trust_zone_class_display_uniqueness_btreeset() {
        let mut displays = BTreeSet::new();
        for class in TrustZoneClass::ORDERED {
            displays.insert(class.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 TrustZoneClass variants produce distinct Display strings"
        );
    }

    #[test]
    fn trust_zone_class_as_str_matches_display() {
        for class in TrustZoneClass::ORDERED {
            assert_eq!(class.as_str(), &class.to_string());
        }
    }

    #[test]
    fn zone_hierarchy_serde_roundtrip() {
        let hierarchy = ZoneHierarchy::standard("admin", 1).expect("build hierarchy");
        let json = serde_json::to_string(&hierarchy).expect("serde deserialization should succeed");
        let back: ZoneHierarchy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hierarchy, back);
    }

    #[test]
    fn owner_zone_has_full_capabilities() {
        let full_caps = TrustZoneClass::Owner.default_ceiling();
        let profile_caps = crate::capability::CapabilityProfile::full()
            .capabilities()
            .clone();
        assert_eq!(
            full_caps, profile_caps,
            "Owner zone ceiling must equal full capability profile"
        );
    }

    #[test]
    fn ceiling_monotonicity_across_zone_classes() {
        // Each zone class from Owner down to Community should have a ceiling
        // that is a superset of (or equal to) the next.
        let owner_caps = TrustZoneClass::Owner.default_ceiling();
        let private_caps = TrustZoneClass::Private.default_ceiling();
        let team_caps = TrustZoneClass::Team.default_ceiling();
        let community_caps = TrustZoneClass::Community.default_ceiling();

        assert!(
            private_caps.is_subset(&owner_caps),
            "private must be subset of owner"
        );
        assert!(
            team_caps.is_subset(&private_caps),
            "team must be subset of private"
        );
        assert!(
            community_caps.is_subset(&team_caps),
            "community must be subset of team"
        );
    }

    #[test]
    fn enrichment_trust_zone_owner_serde() {
        let hierarchy = ZoneHierarchy::standard("admin", 1).expect("build hierarchy");
        let zone = hierarchy
            .zone("owner")
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(zone).expect("serde deserialization should succeed");
        let back: TrustZone =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(*zone, back);
    }

    #[test]
    fn zone_create_request_with_custom_ceiling() {
        let custom = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
        let req = ZoneCreateRequest::new("custom-zone", TrustZoneClass::Team, 1, "tester")
            .with_declared_ceiling(custom.clone());
        assert_eq!(req.declared_ceiling, Some(custom));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-28
    // -----------------------------------------------------------------------

    // ── Copy semantics ──────────────────────────────────────────────

    #[test]
    fn trust_zone_class_copy_semantics() {
        let a = TrustZoneClass::Owner;
        let b = a; // Copy
        assert_eq!(a, b);
        // a is still usable after copy
        assert_eq!(a.as_str(), "owner");
    }

    #[test]
    fn zone_event_type_copy_semantics() {
        let a = ZoneEventType::Assignment;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn zone_event_outcome_copy_semantics() {
        let a = ZoneEventOutcome::Pass;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn trust_zone_class_copy_all_variants() {
        for class in TrustZoneClass::ORDERED {
            let copied = class;
            assert_eq!(class, copied);
            assert_eq!(class.as_str(), copied.as_str());
        }
    }

    #[test]
    fn zone_event_type_copy_all_variants() {
        let variants = [
            ZoneEventType::Assignment,
            ZoneEventType::CeilingCheck,
            ZoneEventType::ZoneTransition,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
        }
    }

    #[test]
    fn zone_event_outcome_copy_all_variants() {
        let variants = [
            ZoneEventOutcome::Pass,
            ZoneEventOutcome::Assigned,
            ZoneEventOutcome::Migrated,
            ZoneEventOutcome::CeilingExceeded,
            ZoneEventOutcome::Denied,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
        }
    }

    // ── Debug distinctness ──────────────────────────────────────────

    #[test]
    fn trust_zone_class_debug_distinct() {
        let mut debug_strings = BTreeSet::new();
        for class in TrustZoneClass::ORDERED {
            debug_strings.insert(format!("{class:?}"));
        }
        assert_eq!(debug_strings.len(), 4);
    }

    #[test]
    fn zone_event_type_debug_distinct() {
        let variants = [
            ZoneEventType::Assignment,
            ZoneEventType::CeilingCheck,
            ZoneEventType::ZoneTransition,
        ];
        let mut debug_strings = BTreeSet::new();
        for v in variants {
            debug_strings.insert(format!("{v:?}"));
        }
        assert_eq!(debug_strings.len(), 3);
    }

    #[test]
    fn zone_event_outcome_debug_distinct() {
        let variants = [
            ZoneEventOutcome::Pass,
            ZoneEventOutcome::Assigned,
            ZoneEventOutcome::Migrated,
            ZoneEventOutcome::CeilingExceeded,
            ZoneEventOutcome::Denied,
        ];
        let mut debug_strings = BTreeSet::new();
        for v in variants {
            debug_strings.insert(format!("{v:?}"));
        }
        assert_eq!(debug_strings.len(), 5);
    }

    #[test]
    fn trust_zone_error_debug_distinct_all_variants() {
        let variants: Vec<TrustZoneError> = vec![
            TrustZoneError::ZoneAlreadyExists {
                zone_name: "z".into(),
            },
            TrustZoneError::ParentZoneMissing {
                zone_name: "z".into(),
                parent_zone: "p".into(),
            },
            TrustZoneError::ZoneMissing {
                zone_name: "z".into(),
            },
            TrustZoneError::CeilingExceedsParent {
                zone_name: "z".into(),
                exceeded: BTreeSet::new(),
            },
            TrustZoneError::CapabilityCeilingExceeded {
                zone_name: "z".into(),
                requested: BTreeSet::new(),
                ceiling: BTreeSet::new(),
            },
            TrustZoneError::PolicyGateDenied {
                entity_id: "e".into(),
                from_zone: "a".into(),
                to_zone: "b".into(),
            },
        ];
        let mut debug_strings = BTreeSet::new();
        for v in &variants {
            debug_strings.insert(format!("{v:?}"));
        }
        assert_eq!(debug_strings.len(), 6);
    }

    // ── Serde variant distinctness ──────────────────────────────────

    #[test]
    fn trust_zone_class_serde_distinct() {
        let mut jsons = BTreeSet::new();
        for class in TrustZoneClass::ORDERED {
            jsons.insert(
                serde_json::to_string(&class).expect("serde deserialization should succeed"),
            );
        }
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn zone_event_type_serde_distinct() {
        let variants = [
            ZoneEventType::Assignment,
            ZoneEventType::CeilingCheck,
            ZoneEventType::ZoneTransition,
        ];
        let mut jsons = BTreeSet::new();
        for v in variants {
            jsons.insert(serde_json::to_string(&v).expect("serde deserialization should succeed"));
        }
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn zone_event_outcome_serde_distinct() {
        let variants = [
            ZoneEventOutcome::Pass,
            ZoneEventOutcome::Assigned,
            ZoneEventOutcome::Migrated,
            ZoneEventOutcome::CeilingExceeded,
            ZoneEventOutcome::Denied,
        ];
        let mut jsons = BTreeSet::new();
        for v in variants {
            jsons.insert(serde_json::to_string(&v).expect("serde deserialization should succeed"));
        }
        assert_eq!(jsons.len(), 5);
    }

    #[test]
    fn trust_zone_error_serde_distinct_all_variants() {
        let variants: Vec<TrustZoneError> = vec![
            TrustZoneError::ZoneAlreadyExists {
                zone_name: "z".into(),
            },
            TrustZoneError::ParentZoneMissing {
                zone_name: "z".into(),
                parent_zone: "p".into(),
            },
            TrustZoneError::ZoneMissing {
                zone_name: "z".into(),
            },
            TrustZoneError::CeilingExceedsParent {
                zone_name: "z".into(),
                exceeded: BTreeSet::new(),
            },
            TrustZoneError::CapabilityCeilingExceeded {
                zone_name: "z".into(),
                requested: BTreeSet::new(),
                ceiling: BTreeSet::new(),
            },
            TrustZoneError::PolicyGateDenied {
                entity_id: "e".into(),
                from_zone: "a".into(),
                to_zone: "b".into(),
            },
        ];
        let mut jsons = BTreeSet::new();
        for v in &variants {
            jsons.insert(serde_json::to_string(v).expect("serde deserialization should succeed"));
        }
        assert_eq!(jsons.len(), 6);
    }

    // ── Clone independence ──────────────────────────────────────────

    #[test]
    fn trust_zone_clone_independence() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("team")
            .expect("serde deserialization should succeed");
        let mut cloned = zone.clone();
        cloned.zone_name = "mutated".into();
        assert_eq!(zone.zone_name, "team");
        assert_ne!(zone.zone_name, cloned.zone_name);
    }

    #[test]
    fn zone_hierarchy_clone_independence() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let mut cloned = hierarchy.clone();
        cloned
            .assign_entity("ext-clone-test", "owner", "trace-clone")
            .expect("serde deserialization should succeed");
        // Original should have no events (beyond creation), clone has one
        assert!(hierarchy.events().is_empty());
        assert!(!cloned.events().is_empty());
    }

    #[test]
    fn zone_create_request_clone_independence() {
        let req = ZoneCreateRequest::new("orig", TrustZoneClass::Team, 1, "admin");
        let mut cloned = req.clone();
        cloned.zone_name = "mutated".into();
        assert_eq!(req.zone_name, "orig");
    }

    #[test]
    fn zone_transition_request_clone_independence() {
        let req = ZoneTransitionRequest::new("ent-1", "team", "t", "p", "d", true);
        let mut cloned = req.clone();
        cloned.entity_id = "ent-mutated".into();
        assert_eq!(req.entity_id, "ent-1");
    }

    #[test]
    fn zone_event_clone_independence() {
        let event = ZoneEvent::base("trace-1", ZoneEventType::Assignment, ZoneEventOutcome::Pass);
        let mut cloned = event.clone();
        cloned.trace_id = "trace-mutated".into();
        assert_eq!(event.trace_id, "trace-1");
    }

    #[test]
    fn trust_zone_error_clone_independence() {
        let err = TrustZoneError::ZoneAlreadyExists {
            zone_name: "orig".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        // They are equal but independent allocations
        if let TrustZoneError::ZoneAlreadyExists { zone_name } = &cloned {
            assert_eq!(zone_name, "orig");
        }
    }

    // ── JSON field-name stability ───────────────────────────────────

    #[test]
    fn trust_zone_class_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&TrustZoneClass::Owner)
                .expect("serde deserialization should succeed"),
            "\"owner\""
        );
        assert_eq!(
            serde_json::to_string(&TrustZoneClass::Private)
                .expect("serde deserialization should succeed"),
            "\"private\""
        );
        assert_eq!(
            serde_json::to_string(&TrustZoneClass::Team)
                .expect("serde deserialization should succeed"),
            "\"team\""
        );
        assert_eq!(
            serde_json::to_string(&TrustZoneClass::Community)
                .expect("serde deserialization should succeed"),
            "\"community\""
        );
    }

    #[test]
    fn zone_event_type_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&ZoneEventType::Assignment)
                .expect("serde deserialization should succeed"),
            "\"assignment\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventType::CeilingCheck)
                .expect("serde deserialization should succeed"),
            "\"ceiling_check\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventType::ZoneTransition)
                .expect("serde deserialization should succeed"),
            "\"zone_transition\""
        );
    }

    #[test]
    fn zone_event_outcome_serde_snake_case_field_values() {
        assert_eq!(
            serde_json::to_string(&ZoneEventOutcome::Pass)
                .expect("serde deserialization should succeed"),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventOutcome::Assigned)
                .expect("serde deserialization should succeed"),
            "\"assigned\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventOutcome::Migrated)
                .expect("serde deserialization should succeed"),
            "\"migrated\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventOutcome::CeilingExceeded)
                .expect("serde deserialization should succeed"),
            "\"ceiling_exceeded\""
        );
        assert_eq!(
            serde_json::to_string(&ZoneEventOutcome::Denied)
                .expect("serde deserialization should succeed"),
            "\"denied\""
        );
    }

    #[test]
    fn trust_zone_json_field_names() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("owner")
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(zone).expect("serde deserialization should succeed");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("zone_id"));
        assert!(obj.contains_key("zone_name"));
        assert!(obj.contains_key("class"));
        assert!(obj.contains_key("parent_zone"));
        assert!(obj.contains_key("policy_version"));
        assert!(obj.contains_key("created_by"));
        assert!(obj.contains_key("declared_ceiling"));
        assert!(obj.contains_key("effective_ceiling"));
        assert_eq!(obj.len(), 8);
    }

    #[test]
    fn zone_create_request_json_field_names() {
        let req = ZoneCreateRequest::new("z", TrustZoneClass::Team, 1, "a")
            .with_parent("p")
            .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch]));
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("zone_name"));
        assert!(obj.contains_key("class"));
        assert!(obj.contains_key("parent_zone_name"));
        assert!(obj.contains_key("declared_ceiling"));
        assert!(obj.contains_key("policy_version"));
        assert!(obj.contains_key("created_by"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn zone_transition_request_json_field_names() {
        let req = ZoneTransitionRequest::new("e", "z", "t", "p", "d", true);
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("entity_id"));
        assert!(obj.contains_key("to_zone_name"));
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_gate_approved"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn zone_event_json_field_names() {
        let event = ZoneEvent::base(
            "trace-1",
            ZoneEventType::Assignment,
            ZoneEventOutcome::Assigned,
        );
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("error_code"));
        assert!(obj.contains_key("entity_id"));
        assert!(obj.contains_key("zone_name"));
        assert!(obj.contains_key("from_zone"));
        assert!(obj.contains_key("to_zone"));
        assert_eq!(obj.len(), 11);
    }

    #[test]
    fn zone_hierarchy_json_field_names() {
        let hierarchy = ZoneHierarchy::new("default");
        let json = serde_json::to_string(&hierarchy).expect("serde deserialization should succeed");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        let obj = v.as_object().expect("serde deserialization should succeed");
        assert!(obj.contains_key("zones"));
        assert!(obj.contains_key("assignments"));
        assert!(obj.contains_key("default_zone"));
        assert!(obj.contains_key("events"));
        assert_eq!(obj.len(), 4);
    }

    // ── Display format checks ───────────────────────────────────────

    #[test]
    fn trust_zone_class_display_exact_values() {
        assert_eq!(TrustZoneClass::Owner.to_string(), "owner");
        assert_eq!(TrustZoneClass::Private.to_string(), "private");
        assert_eq!(TrustZoneClass::Team.to_string(), "team");
        assert_eq!(TrustZoneClass::Community.to_string(), "community");
    }

    #[test]
    fn trust_zone_error_display_zone_already_exists_format() {
        let err = TrustZoneError::ZoneAlreadyExists {
            zone_name: "alpha".into(),
        };
        assert_eq!(err.to_string(), "zone already exists: alpha");
    }

    #[test]
    fn trust_zone_error_display_parent_missing_format() {
        let err = TrustZoneError::ParentZoneMissing {
            zone_name: "child".into(),
            parent_zone: "missing-parent".into(),
        };
        assert_eq!(
            err.to_string(),
            "cannot create zone 'child': missing parent zone 'missing-parent'"
        );
    }

    #[test]
    fn trust_zone_error_display_zone_missing_format() {
        let err = TrustZoneError::ZoneMissing {
            zone_name: "ghost".into(),
        };
        assert_eq!(err.to_string(), "unknown zone: ghost");
    }

    #[test]
    fn trust_zone_error_display_policy_gate_denied_format() {
        let err = TrustZoneError::PolicyGateDenied {
            entity_id: "ext-99".into(),
            from_zone: "community".into(),
            to_zone: "owner".into(),
        };
        let msg = err.to_string();
        assert!(msg.starts_with("policy gate denied"));
        assert!(msg.contains("ext-99"));
        assert!(msg.contains("community"));
        assert!(msg.contains("owner"));
    }

    #[test]
    fn trust_zone_error_display_id_derivation() {
        let id_err = IdError::EmptyCanonicalBytes;
        let err = TrustZoneError::IdDerivation(id_err);
        let msg = err.to_string();
        assert!(msg.contains("zone id derivation failed"));
    }

    // ── Boundary / edge cases ───────────────────────────────────────

    #[test]
    fn zone_hierarchy_empty_default_zone() {
        let hierarchy = ZoneHierarchy::new("");
        assert_eq!(hierarchy.events().len(), 0);
        // Looking up entity should fail because the empty default zone does not exist
        let err = hierarchy.zone_for_entity("anything").unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    }

    #[test]
    fn zone_create_request_empty_name() {
        let mut hierarchy = ZoneHierarchy::new("community");
        // Empty zone name should still work (no validation against empty names)
        let result = hierarchy.add_zone(ZoneCreateRequest::new(
            "",
            TrustZoneClass::Community,
            1,
            "admin",
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn zone_create_request_max_policy_version() {
        let mut hierarchy = ZoneHierarchy::new("community");
        let result = hierarchy.add_zone(ZoneCreateRequest::new(
            "max-ver",
            TrustZoneClass::Owner,
            u64::MAX,
            "admin",
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn zone_create_request_zero_policy_version() {
        let mut hierarchy = ZoneHierarchy::new("community");
        let result = hierarchy.add_zone(ZoneCreateRequest::new(
            "zero-ver",
            TrustZoneClass::Owner,
            0,
            "admin",
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_ceiling_with_empty_requested_set() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        // Empty set should always pass (empty is subset of everything)
        hierarchy
            .enforce_ceiling("community", &BTreeSet::new(), "trace-empty")
            .expect("serde deserialization should succeed");
    }

    #[test]
    fn enforce_ceiling_missing_zone() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let err = hierarchy
            .enforce_ceiling("nonexistent", &BTreeSet::new(), "t")
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    }

    #[test]
    fn assign_entity_empty_entity_id() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("", "community", "t")
            .expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone_for_entity("")
            .expect("serde deserialization should succeed");
        assert_eq!(zone.zone_name, "community");
    }

    #[test]
    fn assign_entity_reassignment_updates_zone() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "team", "t2")
            .expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone_for_entity("ext-1")
            .expect("serde deserialization should succeed");
        assert_eq!(zone.zone_name, "team");
    }

    #[test]
    fn drain_events_returns_empty_when_no_events() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let events = hierarchy.drain_events();
        assert!(events.is_empty());
    }

    #[test]
    fn drain_events_twice_second_is_empty() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t")
            .expect("serde deserialization should succeed");
        let events1 = hierarchy.drain_events();
        assert!(!events1.is_empty());
        let events2 = hierarchy.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn zone_allows_exact_ceiling() {
        // Requesting exactly the full ceiling should pass
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let community = hierarchy
            .zone("community")
            .expect("serde deserialization should succeed");
        let full_ceiling = community.effective_ceiling.clone();
        assert!(community.allows(&full_ceiling));
    }

    #[test]
    fn zone_allows_single_extra_beyond_ceiling_fails() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let community = hierarchy
            .zone("community")
            .expect("serde deserialization should succeed");
        let mut requested = community.effective_ceiling.clone();
        requested.insert(RuntimeCapability::FsWrite);
        assert!(!community.allows(&requested));
    }

    // ── Serde roundtrips (complex structs) ──────────────────────────

    #[test]
    fn zone_hierarchy_with_assignments_serde_roundtrip() {
        let mut hierarchy =
            ZoneHierarchy::standard("admin", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-2", "team", "t2")
            .expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-3", "private", "t3")
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&hierarchy).expect("serde deserialization should succeed");
        let back: ZoneHierarchy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hierarchy, back);
    }

    #[test]
    fn zone_hierarchy_with_events_serde_roundtrip() {
        let mut hierarchy =
            ZoneHierarchy::standard("admin", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        hierarchy
            .enforce_ceiling("community", &capset(&[RuntimeCapability::VmDispatch]), "t2")
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&hierarchy).expect("serde deserialization should succeed");
        let back: ZoneHierarchy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hierarchy, back);
    }

    #[test]
    fn trust_zone_error_serde_roundtrip_all_variants() {
        let variants: Vec<TrustZoneError> = vec![
            TrustZoneError::ZoneAlreadyExists {
                zone_name: "z".into(),
            },
            TrustZoneError::ParentZoneMissing {
                zone_name: "z".into(),
                parent_zone: "p".into(),
            },
            TrustZoneError::ZoneMissing {
                zone_name: "z".into(),
            },
            TrustZoneError::CeilingExceedsParent {
                zone_name: "z".into(),
                exceeded: capset(&[RuntimeCapability::FsWrite, RuntimeCapability::NetworkEgress]),
            },
            TrustZoneError::CapabilityCeilingExceeded {
                zone_name: "z".into(),
                requested: capset(&[RuntimeCapability::FsWrite]),
                ceiling: capset(&[RuntimeCapability::VmDispatch]),
            },
            TrustZoneError::PolicyGateDenied {
                entity_id: "e".into(),
                from_zone: "a".into(),
                to_zone: "b".into(),
            },
        ];
        for err in &variants {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let back: TrustZoneError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(&back, err);
        }
    }

    #[test]
    fn zone_event_with_all_fields_set_serde_roundtrip() {
        let event = ZoneEvent {
            trace_id: "trace-123".into(),
            decision_id: Some("dec-456".into()),
            policy_id: Some("pol-789".into()),
            component: "trust_zone".into(),
            event: ZoneEventType::ZoneTransition,
            outcome: ZoneEventOutcome::Migrated,
            error_code: Some("FE-6001".into()),
            entity_id: Some("ext-alpha".into()),
            zone_name: Some("team".into()),
            from_zone: Some("community".into()),
            to_zone: Some("private".into()),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: ZoneEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, event);
    }

    #[test]
    fn zone_event_minimal_fields_serde_roundtrip() {
        let event = ZoneEvent::base("t", ZoneEventType::Assignment, ZoneEventOutcome::Pass);
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: ZoneEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, event);
    }

    // ── Additional edge cases & behavioral tests ────────────────────

    #[test]
    fn zone_id_differs_per_zone_in_standard_hierarchy() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let mut zone_ids = BTreeSet::new();
        for class in TrustZoneClass::ORDERED {
            let zone = hierarchy
                .zone(class.as_str())
                .expect("serde deserialization should succeed");
            zone_ids.insert(zone.zone_id.clone());
        }
        assert_eq!(zone_ids.len(), 4, "all 4 zones should have distinct IDs");
    }

    #[test]
    fn zone_scoped_id_differs_by_domain() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("team")
            .expect("serde deserialization should succeed");
        let schema = SchemaId::from_definition(b"test-domain-v1");
        let id_a =
            derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, b"data")
                .expect("serde deserialization should succeed");
        let id_b = derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, b"data")
            .expect("serde deserialization should succeed");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn zone_scoped_id_differs_by_canonical_bytes() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let zone = hierarchy
            .zone("owner")
            .expect("serde deserialization should succeed");
        let schema = SchemaId::from_definition(b"test-schema-v1");
        let id_a =
            derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, b"data-a")
                .expect("serde deserialization should succeed");
        let id_b =
            derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, b"data-b")
                .expect("serde deserialization should succeed");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn transition_approved_then_denied_preserves_first_move() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");

        // Approve transition to team
        hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-1", "team", "t2", "p", "d1", true,
            ))
            .expect("serde deserialization should succeed");
        assert_eq!(
            hierarchy
                .zone_for_entity("ext-1")
                .expect("serde deserialization should succeed")
                .zone_name,
            "team"
        );

        // Deny transition to owner
        let err = hierarchy
            .transition_entity(ZoneTransitionRequest::new(
                "ext-1", "owner", "t3", "p", "d2", false,
            ))
            .unwrap_err();
        assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
        // Should still be in team
        assert_eq!(
            hierarchy
                .zone_for_entity("ext-1")
                .expect("serde deserialization should succeed")
                .zone_name,
            "team"
        );
    }

    #[test]
    fn multiple_entities_independent_assignments() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-2", "team", "t2")
            .expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-3", "owner", "t3")
            .expect("serde deserialization should succeed");
        assert_eq!(
            hierarchy
                .zone_for_entity("ext-1")
                .expect("serde deserialization should succeed")
                .zone_name,
            "community"
        );
        assert_eq!(
            hierarchy
                .zone_for_entity("ext-2")
                .expect("serde deserialization should succeed")
                .zone_name,
            "team"
        );
        assert_eq!(
            hierarchy
                .zone_for_entity("ext-3")
                .expect("serde deserialization should succeed")
                .zone_name,
            "owner"
        );
    }

    #[test]
    fn event_count_matches_operations() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        assert_eq!(hierarchy.events().len(), 0);

        hierarchy
            .assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        assert_eq!(hierarchy.events().len(), 1);

        hierarchy
            .enforce_ceiling("community", &capset(&[RuntimeCapability::VmDispatch]), "t2")
            .expect("serde deserialization should succeed");
        assert_eq!(hierarchy.events().len(), 2);

        // Failed enforce should also emit an event
        let _ =
            hierarchy.enforce_ceiling("community", &capset(&[RuntimeCapability::FsWrite]), "t3");
        assert_eq!(hierarchy.events().len(), 3);
    }

    #[test]
    fn zone_with_declared_ceiling_empty_set() {
        let mut hierarchy = ZoneHierarchy::new("community");
        hierarchy
            .add_zone(ZoneCreateRequest::new(
                "owner",
                TrustZoneClass::Owner,
                1,
                "root",
            ))
            .expect("serde deserialization should succeed");
        // Child with empty declared ceiling => effective is intersection of empty + parent = empty
        hierarchy
            .add_zone(
                ZoneCreateRequest::new("child", TrustZoneClass::Private, 1, "root")
                    .with_parent("owner")
                    .with_declared_ceiling(BTreeSet::new()),
            )
            .expect("serde deserialization should succeed");
        let child = hierarchy
            .zone("child")
            .expect("serde deserialization should succeed");
        assert!(child.effective_ceiling.is_empty());
    }

    #[test]
    fn parent_zone_field_set_correctly() {
        let hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let owner = hierarchy
            .zone("owner")
            .expect("serde deserialization should succeed");
        assert!(owner.parent_zone.is_none());

        let private = hierarchy
            .zone("private")
            .expect("serde deserialization should succeed");
        assert_eq!(private.parent_zone, Some(owner.zone_id.clone()));
    }

    #[test]
    fn created_by_preserved_in_zone() {
        let hierarchy = ZoneHierarchy::standard("test-creator", 1)
            .expect("serde deserialization should succeed");
        for class in TrustZoneClass::ORDERED {
            let zone = hierarchy
                .zone(class.as_str())
                .expect("serde deserialization should succeed");
            assert_eq!(zone.created_by, "test-creator");
        }
    }

    #[test]
    fn zone_event_component_is_trust_zone() {
        let mut hierarchy =
            ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        hierarchy
            .assign_entity("ext-1", "community", "t")
            .expect("serde deserialization should succeed");
        for event in hierarchy.events() {
            assert_eq!(event.component, "trust_zone");
        }
    }

    #[test]
    fn standard_hierarchy_policy_version_propagated() {
        let hierarchy =
            ZoneHierarchy::standard("m", 42).expect("serde deserialization should succeed");
        for class in TrustZoneClass::ORDERED {
            let zone = hierarchy
                .zone(class.as_str())
                .expect("serde deserialization should succeed");
            assert_eq!(zone.policy_version, 42);
        }
    }

    #[test]
    fn from_id_error_conversion() {
        let id_err = IdError::EmptyCanonicalBytes;
        let zone_err: TrustZoneError = id_err.into();
        assert!(matches!(zone_err, TrustZoneError::IdDerivation(_)));
    }

    #[test]
    fn zone_hierarchy_deterministic_serialization_with_events() {
        let mut a = ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        let mut b = ZoneHierarchy::standard("m", 1).expect("serde deserialization should succeed");
        a.assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        b.assign_entity("ext-1", "community", "t1")
            .expect("serde deserialization should succeed");
        let json_a = serde_json::to_string(&a).expect("serde deserialization should succeed");
        let json_b = serde_json::to_string(&b).expect("serde deserialization should succeed");
        assert_eq!(json_a, json_b);
    }
}
