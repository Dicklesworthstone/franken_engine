//! Canonical shape-transition algebra and property-cell invalidation receipts.
//!
//! This module provides a deterministic, serializable foundation for object
//! shape transitions. It is intentionally compact so runtime surfaces can
//! expose shape history, invalidation receipts, and artifact bundles without
//! depending on the full object-model track.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    path::{Path, PathBuf},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const COMPONENT: &str = "shape_transition_algebra";
pub const SHAPE_LATTICE_SCHEMA_VERSION: &str = "frankenengine.shape-lattice.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PropertyAttributes {
    pub writable: bool,
    pub enumerable: bool,
    pub configurable: bool,
}

impl Default for PropertyAttributes {
    fn default() -> Self {
        Self {
            writable: true,
            enumerable: true,
            configurable: true,
        }
    }
}

impl PropertyAttributes {
    pub fn frozen() -> Self {
        Self {
            writable: false,
            enumerable: true,
            configurable: false,
        }
    }

    pub fn sealed() -> Self {
        Self {
            writable: true,
            enumerable: true,
            configurable: false,
        }
    }

    pub fn non_enumerable() -> Self {
        Self {
            writable: true,
            enumerable: false,
            configurable: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PropertyLayoutDescriptor {
    pub property_key: String,
    pub slot_index: usize,
    pub attributes: PropertyAttributes,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ShapeDescriptor {
    pub shape_id: u64,
    pub fingerprint: String,
    pub prototype_fingerprint: Option<String>,
    pub property_layout: Vec<PropertyLayoutDescriptor>,
}

impl ShapeDescriptor {
    pub fn property_count(&self) -> usize {
        self.property_layout.len()
    }

    pub fn slot_for(&self, key: &str) -> Option<usize> {
        self.property_layout
            .iter()
            .find(|d| d.property_key == key)
            .map(|d| d.slot_index)
    }

    pub fn keys(&self) -> Vec<String> {
        self.property_layout
            .iter()
            .map(|d| d.property_key.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransitionKind {
    AddProperty,
    DeleteProperty,
    ReconfigureProperty,
    PropertyCellWrite,
    PrototypeWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvalidatedAssumptionKind {
    ShapeGuard,
    PropertyCell,
    PropertyDescriptor,
    PrototypeChain,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PropertyCellInvalidationReceipt {
    pub receipt_id: String,
    pub transition_kind: TransitionKind,
    pub invalidated_assumptions: Vec<InvalidatedAssumptionKind>,
    pub property_key: Option<String>,
    pub from_shape_id: u64,
    pub to_shape_id: u64,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ShapeTransition {
    pub from_shape_id: u64,
    pub to_shape_id: u64,
    pub transition_kind: TransitionKind,
    pub property_key: Option<String>,
    pub property_layout: Option<PropertyLayoutDescriptor>,
    pub prototype_fingerprint: Option<String>,
    pub invalidation_receipt: PropertyCellInvalidationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ShapeMutation {
    AddProperty {
        key: String,
        attributes: PropertyAttributes,
    },
    DeleteProperty {
        key: String,
    },
    ReconfigureProperty {
        key: String,
        attributes: PropertyAttributes,
    },
    WritePropertyCell {
        key: String,
    },
    WritePrototype {
        prototype_fingerprint: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeMutationOutcome {
    pub shape: ShapeDescriptor,
    pub transition: ShapeTransition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeManifest {
    pub schema_version: String,
    pub component: String,
    pub root_shape_id: u64,
    pub shapes: Vec<ShapeDescriptor>,
    pub transitions: Vec<ShapeTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeTraceEvent {
    pub trace_id: String,
    pub component: String,
    pub step: u64,
    pub object_id: u32,
    pub from_shape_id: u64,
    pub to_shape_id: u64,
    pub to_shape_fingerprint: String,
    pub transition_kind: TransitionKind,
    pub property_key: Option<String>,
    pub invalidation_receipt: PropertyCellInvalidationReceipt,
    pub property_cell_revision_before: Option<u64>,
    pub property_cell_revision_after: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeArtifactPaths {
    pub shape_lattice_manifest: String,
    pub run_manifest: String,
    pub events: String,
    pub commands: String,
    pub trace_ids: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeTraceIds {
    pub trace_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeRunManifest {
    pub schema_version: String,
    pub component: String,
    pub generated_at_utc: String,
    pub trace_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub policy_ids: Vec<String>,
    pub shape_count: usize,
    pub transition_count: usize,
    pub receipt_count: usize,
    pub artifact_paths: ShapeLatticeArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeBundle {
    pub manifest: ShapeLatticeManifest,
    pub trace_events: Vec<ShapeTraceEvent>,
    pub trace_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub policy_ids: Vec<String>,
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLatticeBundleReport {
    pub artifact_dir: PathBuf,
    pub shape_lattice_manifest_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub trace_ids_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ShapeAlgebraError {
    #[error("unknown shape `{shape_id}`")]
    UnknownShape { shape_id: u64 },
    #[error("property `{key}` already exists on shape `{shape_id}`")]
    PropertyAlreadyExists { shape_id: u64, key: String },
    #[error("property `{key}` not present on shape `{shape_id}`")]
    MissingProperty { shape_id: u64, key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct ShapeSkeleton {
    prototype_fingerprint: Option<String>,
    property_layout: Vec<PropertyLayoutDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct TransitionLookupKey {
    from_shape_id: u64,
    mutation: ShapeMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeTransitionAlgebra {
    root_shape_id: u64,
    shapes: BTreeMap<u64, ShapeDescriptor>,
    shape_index: BTreeMap<String, u64>,
    transition_table: BTreeMap<TransitionLookupKey, ShapeTransition>,
}

impl Default for ShapeTransitionAlgebra {
    fn default() -> Self {
        let mut shapes = BTreeMap::new();
        let mut shape_index = BTreeMap::new();
        let root = make_shape_descriptor(None, Vec::new());
        shape_index.insert(root.fingerprint.clone(), root.shape_id);
        shapes.insert(root.shape_id, root.clone());

        Self {
            root_shape_id: root.shape_id,
            shapes,
            shape_index,
            transition_table: BTreeMap::new(),
        }
    }
}

impl ShapeTransitionAlgebra {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn root_shape_id(&self) -> u64 {
        self.root_shape_id
    }

    pub fn shape(&self, shape_id: u64) -> Option<&ShapeDescriptor> {
        self.shapes.get(&shape_id)
    }

    pub fn manifest(&self) -> ShapeLatticeManifest {
        ShapeLatticeManifest {
            schema_version: SHAPE_LATTICE_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            root_shape_id: self.root_shape_id,
            shapes: self.shapes.values().cloned().collect(),
            transitions: self.transition_table.values().cloned().collect(),
        }
    }

    pub fn apply_mutation(
        &mut self,
        shape_id: u64,
        mutation: ShapeMutation,
    ) -> Result<ShapeMutationOutcome, ShapeAlgebraError> {
        let lookup_key = TransitionLookupKey {
            from_shape_id: shape_id,
            mutation: mutation.clone(),
        };
        if let Some(existing) = self.transition_table.get(&lookup_key).cloned() {
            let shape = self.shapes.get(&existing.to_shape_id).cloned().ok_or(
                ShapeAlgebraError::UnknownShape {
                    shape_id: existing.to_shape_id,
                },
            )?;
            return Ok(ShapeMutationOutcome {
                shape,
                transition: existing,
            });
        }

        let base_shape = self
            .shapes
            .get(&shape_id)
            .cloned()
            .ok_or(ShapeAlgebraError::UnknownShape { shape_id })?;

        let (
            next_shape,
            transition_kind,
            property_key,
            property_layout,
            prototype_fingerprint,
            invalidated_assumptions,
        ) = match mutation {
            ShapeMutation::AddProperty { key, attributes } => {
                if base_shape
                    .property_layout
                    .iter()
                    .any(|descriptor| descriptor.property_key == key)
                {
                    return Err(ShapeAlgebraError::PropertyAlreadyExists { shape_id, key });
                }

                let mut property_layout = base_shape.property_layout.clone();
                let descriptor = PropertyLayoutDescriptor {
                    property_key: key.clone(),
                    slot_index: property_layout.len(),
                    attributes,
                };
                property_layout.push(descriptor.clone());
                (
                    self.intern_shape(base_shape.prototype_fingerprint.clone(), property_layout),
                    TransitionKind::AddProperty,
                    Some(key),
                    Some(descriptor),
                    base_shape.prototype_fingerprint.clone(),
                    vec![
                        InvalidatedAssumptionKind::ShapeGuard,
                        InvalidatedAssumptionKind::PropertyCell,
                    ],
                )
            }
            ShapeMutation::DeleteProperty { key } => {
                let retained = base_shape
                    .property_layout
                    .iter()
                    .filter(|descriptor| descriptor.property_key != key)
                    .map(|descriptor| descriptor.property_key.clone())
                    .collect::<Vec<_>>();
                if retained.len() == base_shape.property_layout.len() {
                    return Err(ShapeAlgebraError::MissingProperty { shape_id, key });
                }

                let property_layout = retained
                    .into_iter()
                    .enumerate()
                    .map(|(slot_index, property_key)| {
                        let descriptor = base_shape
                            .property_layout
                            .iter()
                            .find(|descriptor| descriptor.property_key == property_key)
                            .expect("retained property must exist");
                        PropertyLayoutDescriptor {
                            property_key,
                            slot_index,
                            attributes: descriptor.attributes,
                        }
                    })
                    .collect::<Vec<_>>();
                (
                    self.intern_shape(base_shape.prototype_fingerprint.clone(), property_layout),
                    TransitionKind::DeleteProperty,
                    Some(key),
                    None,
                    base_shape.prototype_fingerprint.clone(),
                    vec![
                        InvalidatedAssumptionKind::ShapeGuard,
                        InvalidatedAssumptionKind::PropertyCell,
                        InvalidatedAssumptionKind::PropertyDescriptor,
                    ],
                )
            }
            ShapeMutation::ReconfigureProperty { key, attributes } => {
                let mut found = false;
                let property_layout = base_shape
                    .property_layout
                    .iter()
                    .map(|descriptor| {
                        if descriptor.property_key == key {
                            found = true;
                            PropertyLayoutDescriptor {
                                property_key: descriptor.property_key.clone(),
                                slot_index: descriptor.slot_index,
                                attributes,
                            }
                        } else {
                            descriptor.clone()
                        }
                    })
                    .collect::<Vec<_>>();
                if !found {
                    return Err(ShapeAlgebraError::MissingProperty { shape_id, key });
                }
                let next_shape =
                    self.intern_shape(base_shape.prototype_fingerprint.clone(), property_layout);
                let descriptor = next_shape
                    .property_layout
                    .iter()
                    .find(|descriptor| descriptor.property_key == key)
                    .cloned();
                (
                    next_shape,
                    TransitionKind::ReconfigureProperty,
                    Some(key),
                    descriptor,
                    base_shape.prototype_fingerprint.clone(),
                    vec![
                        InvalidatedAssumptionKind::ShapeGuard,
                        InvalidatedAssumptionKind::PropertyCell,
                        InvalidatedAssumptionKind::PropertyDescriptor,
                    ],
                )
            }
            ShapeMutation::WritePropertyCell { key } => {
                let descriptor = base_shape
                    .property_layout
                    .iter()
                    .find(|descriptor| descriptor.property_key == key)
                    .cloned()
                    .ok_or(ShapeAlgebraError::MissingProperty {
                        shape_id,
                        key: key.clone(),
                    })?;
                (
                    base_shape.clone(),
                    TransitionKind::PropertyCellWrite,
                    Some(key),
                    Some(descriptor),
                    base_shape.prototype_fingerprint.clone(),
                    vec![InvalidatedAssumptionKind::PropertyCell],
                )
            }
            ShapeMutation::WritePrototype {
                prototype_fingerprint,
            } => {
                let assumptions = if prototype_fingerprint == base_shape.prototype_fingerprint {
                    Vec::new()
                } else {
                    vec![
                        InvalidatedAssumptionKind::ShapeGuard,
                        InvalidatedAssumptionKind::PrototypeChain,
                    ]
                };
                (
                    self.intern_shape(
                        prototype_fingerprint.clone(),
                        base_shape.property_layout.clone(),
                    ),
                    TransitionKind::PrototypeWrite,
                    None,
                    None,
                    prototype_fingerprint,
                    assumptions,
                )
            }
        };

        let receipt = build_invalidation_receipt(
            transition_kind.clone(),
            property_key.clone(),
            shape_id,
            next_shape.shape_id,
            &invalidated_assumptions,
        );
        let transition = ShapeTransition {
            from_shape_id: shape_id,
            to_shape_id: next_shape.shape_id,
            transition_kind,
            property_key,
            property_layout,
            prototype_fingerprint,
            invalidation_receipt: receipt,
        };
        self.transition_table.insert(lookup_key, transition.clone());
        Ok(ShapeMutationOutcome {
            shape: next_shape,
            transition,
        })
    }

    fn intern_shape(
        &mut self,
        prototype_fingerprint: Option<String>,
        property_layout: Vec<PropertyLayoutDescriptor>,
    ) -> ShapeDescriptor {
        let descriptor = make_shape_descriptor(prototype_fingerprint, property_layout);
        if let Some(existing_shape_id) = self.shape_index.get(&descriptor.fingerprint).copied() {
            return self
                .shapes
                .get(&existing_shape_id)
                .cloned()
                .expect("shape index and registry must stay aligned");
        }
        self.shape_index
            .insert(descriptor.fingerprint.clone(), descriptor.shape_id);
        self.shapes.insert(descriptor.shape_id, descriptor.clone());
        descriptor
    }
}

pub fn emit_shape_lattice_bundle(
    artifact_dir: &Path,
    bundle: &ShapeLatticeBundle,
) -> io::Result<ShapeLatticeBundleReport> {
    fs::create_dir_all(artifact_dir)?;

    let artifact_paths = ShapeLatticeArtifactPaths {
        shape_lattice_manifest: "shape_lattice_manifest.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events: "events.jsonl".to_string(),
        commands: "commands.txt".to_string(),
        trace_ids: "trace_ids.json".to_string(),
    };

    let trace_ids = ShapeLatticeTraceIds {
        trace_ids: bundle.trace_ids.clone(),
        decision_ids: bundle.decision_ids.clone(),
        policy_ids: bundle.policy_ids.clone(),
    };
    let receipt_count = bundle.trace_events.len();
    let run_manifest = ShapeLatticeRunManifest {
        schema_version: SHAPE_LATTICE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_ids: bundle.trace_ids.clone(),
        decision_ids: bundle.decision_ids.clone(),
        policy_ids: bundle.policy_ids.clone(),
        shape_count: bundle.manifest.shapes.len(),
        transition_count: bundle.manifest.transitions.len(),
        receipt_count,
        artifact_paths: artifact_paths.clone(),
    };

    let shape_lattice_manifest_path = artifact_dir.join(&artifact_paths.shape_lattice_manifest);
    let run_manifest_path = artifact_dir.join(&artifact_paths.run_manifest);
    let events_path = artifact_dir.join(&artifact_paths.events);
    let commands_path = artifact_dir.join(&artifact_paths.commands);
    let trace_ids_path = artifact_dir.join(&artifact_paths.trace_ids);

    fs::write(
        &shape_lattice_manifest_path,
        serde_json::to_vec_pretty(&bundle.manifest).expect("shape lattice manifest must serialize"),
    )?;
    fs::write(
        &run_manifest_path,
        serde_json::to_vec_pretty(&run_manifest)
            .expect("shape lattice run manifest must serialize"),
    )?;
    let event_lines = bundle
        .trace_events
        .iter()
        .map(|event| serde_json::to_string(event).expect("shape trace event must serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &events_path,
        if event_lines.is_empty() {
            String::new()
        } else {
            format!("{event_lines}\n")
        },
    )?;
    fs::write(
        &commands_path,
        if bundle.commands.is_empty() {
            String::new()
        } else {
            format!("{}\n", bundle.commands.join("\n"))
        },
    )?;
    fs::write(
        &trace_ids_path,
        serde_json::to_vec_pretty(&trace_ids).expect("shape trace ids must serialize"),
    )?;

    Ok(ShapeLatticeBundleReport {
        artifact_dir: artifact_dir.to_path_buf(),
        shape_lattice_manifest_path,
        run_manifest_path,
        events_path,
        commands_path,
        trace_ids_path,
    })
}

fn make_shape_descriptor(
    prototype_fingerprint: Option<String>,
    property_layout: Vec<PropertyLayoutDescriptor>,
) -> ShapeDescriptor {
    let skeleton = ShapeSkeleton {
        prototype_fingerprint: prototype_fingerprint.clone(),
        property_layout: property_layout.clone(),
    };
    let payload = serde_json::to_vec(&skeleton).expect("shape skeleton must serialize");
    let digest = Sha256::digest(payload);
    let fingerprint = hex::encode(digest);
    let mut shape_id_bytes = [0_u8; 8];
    shape_id_bytes.copy_from_slice(&digest[..8]);

    ShapeDescriptor {
        shape_id: u64::from_be_bytes(shape_id_bytes),
        fingerprint,
        prototype_fingerprint,
        property_layout,
    }
}

// ---------------------------------------------------------------------------
// PropertyCellState — state machine for property assumption tracking
// ---------------------------------------------------------------------------

/// State machine for property-cell invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropertyCellState {
    Uninitialised,
    Constant,
    Stable,
    Invalidated,
}

impl PropertyCellState {
    pub fn is_valid_for_ic(&self) -> bool {
        matches!(self, Self::Constant | Self::Stable)
    }

    pub fn on_write(&self, kind_changed: bool) -> Self {
        match self {
            Self::Uninitialised => Self::Constant,
            Self::Constant if kind_changed => Self::Invalidated,
            Self::Constant => Self::Stable,
            Self::Stable if kind_changed => Self::Invalidated,
            Self::Stable => Self::Stable,
            Self::Invalidated => Self::Invalidated,
        }
    }
}

impl fmt::Display for PropertyCellState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialised => write!(f, "uninitialised"),
            Self::Constant => write!(f, "constant"),
            Self::Stable => write!(f, "stable"),
            Self::Invalidated => write!(f, "invalidated"),
        }
    }
}

/// Tracks invalidation state of a single property on a specific shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyCellTracker {
    pub shape_id: u64,
    pub property_name: String,
    pub state: PropertyCellState,
    pub dependent_ic_count: u32,
    pub write_epoch: u64,
}

impl PropertyCellTracker {
    pub fn new(shape_id: u64, property_name: impl Into<String>) -> Self {
        Self {
            shape_id,
            property_name: property_name.into(),
            state: PropertyCellState::Uninitialised,
            dependent_ic_count: 0,
            write_epoch: 0,
        }
    }

    pub fn record_write(&mut self, kind_changed: bool) -> bool {
        let old = self.state;
        self.state = self.state.on_write(kind_changed);
        self.write_epoch = self.write_epoch.saturating_add(1);
        old != PropertyCellState::Invalidated && self.state == PropertyCellState::Invalidated
    }

    pub fn add_dependent(&mut self) {
        self.dependent_ic_count = self.dependent_ic_count.saturating_add(1);
    }
    pub fn remove_dependent(&mut self) {
        self.dependent_ic_count = self.dependent_ic_count.saturating_sub(1);
    }
}

impl fmt::Display for PropertyCellTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cell({}.{}: {}, deps={}, epoch={})",
            self.shape_id,
            self.property_name,
            self.state,
            self.dependent_ic_count,
            self.write_epoch
        )
    }
}

/// Table of property cell trackers for IC invalidation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PropertyCellTable {
    cells: Vec<PropertyCellTracker>,
    total_invalidations: u64,
}

impl PropertyCellTable {
    pub fn new() -> Self {
        Self {
            cells: Vec::new(),
            total_invalidations: 0,
        }
    }
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }
    pub fn total_invalidations(&self) -> u64 {
        self.total_invalidations
    }

    pub fn get_or_create(
        &mut self,
        shape_id: u64,
        property_name: &str,
    ) -> &mut PropertyCellTracker {
        let pos = self
            .cells
            .iter()
            .position(|c| c.shape_id == shape_id && c.property_name == property_name);
        if let Some(idx) = pos {
            &mut self.cells[idx]
        } else {
            self.cells
                .push(PropertyCellTracker::new(shape_id, property_name));
            self.cells.last_mut().expect("just pushed")
        }
    }

    pub fn get(&self, shape_id: u64, property_name: &str) -> Option<&PropertyCellTracker> {
        self.cells
            .iter()
            .find(|c| c.shape_id == shape_id && c.property_name == property_name)
    }

    pub fn record_write(&mut self, shape_id: u64, property_name: &str, kind_changed: bool) -> bool {
        let cell = self.get_or_create(shape_id, property_name);
        let invalidated = cell.record_write(kind_changed);
        if invalidated {
            self.total_invalidations = self.total_invalidations.saturating_add(1);
        }
        invalidated
    }

    pub fn invalidate_shape(&mut self, shape_id: u64) -> u32 {
        let mut count: u32 = 0;
        for cell in &mut self.cells {
            if cell.shape_id == shape_id && cell.state != PropertyCellState::Invalidated {
                cell.state = PropertyCellState::Invalidated;
                cell.write_epoch = cell.write_epoch.saturating_add(1);
                count += 1;
            }
        }
        if count > 0 {
            self.total_invalidations = self.total_invalidations.saturating_add(count as u64);
        }
        count
    }
}

// ---------------------------------------------------------------------------
// InlineCacheState — monomorphic/polymorphic/megamorphic IC progression
// ---------------------------------------------------------------------------

const MAX_POLYMORPHIC_IC_ENTRIES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicIcEntry {
    pub shape_id: u64,
    pub slot_offset: u32,
    pub hit_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InlineCacheState {
    Uninitialised,
    Monomorphic {
        shape_id: u64,
        slot_offset: u32,
        hit_count: u64,
    },
    Polymorphic {
        entries: Vec<PolymorphicIcEntry>,
        total_hits: u64,
    },
    Megamorphic {
        observed_shapes: u32,
        total_accesses: u64,
    },
}

impl InlineCacheState {
    pub fn record_access(&self, shape_id: u64, slot_offset: u32) -> (Self, bool) {
        match self {
            Self::Uninitialised => (
                Self::Monomorphic {
                    shape_id,
                    slot_offset,
                    hit_count: 1,
                },
                false,
            ),
            Self::Monomorphic {
                shape_id: cached,
                slot_offset: cached_off,
                hit_count,
            } => {
                if *cached == shape_id {
                    (
                        Self::Monomorphic {
                            shape_id,
                            slot_offset: *cached_off,
                            hit_count: hit_count.saturating_add(1),
                        },
                        false,
                    )
                } else {
                    let entries = vec![
                        PolymorphicIcEntry {
                            shape_id: *cached,
                            slot_offset: *cached_off,
                            hit_count: *hit_count,
                        },
                        PolymorphicIcEntry {
                            shape_id,
                            slot_offset,
                            hit_count: 1,
                        },
                    ];
                    (
                        Self::Polymorphic {
                            entries,
                            total_hits: hit_count.saturating_add(1),
                        },
                        true,
                    )
                }
            }
            Self::Polymorphic {
                entries,
                total_hits,
            } => {
                let mut new_entries = entries.clone();
                let new_total = total_hits.saturating_add(1);
                if let Some(entry) = new_entries.iter_mut().find(|e| e.shape_id == shape_id) {
                    entry.hit_count = entry.hit_count.saturating_add(1);
                    (
                        Self::Polymorphic {
                            entries: new_entries,
                            total_hits: new_total,
                        },
                        false,
                    )
                } else if new_entries.len() < MAX_POLYMORPHIC_IC_ENTRIES {
                    new_entries.push(PolymorphicIcEntry {
                        shape_id,
                        slot_offset,
                        hit_count: 1,
                    });
                    (
                        Self::Polymorphic {
                            entries: new_entries,
                            total_hits: new_total,
                        },
                        true,
                    )
                } else {
                    (
                        Self::Megamorphic {
                            observed_shapes: (entries.len() as u32).saturating_add(1),
                            total_accesses: new_total,
                        },
                        true,
                    )
                }
            }
            Self::Megamorphic {
                observed_shapes,
                total_accesses,
            } => (
                Self::Megamorphic {
                    observed_shapes: *observed_shapes,
                    total_accesses: total_accesses.saturating_add(1),
                },
                false,
            ),
        }
    }

    pub fn is_fast_path(&self) -> bool {
        matches!(self, Self::Monomorphic { .. } | Self::Polymorphic { .. })
    }
    pub fn is_megamorphic(&self) -> bool {
        matches!(self, Self::Megamorphic { .. })
    }

    pub fn hit_rate_millionths(&self) -> u64 {
        match self {
            Self::Uninitialised | Self::Megamorphic { .. } => 0,
            Self::Monomorphic { hit_count, .. } => {
                if *hit_count == 0 {
                    0
                } else {
                    1_000_000
                }
            }
            Self::Polymorphic {
                entries,
                total_hits,
            } => {
                if *total_hits == 0 {
                    return 0;
                }
                entries
                    .iter()
                    .map(|e| e.hit_count)
                    .max()
                    .unwrap_or(0)
                    .saturating_mul(1_000_000)
                    / total_hits
            }
        }
    }
}

impl fmt::Display for InlineCacheState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialised => write!(f, "IC:uninit"),
            Self::Monomorphic {
                shape_id,
                hit_count,
                ..
            } => write!(f, "IC:mono(shape={shape_id}, hits={hit_count})"),
            Self::Polymorphic {
                entries,
                total_hits,
            } => write!(f, "IC:poly(entries={}, hits={total_hits})", entries.len()),
            Self::Megamorphic {
                observed_shapes,
                total_accesses,
            } => write!(
                f,
                "IC:mega(shapes={observed_shapes}, accesses={total_accesses})"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// ShapeGuardWitness — deopt evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardFailureReason {
    ShapeMismatch {
        expected_shape_id: u64,
        actual_shape_id: u64,
    },
    CellInvalidated {
        shape_id: u64,
        property_name: String,
        cell_state: PropertyCellState,
    },
    DictionaryPromotion {
        shape_id: u64,
    },
    PrototypeChanged {
        shape_id: u64,
    },
    NonExtensible {
        shape_id: u64,
    },
}

impl fmt::Display for GuardFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeMismatch {
                expected_shape_id,
                actual_shape_id,
            } => write!(
                f,
                "shape mismatch: expected {expected_shape_id}, got {actual_shape_id}"
            ),
            Self::CellInvalidated {
                shape_id,
                property_name,
                cell_state,
            } => write!(
                f,
                "cell invalidated: shape {shape_id}.{property_name} state={cell_state}"
            ),
            Self::DictionaryPromotion { shape_id } => {
                write!(f, "dictionary promotion: shape {shape_id}")
            }
            Self::PrototypeChanged { shape_id } => write!(f, "prototype changed: shape {shape_id}"),
            Self::NonExtensible { shape_id } => write!(f, "non-extensible: shape {shape_id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeGuardWitness {
    pub instruction_offset: u32,
    pub reason: GuardFailureReason,
    pub ic_state_before: InlineCacheState,
    pub failure_count: u64,
    pub permanent_deopt: bool,
}

impl ShapeGuardWitness {
    pub fn new(
        instruction_offset: u32,
        reason: GuardFailureReason,
        ic_state: InlineCacheState,
        failure_count: u64,
    ) -> Self {
        Self {
            instruction_offset,
            reason,
            ic_state_before: ic_state,
            failure_count,
            permanent_deopt: false,
        }
    }
    pub fn mark_permanent(&mut self) {
        self.permanent_deopt = true;
    }
}

impl fmt::Display for ShapeGuardWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "guard_fail@{}: {} (failures={}, perm={})",
            self.instruction_offset, self.reason, self.failure_count, self.permanent_deopt
        )
    }
}

// ---------------------------------------------------------------------------
// InlineCacheTable — per-function IC state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InlineCacheTable {
    entries: BTreeMap<u32, InlineCacheState>,
    witnesses: Vec<ShapeGuardWitness>,
    total_hits: u64,
    total_misses: u64,
}

impl InlineCacheTable {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            witnesses: Vec::new(),
            total_hits: 0,
            total_misses: 0,
        }
    }
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn total_hits(&self) -> u64 {
        self.total_hits
    }
    pub fn total_misses(&self) -> u64 {
        self.total_misses
    }
    pub fn witnesses(&self) -> &[ShapeGuardWitness] {
        &self.witnesses
    }
    pub fn get(&self, offset: u32) -> Option<&InlineCacheState> {
        self.entries.get(&offset)
    }

    pub fn record_access(&mut self, offset: u32, shape_id: u64, slot_offset: u32) -> bool {
        let current = self
            .entries
            .get(&offset)
            .cloned()
            .unwrap_or(InlineCacheState::Uninitialised);
        let (new_state, degraded) = current.record_access(shape_id, slot_offset);
        if degraded {
            self.total_misses = self.total_misses.saturating_add(1);
        } else {
            self.total_hits = self.total_hits.saturating_add(1);
        }
        self.entries.insert(offset, new_state);
        !degraded
    }

    pub fn record_guard_failure(&mut self, instruction_offset: u32, reason: GuardFailureReason) {
        let ic_state = self
            .entries
            .get(&instruction_offset)
            .cloned()
            .unwrap_or(InlineCacheState::Uninitialised);
        let existing_count = self
            .witnesses
            .iter()
            .filter(|w| w.instruction_offset == instruction_offset)
            .count() as u64;
        self.witnesses.push(ShapeGuardWitness::new(
            instruction_offset,
            reason,
            ic_state,
            existing_count + 1,
        ));
        self.total_misses = self.total_misses.saturating_add(1);
    }

    pub fn hit_rate_millionths(&self) -> u64 {
        let total = self.total_hits.saturating_add(self.total_misses);
        if total == 0 {
            return 0;
        }
        self.total_hits.saturating_mul(1_000_000) / total
    }

    pub fn summary(&self) -> InlineCacheSummary {
        let (mut mono, mut poly, mut mega, mut uninit) = (0u32, 0u32, 0u32, 0u32);
        for state in self.entries.values() {
            match state {
                InlineCacheState::Uninitialised => uninit += 1,
                InlineCacheState::Monomorphic { .. } => mono += 1,
                InlineCacheState::Polymorphic { .. } => poly += 1,
                InlineCacheState::Megamorphic { .. } => mega += 1,
            }
        }
        InlineCacheSummary {
            entry_count: self.entries.len() as u32,
            monomorphic_count: mono,
            polymorphic_count: poly,
            megamorphic_count: mega,
            uninitialised_count: uninit,
            total_hits: self.total_hits,
            total_misses: self.total_misses,
            hit_rate_millionths: self.hit_rate_millionths(),
            witness_count: self.witnesses.len() as u32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineCacheSummary {
    pub entry_count: u32,
    pub monomorphic_count: u32,
    pub polymorphic_count: u32,
    pub megamorphic_count: u32,
    pub uninitialised_count: u32,
    pub total_hits: u64,
    pub total_misses: u64,
    pub hit_rate_millionths: u64,
    pub witness_count: u32,
}

impl ShapeTransitionAlgebra {
    pub fn all_property_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        for shape in self.shapes.values() {
            for d in &shape.property_layout {
                keys.insert(d.property_key.clone());
            }
        }
        keys
    }
    pub fn shape_count(&self) -> usize {
        self.shapes.len()
    }
    pub fn transition_count(&self) -> usize {
        self.transition_table.len()
    }

    pub fn shape_ids(&self) -> Vec<u64> {
        self.shapes.keys().copied().collect()
    }

    pub fn transitions_from(&self, shape_id: u64) -> Vec<&ShapeTransition> {
        self.transition_table
            .iter()
            .filter(|(k, _)| k.from_shape_id == shape_id)
            .map(|(_, v)| v)
            .collect()
    }

    pub fn lineage(&self, shape_id: u64) -> Result<ShapeLineage, ShapeAlgebraError> {
        if !self.shapes.contains_key(&shape_id) {
            return Err(ShapeAlgebraError::UnknownShape { shape_id });
        }
        let mut steps = Vec::new();
        let mut visited = BTreeSet::new();
        let mut current = shape_id;
        while visited.insert(current) {
            let parent_transition = self
                .transition_table
                .values()
                .find(|t| t.to_shape_id == current && t.from_shape_id != current);
            if let Some(t) = parent_transition {
                steps.push(LineageStep {
                    from_shape_id: t.from_shape_id,
                    to_shape_id: t.to_shape_id,
                    transition_kind: t.transition_kind.clone(),
                    property_key: t.property_key.clone(),
                });
                current = t.from_shape_id;
            } else {
                break;
            }
        }
        steps.reverse();
        Ok(ShapeLineage {
            leaf_shape_id: shape_id,
            depth: steps.len() as u32,
            steps,
        })
    }

    pub fn find_convergences(&self) -> Vec<ConvergenceWitness> {
        let mut incoming: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for t in self.transition_table.values() {
            if t.from_shape_id != t.to_shape_id {
                incoming
                    .entry(t.to_shape_id)
                    .or_default()
                    .push(t.from_shape_id);
            }
        }
        incoming
            .into_iter()
            .filter(|(_, sources)| sources.len() > 1)
            .map(|(target_shape_id, source_shape_ids)| ConvergenceWitness {
                target_shape_id,
                source_shape_ids,
            })
            .collect()
    }

    pub fn classify_deopt(&self, transition: &ShapeTransition) -> DeoptEvent {
        let trigger = match transition.transition_kind {
            TransitionKind::AddProperty | TransitionKind::DeleteProperty => {
                DeoptTrigger::ShapeTransition
            }
            TransitionKind::ReconfigureProperty => DeoptTrigger::DescriptorChange,
            TransitionKind::PropertyCellWrite => DeoptTrigger::CellInvalidation,
            TransitionKind::PrototypeWrite => DeoptTrigger::PrototypeMutation,
        };
        DeoptEvent {
            trigger,
            from_shape_id: transition.from_shape_id,
            to_shape_id: transition.to_shape_id,
            property_key: transition.property_key.clone(),
            invalidated_assumption_count: transition
                .invalidation_receipt
                .invalidated_assumptions
                .len() as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// Lineage / convergence / deopt types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageStep {
    pub from_shape_id: u64,
    pub to_shape_id: u64,
    pub transition_kind: TransitionKind,
    pub property_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeLineage {
    pub leaf_shape_id: u64,
    pub depth: u32,
    pub steps: Vec<LineageStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceWitness {
    pub target_shape_id: u64,
    pub source_shape_ids: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeoptTrigger {
    ShapeTransition,
    CellInvalidation,
    PrototypeMutation,
    DescriptorChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeoptEvent {
    pub trigger: DeoptTrigger,
    pub from_shape_id: u64,
    pub to_shape_id: u64,
    pub property_key: Option<String>,
    pub invalidated_assumption_count: u32,
}

// ---------------------------------------------------------------------------
// Corpus pattern
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapeTransitionSpecimen {
    pub label: String,
    pub mutations: Vec<ShapeMutation>,
    pub expected_shape_count: usize,
    pub expected_transition_count: usize,
}

pub fn shape_transition_corpus() -> Vec<ShapeTransitionSpecimen> {
    vec![
        ShapeTransitionSpecimen {
            label: "empty-object".into(),
            mutations: vec![],
            expected_shape_count: 1,
            expected_transition_count: 0,
        },
        ShapeTransitionSpecimen {
            label: "single-add".into(),
            mutations: vec![ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            }],
            expected_shape_count: 2,
            expected_transition_count: 1,
        },
        ShapeTransitionSpecimen {
            label: "add-then-delete".into(),
            mutations: vec![
                ShapeMutation::AddProperty {
                    key: "x".into(),
                    attributes: PropertyAttributes::default(),
                },
                ShapeMutation::DeleteProperty { key: "x".into() },
            ],
            expected_shape_count: 2,
            expected_transition_count: 2,
        },
        ShapeTransitionSpecimen {
            label: "add-two-properties".into(),
            mutations: vec![
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            ],
            expected_shape_count: 3,
            expected_transition_count: 2,
        },
        ShapeTransitionSpecimen {
            label: "add-and-reconfigure".into(),
            mutations: vec![
                ShapeMutation::AddProperty {
                    key: "p".into(),
                    attributes: PropertyAttributes::default(),
                },
                ShapeMutation::ReconfigureProperty {
                    key: "p".into(),
                    attributes: PropertyAttributes::frozen(),
                },
            ],
            expected_shape_count: 3,
            expected_transition_count: 2,
        },
        ShapeTransitionSpecimen {
            label: "cell-write-no-shape-change".into(),
            mutations: vec![
                ShapeMutation::AddProperty {
                    key: "v".into(),
                    attributes: PropertyAttributes::default(),
                },
                ShapeMutation::WritePropertyCell { key: "v".into() },
            ],
            expected_shape_count: 2,
            expected_transition_count: 2,
        },
        ShapeTransitionSpecimen {
            label: "prototype-write".into(),
            mutations: vec![ShapeMutation::WritePrototype {
                prototype_fingerprint: Some("proto-a".into()),
            }],
            expected_shape_count: 2,
            expected_transition_count: 1,
        },
        ShapeTransitionSpecimen {
            label: "same-prototype-write".into(),
            mutations: vec![ShapeMutation::WritePrototype {
                prototype_fingerprint: None,
            }],
            expected_shape_count: 1,
            expected_transition_count: 1,
        },
    ]
}

pub fn run_shape_transition_corpus() -> Vec<(String, bool, String)> {
    let mut results = Vec::new();
    for specimen in shape_transition_corpus() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let mut current_shape = algebra.root_shape_id();
        let mut ok = true;
        let mut detail = String::new();
        for mutation in &specimen.mutations {
            match algebra.apply_mutation(current_shape, mutation.clone()) {
                Ok(outcome) => {
                    current_shape = outcome.shape.shape_id;
                }
                Err(e) => {
                    ok = false;
                    detail = format!("mutation error: {e}");
                    break;
                }
            }
        }
        if ok {
            if algebra.shape_count() != specimen.expected_shape_count {
                ok = false;
                detail = format!(
                    "shape count: expected {}, got {}",
                    specimen.expected_shape_count,
                    algebra.shape_count()
                );
            } else if algebra.transition_count() != specimen.expected_transition_count {
                ok = false;
                detail = format!(
                    "transition count: expected {}, got {}",
                    specimen.expected_transition_count,
                    algebra.transition_count()
                );
            } else {
                detail = "pass".into();
            }
        }
        results.push((specimen.label.clone(), ok, detail));
    }
    results
}

fn build_invalidation_receipt(
    transition_kind: TransitionKind,
    property_key: Option<String>,
    from_shape_id: u64,
    to_shape_id: u64,
    invalidated_assumptions: &[InvalidatedAssumptionKind],
) -> PropertyCellInvalidationReceipt {
    #[derive(Serialize)]
    struct ReceiptSeed<'a> {
        transition_kind: &'a TransitionKind,
        property_key: &'a Option<String>,
        from_shape_id: u64,
        to_shape_id: u64,
        invalidated_assumptions: &'a [InvalidatedAssumptionKind],
    }

    let summary = if invalidated_assumptions.is_empty() {
        "no optimized assumptions invalidated".to_string()
    } else if let Some(property_key) = property_key.as_deref() {
        format!(
            "{transition_kind:?} on `{property_key}` invalidated {}",
            invalidated_assumptions
                .iter()
                .map(|assumption| format!("{assumption:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "{transition_kind:?} invalidated {}",
            invalidated_assumptions
                .iter()
                .map(|assumption| format!("{assumption:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut sorted_assumptions = invalidated_assumptions.to_vec();
    sorted_assumptions.sort();
    let payload = serde_json::to_vec(&ReceiptSeed {
        transition_kind: &transition_kind,
        property_key: &property_key,
        from_shape_id,
        to_shape_id,
        invalidated_assumptions: &sorted_assumptions,
    })
    .expect("receipt seed must serialize");
    let receipt_id = hex::encode(Sha256::digest(payload));

    PropertyCellInvalidationReceipt {
        receipt_id,
        transition_kind,
        invalidated_assumptions: invalidated_assumptions.to_vec(),
        property_key,
        from_shape_id,
        to_shape_id,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InvalidatedAssumptionKind, PropertyAttributes, ShapeLatticeBundle, ShapeMutation,
        ShapeTransitionAlgebra, TransitionKind, emit_shape_lattice_bundle,
    };
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_artifact_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        env::temp_dir().join(format!("franken-shape-{label}-{nanos}"))
    }

    #[test]
    fn canonical_shape_ids_are_reused_for_identical_layouts() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let first = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let second = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();

        assert_eq!(first.shape.shape_id, second.shape.shape_id);
        assert_eq!(first.shape.fingerprint, second.shape.fingerprint);
        assert_eq!(first.transition, second.transition);
    }

    #[test]
    fn delete_property_reindexes_slots_and_invalidates_shape_receipts() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let with_a = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let with_ab = algebra
            .apply_mutation(
                with_a.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "b".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let deleted = algebra
            .apply_mutation(
                with_ab.shape.shape_id,
                ShapeMutation::DeleteProperty {
                    key: "a".to_string(),
                },
            )
            .unwrap();

        assert_eq!(
            deleted.transition.transition_kind,
            TransitionKind::DeleteProperty
        );
        assert_eq!(deleted.shape.property_layout.len(), 1);
        assert_eq!(deleted.shape.property_layout[0].property_key, "b");
        assert_eq!(deleted.shape.property_layout[0].slot_index, 0);
        assert!(
            deleted
                .transition
                .invalidation_receipt
                .invalidated_assumptions
                .contains(&InvalidatedAssumptionKind::ShapeGuard)
        );
        assert!(
            deleted
                .transition
                .invalidation_receipt
                .invalidated_assumptions
                .contains(&InvalidatedAssumptionKind::PropertyDescriptor)
        );
    }

    #[test]
    fn reconfigure_and_prototype_writes_emit_expected_receipts() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let initial = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let reconfigured = algebra
            .apply_mutation(
                initial.shape.shape_id,
                ShapeMutation::ReconfigureProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes {
                        writable: false,
                        enumerable: true,
                        configurable: false,
                    },
                },
            )
            .unwrap();
        let reconfigured_layout = &reconfigured.shape.property_layout[0];
        assert!(!reconfigured_layout.attributes.writable);
        assert!(!reconfigured_layout.attributes.configurable);
        assert!(
            reconfigured
                .transition
                .invalidation_receipt
                .invalidated_assumptions
                .contains(&InvalidatedAssumptionKind::PropertyDescriptor)
        );

        let prototype = algebra
            .apply_mutation(
                reconfigured.shape.shape_id,
                ShapeMutation::WritePrototype {
                    prototype_fingerprint: Some("proto.alpha".to_string()),
                },
            )
            .unwrap();
        assert_eq!(
            prototype.transition.transition_kind,
            TransitionKind::PrototypeWrite
        );
        assert_eq!(
            prototype.shape.prototype_fingerprint.as_deref(),
            Some("proto.alpha")
        );
        assert!(
            prototype
                .transition
                .invalidation_receipt
                .invalidated_assumptions
                .contains(&InvalidatedAssumptionKind::PrototypeChain)
        );
    }

    #[test]
    fn property_cell_write_keeps_shape_but_emits_cell_receipt() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let initial = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".to_string(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let write = algebra
            .apply_mutation(
                initial.shape.shape_id,
                ShapeMutation::WritePropertyCell {
                    key: "a".to_string(),
                },
            )
            .unwrap();

        assert_eq!(write.shape.shape_id, initial.shape.shape_id);
        assert_eq!(
            write.transition.transition_kind,
            TransitionKind::PropertyCellWrite
        );
        assert_eq!(
            write
                .transition
                .invalidation_receipt
                .invalidated_assumptions,
            vec![InvalidatedAssumptionKind::PropertyCell]
        );
    }

    #[test]
    fn bundle_writer_emits_required_artifacts() {
        let algebra = ShapeTransitionAlgebra::new();
        let bundle = ShapeLatticeBundle {
            manifest: algebra.manifest(),
            trace_events: Vec::new(),
            trace_ids: vec!["trace-shape".to_string()],
            decision_ids: vec!["decision-shape".to_string()],
            policy_ids: vec!["policy-shape".to_string()],
            commands: vec!["cargo test --test bytecode_vm".to_string()],
        };
        let artifact_dir = unique_artifact_dir("bundle");
        let report = emit_shape_lattice_bundle(&artifact_dir, &bundle).unwrap();

        assert!(report.shape_lattice_manifest_path.exists());
        assert!(report.run_manifest_path.exists());
        assert!(report.events_path.exists());
        assert!(report.commands_path.exists());
        assert!(report.trace_ids_path.exists());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(report.run_manifest_path).unwrap()).unwrap();
        assert_eq!(
            manifest["artifact_paths"]["shape_lattice_manifest"],
            "shape_lattice_manifest.json"
        );
    }

    // -----------------------------------------------------------------------
    // PropertyCellState tests
    // -----------------------------------------------------------------------

    #[test]
    fn cell_state_uninitialised_not_valid_for_ic() {
        let s = super::PropertyCellState::Uninitialised;
        assert!(!s.is_valid_for_ic());
    }

    #[test]
    fn cell_state_constant_is_valid() {
        let s = super::PropertyCellState::Uninitialised.on_write(false);
        assert_eq!(s, super::PropertyCellState::Constant);
        assert!(s.is_valid_for_ic());
    }

    #[test]
    fn cell_state_stable_on_same_kind_write() {
        let s = super::PropertyCellState::Constant.on_write(false);
        assert_eq!(s, super::PropertyCellState::Stable);
        assert!(s.is_valid_for_ic());
    }

    #[test]
    fn cell_state_invalidated_on_kind_change() {
        let s = super::PropertyCellState::Stable.on_write(true);
        assert_eq!(s, super::PropertyCellState::Invalidated);
        assert!(!s.is_valid_for_ic());
    }

    #[test]
    fn cell_state_stays_invalidated() {
        let s = super::PropertyCellState::Invalidated.on_write(false);
        assert_eq!(s, super::PropertyCellState::Invalidated);
    }

    #[test]
    fn cell_state_display() {
        assert_eq!(
            format!("{}", super::PropertyCellState::Constant),
            "constant"
        );
        assert_eq!(
            format!("{}", super::PropertyCellState::Invalidated),
            "invalidated"
        );
    }

    // -----------------------------------------------------------------------
    // PropertyCellTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn cell_tracker_write_transitions() {
        let mut cell = super::PropertyCellTracker::new(42, "x");
        assert_eq!(cell.state, super::PropertyCellState::Uninitialised);
        assert!(!cell.record_write(false)); // -> Constant
        assert_eq!(cell.write_epoch, 1);
        assert!(!cell.record_write(false)); // -> Stable
        assert!(cell.record_write(true)); // -> Invalidated (returns true)
        assert_eq!(cell.state, super::PropertyCellState::Invalidated);
    }

    #[test]
    fn cell_tracker_dependents() {
        let mut cell = super::PropertyCellTracker::new(1, "a");
        cell.add_dependent();
        cell.add_dependent();
        assert_eq!(cell.dependent_ic_count, 2);
        cell.remove_dependent();
        assert_eq!(cell.dependent_ic_count, 1);
    }

    #[test]
    fn cell_tracker_display() {
        let cell = super::PropertyCellTracker::new(1, "foo");
        assert!(format!("{cell}").contains("foo"));
    }

    // -----------------------------------------------------------------------
    // PropertyCellTable tests
    // -----------------------------------------------------------------------

    #[test]
    fn cell_table_get_or_create_dedup() {
        let mut table = super::PropertyCellTable::new();
        table.get_or_create(1, "x");
        assert_eq!(table.cell_count(), 1);
        table.get_or_create(1, "x");
        assert_eq!(table.cell_count(), 1);
        table.get_or_create(1, "y");
        assert_eq!(table.cell_count(), 2);
    }

    #[test]
    fn cell_table_invalidate_shape() {
        let mut table = super::PropertyCellTable::new();
        table.record_write(1, "a", false);
        table.record_write(1, "b", false);
        table.record_write(2, "c", false);
        let count = table.invalidate_shape(1);
        assert_eq!(count, 2);
        assert_eq!(
            table.get(1, "a").unwrap().state,
            super::PropertyCellState::Invalidated
        );
        assert_eq!(
            table.get(2, "c").unwrap().state,
            super::PropertyCellState::Constant
        );
    }

    #[test]
    fn cell_table_record_write_tracks_invalidations() {
        let mut table = super::PropertyCellTable::new();
        table.record_write(1, "x", false); // Uninit -> Constant
        table.record_write(1, "x", false); // Constant -> Stable
        assert_eq!(table.total_invalidations(), 0);
        table.record_write(1, "x", true); // Stable -> Invalidated
        assert_eq!(table.total_invalidations(), 1);
    }

    // -----------------------------------------------------------------------
    // InlineCacheState tests
    // -----------------------------------------------------------------------

    #[test]
    fn ic_uninit_to_monomorphic() {
        let ic = super::InlineCacheState::Uninitialised;
        let (new_ic, degraded) = ic.record_access(10, 0);
        assert!(!degraded);
        assert!(matches!(
            new_ic,
            super::InlineCacheState::Monomorphic {
                shape_id: 10,
                hit_count: 1,
                ..
            }
        ));
    }

    #[test]
    fn ic_monomorphic_hit() {
        let ic = super::InlineCacheState::Monomorphic {
            shape_id: 10,
            slot_offset: 0,
            hit_count: 5,
        };
        let (new_ic, degraded) = ic.record_access(10, 0);
        assert!(!degraded);
        assert!(matches!(
            new_ic,
            super::InlineCacheState::Monomorphic { hit_count: 6, .. }
        ));
    }

    #[test]
    fn ic_monomorphic_to_polymorphic() {
        let ic = super::InlineCacheState::Monomorphic {
            shape_id: 10,
            slot_offset: 0,
            hit_count: 5,
        };
        let (new_ic, degraded) = ic.record_access(20, 1);
        assert!(degraded);
        assert!(matches!(
            new_ic,
            super::InlineCacheState::Polymorphic { .. }
        ));
        if let super::InlineCacheState::Polymorphic { entries, .. } = &new_ic {
            assert_eq!(entries.len(), 2);
        }
    }

    #[test]
    fn ic_polymorphic_to_megamorphic() {
        let entries: Vec<super::PolymorphicIcEntry> = (0..4u64)
            .map(|i| super::PolymorphicIcEntry {
                shape_id: i,
                slot_offset: i as u32,
                hit_count: 1,
            })
            .collect();
        let ic = super::InlineCacheState::Polymorphic {
            entries,
            total_hits: 4,
        };
        let (new_ic, degraded) = ic.record_access(99, 99);
        assert!(degraded);
        assert!(new_ic.is_megamorphic());
    }

    #[test]
    fn ic_hit_rate_monomorphic_is_max() {
        let ic = super::InlineCacheState::Monomorphic {
            shape_id: 1,
            slot_offset: 0,
            hit_count: 100,
        };
        assert_eq!(ic.hit_rate_millionths(), 1_000_000);
    }

    #[test]
    fn ic_hit_rate_megamorphic_is_zero() {
        let ic = super::InlineCacheState::Megamorphic {
            observed_shapes: 10,
            total_accesses: 100,
        };
        assert_eq!(ic.hit_rate_millionths(), 0);
    }

    #[test]
    fn ic_fast_path_checks() {
        assert!(!super::InlineCacheState::Uninitialised.is_fast_path());
        let mono = super::InlineCacheState::Monomorphic {
            shape_id: 1,
            slot_offset: 0,
            hit_count: 1,
        };
        assert!(mono.is_fast_path());
        let mega = super::InlineCacheState::Megamorphic {
            observed_shapes: 5,
            total_accesses: 100,
        };
        assert!(!mega.is_fast_path());
    }

    #[test]
    fn ic_display() {
        assert!(format!("{}", super::InlineCacheState::Uninitialised).contains("uninit"));
        let mono = super::InlineCacheState::Monomorphic {
            shape_id: 1,
            slot_offset: 0,
            hit_count: 1,
        };
        assert!(format!("{mono}").contains("mono"));
    }

    // -----------------------------------------------------------------------
    // ShapeGuardWitness tests
    // -----------------------------------------------------------------------

    #[test]
    fn guard_witness_creation_and_permanent() {
        let mut w = super::ShapeGuardWitness::new(
            42,
            super::GuardFailureReason::ShapeMismatch {
                expected_shape_id: 1,
                actual_shape_id: 2,
            },
            super::InlineCacheState::Uninitialised,
            1,
        );
        assert!(!w.permanent_deopt);
        w.mark_permanent();
        assert!(w.permanent_deopt);
    }

    #[test]
    fn guard_failure_reason_display() {
        let r = super::GuardFailureReason::DictionaryPromotion { shape_id: 5 };
        assert!(format!("{r}").contains("dictionary"));
    }

    #[test]
    fn guard_witness_display() {
        let w = super::ShapeGuardWitness::new(
            10,
            super::GuardFailureReason::PrototypeChanged { shape_id: 3 },
            super::InlineCacheState::Uninitialised,
            1,
        );
        assert!(format!("{w}").contains("guard_fail@10"));
    }

    // -----------------------------------------------------------------------
    // InlineCacheTable tests
    // -----------------------------------------------------------------------

    #[test]
    fn ic_table_record_access_hit() {
        let mut table = super::InlineCacheTable::new();
        let hit = table.record_access(0, 1, 0);
        assert!(hit);
        assert_eq!(table.entry_count(), 1);
        assert_eq!(table.total_hits(), 1);
    }

    #[test]
    fn ic_table_guard_failure() {
        let mut table = super::InlineCacheTable::new();
        table.record_guard_failure(
            0,
            super::GuardFailureReason::ShapeMismatch {
                expected_shape_id: 1,
                actual_shape_id: 2,
            },
        );
        assert_eq!(table.witnesses().len(), 1);
        assert_eq!(table.total_misses(), 1);
    }

    #[test]
    fn ic_table_summary() {
        let mut table = super::InlineCacheTable::new();
        table.record_access(0, 1, 0);
        table.record_access(0, 1, 0);
        table.record_access(4, 2, 0);
        table.record_access(4, 3, 1);

        let summary = table.summary();
        assert_eq!(summary.entry_count, 2);
        assert!(summary.monomorphic_count >= 1);
    }

    #[test]
    fn ic_table_hit_rate() {
        let mut table = super::InlineCacheTable::new();
        table.record_access(0, 1, 0); // hit
        table.record_access(0, 1, 0); // hit
        table.record_access(0, 2, 1); // miss (degradation)
        let rate = table.hit_rate_millionths();
        assert!(rate > 0);
        assert!(rate < 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests for new types
    // -----------------------------------------------------------------------

    #[test]
    fn serde_round_trip_cell_state() {
        let state = super::PropertyCellState::Stable;
        let json = serde_json::to_string(&state).unwrap();
        let back: super::PropertyCellState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn serde_round_trip_ic_state() {
        let ic = super::InlineCacheState::Polymorphic {
            entries: vec![
                super::PolymorphicIcEntry {
                    shape_id: 1,
                    slot_offset: 0,
                    hit_count: 10,
                },
                super::PolymorphicIcEntry {
                    shape_id: 2,
                    slot_offset: 1,
                    hit_count: 5,
                },
            ],
            total_hits: 15,
        };
        let json = serde_json::to_string(&ic).unwrap();
        let back: super::InlineCacheState = serde_json::from_str(&json).unwrap();
        assert_eq!(ic, back);
    }

    #[test]
    fn serde_round_trip_guard_witness() {
        let w = super::ShapeGuardWitness::new(
            10,
            super::GuardFailureReason::NonExtensible { shape_id: 5 },
            super::InlineCacheState::Uninitialised,
            1,
        );
        let json = serde_json::to_string(&w).unwrap();
        let back: super::ShapeGuardWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn serde_round_trip_ic_summary() {
        let s = super::InlineCacheSummary {
            entry_count: 5,
            monomorphic_count: 3,
            polymorphic_count: 1,
            megamorphic_count: 1,
            uninitialised_count: 0,
            total_hits: 100,
            total_misses: 10,
            hit_rate_millionths: 909_091,
            witness_count: 2,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: super::InlineCacheSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // ShapeTransitionAlgebra enrichment tests
    // -----------------------------------------------------------------------

    #[test]
    fn algebra_all_property_keys() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let s1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        algebra
            .apply_mutation(
                s1.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let keys: Vec<String> = algebra.all_property_keys().into_iter().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn algebra_shape_and_transition_counts() {
        let mut algebra = ShapeTransitionAlgebra::new();
        assert_eq!(algebra.shape_count(), 1);
        assert_eq!(algebra.transition_count(), 0);
        let root = algebra.root_shape_id();
        algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "x".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(algebra.shape_count(), 2);
        assert_eq!(algebra.transition_count(), 1);
    }

    #[test]
    fn algebra_error_on_unknown_shape() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let result = algebra.apply_mutation(
            999999,
            ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            },
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PropertyAttributes constructor tests
    // -----------------------------------------------------------------------

    #[test]
    fn property_attributes_frozen() {
        let attrs = PropertyAttributes::frozen();
        assert!(!attrs.writable);
        assert!(attrs.enumerable);
        assert!(!attrs.configurable);
    }

    #[test]
    fn property_attributes_sealed() {
        let attrs = PropertyAttributes::sealed();
        assert!(attrs.writable);
        assert!(attrs.enumerable);
        assert!(!attrs.configurable);
    }

    #[test]
    fn property_attributes_non_enumerable() {
        let attrs = PropertyAttributes::non_enumerable();
        assert!(attrs.writable);
        assert!(!attrs.enumerable);
        assert!(attrs.configurable);
    }

    // -----------------------------------------------------------------------
    // ShapeDescriptor helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn shape_descriptor_property_count() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let root_shape = algebra.shape(root).unwrap();
        assert_eq!(root_shape.property_count(), 0);
        let outcome = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "x".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(outcome.shape.property_count(), 1);
    }

    #[test]
    fn shape_descriptor_slot_for() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let s1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let s2 = algebra
            .apply_mutation(
                s1.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(s2.shape.slot_for("a"), Some(0));
        assert_eq!(s2.shape.slot_for("b"), Some(1));
        assert_eq!(s2.shape.slot_for("c"), None);
    }

    #[test]
    fn shape_descriptor_keys() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let s1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "x".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        assert_eq!(s1.shape.keys(), vec!["x"]);
    }

    // -----------------------------------------------------------------------
    // Lineage / convergence / deopt tests
    // -----------------------------------------------------------------------

    #[test]
    fn lineage_root_has_zero_depth() {
        let algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let lineage = algebra.lineage(root).unwrap();
        assert_eq!(lineage.depth, 0);
        assert!(lineage.steps.is_empty());
    }

    #[test]
    fn lineage_single_step() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let outcome = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let lineage = algebra.lineage(outcome.shape.shape_id).unwrap();
        assert_eq!(lineage.depth, 1);
        assert_eq!(lineage.steps[0].from_shape_id, root);
        assert_eq!(lineage.steps[0].to_shape_id, outcome.shape.shape_id);
    }

    #[test]
    fn lineage_unknown_shape_error() {
        let algebra = ShapeTransitionAlgebra::new();
        assert!(algebra.lineage(999999).is_err());
    }

    #[test]
    fn shape_ids_returns_all() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let ids = algebra.shape_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn transitions_from_root() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let transitions = algebra.transitions_from(root);
        assert_eq!(transitions.len(), 2);
    }

    #[test]
    fn find_convergences_basic() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        // root -> {a} -> {a,b}
        let s_a = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        algebra
            .apply_mutation(
                s_a.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        // root -> {b} -> {b,a} -- different shape due to different layout order
        let s_b = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "b".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        algebra
            .apply_mutation(
                s_b.shape.shape_id,
                ShapeMutation::AddProperty {
                    key: "a".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        // May or may not have convergences depending on fingerprint equality
        let _convergences = algebra.find_convergences();
        // Just verify it runs without panic
    }

    #[test]
    fn classify_deopt_add_property() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let outcome = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "x".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let deopt = algebra.classify_deopt(&outcome.transition);
        assert_eq!(deopt.trigger, super::DeoptTrigger::ShapeTransition);
        assert!(deopt.invalidated_assumption_count > 0);
    }

    #[test]
    fn classify_deopt_prototype_write() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let outcome = algebra
            .apply_mutation(
                root,
                ShapeMutation::WritePrototype {
                    prototype_fingerprint: Some("proto-x".into()),
                },
            )
            .unwrap();
        let deopt = algebra.classify_deopt(&outcome.transition);
        assert_eq!(deopt.trigger, super::DeoptTrigger::PrototypeMutation);
    }

    #[test]
    fn classify_deopt_cell_write() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let s1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "v".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let outcome = algebra
            .apply_mutation(
                s1.shape.shape_id,
                ShapeMutation::WritePropertyCell { key: "v".into() },
            )
            .unwrap();
        let deopt = algebra.classify_deopt(&outcome.transition);
        assert_eq!(deopt.trigger, super::DeoptTrigger::CellInvalidation);
    }

    #[test]
    fn classify_deopt_descriptor_change() {
        let mut algebra = ShapeTransitionAlgebra::new();
        let root = algebra.root_shape_id();
        let s1 = algebra
            .apply_mutation(
                root,
                ShapeMutation::AddProperty {
                    key: "p".into(),
                    attributes: PropertyAttributes::default(),
                },
            )
            .unwrap();
        let outcome = algebra
            .apply_mutation(
                s1.shape.shape_id,
                ShapeMutation::ReconfigureProperty {
                    key: "p".into(),
                    attributes: PropertyAttributes::frozen(),
                },
            )
            .unwrap();
        let deopt = algebra.classify_deopt(&outcome.transition);
        assert_eq!(deopt.trigger, super::DeoptTrigger::DescriptorChange);
    }

    // -----------------------------------------------------------------------
    // Corpus tests
    // -----------------------------------------------------------------------

    #[test]
    fn corpus_all_specimens_pass() {
        let results = super::run_shape_transition_corpus();
        for (label, ok, detail) in &results {
            assert!(ok, "specimen '{label}' failed: {detail}");
        }
    }

    #[test]
    fn corpus_has_expected_count() {
        let corpus = super::shape_transition_corpus();
        assert!(corpus.len() >= 8, "corpus should have at least 8 specimens");
    }

    // -----------------------------------------------------------------------
    // Serde round-trips for new types
    // -----------------------------------------------------------------------

    #[test]
    fn serde_round_trip_lineage_step() {
        let step = super::LineageStep {
            from_shape_id: 1,
            to_shape_id: 2,
            transition_kind: TransitionKind::AddProperty,
            property_key: Some("x".into()),
        };
        let json = serde_json::to_string(&step).unwrap();
        let back: super::LineageStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    #[test]
    fn serde_round_trip_deopt_event() {
        let evt = super::DeoptEvent {
            trigger: super::DeoptTrigger::CellInvalidation,
            from_shape_id: 10,
            to_shape_id: 10,
            property_key: Some("x".into()),
            invalidated_assumption_count: 1,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: super::DeoptEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    #[test]
    fn serde_round_trip_convergence_witness() {
        let w = super::ConvergenceWitness {
            target_shape_id: 42,
            source_shape_ids: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: super::ConvergenceWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn serde_round_trip_specimen() {
        let specimen = super::ShapeTransitionSpecimen {
            label: "test".into(),
            mutations: vec![ShapeMutation::AddProperty {
                key: "x".into(),
                attributes: PropertyAttributes::default(),
            }],
            expected_shape_count: 2,
            expected_transition_count: 1,
        };
        let json = serde_json::to_string(&specimen).unwrap();
        let back: super::ShapeTransitionSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(specimen.label, back.label);
    }
}
