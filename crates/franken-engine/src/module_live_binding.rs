use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::esm_loader::{BindingType, ModuleGraph, ModuleStatus};
use crate::hash_tiers::ContentHash;

/// Serde helper: serialize `BTreeMap<BindingId, BindingCell>` as a Vec of entries
/// because JSON map keys must be strings.
mod binding_cell_map_serde {
    use super::{BindingCell, BindingId};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Entry {
        key: BindingId,
        value: BindingCell,
    }

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<BindingId, BindingCell>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let entries: Vec<Entry> = map
            .iter()
            .map(|(key, value)| Entry {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<BindingId, BindingCell>, D::Error> {
        let entries: Vec<Entry> = Vec::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect())
    }
}

pub const BEAD_ID: &str = "bd-1lsy.4.10.1";
pub const MODULE_LIVE_BINDING_SCHEMA_VERSION: &str =
    "franken-engine.module-live-binding.contract.v1";
pub const NAMESPACE_OBJECT_SCHEMA_VERSION: &str = "franken-engine.module-namespace-object.v1";

// ---------------------------------------------------------------------------
// Binding cell — the mutable slot behind every live export
// ---------------------------------------------------------------------------

/// State of a live-binding cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingCellState {
    /// The exporting module has not yet been evaluated.
    Uninitialized,
    /// The binding holds a concrete value.
    Initialized,
    /// The binding has been marked dead (module threw during evaluation).
    Dead,
}

impl fmt::Display for BindingCellState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.write_str("uninitialized"),
            Self::Initialized => f.write_str("initialized"),
            Self::Dead => f.write_str("dead"),
        }
    }
}

/// A live-binding cell represents one exported name from one module.
///
/// ES2020 §15.2.1.16.4.2: When the exporting module mutates the local
/// variable that backs an export, all importers observe the updated value
/// because they share the same binding cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingCell {
    /// The module that owns this binding.
    pub source_module: String,
    /// The exported name (what importers see).
    pub export_name: String,
    /// The local name inside the exporting module.
    pub local_name: String,
    /// How this binding was resolved.
    pub binding_type: BindingType,
    /// Current state.
    pub state: BindingCellState,
    /// Fixed-point millionths value when initialized.
    pub value_millionths: Option<i64>,
    /// String value when initialized (for non-numeric bindings).
    pub value_string: Option<String>,
    /// Monotonic version counter — incremented on every mutation.
    pub version: u64,
}

impl BindingCell {
    pub fn new(
        source_module: &str,
        export_name: &str,
        local_name: &str,
        binding_type: BindingType,
    ) -> Self {
        Self {
            source_module: source_module.to_string(),
            export_name: export_name.to_string(),
            local_name: local_name.to_string(),
            binding_type,
            state: BindingCellState::Uninitialized,
            value_millionths: None,
            value_string: None,
            version: 0,
        }
    }

    /// Update the binding value, incrementing the version counter.
    pub fn initialize_millionths(&mut self, value: i64) {
        self.state = BindingCellState::Initialized;
        self.value_millionths = Some(value);
        self.value_string = None;
        self.version += 1;
    }

    /// Update the binding with a string value.
    pub fn initialize_string(&mut self, value: String) {
        self.state = BindingCellState::Initialized;
        self.value_millionths = None;
        self.value_string = Some(value);
        self.version += 1;
    }

    /// Mark the binding as dead (module evaluation failed).
    pub fn mark_dead(&mut self) {
        self.state = BindingCellState::Dead;
        self.version += 1;
    }

    /// Mutate the millionths value in place (live-binding update).
    pub fn mutate_millionths(&mut self, value: i64) -> Result<(), LiveBindingError> {
        if self.state == BindingCellState::Dead {
            return Err(LiveBindingError::BindingDead {
                module: self.source_module.clone(),
                export_name: self.export_name.clone(),
            });
        }
        self.state = BindingCellState::Initialized;
        self.value_millionths = Some(value);
        self.value_string = None;
        self.version += 1;
        Ok(())
    }

    /// Mutate the string value in place.
    pub fn mutate_string(&mut self, value: String) -> Result<(), LiveBindingError> {
        if self.state == BindingCellState::Dead {
            return Err(LiveBindingError::BindingDead {
                module: self.source_module.clone(),
                export_name: self.export_name.clone(),
            });
        }
        self.state = BindingCellState::Initialized;
        self.value_millionths = None;
        self.value_string = Some(value);
        self.version += 1;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.state == BindingCellState::Initialized
    }
}

impl fmt::Display for BindingCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}::{} (v{}, {})",
            self.source_module, self.export_name, self.version, self.state
        )
    }
}

// ---------------------------------------------------------------------------
// Binding identity — uniquely identifies a cell in the binding map
// ---------------------------------------------------------------------------

/// Unique identity of a live-binding cell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BindingId {
    pub module_specifier: String,
    pub export_name: String,
}

impl BindingId {
    pub fn new(module_specifier: &str, export_name: &str) -> Self {
        Self {
            module_specifier: module_specifier.to_string(),
            export_name: export_name.to_string(),
        }
    }
}

impl fmt::Display for BindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.module_specifier, self.export_name)
    }
}

// ---------------------------------------------------------------------------
// Namespace object — ES2020 §10.4.6 Module Namespace Exotic Objects
// ---------------------------------------------------------------------------

/// A module namespace object contains all exports from a module as
/// live-binding references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceObject {
    pub schema_version: String,
    /// The module this namespace represents.
    pub module_specifier: String,
    /// Sorted list of exported names (ES2020 §10.4.6.11).
    pub export_names: Vec<String>,
    /// Map from export name to binding ID for live-binding lookup.
    pub bindings: BTreeMap<String, BindingId>,
    /// Content hash of the source at namespace construction time.
    pub source_hash: ContentHash,
}

impl NamespaceObject {
    /// Look up a binding ID by export name.
    pub fn get_binding(&self, export_name: &str) -> Option<&BindingId> {
        self.bindings.get(export_name)
    }

    /// Check if the namespace has a given export.
    pub fn has_export(&self, export_name: &str) -> bool {
        self.bindings.contains_key(export_name)
    }

    /// Number of exports in the namespace.
    pub fn len(&self) -> usize {
        self.export_names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.export_names.is_empty()
    }
}

impl fmt::Display for NamespaceObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Namespace({}, {} exports)",
            self.module_specifier,
            self.export_names.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Import binding — how an importer references a live binding
// ---------------------------------------------------------------------------

/// An import binding maps a local name in the importing module to a
/// live-binding cell in the exporting module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBinding {
    /// The importing module.
    pub importer: String,
    /// The local name used in the importing module.
    pub local_name: String,
    /// The binding cell this import resolves to.
    pub target: BindingId,
    /// Whether this is a namespace import (`import * as ns`).
    pub is_namespace: bool,
}

impl fmt::Display for ImportBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_namespace {
            write!(
                f,
                "{}.{} -> Namespace({})",
                self.importer, self.local_name, self.target.module_specifier
            )
        } else {
            write!(
                f,
                "{}.{} -> {}",
                self.importer, self.local_name, self.target
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Live binding map — the central binding table
// ---------------------------------------------------------------------------

/// Event emitted during binding operations for replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingEvent {
    CellCreated {
        binding_id: BindingId,
        binding_type: BindingType,
    },
    CellInitialized {
        binding_id: BindingId,
        version: u64,
    },
    CellMutated {
        binding_id: BindingId,
        version: u64,
    },
    CellDied {
        binding_id: BindingId,
    },
    NamespaceCreated {
        module_specifier: String,
        export_count: usize,
    },
    ImportWired {
        importer: String,
        local_name: String,
        target: BindingId,
    },
}

/// The live-binding map holds all binding cells for all modules in a graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveBindingMap {
    pub schema_version: String,
    /// All binding cells indexed by (module, export_name).
    #[serde(with = "binding_cell_map_serde")]
    pub cells: BTreeMap<BindingId, BindingCell>,
    /// All namespace objects indexed by module specifier.
    pub namespaces: BTreeMap<String, NamespaceObject>,
    /// All import bindings indexed by (importer, local_name).
    pub imports: Vec<ImportBinding>,
    /// Event trace for replay evidence.
    pub events: Vec<BindingEvent>,
}

impl LiveBindingMap {
    pub fn new() -> Self {
        Self {
            schema_version: MODULE_LIVE_BINDING_SCHEMA_VERSION.to_string(),
            cells: BTreeMap::new(),
            namespaces: BTreeMap::new(),
            imports: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Register a new binding cell.
    pub fn register_cell(&mut self, cell: BindingCell) -> BindingId {
        let id = BindingId::new(&cell.source_module, &cell.export_name);
        self.events.push(BindingEvent::CellCreated {
            binding_id: id.clone(),
            binding_type: cell.binding_type,
        });
        self.cells.insert(id.clone(), cell);
        id
    }

    /// Get a binding cell by ID.
    pub fn get_cell(&self, id: &BindingId) -> Option<&BindingCell> {
        self.cells.get(id)
    }

    /// Get a mutable binding cell by ID.
    pub fn get_cell_mut(&mut self, id: &BindingId) -> Option<&mut BindingCell> {
        self.cells.get_mut(id)
    }

    /// Initialize a binding cell with a millionths value.
    pub fn initialize_millionths(
        &mut self,
        id: &BindingId,
        value: i64,
    ) -> Result<(), LiveBindingError> {
        let cell = self
            .cells
            .get_mut(id)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: id.module_specifier.clone(),
                export_name: id.export_name.clone(),
            })?;
        cell.initialize_millionths(value);
        self.events.push(BindingEvent::CellInitialized {
            binding_id: id.clone(),
            version: cell.version,
        });
        Ok(())
    }

    /// Initialize a binding cell with a string value.
    pub fn initialize_string(
        &mut self,
        id: &BindingId,
        value: String,
    ) -> Result<(), LiveBindingError> {
        let cell = self
            .cells
            .get_mut(id)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: id.module_specifier.clone(),
                export_name: id.export_name.clone(),
            })?;
        cell.initialize_string(value);
        self.events.push(BindingEvent::CellInitialized {
            binding_id: id.clone(),
            version: cell.version,
        });
        Ok(())
    }

    /// Mutate a binding cell's millionths value (live update).
    pub fn mutate_millionths(
        &mut self,
        id: &BindingId,
        value: i64,
    ) -> Result<(), LiveBindingError> {
        let cell = self
            .cells
            .get_mut(id)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: id.module_specifier.clone(),
                export_name: id.export_name.clone(),
            })?;
        cell.mutate_millionths(value)?;
        self.events.push(BindingEvent::CellMutated {
            binding_id: id.clone(),
            version: cell.version,
        });
        Ok(())
    }

    /// Mutate a binding cell's string value.
    pub fn mutate_string(&mut self, id: &BindingId, value: String) -> Result<(), LiveBindingError> {
        let cell = self
            .cells
            .get_mut(id)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: id.module_specifier.clone(),
                export_name: id.export_name.clone(),
            })?;
        cell.mutate_string(value)?;
        self.events.push(BindingEvent::CellMutated {
            binding_id: id.clone(),
            version: cell.version,
        });
        Ok(())
    }

    /// Mark a binding cell as dead.
    pub fn mark_dead(&mut self, id: &BindingId) -> Result<(), LiveBindingError> {
        let cell = self
            .cells
            .get_mut(id)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: id.module_specifier.clone(),
                export_name: id.export_name.clone(),
            })?;
        cell.mark_dead();
        self.events.push(BindingEvent::CellDied {
            binding_id: id.clone(),
        });
        Ok(())
    }

    /// Register a namespace object.
    pub fn register_namespace(&mut self, ns: NamespaceObject) {
        let specifier = ns.module_specifier.clone();
        let export_count = ns.export_names.len();
        self.namespaces.insert(specifier.clone(), ns);
        self.events.push(BindingEvent::NamespaceCreated {
            module_specifier: specifier,
            export_count,
        });
    }

    /// Get a namespace object by module specifier.
    pub fn get_namespace(&self, module_specifier: &str) -> Option<&NamespaceObject> {
        self.namespaces.get(module_specifier)
    }

    /// Wire an import binding.
    pub fn wire_import(&mut self, binding: ImportBinding) {
        self.events.push(BindingEvent::ImportWired {
            importer: binding.importer.clone(),
            local_name: binding.local_name.clone(),
            target: binding.target.clone(),
        });
        self.imports.push(binding);
    }

    /// Read a binding value through an import binding (live read).
    pub fn read_through_import(
        &self,
        importer: &str,
        local_name: &str,
    ) -> Result<&BindingCell, LiveBindingError> {
        let import = self
            .imports
            .iter()
            .find(|ib| ib.importer == importer && ib.local_name == local_name)
            .ok_or_else(|| LiveBindingError::ImportNotWired {
                importer: importer.to_string(),
                local_name: local_name.to_string(),
            })?;
        self.cells
            .get(&import.target)
            .ok_or_else(|| LiveBindingError::BindingNotFound {
                module: import.target.module_specifier.clone(),
                export_name: import.target.export_name.clone(),
            })
    }

    /// Total number of binding cells.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Total number of namespace objects.
    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }

    /// Total number of import bindings.
    pub fn import_count(&self) -> usize {
        self.imports.len()
    }

    /// Render a human-readable summary.
    pub fn render_summary(&self) -> String {
        [
            format!("Live binding map (schema {})", self.schema_version),
            format!("  Cells: {}", self.cells.len()),
            format!("  Namespaces: {}", self.namespaces.len()),
            format!("  Import bindings: {}", self.imports.len()),
            format!("  Events: {}", self.events.len()),
        ]
        .join("\n")
    }
}

impl Default for LiveBindingMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Build live bindings from a module graph
// ---------------------------------------------------------------------------

/// Build a complete live-binding map from a linked module graph.
///
/// This walks every module in the graph, creates binding cells for all
/// exports, constructs namespace objects, and wires import bindings.
pub fn build_live_bindings(graph: &ModuleGraph) -> Result<LiveBindingMap, LiveBindingError> {
    let mut map = LiveBindingMap::new();

    // Phase 1: Create binding cells for all direct exports
    for module in graph.modules() {
        if module.status < ModuleStatus::Linked {
            return Err(LiveBindingError::ModuleNotLinked {
                module: module.specifier.clone(),
                status: module.status.to_string(),
            });
        }

        for export in &module.exports {
            if export.module_request.is_some() {
                // Re-export — will be resolved in phase 2
                continue;
            }
            let local_name = export.local_name.as_deref().unwrap_or(&export.export_name);
            let cell = BindingCell::new(
                &module.specifier,
                &export.export_name,
                local_name,
                BindingType::Direct,
            );
            map.register_cell(cell);
        }
    }

    // Phase 2: Resolve re-exports and create additional cells
    for module in graph.modules() {
        for export in &module.exports {
            if export.module_request.is_none() {
                continue; // Already handled in phase 1
            }
            let target_module = export.module_request.as_deref().unwrap();
            let import_name = export.import_name.as_deref().unwrap_or(&export.export_name);

            // The re-export binding points to the source module's cell
            let source_id = BindingId::new(target_module, import_name);
            if map.cells.contains_key(&source_id) {
                // Create an alias cell for the re-export
                let re_export_id = BindingId::new(&module.specifier, &export.export_name);
                if !map.cells.contains_key(&re_export_id) {
                    let cell = BindingCell::new(
                        &module.specifier,
                        &export.export_name,
                        import_name,
                        BindingType::ReExport,
                    );
                    map.register_cell(cell);
                }
            }
        }
    }

    // Phase 3: Build namespace objects for all modules
    for module in graph.modules() {
        let mut export_names = Vec::new();
        let mut bindings = BTreeMap::new();

        for export in &module.exports {
            let binding_id = if export.module_request.is_some() {
                let target = export.module_request.as_deref().unwrap();
                let import = export.import_name.as_deref().unwrap_or(&export.export_name);
                BindingId::new(target, import)
            } else {
                BindingId::new(&module.specifier, &export.export_name)
            };
            export_names.push(export.export_name.clone());
            bindings.insert(export.export_name.clone(), binding_id);
        }

        // ES2020 §10.4.6.11: export names are sorted
        export_names.sort();

        let ns = NamespaceObject {
            schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
            module_specifier: module.specifier.clone(),
            export_names,
            bindings,
            source_hash: module.content_hash,
        };
        map.register_namespace(ns);
    }

    // Phase 4: Wire import bindings
    for module in graph.modules() {
        for import in &module.imports {
            let is_namespace = import.import_name == "*";
            let target = if is_namespace {
                // Namespace import — target is the default binding of the
                // source module (conceptually the namespace object itself).
                BindingId::new(&import.module_request, "*")
            } else {
                BindingId::new(&import.module_request, &import.import_name)
            };

            let binding = ImportBinding {
                importer: module.specifier.clone(),
                local_name: import.local_name.clone(),
                target,
                is_namespace,
            };
            map.wire_import(binding);
        }
    }

    Ok(map)
}

/// Verify that all import bindings resolve to existing cells.
pub fn validate_bindings(map: &LiveBindingMap) -> Vec<LiveBindingError> {
    let mut errors = Vec::new();
    for import in &map.imports {
        if import.is_namespace {
            // Namespace imports point to the namespace object, not a cell
            if !map.namespaces.contains_key(&import.target.module_specifier) {
                errors.push(LiveBindingError::NamespaceNotFound {
                    module: import.target.module_specifier.clone(),
                });
            }
        } else if !map.cells.contains_key(&import.target) {
            errors.push(LiveBindingError::BindingNotFound {
                module: import.target.module_specifier.clone(),
                export_name: import.target.export_name.clone(),
            });
        }
    }
    errors
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiveBindingError {
    ModuleNotLinked {
        module: String,
        status: String,
    },
    BindingNotFound {
        module: String,
        export_name: String,
    },
    BindingDead {
        module: String,
        export_name: String,
    },
    ImportNotWired {
        importer: String,
        local_name: String,
    },
    NamespaceNotFound {
        module: String,
    },
}

impl fmt::Display for LiveBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleNotLinked { module, status } => {
                write!(f, "module {module} is not linked (status: {status})")
            }
            Self::BindingNotFound {
                module,
                export_name,
            } => {
                write!(f, "binding {module}::{export_name} not found")
            }
            Self::BindingDead {
                module,
                export_name,
            } => {
                write!(
                    f,
                    "binding {module}::{export_name} is dead (evaluation failed)"
                )
            }
            Self::ImportNotWired {
                importer,
                local_name,
            } => {
                write!(f, "import {importer}.{local_name} is not wired")
            }
            Self::NamespaceNotFound { module } => {
                write!(f, "namespace for module {module} not found")
            }
        }
    }
}

impl std::error::Error for LiveBindingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cell(module: &str, export: &str) -> BindingCell {
        BindingCell::new(module, export, export, BindingType::Direct)
    }

    #[test]
    fn binding_cell_initial_state() {
        let cell = make_cell("mod_a", "foo");
        assert_eq!(cell.state, BindingCellState::Uninitialized);
        assert!(!cell.is_initialized());
        assert_eq!(cell.version, 0);
        assert!(cell.value_millionths.is_none());
        assert!(cell.value_string.is_none());
    }

    #[test]
    fn binding_cell_initialize_millionths() {
        let mut cell = make_cell("mod_a", "foo");
        cell.initialize_millionths(1_000_000);
        assert_eq!(cell.state, BindingCellState::Initialized);
        assert!(cell.is_initialized());
        assert_eq!(cell.value_millionths, Some(1_000_000));
        assert_eq!(cell.version, 1);
    }

    #[test]
    fn binding_cell_initialize_string() {
        let mut cell = make_cell("mod_a", "foo");
        cell.initialize_string("hello".to_string());
        assert_eq!(cell.state, BindingCellState::Initialized);
        assert_eq!(cell.value_string.as_deref(), Some("hello"));
        assert!(cell.value_millionths.is_none());
        assert_eq!(cell.version, 1);
    }

    #[test]
    fn binding_cell_mutate_increments_version() {
        let mut cell = make_cell("mod_a", "foo");
        cell.initialize_millionths(1_000_000);
        assert_eq!(cell.version, 1);
        cell.mutate_millionths(2_000_000).unwrap();
        assert_eq!(cell.version, 2);
        assert_eq!(cell.value_millionths, Some(2_000_000));
    }

    #[test]
    fn binding_cell_mutate_dead_fails() {
        let mut cell = make_cell("mod_a", "foo");
        cell.mark_dead();
        let err = cell.mutate_millionths(1).unwrap_err();
        assert_eq!(
            err,
            LiveBindingError::BindingDead {
                module: "mod_a".to_string(),
                export_name: "foo".to_string(),
            }
        );
    }

    #[test]
    fn binding_cell_display() {
        let mut cell = make_cell("mod_a", "foo");
        cell.initialize_millionths(42);
        let s = cell.to_string();
        assert!(s.contains("mod_a"));
        assert!(s.contains("foo"));
        assert!(s.contains("v1"));
    }

    #[test]
    fn binding_id_display() {
        let id = BindingId::new("mod_a", "foo");
        assert_eq!(id.to_string(), "mod_a::foo");
    }

    #[test]
    fn binding_id_ord() {
        let a = BindingId::new("a", "x");
        let b = BindingId::new("b", "x");
        let c = BindingId::new("a", "y");
        assert!(a < b);
        assert!(a < c);
    }

    #[test]
    fn namespace_object_accessors() {
        let ns = NamespaceObject {
            schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
            module_specifier: "mod_a".to_string(),
            export_names: vec!["bar".to_string(), "foo".to_string()],
            bindings: {
                let mut m = BTreeMap::new();
                m.insert("foo".to_string(), BindingId::new("mod_a", "foo"));
                m.insert("bar".to_string(), BindingId::new("mod_a", "bar"));
                m
            },
            source_hash: ContentHash::compute(b"source"),
        };
        assert_eq!(ns.len(), 2);
        assert!(!ns.is_empty());
        assert!(ns.has_export("foo"));
        assert!(!ns.has_export("baz"));
        assert_eq!(ns.get_binding("foo"), Some(&BindingId::new("mod_a", "foo")));
    }

    #[test]
    fn namespace_object_display() {
        let ns = NamespaceObject {
            schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
            module_specifier: "mod_a".to_string(),
            export_names: vec!["foo".to_string()],
            bindings: BTreeMap::new(),
            source_hash: ContentHash::compute(b"x"),
        };
        let s = ns.to_string();
        assert!(s.contains("mod_a"));
        assert!(s.contains("1 exports"));
    }

    #[test]
    fn live_binding_map_register_and_read() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "foo");
        let id = map.register_cell(cell);
        assert_eq!(id, BindingId::new("mod_a", "foo"));
        let retrieved = map.get_cell(&id).unwrap();
        assert_eq!(retrieved.source_module, "mod_a");
        assert_eq!(retrieved.export_name, "foo");
    }

    #[test]
    fn live_binding_map_initialize_and_mutate() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "counter");
        let id = map.register_cell(cell);
        map.initialize_millionths(&id, 0).unwrap();
        assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(0));
        map.mutate_millionths(&id, 1_000_000).unwrap();
        assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(1_000_000));
        assert_eq!(map.get_cell(&id).unwrap().version, 2);
    }

    #[test]
    fn live_binding_map_mark_dead_prevents_mutation() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "val");
        let id = map.register_cell(cell);
        map.mark_dead(&id).unwrap();
        assert!(map.mutate_millionths(&id, 1).is_err());
    }

    #[test]
    fn live_binding_map_not_found_error() {
        let map = LiveBindingMap::new();
        let id = BindingId::new("nonexistent", "x");
        let err = map.get_cell(&id);
        assert!(err.is_none());
    }

    #[test]
    fn import_binding_wire_and_read_through() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "foo");
        let id = map.register_cell(cell);
        map.initialize_millionths(&id, 42).unwrap();

        let import = ImportBinding {
            importer: "mod_b".to_string(),
            local_name: "myFoo".to_string(),
            target: id.clone(),
            is_namespace: false,
        };
        map.wire_import(import);

        let cell = map.read_through_import("mod_b", "myFoo").unwrap();
        assert_eq!(cell.value_millionths, Some(42));
    }

    #[test]
    fn live_binding_sees_mutation_through_import() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "counter");
        let id = map.register_cell(cell);
        map.initialize_millionths(&id, 0).unwrap();

        let import = ImportBinding {
            importer: "mod_b".to_string(),
            local_name: "cnt".to_string(),
            target: id.clone(),
            is_namespace: false,
        };
        map.wire_import(import);

        // Before mutation
        assert_eq!(
            map.read_through_import("mod_b", "cnt")
                .unwrap()
                .value_millionths,
            Some(0)
        );

        // Mutate in source module
        map.mutate_millionths(&id, 1_000_000).unwrap();

        // After mutation — importer sees updated value
        assert_eq!(
            map.read_through_import("mod_b", "cnt")
                .unwrap()
                .value_millionths,
            Some(1_000_000)
        );
    }

    #[test]
    fn event_trace_records_operations() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "x");
        let id = map.register_cell(cell);
        map.initialize_millionths(&id, 1).unwrap();
        map.mutate_millionths(&id, 2).unwrap();
        map.mark_dead(&id).unwrap();
        // 1 created + 1 initialized + 1 mutated + 1 died = 4 events
        assert_eq!(map.events.len(), 4);
    }

    #[test]
    fn render_summary_includes_counts() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "x");
        map.register_cell(cell);
        let summary = map.render_summary();
        assert!(summary.contains("Cells: 1"));
        assert!(summary.contains("Events: 1"));
    }

    #[test]
    fn binding_cell_serde_roundtrip() {
        let mut cell = make_cell("mod_a", "foo");
        cell.initialize_millionths(42);
        let json = serde_json::to_string(&cell).unwrap();
        let back: BindingCell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, back);
    }

    #[test]
    fn binding_id_serde_roundtrip() {
        let id = BindingId::new("mod_a", "foo");
        let json = serde_json::to_string(&id).unwrap();
        let back: BindingId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn namespace_object_serde_roundtrip() {
        let ns = NamespaceObject {
            schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
            module_specifier: "mod_a".to_string(),
            export_names: vec!["foo".to_string()],
            bindings: {
                let mut m = BTreeMap::new();
                m.insert("foo".to_string(), BindingId::new("mod_a", "foo"));
                m
            },
            source_hash: ContentHash::compute(b"source"),
        };
        let json = serde_json::to_string(&ns).unwrap();
        let back: NamespaceObject = serde_json::from_str(&json).unwrap();
        assert_eq!(ns, back);
    }

    #[test]
    fn import_binding_serde_roundtrip() {
        let ib = ImportBinding {
            importer: "mod_b".to_string(),
            local_name: "x".to_string(),
            target: BindingId::new("mod_a", "x"),
            is_namespace: false,
        };
        let json = serde_json::to_string(&ib).unwrap();
        let back: ImportBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(ib, back);
    }

    #[test]
    fn binding_event_serde_roundtrip() {
        let ev = BindingEvent::CellCreated {
            binding_id: BindingId::new("mod_a", "x"),
            binding_type: BindingType::Direct,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: BindingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn live_binding_map_serde_roundtrip() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "x");
        map.register_cell(cell);
        let json = serde_json::to_string(&map).unwrap();
        let back: LiveBindingMap = serde_json::from_str(&json).unwrap();
        assert_eq!(map, back);
    }

    #[test]
    fn binding_cell_state_display() {
        assert_eq!(BindingCellState::Uninitialized.to_string(), "uninitialized");
        assert_eq!(BindingCellState::Initialized.to_string(), "initialized");
        assert_eq!(BindingCellState::Dead.to_string(), "dead");
    }

    #[test]
    fn binding_cell_state_serde() {
        for state in [
            BindingCellState::Uninitialized,
            BindingCellState::Initialized,
            BindingCellState::Dead,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: BindingCellState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn live_binding_error_display() {
        let err = LiveBindingError::ModuleNotLinked {
            module: "mod_a".to_string(),
            status: "unlinked".to_string(),
        };
        assert!(err.to_string().contains("mod_a"));
        assert!(err.to_string().contains("not linked"));
    }

    #[test]
    fn validate_bindings_empty_map_passes() {
        let map = LiveBindingMap::new();
        assert!(validate_bindings(&map).is_empty());
    }

    #[test]
    fn validate_bindings_detects_missing_cell() {
        let mut map = LiveBindingMap::new();
        let import = ImportBinding {
            importer: "mod_b".to_string(),
            local_name: "x".to_string(),
            target: BindingId::new("nonexistent", "x"),
            is_namespace: false,
        };
        map.wire_import(import);
        let errors = validate_bindings(&map);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn live_binding_map_counters() {
        let mut map = LiveBindingMap::new();
        assert_eq!(map.cell_count(), 0);
        assert_eq!(map.namespace_count(), 0);
        assert_eq!(map.import_count(), 0);

        let cell = make_cell("mod_a", "x");
        map.register_cell(cell);
        assert_eq!(map.cell_count(), 1);

        let ns = NamespaceObject {
            schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
            module_specifier: "mod_a".to_string(),
            export_names: vec![],
            bindings: BTreeMap::new(),
            source_hash: ContentHash::compute(b"x"),
        };
        map.register_namespace(ns);
        assert_eq!(map.namespace_count(), 1);
    }

    #[test]
    fn initialize_string_and_mutate_string() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "name");
        let id = map.register_cell(cell);
        map.initialize_string(&id, "alice".to_string()).unwrap();
        assert_eq!(
            map.get_cell(&id).unwrap().value_string.as_deref(),
            Some("alice")
        );
        map.mutate_string(&id, "bob".to_string()).unwrap();
        assert_eq!(
            map.get_cell(&id).unwrap().value_string.as_deref(),
            Some("bob")
        );
        assert_eq!(map.get_cell(&id).unwrap().version, 2);
    }

    #[test]
    fn multiple_importers_share_same_cell() {
        let mut map = LiveBindingMap::new();
        let cell = make_cell("mod_a", "shared");
        let id = map.register_cell(cell);
        map.initialize_millionths(&id, 0).unwrap();

        // Two importers both import the same binding
        map.wire_import(ImportBinding {
            importer: "mod_b".to_string(),
            local_name: "s1".to_string(),
            target: id.clone(),
            is_namespace: false,
        });
        map.wire_import(ImportBinding {
            importer: "mod_c".to_string(),
            local_name: "s2".to_string(),
            target: id.clone(),
            is_namespace: false,
        });

        // Mutate from source
        map.mutate_millionths(&id, 999).unwrap();

        // Both importers see the mutation
        assert_eq!(
            map.read_through_import("mod_b", "s1")
                .unwrap()
                .value_millionths,
            Some(999)
        );
        assert_eq!(
            map.read_through_import("mod_c", "s2")
                .unwrap()
                .value_millionths,
            Some(999)
        );
    }
}
