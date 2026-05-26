//! Bead: bd-1lsy.5.8.1 [RGC-406A]
//!
//! ART/MPHF-backed package, export, and subpath indexes for the module
//! resolver.
//!
//! Compiles package names, export maps, and hot subpath tables into
//! deterministic indexed structures that answer common resolver queries
//! in O(1) amortized time without repeated linear scans.
//!
//! # Design
//!
//! - **Adaptive Radix Trie (ART)** — safe, `Vec`-backed trie for
//!   prefix-based package-name lookups (scoped packages, subpath
//!   patterns). Supports longest-prefix-match and prefix enumeration.
//! - **Hash Index** — open-addressed hash table with linear probing
//!   for O(1) amortized exact-match on known export keys.
//!   Falls back gracefully (returns `None`) for keys outside the
//!   build-time keyset.
//! - **Subpath Index** — combines ART prefix search with MPHF exact
//!   match to resolve `package/subpath` specifiers in one lookup.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for resolver package index artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.resolver-package-index.v1";

/// Bead originating this module.
pub const BEAD_ID: &str = "bd-1lsy.5.8.1";

/// Component name for structured logging.
pub const COMPONENT: &str = "resolver_package_index";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-406A";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Maximum ART depth (bytes in key). Prevents degenerate inputs from
/// consuming unbounded memory.
pub const MAX_ART_DEPTH: usize = 512;

/// Maximum number of entries in an MPHF index before we refuse to build.
pub const MAX_MPHF_ENTRIES: usize = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

/// FNV-1a 64-bit hash for deterministic hashing of string keys.
fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x00000100000001B3);
    }
    h
}

fn clamped_millionths(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let ratio = numerator.saturating_mul(MILLIONTHS) / denominator;
    ratio.min(MILLIONTHS)
}

// ---------------------------------------------------------------------------
// IndexBuildError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexBuildError {
    EmptyKeySet,
    KeyTooLong { key: String, max_depth: usize },
    TooManyEntries { count: usize, max: usize },
    DuplicateKey { key: String },
    MphfConstructionFailed { reason: String },
}

impl fmt::Display for IndexBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKeySet => write!(f, "cannot build index from empty key set"),
            Self::KeyTooLong { key, max_depth } => {
                write!(f, "key '{}' exceeds max depth {}", key, max_depth)
            }
            Self::TooManyEntries { count, max } => {
                write!(f, "entry count {} exceeds maximum {}", count, max)
            }
            Self::DuplicateKey { key } => write!(f, "duplicate key: '{}'", key),
            Self::MphfConstructionFailed { reason } => {
                write!(f, "MPHF construction failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for IndexBuildError {}

// ---------------------------------------------------------------------------
// IndexLookupOutcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexLookupOutcome {
    Hit,
    Miss,
    FallbackUsed,
}

impl IndexLookupOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::FallbackUsed => "fallback_used",
        }
    }
}

// ---------------------------------------------------------------------------
// PackageEntry — what we store for each indexed package
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    pub package_name: String,
    pub export_keys: Vec<String>,
    pub main_entry: Option<String>,
    pub syntax_hint: Option<String>,
    pub content_hash: ContentHash,
}

impl PackageEntry {
    pub fn new(package_name: impl Into<String>, content_hash: ContentHash) -> Self {
        Self {
            package_name: package_name.into(),
            export_keys: Vec::new(),
            main_entry: None,
            syntax_hint: None,
            content_hash,
        }
    }

    pub fn with_exports(mut self, exports: Vec<String>) -> Self {
        self.export_keys = exports;
        self
    }

    pub fn with_main_entry(mut self, main: impl Into<String>) -> Self {
        self.main_entry = Some(main.into());
        self
    }

    pub fn with_syntax_hint(mut self, hint: impl Into<String>) -> Self {
        self.syntax_hint = Some(hint.into());
        self
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.package_name);
        append_u64(&mut buf, self.export_keys.len() as u64);
        for key in &self.export_keys {
            append_str(&mut buf, key);
        }
        if let Some(ref main) = self.main_entry {
            buf.push(1);
            append_str(&mut buf, main);
        } else {
            buf.push(0);
        }
        if let Some(ref hint) = self.syntax_hint {
            buf.push(1);
            append_str(&mut buf, hint);
        } else {
            buf.push(0);
        }
        buf.extend_from_slice(self.content_hash.as_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// ExportEntry — what we store for each indexed export target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub package_name: String,
    pub export_key: String,
    pub condition_targets: BTreeMap<String, String>,
    pub fallback_target: Option<String>,
}

impl ExportEntry {
    pub fn new(package_name: impl Into<String>, export_key: impl Into<String>) -> Self {
        Self {
            package_name: package_name.into(),
            export_key: export_key.into(),
            condition_targets: BTreeMap::new(),
            fallback_target: None,
        }
    }

    pub fn with_condition(
        mut self,
        condition: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        self.condition_targets
            .insert(condition.into(), target.into());
        self
    }

    pub fn with_fallback(mut self, target: impl Into<String>) -> Self {
        self.fallback_target = Some(target.into());
        self
    }

    pub fn resolve_target(&self, conditions: &[&str]) -> Option<&str> {
        for cond in conditions {
            if let Some(target) = self.condition_targets.get(*cond) {
                return Some(target.as_str());
            }
        }
        self.fallback_target.as_deref()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.package_name);
        append_str(&mut buf, &self.export_key);
        append_u64(&mut buf, self.condition_targets.len() as u64);
        for (k, v) in &self.condition_targets {
            append_str(&mut buf, k);
            append_str(&mut buf, v);
        }
        if let Some(ref fb) = self.fallback_target {
            buf.push(1);
            append_str(&mut buf, fb);
        } else {
            buf.push(0);
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// AdaptiveRadixTrie — safe, Vec-backed prefix trie
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArtNode {
    children: BTreeMap<u8, usize>,
    value_index: Option<usize>,
    prefix: Vec<u8>,
}

impl ArtNode {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            value_index: None,
            prefix: Vec::new(),
        }
    }

    fn with_prefix(prefix: Vec<u8>) -> Self {
        Self {
            children: BTreeMap::new(),
            value_index: None,
            prefix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRadixTrie<V: Clone + Eq + Serialize> {
    nodes: Vec<ArtNode>,
    values: Vec<V>,
}

impl<V: Clone + Eq + Serialize> Default for AdaptiveRadixTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Clone + Eq + Serialize> AdaptiveRadixTrie<V> {
    pub fn new() -> Self {
        Self {
            nodes: vec![ArtNode::new()],
            values: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn insert(&mut self, key: &[u8], value: V) -> Result<(), IndexBuildError> {
        if key.len() > MAX_ART_DEPTH {
            return Err(IndexBuildError::KeyTooLong {
                key: String::from_utf8_lossy(key).to_string(),
                max_depth: MAX_ART_DEPTH,
            });
        }

        let value_idx = self.values.len();
        self.values.push(value);

        let mut node_idx = 0;
        let mut pos = 0;

        while pos < key.len() {
            let node_prefix = self.nodes[node_idx].prefix.clone();
            let common = node_prefix
                .iter()
                .zip(key[pos..].iter())
                .take_while(|(a, b)| a == b)
                .count();

            if common < node_prefix.len() {
                // Split the current node's prefix
                let new_child_idx = self.nodes.len();
                let mut split_node = ArtNode::with_prefix(node_prefix[common + 1..].to_vec());
                split_node.children = self.nodes[node_idx].children.clone();
                split_node.value_index = self.nodes[node_idx].value_index;
                self.nodes.push(split_node);

                self.nodes[node_idx].prefix = node_prefix[..common].to_vec();
                self.nodes[node_idx].children.clear();
                self.nodes[node_idx].value_index = None;

                let edge_byte = node_prefix[common];
                self.nodes[node_idx]
                    .children
                    .insert(edge_byte, new_child_idx);

                pos += common;
                if pos < key.len() {
                    let leaf_idx = self.nodes.len();
                    let leaf = ArtNode {
                        children: BTreeMap::new(),
                        value_index: Some(value_idx),
                        prefix: key[pos + 1..].to_vec(),
                    };
                    self.nodes.push(leaf);
                    self.nodes[node_idx].children.insert(key[pos], leaf_idx);
                } else {
                    self.nodes[node_idx].value_index = Some(value_idx);
                }
                return Ok(());
            }

            pos += common;

            if pos >= key.len() {
                self.nodes[node_idx].value_index = Some(value_idx);
                return Ok(());
            }

            let next_byte = key[pos];
            if let Some(&child_idx) = self.nodes[node_idx].children.get(&next_byte) {
                node_idx = child_idx;
                pos += 1;
            } else {
                let leaf_idx = self.nodes.len();
                let leaf = ArtNode {
                    children: BTreeMap::new(),
                    value_index: Some(value_idx),
                    prefix: key[pos + 1..].to_vec(),
                };
                self.nodes.push(leaf);
                self.nodes[node_idx].children.insert(next_byte, leaf_idx);
                return Ok(());
            }
        }

        // Exact match on existing node
        self.nodes[node_idx].value_index = Some(value_idx);
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let mut node_idx = 0;
        let mut pos = 0;

        while pos <= key.len() {
            let prefix = &self.nodes[node_idx].prefix;
            if key.len() - pos < prefix.len() {
                return None;
            }
            if key[pos..pos + prefix.len()] != *prefix {
                return None;
            }
            pos += prefix.len();

            if pos == key.len() {
                return self.nodes[node_idx]
                    .value_index
                    .map(|idx| &self.values[idx]);
            }

            let next_byte = key[pos];
            if let Some(&child_idx) = self.nodes[node_idx].children.get(&next_byte) {
                node_idx = child_idx;
                pos += 1;
            } else {
                return None;
            }
        }
        None
    }

    /// Find the longest prefix of `key` that has a stored value.
    pub fn longest_prefix_match(&self, key: &[u8]) -> Option<(usize, &V)> {
        let mut node_idx = 0;
        let mut pos = 0;
        let mut best: Option<(usize, usize)> = None;

        loop {
            let prefix = &self.nodes[node_idx].prefix;
            if key.len() - pos < prefix.len() {
                break;
            }
            if key[pos..pos + prefix.len()] != *prefix {
                break;
            }
            pos += prefix.len();

            if let Some(vi) = self.nodes[node_idx].value_index {
                best = Some((pos, vi));
            }

            if pos >= key.len() {
                break;
            }

            let next_byte = key[pos];
            if let Some(&child_idx) = self.nodes[node_idx].children.get(&next_byte) {
                node_idx = child_idx;
                pos += 1;
            } else {
                break;
            }
        }

        best.map(|(len, vi)| (len, &self.values[vi]))
    }

    /// Collect all values whose keys start with `prefix`.
    pub fn prefix_scan(&self, prefix: &[u8]) -> Vec<&V> {
        let mut result = Vec::new();
        let mut node_idx = 0;
        let mut pos = 0;

        // Navigate to the node matching the prefix
        loop {
            let node_prefix = &self.nodes[node_idx].prefix;
            let remaining_prefix = &prefix[pos..];

            if remaining_prefix.is_empty() {
                // Prefix fully consumed — collect everything under this node
                self.collect_subtree(node_idx, &mut result);
                return result;
            }

            let common = node_prefix
                .iter()
                .zip(remaining_prefix.iter())
                .take_while(|(a, b)| a == b)
                .count();

            if common < node_prefix.len() {
                if common < remaining_prefix.len() {
                    // prefix diverges from node prefix — no matches
                    return result;
                }
                // remaining_prefix is a prefix of node_prefix — collect subtree
                self.collect_subtree(node_idx, &mut result);
                return result;
            }

            pos += common;

            if pos >= prefix.len() {
                self.collect_subtree(node_idx, &mut result);
                return result;
            }

            let next_byte = prefix[pos];
            if let Some(&child_idx) = self.nodes[node_idx].children.get(&next_byte) {
                node_idx = child_idx;
                pos += 1;
            } else {
                return result;
            }
        }
    }

    fn collect_subtree<'a>(&'a self, node_idx: usize, result: &mut Vec<&'a V>) {
        if let Some(vi) = self.nodes[node_idx].value_index {
            result.push(&self.values[vi]);
        }
        for &child_idx in self.nodes[node_idx].children.values() {
            self.collect_subtree(child_idx, result);
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ---------------------------------------------------------------------------
// MphfIndex — open-addressed hash table for exact-match lookups
// ---------------------------------------------------------------------------

/// Open-addressed hash table with linear probing and key verification.
///
/// Provides O(1) amortized exact-match lookups. Construction always
/// succeeds (no displacement failures). Load factor is kept below 75%.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MphfIndex<V: Clone + Eq + Serialize> {
    slots: Vec<Option<(Vec<u8>, V)>>,
    len: usize,
}

impl<V: Clone + Eq + Serialize> Default for MphfIndex<V> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }
}

impl<V: Clone + Eq + Serialize> MphfIndex<V> {
    pub fn build(entries: Vec<(Vec<u8>, V)>) -> Result<Self, IndexBuildError> {
        if entries.is_empty() {
            return Err(IndexBuildError::EmptyKeySet);
        }
        if entries.len() > MAX_MPHF_ENTRIES {
            return Err(IndexBuildError::TooManyEntries {
                count: entries.len(),
                max: MAX_MPHF_ENTRIES,
            });
        }

        // Check for duplicates
        let mut seen = BTreeSet::new();
        for (key, _) in &entries {
            if !seen.insert(key.clone()) {
                return Err(IndexBuildError::DuplicateKey {
                    key: String::from_utf8_lossy(key).to_string(),
                });
            }
        }

        let n = entries.len();
        // Table size ≈ 2x entries for low collision rate with linear probing
        let capacity = (n * 2).next_power_of_two().max(4);
        let mask = capacity - 1;
        let mut slots: Vec<Option<(Vec<u8>, V)>> = (0..capacity).map(|_| None).collect();

        for (key, value) in entries {
            let mut h = fnv1a_hash(&key) as usize & mask;
            loop {
                if slots[h].is_none() {
                    slots[h] = Some((key, value));
                    break;
                }
                h = (h + 1) & mask;
            }
        }

        Ok(Self { slots, len: n })
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut h = fnv1a_hash(key) as usize & mask;
        loop {
            match &self.slots[h] {
                Some((stored_key, value)) if stored_key == key => return Some(value),
                Some(_) => h = (h + 1) & mask,
                None => return None,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn occupancy_millionths(&self) -> u64 {
        clamped_millionths(self.len as u64, self.slots.len() as u64)
    }
}

// ---------------------------------------------------------------------------
// PackageIndex — combines ART + MPHF for package resolution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndex {
    art: AdaptiveRadixTrie<PackageEntry>,
    export_index: MphfIndex<ExportEntry>,
    index_id: String,
    schema_version: String,
    build_epoch: SecurityEpoch,
    package_count: u64,
    export_count: u64,
    content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndexConfig {
    pub index_id: String,
    pub build_epoch: SecurityEpoch,
}

impl PackageIndexConfig {
    pub fn new(index_id: impl Into<String>, build_epoch: SecurityEpoch) -> Self {
        Self {
            index_id: index_id.into(),
            build_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndexStats {
    pub package_count: u64,
    pub export_count: u64,
    pub art_node_count: u64,
    pub mphf_slot_count: u64,
    pub mphf_occupancy_millionths: u64,
    pub content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupResult<T> {
    pub value: Option<T>,
    pub outcome: IndexLookupOutcome,
}

impl<T> LookupResult<T> {
    pub fn hit(value: T) -> Self {
        Self {
            value: Some(value),
            outcome: IndexLookupOutcome::Hit,
        }
    }

    pub fn miss() -> Self {
        Self {
            value: None,
            outcome: IndexLookupOutcome::Miss,
        }
    }
}

impl PackageIndex {
    pub fn build(
        config: PackageIndexConfig,
        packages: Vec<PackageEntry>,
        exports: Vec<ExportEntry>,
    ) -> Result<Self, IndexBuildError> {
        let mut art = AdaptiveRadixTrie::new();
        for pkg in &packages {
            art.insert(pkg.package_name.as_bytes(), pkg.clone())?;
        }

        let export_entries: Vec<(Vec<u8>, ExportEntry)> = exports
            .iter()
            .map(|e| {
                let key = format!("{}:{}", e.package_name, e.export_key);
                (key.into_bytes(), e.clone())
            })
            .collect();

        let export_index = if export_entries.is_empty() {
            MphfIndex::default()
        } else {
            MphfIndex::build(export_entries)?
        };

        let package_count = packages.len() as u64;
        let export_count = exports.len() as u64;

        // Compute content hash over all entries
        let mut hash_buf = Vec::new();
        append_str(&mut hash_buf, &config.index_id);
        append_str(&mut hash_buf, SCHEMA_VERSION);
        append_u64(&mut hash_buf, config.build_epoch.as_u64());
        append_u64(&mut hash_buf, package_count);
        for pkg in &packages {
            hash_buf.extend_from_slice(&pkg.canonical_bytes());
        }
        append_u64(&mut hash_buf, export_count);
        for exp in &exports {
            hash_buf.extend_from_slice(&exp.canonical_bytes());
        }
        let content_hash = compute_digest(&hash_buf);

        Ok(Self {
            art,
            export_index,
            index_id: config.index_id,
            schema_version: SCHEMA_VERSION.to_string(),
            build_epoch: config.build_epoch,
            package_count,
            export_count,
            content_hash,
        })
    }

    pub fn lookup_package(&self, name: &str) -> LookupResult<PackageEntry> {
        match self.art.get(name.as_bytes()) {
            Some(entry) => LookupResult::hit(entry.clone()),
            None => LookupResult::miss(),
        }
    }

    pub fn lookup_export(&self, package_name: &str, export_key: &str) -> LookupResult<ExportEntry> {
        let key = format!("{package_name}:{export_key}");
        match self.export_index.get(key.as_bytes()) {
            Some(entry) => LookupResult::hit(entry.clone()),
            None => LookupResult::miss(),
        }
    }

    pub fn resolve_subpath(&self, specifier: &str, conditions: &[&str]) -> LookupResult<String> {
        // Try to find the package name via longest prefix match
        let bytes = specifier.as_bytes();
        if let Some((prefix_len, pkg)) = self.art.longest_prefix_match(bytes) {
            let subpath = if prefix_len < specifier.len() {
                let rest = &specifier[prefix_len..];
                if rest.starts_with('/') {
                    format!(".{rest}")
                } else {
                    format!("./{rest}")
                }
            } else {
                ".".to_string()
            };

            // Look up the export for this subpath
            let key = format!("{}:{}", pkg.package_name, subpath);
            if let Some(export) = self.export_index.get(key.as_bytes())
                && let Some(target) = export.resolve_target(conditions)
            {
                return LookupResult::hit(target.to_string());
            }

            // Try main entry fallback
            if subpath == "."
                && let Some(ref main) = pkg.main_entry
            {
                return LookupResult::hit(main.clone());
            }
        }

        LookupResult::miss()
    }

    pub fn packages_under_scope(&self, scope: &str) -> Vec<PackageEntry> {
        self.art
            .prefix_scan(scope.as_bytes())
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> PackageIndexStats {
        PackageIndexStats {
            package_count: self.package_count,
            export_count: self.export_count,
            art_node_count: self.art.node_count() as u64,
            mphf_slot_count: self.export_index.slot_count() as u64,
            mphf_occupancy_millionths: self.export_index.occupancy_millionths(),
            content_hash: self.content_hash,
        }
    }

    pub fn index_id(&self) -> &str {
        &self.index_id
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn build_epoch(&self) -> SecurityEpoch {
        self.build_epoch
    }

    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    pub fn package_count(&self) -> u64 {
        self.package_count
    }

    pub fn export_count(&self) -> u64 {
        self.export_count
    }
}

// ---------------------------------------------------------------------------
// IndexBuildReceipt — evidence artifact for index construction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexBuildReceipt {
    pub schema_version: String,
    pub index_id: String,
    pub build_epoch: SecurityEpoch,
    pub package_count: u64,
    pub export_count: u64,
    pub art_node_count: u64,
    pub mphf_slot_count: u64,
    pub mphf_occupancy_millionths: u64,
    pub content_hash: ContentHash,
    pub build_duration_ns: u64,
    pub component: String,
    pub policy_id: String,
}

impl IndexBuildReceipt {
    pub fn from_index(index: &PackageIndex, build_duration_ns: u64) -> Self {
        let stats = index.stats();
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            index_id: index.index_id.clone(),
            build_epoch: index.build_epoch,
            package_count: stats.package_count,
            export_count: stats.export_count,
            art_node_count: stats.art_node_count,
            mphf_slot_count: stats.mphf_slot_count,
            mphf_occupancy_millionths: stats.mphf_occupancy_millionths,
            content_hash: stats.content_hash,
            build_duration_ns,
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.index_id);
        append_u64(&mut buf, self.build_epoch.as_u64());
        append_u64(&mut buf, self.package_count);
        append_u64(&mut buf, self.export_count);
        append_u64(&mut buf, self.art_node_count);
        append_u64(&mut buf, self.mphf_slot_count);
        append_u64(&mut buf, self.mphf_occupancy_millionths);
        buf.extend_from_slice(self.content_hash.as_bytes());
        append_u64(&mut buf, self.build_duration_ns);
        append_str(&mut buf, &self.component);
        append_str(&mut buf, &self.policy_id);
        buf
    }

    pub fn evidence_hash(&self) -> ContentHash {
        compute_digest(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// SubpathResolutionReceipt — evidence for a subpath resolution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubpathResolutionReceipt {
    pub schema_version: String,
    pub index_id: String,
    pub specifier: String,
    pub resolved_target: Option<String>,
    pub outcome: IndexLookupOutcome,
    pub conditions_tried: Vec<String>,
    pub content_hash: ContentHash,
}

impl SubpathResolutionReceipt {
    pub fn new(
        index: &PackageIndex,
        specifier: &str,
        result: &LookupResult<String>,
        conditions: &[&str],
    ) -> Self {
        let mut buf = Vec::new();
        append_str(&mut buf, &index.index_id);
        append_str(&mut buf, specifier);
        if let Some(ref target) = result.value {
            buf.push(1);
            append_str(&mut buf, target);
        } else {
            buf.push(0);
        }
        append_str(&mut buf, result.outcome.as_str());
        let content_hash = compute_digest(&buf);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            index_id: index.index_id.clone(),
            specifier: specifier.to_string(),
            resolved_target: result.value.clone(),
            outcome: result.outcome.clone(),
            conditions_tried: conditions.iter().map(|c| c.to_string()).collect(),
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_hash() -> ContentHash {
        ContentHash::compute(b"test-package")
    }

    fn make_package(name: &str, exports: Vec<&str>) -> PackageEntry {
        PackageEntry::new(name, test_hash())
            .with_exports(exports.into_iter().map(String::from).collect())
    }

    fn make_export(pkg: &str, key: &str, conditions: &[(&str, &str)]) -> ExportEntry {
        let mut e = ExportEntry::new(pkg, key);
        for &(cond, target) in conditions {
            e = e.with_condition(cond, target);
        }
        e
    }

    // --- ART tests ---

    #[test]
    fn art_insert_and_get_single_key() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"react", 42u32)
            .expect("operation should succeed for valid inputs");
        assert_eq!(art.get(b"react"), Some(&42));
        assert_eq!(art.get(b"reac"), None);
        assert_eq!(art.get(b"reactx"), None);
    }

    #[test]
    fn art_insert_multiple_keys() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"react", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"react-dom", 2)
            .expect("operation should succeed for valid inputs");
        art.insert(b"redux", 3)
            .expect("operation should succeed for valid inputs");
        assert_eq!(art.get(b"react"), Some(&1));
        assert_eq!(art.get(b"react-dom"), Some(&2));
        assert_eq!(art.get(b"redux"), Some(&3));
        assert_eq!(art.len(), 3);
    }

    #[test]
    fn art_prefix_sharing() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"@scope/foo", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"@scope/bar", 2)
            .expect("operation should succeed for valid inputs");
        art.insert(b"@scope/baz", 3)
            .expect("operation should succeed for valid inputs");
        assert_eq!(art.get(b"@scope/foo"), Some(&1));
        assert_eq!(art.get(b"@scope/bar"), Some(&2));
        assert_eq!(art.get(b"@scope/baz"), Some(&3));
        assert_eq!(art.get(b"@scope/"), None);
    }

    #[test]
    fn art_longest_prefix_match() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"react", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"react-dom", 2)
            .expect("operation should succeed for valid inputs");

        let result = art.longest_prefix_match(b"react-dom/server");
        assert!(result.is_some());
        let (len, val) = result.expect("operation should succeed for valid inputs");
        assert_eq!(*val, 2);
        assert_eq!(len, 9); // "react-dom".len()

        let result2 = art.longest_prefix_match(b"react/jsx-runtime");
        assert!(result2.is_some());
        let (len2, val2) = result2.expect("operation should succeed for valid inputs");
        assert_eq!(*val2, 1);
        assert_eq!(len2, 5);
    }

    #[test]
    fn art_prefix_scan() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"@babel/core", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"@babel/parser", 2)
            .expect("operation should succeed for valid inputs");
        art.insert(b"@babel/traverse", 3)
            .expect("operation should succeed for valid inputs");
        art.insert(b"lodash", 4)
            .expect("operation should succeed for valid inputs");

        let results = art.prefix_scan(b"@babel/");
        assert_eq!(results.len(), 3);

        let results2 = art.prefix_scan(b"lodash");
        assert_eq!(results2.len(), 1);
        assert_eq!(*results2[0], 4);

        let results3 = art.prefix_scan(b"nonexist");
        assert!(results3.is_empty());
    }

    #[test]
    fn art_empty_key() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"", 1u32)
            .expect("operation should succeed for valid inputs");
        assert_eq!(art.get(b""), Some(&1));
    }

    #[test]
    fn art_key_too_long_rejected() {
        let mut art = AdaptiveRadixTrie::<u32>::new();
        let long_key = vec![b'a'; MAX_ART_DEPTH + 1];
        let result = art.insert(&long_key, 1);
        assert!(matches!(result, Err(IndexBuildError::KeyTooLong { .. })));
    }

    #[test]
    fn art_overwrite_value() {
        let mut art = AdaptiveRadixTrie::new();
        art.insert(b"key", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"key", 2)
            .expect("operation should succeed for valid inputs");
        // Both values exist but latest value_index wins
        assert!(art.get(b"key").is_some());
    }

    #[test]
    fn art_node_count_grows_with_inserts() {
        let mut art = AdaptiveRadixTrie::new();
        let initial = art.node_count();
        art.insert(b"abc", 1u32)
            .expect("operation should succeed for valid inputs");
        art.insert(b"abd", 2)
            .expect("operation should succeed for valid inputs");
        assert!(art.node_count() > initial);
    }

    // --- MPHF tests ---

    #[test]
    fn mphf_build_and_lookup() {
        let entries = vec![
            (b"react".to_vec(), 1u32),
            (b"react-dom".to_vec(), 2),
            (b"redux".to_vec(), 3),
        ];
        let index = MphfIndex::build(entries).expect("builder should produce a valid value");
        assert_eq!(index.get(b"react"), Some(&1));
        assert_eq!(index.get(b"react-dom"), Some(&2));
        assert_eq!(index.get(b"redux"), Some(&3));
        assert_eq!(index.get(b"vue"), None);
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn mphf_empty_keyset_rejected() {
        let result = MphfIndex::<u32>::build(vec![]);
        assert!(matches!(result, Err(IndexBuildError::EmptyKeySet)));
    }

    #[test]
    fn mphf_duplicate_keys_rejected() {
        let entries = vec![(b"react".to_vec(), 1u32), (b"react".to_vec(), 2)];
        let result = MphfIndex::build(entries);
        assert!(matches!(result, Err(IndexBuildError::DuplicateKey { .. })));
    }

    #[test]
    fn mphf_single_entry() {
        let entries = vec![(b"only".to_vec(), 42u32)];
        let index = MphfIndex::build(entries).expect("builder should produce a valid value");
        assert_eq!(index.get(b"only"), Some(&42));
        assert_eq!(index.get(b"other"), None);
    }

    #[test]
    fn mphf_occupancy_reasonable() {
        let entries = vec![
            (b"a".to_vec(), 1u32),
            (b"b".to_vec(), 2),
            (b"c".to_vec(), 3),
        ];
        let index = MphfIndex::build(entries).expect("builder should produce a valid value");
        // With slot padding, occupancy is < 100% but still high
        let occ = index.occupancy_millionths();
        assert!(occ > 250_000, "occupancy should be above 25%: {occ}");
        assert!(occ <= MILLIONTHS);
    }

    #[test]
    fn mphf_many_entries() {
        let entries: Vec<(Vec<u8>, u32)> = (0..200)
            .map(|i| (format!("pkg-{i:04}").into_bytes(), i))
            .collect();
        let index = MphfIndex::build(entries).expect("builder should produce a valid value");
        for i in 0..200 {
            let key = format!("pkg-{i:04}");
            assert_eq!(index.get(key.as_bytes()), Some(&i));
        }
        assert_eq!(index.get(b"pkg-9999"), None);
    }

    // --- PackageEntry tests ---

    #[test]
    fn package_entry_canonical_bytes_deterministic() {
        let e1 = make_package("react", vec![".", "./jsx-runtime"]);
        let e2 = make_package("react", vec![".", "./jsx-runtime"]);
        assert_eq!(e1.canonical_bytes(), e2.canonical_bytes());
    }

    #[test]
    fn package_entry_with_main_and_syntax() {
        let entry = PackageEntry::new("lodash", test_hash())
            .with_main_entry("./lodash.js")
            .with_syntax_hint("cjs");
        assert_eq!(entry.main_entry.as_deref(), Some("./lodash.js"));
        assert_eq!(entry.syntax_hint.as_deref(), Some("cjs"));
    }

    // --- ExportEntry tests ---

    #[test]
    fn export_entry_resolve_target_by_condition() {
        let e = make_export(
            "react",
            ".",
            &[
                ("import", "./esm/react.js"),
                ("require", "./cjs/react.js"),
                ("default", "./index.js"),
            ],
        );
        assert_eq!(e.resolve_target(&["import"]), Some("./esm/react.js"));
        assert_eq!(e.resolve_target(&["require"]), Some("./cjs/react.js"));
        assert_eq!(e.resolve_target(&["node", "default"]), Some("./index.js"));
        assert_eq!(e.resolve_target(&["nonexistent"]), None);
    }

    #[test]
    fn export_entry_resolve_with_fallback() {
        let e = ExportEntry::new("pkg", ".")
            .with_condition("import", "./esm.js")
            .with_fallback("./cjs.js");
        assert_eq!(e.resolve_target(&["import"]), Some("./esm.js"));
        assert_eq!(e.resolve_target(&["require"]), Some("./cjs.js"));
    }

    #[test]
    fn export_entry_canonical_bytes_deterministic() {
        let e1 = make_export("react", ".", &[("import", "./esm.js")]);
        let e2 = make_export("react", ".", &[("import", "./esm.js")]);
        assert_eq!(e1.canonical_bytes(), e2.canonical_bytes());
    }

    // --- PackageIndex tests ---

    #[test]
    fn package_index_build_and_lookup() {
        let config = PackageIndexConfig::new("test-idx", test_epoch());
        let packages = vec![
            make_package("react", vec![".", "./jsx-runtime"]),
            make_package("react-dom", vec![".", "./server"]),
            make_package("lodash", vec!["."]),
        ];
        let exports = vec![
            make_export("react", ".", &[("import", "./esm/react.js")]),
            make_export("react", "./jsx-runtime", &[("import", "./esm/jsx.js")]),
            make_export("react-dom", ".", &[("import", "./esm/react-dom.js")]),
        ];

        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");

        let pkg = index.lookup_package("react");
        assert_eq!(pkg.outcome, IndexLookupOutcome::Hit);
        assert_eq!(
            pkg.value
                .expect("operation should succeed for valid inputs")
                .package_name,
            "react"
        );

        let miss = index.lookup_package("vue");
        assert_eq!(miss.outcome, IndexLookupOutcome::Miss);

        let exp = index.lookup_export("react", ".");
        assert_eq!(exp.outcome, IndexLookupOutcome::Hit);

        let exp_miss = index.lookup_export("react", "./nonexist");
        assert_eq!(exp_miss.outcome, IndexLookupOutcome::Miss);
    }

    #[test]
    fn package_index_resolve_subpath() {
        let config = PackageIndexConfig::new("test-idx", test_epoch());
        let packages =
            vec![make_package("react", vec![".", "./jsx-runtime"]).with_main_entry("./index.js")];
        let exports = vec![
            make_export("react", ".", &[("import", "./esm/react.js")]),
            make_export("react", "./jsx-runtime", &[("import", "./esm/jsx.js")]),
        ];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");

        let r1 = index.resolve_subpath("react", &["import"]);
        assert_eq!(r1.outcome, IndexLookupOutcome::Hit);
        assert_eq!(r1.value.as_deref(), Some("./esm/react.js"));

        let r2 = index.resolve_subpath("react/jsx-runtime", &["import"]);
        assert_eq!(r2.outcome, IndexLookupOutcome::Hit);
        assert_eq!(r2.value.as_deref(), Some("./esm/jsx.js"));

        let r3 = index.resolve_subpath("nonexist", &["import"]);
        assert_eq!(r3.outcome, IndexLookupOutcome::Miss);
    }

    #[test]
    fn package_index_scoped_packages() {
        let config = PackageIndexConfig::new("test-idx", test_epoch());
        let packages = vec![
            make_package("@babel/core", vec!["."]),
            make_package("@babel/parser", vec!["."]),
            make_package("@babel/traverse", vec!["."]),
            make_package("lodash", vec!["."]),
        ];
        let exports = vec![
            make_export("@babel/core", ".", &[("import", "./lib/index.mjs")]),
            make_export("@babel/parser", ".", &[("import", "./lib/index.mjs")]),
            make_export("@babel/traverse", ".", &[("import", "./lib/index.mjs")]),
            make_export("lodash", ".", &[("require", "./lodash.js")]),
        ];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");

        let scoped = index.packages_under_scope("@babel/");
        assert_eq!(scoped.len(), 3);

        let all = index.packages_under_scope("");
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn package_index_stats() {
        let config = PackageIndexConfig::new("test-idx", test_epoch());
        let packages = vec![
            make_package("react", vec!["."]),
            make_package("lodash", vec!["."]),
        ];
        let exports = vec![
            make_export("react", ".", &[("import", "./esm.js")]),
            make_export("lodash", ".", &[("require", "./lodash.js")]),
        ];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");
        let stats = index.stats();
        assert_eq!(stats.package_count, 2);
        assert_eq!(stats.export_count, 2);
        assert!(stats.art_node_count > 0);
    }

    #[test]
    fn package_index_content_hash_deterministic() {
        let make_idx = || {
            let config = PackageIndexConfig::new("idx", test_epoch());
            let packages = vec![make_package("react", vec!["."])];
            let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
            PackageIndex::build(config, packages, exports)
                .expect("builder should produce a valid value")
        };
        let h1 = *make_idx().content_hash();
        let h2 = *make_idx().content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn package_index_empty_exports_allowed() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("lodash", vec![])];
        let index = PackageIndex::build(config, packages, vec![])
            .expect("builder should produce a valid value");
        assert_eq!(index.package_count(), 1);
        assert_eq!(index.export_count(), 0);
    }

    // --- IndexBuildReceipt tests ---

    #[test]
    fn build_receipt_evidence_hash_deterministic() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");
        let r1 = IndexBuildReceipt::from_index(&index, 1000);
        let r2 = IndexBuildReceipt::from_index(&index, 1000);
        assert_eq!(r1.evidence_hash(), r2.evidence_hash());
    }

    #[test]
    fn build_receipt_fields() {
        let config = PackageIndexConfig::new("my-idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");
        let receipt = IndexBuildReceipt::from_index(&index, 5000);
        assert_eq!(receipt.index_id, "my-idx");
        assert_eq!(receipt.package_count, 1);
        assert_eq!(receipt.export_count, 1);
        assert_eq!(receipt.build_duration_ns, 5000);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.policy_id, POLICY_ID);
    }

    // --- SubpathResolutionReceipt tests ---

    #[test]
    fn subpath_receipt_captures_outcome() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");

        let result = index.resolve_subpath("react", &["import"]);
        let receipt = SubpathResolutionReceipt::new(&index, "react", &result, &["import"]);
        assert_eq!(receipt.outcome, IndexLookupOutcome::Hit);
        assert_eq!(receipt.resolved_target.as_deref(), Some("./esm.js"));
        assert_eq!(receipt.conditions_tried, vec!["import"]);
    }

    #[test]
    fn subpath_receipt_miss() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");

        let result = index.resolve_subpath("nonexist", &["import"]);
        let receipt = SubpathResolutionReceipt::new(&index, "nonexist", &result, &["import"]);
        assert_eq!(receipt.outcome, IndexLookupOutcome::Miss);
        assert!(receipt.resolved_target.is_none());
    }

    // --- Serde roundtrip tests ---

    #[test]
    fn package_entry_serde_roundtrip() {
        let entry = make_package("react", vec![".", "./jsx-runtime"])
            .with_main_entry("./index.js")
            .with_syntax_hint("esm");
        let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
        let decoded: PackageEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn export_entry_serde_roundtrip() {
        let entry = make_export(
            "react",
            ".",
            &[("import", "./esm.js"), ("require", "./cjs.js")],
        )
        .with_fallback("./index.js");
        let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
        let decoded: ExportEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn index_build_receipt_serde_roundtrip() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");
        let receipt = IndexBuildReceipt::from_index(&index, 1000);
        let json = serde_json::to_string(&receipt).expect("serialize derived Serialize");
        let decoded: IndexBuildReceipt =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(receipt, decoded);
    }

    // --- FNV hash tests ---

    #[test]
    fn fnv1a_hash_deterministic() {
        let h1 = fnv1a_hash(b"react");
        let h2 = fnv1a_hash(b"react");
        assert_eq!(h1, h2);
        assert_ne!(h1, fnv1a_hash(b"redux"));
    }

    // --- Clamped millionths ---

    #[test]
    fn clamped_millionths_basic() {
        assert_eq!(clamped_millionths(1, 2), 500_000);
        assert_eq!(clamped_millionths(1, 1), MILLIONTHS);
        assert_eq!(clamped_millionths(0, 100), 0);
        assert_eq!(clamped_millionths(0, 0), 0);
    }

    // --- Error display ---

    #[test]
    fn index_build_error_display() {
        let e = IndexBuildError::EmptyKeySet;
        assert!(e.to_string().contains("empty key set"));

        let e2 = IndexBuildError::DuplicateKey {
            key: "react".to_string(),
        };
        assert!(e2.to_string().contains("react"));
    }

    #[test]
    fn lookup_outcome_as_str() {
        assert_eq!(IndexLookupOutcome::Hit.as_str(), "hit");
        assert_eq!(IndexLookupOutcome::Miss.as_str(), "miss");
        assert_eq!(IndexLookupOutcome::FallbackUsed.as_str(), "fallback_used");
    }

    #[test]
    fn package_index_accessors() {
        let config = PackageIndexConfig::new("my-idx", test_epoch());
        let packages = vec![make_package("react", vec!["."])];
        let exports = vec![make_export("react", ".", &[("import", "./esm.js")])];
        let index = PackageIndex::build(config, packages, exports)
            .expect("builder should produce a valid value");
        assert_eq!(index.index_id(), "my-idx");
        assert_eq!(index.schema_version(), SCHEMA_VERSION);
        assert_eq!(index.build_epoch(), test_epoch());
        assert_eq!(index.package_count(), 1);
        assert_eq!(index.export_count(), 1);
    }

    #[test]
    fn package_index_main_entry_fallback() {
        let config = PackageIndexConfig::new("idx", test_epoch());
        let packages = vec![make_package("lodash", vec![]).with_main_entry("./lodash.js")];
        // No exports registered — should fall back to main_entry
        let index = PackageIndex::build(config, packages, vec![])
            .expect("builder should produce a valid value");
        let result = index.resolve_subpath("lodash", &["import"]);
        assert_eq!(result.outcome, IndexLookupOutcome::Hit);
        assert_eq!(result.value.as_deref(), Some("./lodash.js"));
    }
}
