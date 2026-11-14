//! Exact filesystem inputs consumed by module loading and package resolution.
//!
//! Hash the bytes already read, before parsing them. A directory snapshot made
//! after execution cannot identify which package source actually ran, and a
//! preflight-only hash check cannot prevent a later changed read.

use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};

use crate::hash_tiers::ContentHash;

const MAX_INPUTS: usize = 65_536;
const MAX_RETAINED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default)]
struct ObservedInputs {
    hashes: BTreeMap<String, String>,
    retained_bytes: usize,
    failure: Option<String>,
}

/// Per-execution filesystem module integrity state. Clones share the observed
/// inputs of one run; [`Self::new_attempt`] starts a fresh run with the same
/// optional replay expectation. No source bytes are retained.
#[derive(Debug, Clone, Default)]
pub struct ModuleSourceIntegrity {
    expected: Option<Arc<BTreeMap<String, String>>>,
    observed: Arc<Mutex<ObservedInputs>>,
}

impl ModuleSourceIntegrity {
    /// Require every consumed source or package manifest to match this exact
    /// root-relative content-hash map. An empty map forbids filesystem inputs.
    pub fn replaying(expected: BTreeMap<String, String>) -> Self {
        Self {
            expected: Some(Arc::new(expected)),
            observed: Arc::default(),
        }
    }

    pub(crate) fn new_attempt(&self) -> Self {
        Self {
            expected: self.expected.clone(),
            observed: Arc::default(),
        }
    }

    pub(super) fn observe(&self, root: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "module integrity input escapes the configured root".to_string())?;
        let mut parts = Vec::new();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err("module integrity input is not a canonical relative path".to_string());
            };
            parts.push(
                part.to_str()
                    .ok_or_else(|| "module integrity input path is not valid UTF-8".to_string())?,
            );
        }
        if parts.is_empty() {
            return Err("module integrity input has an empty relative path".to_string());
        }
        let key = parts.join("/");
        let hash = ContentHash::compute(bytes).to_hex();
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| "module integrity state is poisoned".to_string())?;
        if let Some(error) = &observed.failure {
            return Err(error.clone());
        }
        let failure = if let Some(expected) = &self.expected {
            match expected.get(&key) {
                Some(expected_hash) if expected_hash == &hash => None,
                Some(_) => Some(format!("module integrity content mismatch for `{key}`")),
                None => Some(format!("module integrity input `{key}` was not recorded")),
            }
        } else {
            None
        }
        .or_else(|| {
            observed.hashes.get(&key).and_then(|previous| {
                (previous != &hash)
                    .then(|| format!("module integrity input `{key}` changed during execution"))
            })
        });
        if let Some(error) = failure {
            observed.failure = Some(error.clone());
            return Err(error);
        }
        if !observed.hashes.contains_key(&key) {
            // Include a conservative per-map-entry allowance, not just text.
            let retained_bytes = observed
                .retained_bytes
                .saturating_add(key.len())
                .saturating_add(hash.len())
                .saturating_add(128);
            if observed.hashes.len() >= MAX_INPUTS || retained_bytes > MAX_RETAINED_BYTES {
                let error = "module integrity input budget exceeded".to_string();
                observed.failure = Some(error.clone());
                return Err(error);
            }
            observed.retained_bytes = retained_bytes;
            observed.hashes.insert(key, hash);
        }
        Ok(())
    }

    /// Finish only an exact replay: missing inputs and an earlier integrity
    /// rejection remain failures even when guest code caught a loader error.
    pub(crate) fn finish(&self) -> Result<BTreeMap<String, String>, String> {
        let observed = self
            .observed
            .lock()
            .map_err(|_| "module integrity state is poisoned".to_string())?;
        if let Some(error) = &observed.failure {
            return Err(error.clone());
        }
        if let Some(expected) = &self.expected
            && let Some(missing) = expected
                .keys()
                .find(|key| !observed.hashes.contains_key(*key))
        {
            return Err(format!(
                "module integrity recorded input `{missing}` was not consumed"
            ));
        }
        Ok(observed.hashes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_read_cannot_replace_the_bytes_that_ran() {
        let integrity = ModuleSourceIntegrity::default();
        let root = Path::new("/modules");
        let path = root.join("node_modules/package/index.js");
        integrity.observe(root, &path, b"original").unwrap();
        assert!(integrity.observe(root, &path, b"changed").is_err());
        assert!(integrity.finish().is_err());
        let fresh = integrity.new_attempt();
        fresh.observe(root, &path, b"changed").unwrap();
        assert_eq!(fresh.finish().unwrap().len(), 1);
    }

    #[test]
    fn replay_rejects_new_changed_and_missing_inputs() {
        let root = Path::new("/modules");
        let path = root.join("package.json");
        let expected = BTreeMap::from([(
            "package.json".to_string(),
            ContentHash::compute(b"{}").to_hex(),
        )]);
        let replay = ModuleSourceIntegrity::replaying(expected);
        assert!(replay.finish().is_err());
        assert!(replay.observe(root, &path, b"changed").is_err());
        assert!(replay.observe(root, &path, b"{}").is_err());
        let fresh = replay.new_attempt();
        fresh.observe(root, &path, b"{}").unwrap();
        assert!(fresh.finish().is_ok());
        assert!(fresh.observe(root, &root.join("new.js"), b"42").is_err());
        assert!(fresh.finish().is_err());
    }
}
