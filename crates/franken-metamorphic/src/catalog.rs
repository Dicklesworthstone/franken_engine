use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::relation::RelationSpec;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationCatalog {
    pub schema_version: u32,
    pub relations: Vec<RelationSpec>,
}

impl RelationCatalog {
    pub fn from_toml_str(toml_source: &str) -> Result<Self, toml::de::Error> {
        toml::from_str::<Self>(toml_source)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, CatalogLoadError> {
        let source = fs::read_to_string(path).map_err(CatalogLoadError::Io)?;
        Self::from_toml_str(&source).map_err(CatalogLoadError::Toml)
    }

    pub fn load_default() -> Result<Self, CatalogLoadError> {
        let source = include_str!("../metamorphic_relations.toml");
        Self::from_toml_str(source).map_err(CatalogLoadError::Toml)
    }

    pub fn enabled_relations(&self) -> impl Iterator<Item = &RelationSpec> {
        self.relations.iter().filter(|relation| relation.enabled)
    }

    pub fn content_hash(&self) -> String {
        let canonical_json = serde_json::to_vec(self)
            .expect("relation catalog should serialize for content hashing");
        let digest = Sha256::digest(canonical_json);
        format!("sha256:{}", hex::encode(digest))
    }
}

#[derive(Debug)]
pub enum CatalogLoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for CatalogLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read relation catalog: {error}"),
            Self::Toml(error) => write!(f, "failed to parse relation catalog TOML: {error}"),
        }
    }
}

impl std::error::Error for CatalogLoadError {}

#[cfg(test)]
mod tests {
    use super::RelationCatalog;

    #[test]
    fn default_catalog_loads_and_has_enabled_relation() {
        let catalog = RelationCatalog::load_default().expect("default catalog should load");
        assert_eq!(catalog.schema_version, 2);
        assert!(
            catalog
                .enabled_relations()
                .any(|relation| relation.id == "parser_whitespace_invariance")
        );
    }

    #[test]
    fn content_hash_is_stable_for_same_catalog() {
        let left = RelationCatalog::load_default().expect("default catalog should load");
        let right = RelationCatalog::load_default().expect("default catalog should load");
        assert_eq!(left.content_hash(), right.content_hash());
    }
}
