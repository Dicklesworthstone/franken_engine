#![forbid(unsafe_code)]

pub mod catalog;
pub mod engine_adapter;
pub mod relation;
pub mod relations;
pub mod runner;

pub use engine_adapter::{EngineEval, EngineEvalAdapter, ParseOutcome};

use catalog::RelationCatalog;
use relation::RelationSpec;
use relations::CatalogBackedRelation;

pub fn find_relation(catalog: &RelationCatalog, relation_id: &str) -> Option<RelationSpec> {
    catalog
        .relations
        .iter()
        .find(|relation| relation.id == relation_id)
        .cloned()
}

pub fn build_relation(
    catalog: &RelationCatalog,
    relation_id: &str,
) -> Option<CatalogBackedRelation> {
    find_relation(catalog, relation_id).map(CatalogBackedRelation::new)
}

pub fn build_enabled_relations(catalog: &RelationCatalog) -> Vec<CatalogBackedRelation> {
    catalog
        .enabled_relations()
        .cloned()
        .map(CatalogBackedRelation::new)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::relation::MetamorphicRelation;

    use super::{build_enabled_relations, build_relation};
    use crate::catalog::RelationCatalog;

    #[test]
    fn parser_relation_is_constructed_from_default_catalog() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relation = build_relation(&catalog, "parser_whitespace_invariance")
            .expect("relation should exist");
        assert_eq!(relation.spec().id, "parser_whitespace_invariance");
    }

    #[test]
    fn default_catalog_exposes_multiple_enabled_relations() {
        let catalog = RelationCatalog::load_default().expect("catalog should load");
        let relations = build_enabled_relations(&catalog);
        assert!(
            relations.len() >= 10,
            "expected broad enabled relation coverage"
        );
    }
}
