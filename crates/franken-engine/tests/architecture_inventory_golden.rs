#![forbid(unsafe_code)]

use frankenengine_engine::architecture_inventory::{
    collect_workspace_inventory, default_repo_root,
};

#[test]
fn architecture_inventory_markdown_matches_golden_artifact() {
    let repo_root = default_repo_root();
    let inventory =
        collect_workspace_inventory(&repo_root).expect("architecture inventory should generate");
    let actual = inventory.render_markdown();
    let expected = include_str!("../../../docs/ARCHITECTURE_INVENTORY.md");

    assert_eq!(
        actual, expected,
        "architecture inventory drifted; run scripts/generate_architecture_inventory.sh and review docs/ARCHITECTURE_INVENTORY.md"
    );
}
