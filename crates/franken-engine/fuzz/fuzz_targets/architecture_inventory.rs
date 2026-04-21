#![no_main]

use std::fs;

use frankenengine_engine::architecture_inventory::collect_workspace_inventory;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir should be available");
    let repo_root = temp.path();
    let crate_root = repo_root.join("crates/franken-engine");
    let src_root = crate_root.join("src");
    fs::create_dir_all(src_root.join("bin")).expect("fixture src tree should be writable");

    let module_count = data.first().copied().unwrap_or(0) as usize % 12;
    let mut lib_source = String::new();
    for index in 0..module_count {
        let byte = data.get(index + 1).copied().unwrap_or(index as u8);
        let module_name = format!("m{byte:02x}_{index}");
        let disabled = data.get(index + 17).copied().unwrap_or(0) & 1 == 1;
        if disabled {
            lib_source.push_str(&format!("// pub mod {module_name};\n"));
        } else {
            lib_source.push_str(&format!("pub mod {module_name};\n"));
            fs::write(src_root.join(format!("{module_name}.rs")), "")
                .expect("fixture module should be writable");
        }
    }

    let bin_count = data.get(33).copied().unwrap_or(0) as usize % 4;
    let mut manifest = String::from(
        "[package]\nname = \"fake-franken-engine\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    );
    for index in 0..bin_count {
        let byte = data.get(34 + index).copied().unwrap_or(index as u8);
        let bin_name = format!("tool-{byte:02x}-{index}");
        let bin_path = format!("src/bin/tool_{byte:02x}_{index}.rs");
        manifest.push_str(&format!(
            "\n[[bin]]\nname = \"{bin_name}\"\npath = \"{bin_path}\"\n"
        ));
        fs::write(
            src_root
                .join("bin")
                .join(format!("tool_{byte:02x}_{index}.rs")),
            "fn main() {}\n",
        )
        .expect("fixture bin should be writable");
    }

    fs::write(src_root.join("lib.rs"), lib_source).expect("fixture lib.rs should be writable");
    fs::write(crate_root.join("Cargo.toml"), manifest)
        .expect("fixture manifest should be writable");

    let inventory =
        collect_workspace_inventory(repo_root).expect("constructed fixture should inventory");
    let first = inventory.render_markdown();
    let second = inventory.render_markdown();
    assert_eq!(first, second);
    assert!(first.contains("# FrankenEngine Architecture Inventory"));
});
