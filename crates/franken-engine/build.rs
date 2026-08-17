#![forbid(unsafe_code)]

fn is_cargo_unit_hash(value: &str) -> bool {
    value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn profile_directory_from_out_dir(out_dir: &std::path::Path) -> Option<String> {
    if out_dir.file_name()?.to_str()? != "out" {
        return None;
    }

    let unit_dir = out_dir.parent()?;
    let unit_name = unit_dir.file_name()?.to_str()?;
    let unit_parent = unit_dir.parent()?;
    let unit_parent_name = unit_parent.file_name()?.to_str()?;

    let profile_dir = if unit_parent_name == "frankenengine-engine"
        && is_cargo_unit_hash(unit_name)
        && unit_parent.parent()?.file_name()?.to_str()? == "build"
    {
        // New layout: `<profile>/build/<package>/<unit-hash>/out`.
        unit_parent.parent()?.parent()?
    } else if unit_parent_name == "build"
        && unit_name
            .strip_prefix("frankenengine-engine-")
            .is_some_and(is_cargo_unit_hash)
    {
        // Legacy layout: `<profile>/build/<package>-<unit-hash>/out`.
        unit_parent.parent()?
    } else {
        return None;
    };
    profile_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

fn main() {
    let profile_class = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".to_string());
    let debug_info = std::env::var("DEBUG").unwrap_or_else(|_| "unknown".to_string());
    let profile_directory = std::env::var_os("OUT_DIR")
        .and_then(|out_dir| profile_directory_from_out_dir(std::path::Path::new(&out_dir)))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_PROFILE_CLASS={profile_class}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_PROFILE_DIRECTORY={profile_directory}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_OPT_LEVEL={opt_level}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_DEBUG_INFO={debug_info}");
}
