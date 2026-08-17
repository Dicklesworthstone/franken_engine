#![forbid(unsafe_code)]

fn main() {
    let profile_class = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".to_string());
    let debug_info = std::env::var("DEBUG").unwrap_or_else(|_| "unknown".to_string());
    let profile_directory = std::env::var_os("OUT_DIR")
        .and_then(|out_dir| {
            std::path::Path::new(&out_dir)
                .ancestors()
                .nth(3)
                .and_then(std::path::Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_PROFILE_CLASS={profile_class}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_PROFILE_DIRECTORY={profile_directory}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_OPT_LEVEL={opt_level}");
    println!("cargo:rustc-env=FRANKENENGINE_CARGO_DEBUG_INFO={debug_info}");
}
