#![forbid(unsafe_code)]

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let mut passthrough_args = Vec::<String>::new();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        passthrough_args.push(arg.clone());
        if matches!(
            arg.as_str(),
            "--pairs"
                | "--seed"
                | "--trace-id"
                | "--decision-id"
                | "--policy-id"
                | "--evidence"
                | "--events"
                | "--failures-dir"
        ) {
            if let Some(value) = args.next() {
                passthrough_args.push(value);
            } else {
                return Err(format!("missing value for {arg}").into());
            }
        }
    }

    let executable = std::env::current_exe()?;
    let suite_bin = executable
        .parent()
        .map(|parent| parent.join("run_metamorphic_suite"))
        .unwrap_or_else(|| PathBuf::from("run_metamorphic_suite"));

    let status = std::process::Command::new(suite_bin)
        .args(&passthrough_args)
        .arg("--relation")
        .arg("parser_whitespace_invariance")
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err("run_metamorphic_suite failed for parser relation".into())
    }
}
