#![forbid(unsafe_code)]

use std::{env, fs, process};

use frankenengine_engine::architecture_inventory::{
    collect_workspace_inventory, default_repo_root,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("architecture inventory failed: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mode = Mode::from_args(env::args().skip(1));
    let repo_root = default_repo_root();
    let inventory = collect_workspace_inventory(&repo_root)?;
    let markdown = inventory.render_markdown();
    let output_path = repo_root.join("docs/ARCHITECTURE_INVENTORY.md");

    match mode {
        Mode::Write => {
            fs::write(&output_path, markdown)?;
            println!("wrote {}", output_path.display());
        }
        Mode::Check => {
            let existing = fs::read_to_string(&output_path)?;
            if existing != markdown {
                return Err(format!(
                    "{} is stale; run scripts/generate_architecture_inventory.sh",
                    output_path.display()
                )
                .into());
            }
            println!("{} is up to date", output_path.display());
        }
        Mode::Stdout => {
            print!("{markdown}");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Write,
    Check,
    Stdout,
}

impl Mode {
    fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        let mut mode = Self::Write;
        for arg in args {
            match arg.as_str() {
                "--check" => mode = Self::Check,
                "--stdout" => mode = Self::Stdout,
                _ => {}
            }
        }
        mode
    }
}
