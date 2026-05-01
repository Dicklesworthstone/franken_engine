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
    if mode == Mode::Help {
        print_usage();
        return Ok(());
    }

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
        Mode::Help => unreachable!("help mode returns before inventory collection"),
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Write,
    Check,
    Stdout,
    Help,
}

impl Mode {
    fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        let mut mode = Self::Write;
        for arg in args {
            match arg.as_str() {
                "--help" | "-h" => mode = Self::Help,
                "--check" => mode = Self::Check,
                "--stdout" => mode = Self::Stdout,
                _ => {}
            }
        }
        mode
    }
}

fn print_usage() {
    println!(
        "\
franken-architecture-inventory usage:

  franken-architecture-inventory [--stdout|--check|--help]

Options:
  --stdout   Print the generated architecture inventory markdown to stdout
  --check    Fail if docs/ARCHITECTURE_INVENTORY.md is stale
  --help     Print this help text

Default behavior writes docs/ARCHITECTURE_INVENTORY.md."
    );
}
