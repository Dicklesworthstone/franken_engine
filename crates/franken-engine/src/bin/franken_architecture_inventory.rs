#![forbid(unsafe_code)]

use std::path::PathBuf;
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
    let cli = Cli::from_args(env::args().skip(1))?;
    if cli.mode == Mode::Help {
        print_usage();
        return Ok(());
    }

    // Resolve the tree to inventory: an explicit `--repo-root` wins, otherwise
    // discover from the current working directory (bd-yetou). Always announce
    // the resolved root on stderr so an inventory can be reviewed against the
    // tree it actually describes — a silent wrong-tree run is exactly the
    // failure this fixes.
    let repo_root = cli.repo_root.unwrap_or_else(default_repo_root);
    eprintln!(
        "architecture inventory: repo root = {}",
        repo_root.display()
    );

    let inventory = collect_workspace_inventory(&repo_root)?;
    let markdown = inventory.render_markdown();
    let output_path = repo_root.join("docs/ARCHITECTURE_INVENTORY.md");

    match cli.mode {
        Mode::Write => {
            fs::write(&output_path, markdown)?;
            println!("wrote {}", output_path.display());
        }
        Mode::Check => {
            // Fail loudly if the resolved tree has no inventory doc to compare
            // against, rather than emitting a confusing raw I/O error (bd-yetou).
            if !output_path.is_file() {
                return Err(format!(
                    "{} does not exist under the resolved repo root {}",
                    output_path.display(),
                    repo_root.display()
                )
                .into());
            }
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
        Mode::Help => {
            unreachable!("help mode returns before inventory collection")
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    mode: Mode,
    repo_root: Option<PathBuf>,
}

impl Cli {
    fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut mode = Mode::Write;
        let mut repo_root = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => mode = Mode::Help,
                "--check" => mode = Mode::Check,
                "--stdout" => mode = Mode::Stdout,
                "--repo-root" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--repo-root requires a path argument".to_string())?;
                    repo_root = Some(PathBuf::from(value));
                }
                other if other.starts_with("--repo-root=") => {
                    repo_root = Some(PathBuf::from(
                        other.trim_start_matches("--repo-root=").to_string(),
                    ));
                }
                other => return Err(format!("unrecognized argument: {other}")),
            }
        }
        Ok(Self { mode, repo_root })
    }
}

fn print_usage() {
    println!(
        "\
franken-architecture-inventory usage:

  franken-architecture-inventory [--repo-root <path>] [--stdout|--check|--help]

Options:
  --repo-root <path>   Inventory this tree instead of discovering one from the
                       current working directory (the resolved root is always
                       printed on stderr)
  --stdout   Print the generated architecture inventory markdown to stdout
  --check    Fail if docs/ARCHITECTURE_INVENTORY.md is stale
  --help     Print this help text

The repo root is discovered by walking up from the current working directory
for crates/franken-engine/Cargo.toml, so a prebuilt binary inventories the tree
it is run in rather than the tree it was compiled in. Default behavior writes
docs/ARCHITECTURE_INVENTORY.md under the resolved root."
    );
}
