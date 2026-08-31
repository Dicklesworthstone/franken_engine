#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

SUMMARY_LABEL = "Release binary targets"
SECTION_TITLE = "Release Binary Targets"


class InventoryError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class ReleaseBinary:
    name: str
    source_path: str
    manifest_declared: bool

    def markdown(self) -> str:
        origin = "manifest" if self.manifest_declared else "auto"
        return f"- `{self.name}` — `{self.source_path}` ({origin})"


def slash(path: Path) -> str:
    return path.as_posix()


def load_manifest_bins(repo_root: Path) -> dict[str, str]:
    manifest_path = repo_root / "crates/franken-engine/Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InventoryError(f"missing manifest: {manifest_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise InventoryError(f"invalid TOML in {manifest_path}: {exc}") from exc
    raw_bins = manifest.get("bin", [])
    if not isinstance(raw_bins, list):
        raise InventoryError("Cargo.toml [[bin]] declarations are not an array")
    bins: dict[str, str] = {}
    for index, raw in enumerate(raw_bins):
        if not isinstance(raw, dict):
            raise InventoryError(f"Cargo.toml bin[{index}] is not a table")
        name = raw.get("name")
        path = raw.get("path")
        if not isinstance(name, str) or not name:
            raise InventoryError(f"Cargo.toml bin[{index}] has no non-empty name")
        if not isinstance(path, str) or not path:
            raise InventoryError(f"Cargo.toml bin[{index}] has no non-empty path")
        source_path = f"crates/franken-engine/{Path(path).as_posix()}"
        if source_path in bins and bins[source_path] != name:
            raise InventoryError(f"manifest path {source_path} maps to multiple binary names")
        bins[source_path] = name
    return bins


def collect_release_binaries(repo_root: Path) -> list[ReleaseBinary]:
    manifest_bins = load_manifest_bins(repo_root)
    bin_root = repo_root / "crates/franken-engine/src/bin"
    by_name: dict[str, ReleaseBinary] = {}
    if bin_root.is_dir():
        for path in sorted(bin_root.iterdir()):
            if not path.is_file() or path.suffix != ".rs":
                continue
            source_path = slash(path.relative_to(repo_root))
            name = manifest_bins.get(source_path, path.stem)
            binary = ReleaseBinary(
                name=name,
                source_path=source_path,
                manifest_declared=source_path in manifest_bins,
            )
            previous = by_name.get(name)
            if previous is not None and previous != binary:
                raise InventoryError(
                    f"binary name {name!r} maps to both {previous.source_path} and {source_path}"
                )
            by_name[name] = binary
    for source_path, name in manifest_bins.items():
        binary = ReleaseBinary(name=name, source_path=source_path, manifest_declared=True)
        previous = by_name.get(name)
        if previous is not None and previous != binary:
            raise InventoryError(
                f"binary name {name!r} maps to both {previous.source_path} and {source_path}"
            )
        by_name.setdefault(name, binary)
    return sorted(by_name.values())


def render_section(binaries: list[ReleaseBinary]) -> str:
    if not binaries:
        body = "None."
    else:
        body = "\n".join(binary.markdown() for binary in binaries)
    return f"## {SECTION_TITLE}\n\n{body}\n\n"


def reconcile_text(text: str, binaries: list[ReleaseBinary]) -> str:
    summary_pattern = re.compile(
        rf"^\| {re.escape(SUMMARY_LABEL)} \| (\d+) \|$", re.MULTILINE
    )
    summary_matches = list(summary_pattern.finditer(text))
    if len(summary_matches) != 1:
        raise InventoryError(
            f"expected exactly one {SUMMARY_LABEL!r} summary row, found {len(summary_matches)}"
        )
    start, end = summary_matches[0].span(1)
    result = text[:start] + str(len(binaries)) + text[end:]

    section_pattern = re.compile(
        rf"^## {re.escape(SECTION_TITLE)}\n\n.*?(?=^## |\Z)", re.MULTILINE | re.DOTALL
    )
    section_matches = list(section_pattern.finditer(result))
    if len(section_matches) != 1:
        raise InventoryError(
            f"expected exactly one {SECTION_TITLE!r} section, found {len(section_matches)}"
        )
    section = render_section(binaries)
    match = section_matches[0]
    return result[: match.start()] + section + result[match.end() :]


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def diff(path: Path, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path.as_posix()}",
            tofile=f"b/{path.as_posix()}",
            n=3,
        )
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile the generated architecture inventory's release-binary count "
            "and section against Cargo.toml plus src/bin."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--fix", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.repo_root.resolve()
    inventory_path = root / "docs/ARCHITECTURE_INVENTORY.md"
    try:
        before = inventory_path.read_text(encoding="utf-8")
        binaries = collect_release_binaries(root)
        after = reconcile_text(before, binaries)
    except (FileNotFoundError, InventoryError) as exc:
        print(f"architecture binary inventory error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        if before == after:
            print(f"architecture_binary_inventory=ok count={len(binaries)}")
            return 0
        sys.stdout.write(diff(Path("docs/ARCHITECTURE_INVENTORY.md"), before, after))
        print(
            "architecture binary inventory is stale; run "
            "python3 scripts/reconcile_architecture_binary_inventory.py --fix",
            file=sys.stderr,
        )
        return 1
    if before == after:
        print(f"architecture_binary_inventory=already_current count={len(binaries)}")
        return 0
    write_atomic(inventory_path, after)
    print(f"architecture_binary_inventory=updated count={len(binaries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
