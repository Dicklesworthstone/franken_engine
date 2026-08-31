#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

SCHEMA_VERSION = "franken-engine.agent-change-routes.v1"
CLAIM_RE = re.compile(r"^FE-CLAIM-[A-Z0-9-]+$")
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class RouteError(RuntimeError):
    pass


@dataclass(frozen=True)
class Match:
    route: dict[str, Any]
    patterns: tuple[str, ...]
    score: int


def repository_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parent.parent


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RouteError(f"unable to read route manifest {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise RouteError(f"invalid JSON in route manifest {path}: {error}") from error
    if not isinstance(payload, dict):
        raise RouteError("route manifest root must be an object")
    return payload


def tracked_paths(root: Path) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            ("git", "-C", str(root), "ls-files", "-z"),
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        ignored = {".git", "target", "__pycache__", ".pytest_cache", ".mypy_cache"}
        paths: list[str] = []
        for directory, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(name for name in dirnames if name not in ignored)
            relative_dir = Path(directory).relative_to(root)
            for filename in sorted(filenames):
                paths.append((relative_dir / filename).as_posix())
        return tuple(paths)
    return tuple(
        item.decode("utf-8", errors="strict")
        for item in completed.stdout.split(b"\0")
        if item
    )


def glob_matches(path: str, pattern: str) -> bool:
    normalized_path = PurePosixPath(path).as_posix()
    normalized_pattern = PurePosixPath(pattern).as_posix()
    return fnmatch.fnmatchcase(normalized_path, normalized_pattern)


def pattern_specificity(pattern: str) -> int:
    wildcard_penalty = sum(pattern.count(token) for token in ("*", "?", "["))
    literal_length = len(re.sub(r"[*?\[\]]", "", pattern))
    exact_bonus = 10_000 if wildcard_penalty == 0 else 0
    suffix_bonus = 500 if pattern.endswith((".rs", ".py", ".sh", ".json", ".md", ".toml")) else 0
    return exact_bonus + suffix_bonus + literal_length * 10 - wildcard_penalty * 100


def validate_manifest(manifest: dict[str, Any], root: Path, paths: Sequence[str]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}, got {manifest.get('schema_version')!r}"
        )
    defaults = manifest.get("defaults")
    if not isinstance(defaults, dict):
        errors.append("defaults must be an object")
    routes = manifest.get("routes")
    if not isinstance(routes, list) or not routes:
        errors.append("routes must be a non-empty array")
        return errors
    ids: list[str] = []
    known_paths = set(paths)
    for index, route in enumerate(routes):
        where = f"routes[{index}]"
        if not isinstance(route, dict):
            errors.append(f"{where} must be an object")
            continue
        route_id = route.get("route_id")
        if not isinstance(route_id, str) or not route_id:
            errors.append(f"{where}.route_id must be a non-empty string")
        else:
            ids.append(route_id)
        if not isinstance(route.get("title"), str) or not route["title"]:
            errors.append(f"{where}.title must be a non-empty string")
        if not isinstance(route.get("layer"), str) or not route["layer"]:
            errors.append(f"{where}.layer must be a non-empty string")
        if not isinstance(route.get("priority"), int):
            errors.append(f"{where}.priority must be an integer")
        patterns = route.get("path_globs")
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(pattern, str) and pattern for pattern in patterns
        ):
            errors.append(f"{where}.path_globs must be a non-empty string array")
        elif not any(any(glob_matches(path, pattern) for path in paths) for pattern in patterns):
            errors.append(f"{where}.path_globs match no tracked path")
        for field in ("anchor_files", "governing_docs"):
            values = route.get(field)
            if not isinstance(values, list) or not values or not all(
                isinstance(value, str) and value for value in values
            ):
                errors.append(f"{where}.{field} must be a non-empty string array")
                continue
            for value in values:
                if value not in known_paths and not (root / value).exists():
                    errors.append(f"{where}.{field} references missing path {value!r}")
        checks = route.get("focused_checks")
        if not isinstance(checks, list) or not checks:
            errors.append(f"{where}.focused_checks must be a non-empty array")
        else:
            for check_index, check in enumerate(checks):
                check_where = f"{where}.focused_checks[{check_index}]"
                if not isinstance(check, dict):
                    errors.append(f"{check_where} must be an object")
                    continue
                for field in ("command", "proves"):
                    if not isinstance(check.get(field), str) or not check[field]:
                        errors.append(f"{check_where}.{field} must be a non-empty string")
        for field in ("downstream_artifacts", "neighbors", "claim_ids", "bead_search_terms"):
            values = route.get(field)
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                errors.append(f"{where}.{field} must be a string array")
        for claim_id in route.get("claim_ids", []):
            if not CLAIM_RE.fullmatch(claim_id):
                errors.append(f"{where}.claim_ids contains invalid id {claim_id!r}")
        hotspot = route.get("hotspot")
        if not isinstance(hotspot, dict):
            errors.append(f"{where}.hotspot must be an object")
        else:
            level = hotspot.get("level")
            if level not in LEVEL_ORDER:
                errors.append(f"{where}.hotspot.level must be one of {sorted(LEVEL_ORDER)}")
            for field in ("reason", "coordination"):
                if not isinstance(hotspot.get(field), str) or not hotspot[field]:
                    errors.append(f"{where}.hotspot.{field} must be a non-empty string")
    duplicates = sorted({route_id for route_id in ids if ids.count(route_id) > 1})
    for route_id in duplicates:
        errors.append(f"duplicate route_id {route_id!r}")
    route_ids = set(ids)
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            continue
        for neighbor in route.get("neighbors", []):
            if neighbor not in route_ids:
                errors.append(f"routes[{index}].neighbors references unknown route {neighbor!r}")
    return errors


def normalize_input_path(value: str, root: Path) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root)
        except ValueError as error:
            raise RouteError(f"path is outside repository root: {value}") from error
    normalized = PurePosixPath(candidate.as_posix()).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in ("", "."):
        raise RouteError(f"path must name a repository entry: {value!r}")
    if normalized == ".." or normalized.startswith("../"):
        raise RouteError(f"path escapes repository root: {value!r}")
    return normalized


def changed_paths(root: Path, base: str, include_worktree: bool) -> tuple[str, ...]:
    commands = [
        ("git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base}...HEAD"),
    ]
    if include_worktree:
        commands.extend(
            (
                ("git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRTUXB"),
                ("git", "-C", str(root), "diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"),
                ("git", "-C", str(root), "ls-files", "--others", "--exclude-standard"),
            )
        )
    paths: set[str] = set()
    for command in commands:
        try:
            completed = subprocess.run(command, check=True, capture_output=True, text=True)
        except OSError as error:
            raise RouteError(f"unable to execute git: {error}") from error
        except subprocess.CalledProcessError as error:
            detail = (error.stderr or error.stdout or "").strip()
            raise RouteError(f"unable to resolve changed paths from {base!r}: {detail}") from error
        paths.update(line.strip() for line in completed.stdout.splitlines() if line.strip())
    return tuple(sorted(paths))


def route_matches(path: str, route: dict[str, Any]) -> Match | None:
    patterns = tuple(pattern for pattern in route["path_globs"] if glob_matches(path, pattern))
    if not patterns:
        return None
    score = int(route["priority"]) * 100_000 + max(pattern_specificity(pattern) for pattern in patterns)
    return Match(route=route, patterns=patterns, score=score)


def matches_for_path(path: str, routes: Sequence[dict[str, Any]]) -> tuple[Match, ...]:
    matches = [match for route in routes if (match := route_matches(path, route)) is not None]
    matches.sort(
        key=lambda match: (
            -match.score,
            LEVEL_ORDER[match.route["hotspot"]["level"]],
            match.route["route_id"],
        )
    )
    return tuple(matches)


def aggregate(
    requested_paths: Sequence[str],
    routes: Sequence[dict[str, Any]],
    defaults: dict[str, Any],
) -> dict[str, Any]:
    by_path: list[dict[str, Any]] = []
    selected: dict[str, dict[str, Any]] = {}
    unmatched: list[str] = []
    for path in requested_paths:
        matches = matches_for_path(path, routes)
        if not matches:
            unmatched.append(path)
            by_path.append({"path": path, "primary_route": None, "matches": []})
            continue
        primary = matches[0].route
        by_path.append(
            {
                "path": path,
                "primary_route": primary["route_id"],
                "matches": [
                    {
                        "route_id": match.route["route_id"],
                        "title": match.route["title"],
                        "layer": match.route["layer"],
                        "matched_patterns": list(match.patterns),
                        "score": match.score,
                    }
                    for match in matches
                ],
            }
        )
        for match in matches:
            selected[match.route["route_id"]] = match.route
    ordered_routes = sorted(
        selected.values(),
        key=lambda route: (
            LEVEL_ORDER[route["hotspot"]["level"]],
            -int(route["priority"]),
            route["route_id"],
        ),
    )
    commands = dedupe(check["command"] for route in ordered_routes for check in route["focused_checks"])
    docs = dedupe(
        [
            *defaults.get("read_first", []),
            *(doc for route in ordered_routes for doc in route["governing_docs"]),
        ]
    )
    anchors = dedupe(anchor for route in ordered_routes for anchor in route["anchor_files"])
    downstream = dedupe(artifact for route in ordered_routes for artifact in route["downstream_artifacts"])
    claims = dedupe(claim for route in ordered_routes for claim in route["claim_ids"])
    bead_terms = dedupe(term for route in ordered_routes for term in route["bead_search_terms"])
    return {
        "schema_version": SCHEMA_VERSION,
        "requested_paths": list(requested_paths),
        "unmatched_paths": unmatched,
        "path_routes": by_path,
        "routes": ordered_routes,
        "read_first": docs,
        "anchor_files": anchors,
        "focused_commands": commands,
        "downstream_artifacts": downstream,
        "claim_ids": claims,
        "bead_search_terms": bead_terms,
        "global_invariants": defaults.get("global_invariants", []),
    }


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def render_text(result: dict[str, Any]) -> str:
    lines = ["Agent change route", "==================", ""]
    for item in result["path_routes"]:
        lines.append(f"Path: {item['path']}")
        if item["primary_route"] is None:
            lines.append("  Primary: UNROUTED")
            continue
        lines.append(f"  Primary: {item['primary_route']}")
        secondary = [match["route_id"] for match in item["matches"][1:]]
        if secondary:
            lines.append(f"  Also touches: {', '.join(secondary)}")
    if result["unmatched_paths"]:
        lines.extend(
            (
                "",
                "Unrouted paths:",
                *(f"  - {path}" for path in result["unmatched_paths"]),
                "  Add or refine a manifest route before treating the change as understood.",
            )
        )
    lines.extend(("", "Read first:", *(f"  - {value}" for value in result["read_first"])))
    lines.extend(("", "Semantic anchors:", *(f"  - {value}" for value in result["anchor_files"])))
    lines.append("")
    lines.append("Selected routes:")
    for route in result["routes"]:
        hotspot = route["hotspot"]
        lines.extend(
            (
                f"  [{hotspot['level'].upper()}] {route['route_id']} — {route['title']}",
                f"    Layer: {route['layer']}",
                f"    Risk: {hotspot['reason']}",
                f"    Coordination: {hotspot['coordination']}",
            )
        )
    lines.extend(("", "Run first:", *(f"  - {value}" for value in result["focused_commands"])))
    lines.extend(
        ("", "Update or inspect after the change:", *(f"  - {value}" for value in result["downstream_artifacts"]))
    )
    if result["claim_ids"]:
        lines.extend(("", f"Claim boundaries: {', '.join(result['claim_ids'])}"))
    if result["bead_search_terms"]:
        lines.extend(("", "Tracker search terms:", *(f"  - {value}" for value in result["bead_search_terms"])))
    if result["global_invariants"]:
        lines.extend(("", "Global invariants:", *(f"  - {value}" for value in result["global_invariants"])))
    return "\n".join(lines) + "\n"


def render_commands(result: dict[str, Any]) -> str:
    return "\n".join(result["focused_commands"]) + ("\n" if result["focused_commands"] else "")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Map repository changes to architectural owners, contracts, focused checks, and truth artifacts."
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Route manifest path; defaults to docs/agent_change_routes_v1.json under the repository root.",
    )
    parser.add_argument("--path", action="append", default=[], help="Repository path to route; repeatable.")
    parser.add_argument(
        "--changed",
        metavar="BASE",
        help="Route files changed between BASE and HEAD. Add --include-worktree to include local changes.",
    )
    parser.add_argument("--include-worktree", action="store_true")
    parser.add_argument("--claim", action="append", default=[], help="Filter selected routes by FE-CLAIM id.")
    parser.add_argument("--route", action="append", default=[], help="Filter selected routes by route id.")
    parser.add_argument("--check", action="store_true", help="Validate the route manifest against the repository.")
    parser.add_argument("--strict", action="store_true", help="Fail when any requested path has no route.")
    parser.add_argument("--format", choices=("text", "json", "commands"), default="text")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = repository_root(args.root)
    manifest_path = args.manifest.resolve() if args.manifest is not None else root / "docs" / "agent_change_routes_v1.json"
    try:
        manifest = load_manifest(manifest_path)
        paths = tracked_paths(root)
        errors = validate_manifest(manifest, root, paths)
        if errors:
            for error in errors:
                print(f"agent-route manifest error: {error}", file=sys.stderr)
            return 1
        if args.check and not args.path and args.changed is None and not args.claim and not args.route:
            print(
                f"agent-route manifest valid: {len(manifest['routes'])} routes, "
                f"{len(paths)} tracked paths, schema={SCHEMA_VERSION}"
            )
            return 0
        requested_paths = [normalize_input_path(value, root) for value in args.path]
        if args.changed is not None:
            requested_paths.extend(changed_paths(root, args.changed, include_worktree=args.include_worktree))
        requested_paths = dedupe(requested_paths)
        routes = list(manifest["routes"])
        if args.claim:
            unknown_claims = sorted(
                set(args.claim) - {claim for route in routes for claim in route.get("claim_ids", [])}
            )
            if unknown_claims:
                raise RouteError(f"unknown claim filter(s): {', '.join(unknown_claims)}")
            routes = [route for route in routes if any(claim in route.get("claim_ids", []) for claim in args.claim)]
        if args.route:
            route_ids = {route["route_id"] for route in routes}
            unknown_routes = sorted(set(args.route) - route_ids)
            if unknown_routes:
                raise RouteError(f"unknown route filter(s): {', '.join(unknown_routes)}")
            routes = [route for route in routes if route["route_id"] in set(args.route)]
        if not requested_paths:
            if args.claim or args.route:
                requested_paths = dedupe(anchor for route in routes for anchor in route["anchor_files"])
            else:
                raise RouteError("provide --path, --changed, --claim, or --route")
        result = aggregate(requested_paths, routes, manifest["defaults"])
        if args.format == "json":
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.format == "commands":
            sys.stdout.write(render_commands(result))
        else:
            sys.stdout.write(render_text(result))
        if args.strict and result["unmatched_paths"]:
            return 2
        return 0
    except RouteError as error:
        print(f"agent-route error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
