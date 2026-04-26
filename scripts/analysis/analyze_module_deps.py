#!/usr/bin/env python3
"""
Module dependency analyzer for franken-engine

This script analyzes the dependency graph of all modules in the franken-engine crate
and classifies them based on reachability from entry points.
"""

import os
import re
import json
from collections import defaultdict, deque
from typing import Dict, Set, List, Tuple

def collect_modules(src_path: str) -> Dict[str, str]:
    """Collect all Rust modules in the source directory."""
    modules = {}

    # Collect main modules
    for filename in os.listdir(src_path):
        if filename.endswith('.rs'):
            module_name = filename[:-3]  # Remove .rs extension
            modules[module_name] = os.path.join(src_path, filename)

    # Collect binary targets
    bin_path = os.path.join(src_path, 'bin')
    if os.path.exists(bin_path):
        for filename in os.listdir(bin_path):
            if filename.endswith('.rs'):
                module_name = f"bin_{filename[:-3]}"
                modules[module_name] = os.path.join(bin_path, filename)

    return modules

def parse_module_dependencies(file_path: str) -> Set[str]:
    """Parse dependencies from a Rust module file."""
    deps = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        return deps

    # Match use statements that reference crate modules
    # Look for patterns like: use crate::module_name or use super::module_name
    use_patterns = [
        r'use\s+crate::([a-zA-Z_][a-zA-Z0-9_]*)',  # use crate::module
        r'use\s+super::([a-zA-Z_][a-zA-Z0-9_]*)',  # use super::module
        r'use\s+([a-zA-Z_][a-zA-Z0-9_]*)::', # use module::
        r'pub\s+mod\s+([a-zA-Z_][a-zA-Z0-9_]*)', # pub mod module
        r'mod\s+([a-zA-Z_][a-zA-Z0-9_]*)', # mod module
    ]

    for pattern in use_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                deps.add(match[0])
            else:
                deps.add(match)

    return deps

def get_entry_points(modules: Dict[str, str]) -> Set[str]:
    """Define the entry points for dependency analysis."""
    entry_points = set()

    # Primary entry points
    entry_points.add("execution_orchestrator")
    entry_points.add("lib")

    # Binary targets are also entry points
    for module_name in modules.keys():
        if module_name.startswith("bin_"):
            entry_points.add(module_name)

    return entry_points

def compute_reachable_modules(entry_point: str, module_deps: Dict[str, Set[str]]) -> Set[str]:
    """Compute all modules reachable from a given entry point using BFS."""
    visited = set()
    to_visit = deque([entry_point])

    while to_visit:
        current = to_visit.popleft()

        if current in visited:
            continue

        visited.add(current)

        # Add dependencies to visit queue
        if current in module_deps:
            for dep in module_deps[current]:
                if dep not in visited:
                    to_visit.append(dep)

    return visited

def classify_module(module_name: str, reachable_from: Set[str]) -> str:
    """Classify a module based on which entry points can reach it."""
    if not reachable_from:
        return "island"

    # Core reachable: reachable from execution_orchestrator or lib
    if "execution_orchestrator" in reachable_from or "lib" in reachable_from:
        return "core_reachable"

    # Check if module name suggests governance/control plane
    governance_indicators = [
        "control_plane", "governance", "policy", "scorecard", "audit",
        "compliance", "security", "attestation", "witness", "evidence"
    ]

    gate_indicators = [
        "gate", "verification", "conformance", "test", "benchmark",
        "harness", "validator", "checker", "runner", "oracle"
    ]

    module_lower = module_name.lower()

    for indicator in governance_indicators:
        if indicator in module_lower:
            return "governance_reachable"
        # Also check if reachable from governance entry points
        for ep in reachable_from:
            if indicator in ep.lower():
                return "governance_reachable"

    for indicator in gate_indicators:
        if indicator in module_lower:
            return "gate_reachable"
        # Also check if reachable from gate entry points
        for ep in reachable_from:
            if indicator in ep.lower():
                return "gate_reachable"

    # Default to governance reachable if reachable from somewhere
    return "governance_reachable"

def analyze_modules():
    """Main analysis function."""
    src_path = "crates/franken-engine/src"

    # Step 1: Collect all modules
    modules = collect_modules(src_path)
    print(f"Found {len(modules)} modules")

    # Step 2: Parse dependencies for each module
    module_deps = {}
    for module_name, file_path in modules.items():
        deps = parse_module_dependencies(file_path)
        module_deps[module_name] = deps

    # Step 3: Define entry points
    entry_points = get_entry_points(modules)
    print(f"Entry points: {sorted(entry_points)}")

    # Step 4: Compute reachability from each entry point
    reachability = {}
    for entry_point in entry_points:
        reachable = compute_reachable_modules(entry_point, module_deps)
        reachability[entry_point] = reachable

    # Step 5: Classify each module
    analysis = {
        "modules": {},
        "entry_points": sorted(entry_points),
        "summary": {
            "total_modules": len(modules),
            "core_reachable": 0,
            "governance_reachable": 0,
            "gate_reachable": 0,
            "island_modules": 0
        }
    }

    for module_name, file_path in modules.items():
        reachable_from = set()

        for entry_point, reachable_modules in reachability.items():
            if module_name in reachable_modules:
                reachable_from.add(entry_point)

        classification = classify_module(module_name, reachable_from)

        module_info = {
            "name": module_name,
            "file_path": file_path,
            "dependencies": sorted(module_deps.get(module_name, set())),
            "classification": classification,
            "reachable_from": sorted(reachable_from)
        }

        analysis["modules"][module_name] = module_info

        # Update summary
        analysis["summary"][classification] += 1

    # Step 6: Output results
    output_file = "docs/architecture/module_classification.json"
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2, sort_keys=True)

    print("\nModule Classification Summary:")
    summary = analysis["summary"]
    print(f"Total modules: {summary['total_modules']}")
    print(f"Core reachable: {summary['core_reachable']}")
    print(f"Governance reachable: {summary['governance_reachable']}")
    print(f"Gate reachable: {summary['gate_reachable']}")
    print(f"Island modules: {summary['island_modules']}")

    # Show examples of each category
    print("\nExamples by category:")
    categories = {
        "Core reachable": "core_reachable",
        "Governance reachable": "governance_reachable",
        "Gate reachable": "gate_reachable",
        "Island": "island"
    }

    for category_name, category_key in categories.items():
        examples = [
            name for name, info in analysis["modules"].items()
            if info["classification"] == category_key
        ][:5]
        print(f"{category_name}: {examples}")

    print(f"\nResults written to {output_file}")
    return analysis

if __name__ == "__main__":
    analyze_modules()
