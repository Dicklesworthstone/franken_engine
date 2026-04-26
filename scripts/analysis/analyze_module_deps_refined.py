#!/usr/bin/env python3
"""
Refined module dependency analyzer for franken-engine

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

    # Note: We'll treat binary targets differently - they are entry points but not modules in the dependency graph
    return modules

def parse_module_dependencies(file_path: str, all_modules: Set[str]) -> Set[str]:
    """Parse dependencies from a Rust module file, only including actual crate modules."""
    deps = set()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        return deps

    # Only look for explicit crate module references
    patterns = [
        r'use\s+crate::([a-zA-Z_][a-zA-Z0-9_]*)',  # use crate::module
        r'use\s+super::([a-zA-Z_][a-zA-Z0-9_]*)',  # use super::module
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            module_name = match[0] if isinstance(match, tuple) else match
            # Only include if it's actually a module in our codebase
            if module_name in all_modules:
                deps.add(module_name)

    return deps

def get_core_entry_points() -> Set[str]:
    """Define the core entry points for dependency analysis."""
    return {"execution_orchestrator", "lib"}

def get_all_entry_points(bin_path: str) -> Set[str]:
    """Get all entry points including binaries."""
    entry_points = get_core_entry_points()

    # Add binary targets
    if os.path.exists(bin_path):
        for filename in os.listdir(bin_path):
            if filename.endswith('.rs'):
                entry_points.add(filename[:-3])  # Remove .rs extension

    return entry_points

def parse_binary_dependencies(bin_path: str, all_modules: Set[str]) -> Dict[str, Set[str]]:
    """Parse dependencies from binary targets."""
    bin_deps = {}

    if not os.path.exists(bin_path):
        return bin_deps

    for filename in os.listdir(bin_path):
        if filename.endswith('.rs'):
            bin_name = filename[:-3]
            file_path = os.path.join(bin_path, filename)
            deps = parse_module_dependencies(file_path, all_modules)
            bin_deps[bin_name] = deps

    return bin_deps

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
                if dep not in visited and dep in module_deps:  # Only follow actual modules
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

    # Check module name
    for indicator in governance_indicators:
        if indicator in module_lower:
            return "governance_reachable"

    for indicator in gate_indicators:
        if indicator in module_lower:
            return "gate_reachable"

    # Check entry points that reach this module
    for ep in reachable_from:
        ep_lower = ep.lower()
        for indicator in governance_indicators:
            if indicator in ep_lower:
                return "governance_reachable"
        for indicator in gate_indicators:
            if indicator in ep_lower:
                return "gate_reachable"

    # Default to governance reachable if reachable from somewhere
    return "governance_reachable"

def analyze_modules():
    """Main analysis function."""
    src_path = "crates/franken-engine/src"
    bin_path = os.path.join(src_path, "bin")

    # Step 1: Collect all modules (excluding binaries)
    modules = collect_modules(src_path)
    all_module_names = set(modules.keys())
    print(f"Found {len(modules)} modules")

    # Step 2: Parse dependencies for each module
    module_deps = {}
    for module_name, file_path in modules.items():
        deps = parse_module_dependencies(file_path, all_module_names)
        module_deps[module_name] = deps

    # Step 3: Parse dependencies for binary targets
    bin_deps = parse_binary_dependencies(bin_path, all_module_names)

    # Add binary dependencies to the dependency graph
    all_deps = {**module_deps, **bin_deps}

    # Step 4: Define entry points
    core_entry_points = get_core_entry_points()
    all_entry_points = get_all_entry_points(bin_path)
    print(f"Core entry points: {sorted(core_entry_points)}")
    print(f"Total entry points: {len(all_entry_points)}")

    # Step 5: Compute reachability from core entry points first
    core_reachability = {}
    for entry_point in core_entry_points:
        if entry_point in all_deps:
            reachable = compute_reachable_modules(entry_point, all_deps)
            core_reachability[entry_point] = reachable

    # Step 6: Compute reachability from all entry points
    all_reachability = {}
    for entry_point in all_entry_points:
        if entry_point in all_deps:
            reachable = compute_reachable_modules(entry_point, all_deps)
            all_reachability[entry_point] = reachable

    # Step 7: Classify each module
    analysis = {
        "modules": {},
        "core_entry_points": sorted(core_entry_points),
        "all_entry_points": sorted(all_entry_points),
        "summary": {
            "total_modules": len(modules),
            "core_reachable": 0,
            "governance_reachable": 0,
            "gate_reachable": 0,
            "island": 0
        }
    }

    for module_name, file_path in modules.items():
        # Find which entry points can reach this module
        reachable_from_core = set()
        reachable_from_all = set()

        for entry_point, reachable_modules in core_reachability.items():
            if module_name in reachable_modules:
                reachable_from_core.add(entry_point)

        for entry_point, reachable_modules in all_reachability.items():
            if module_name in reachable_modules:
                reachable_from_all.add(entry_point)

        classification = classify_module(module_name, reachable_from_all)

        module_info = {
            "name": module_name,
            "file_path": file_path,
            "dependencies": sorted(module_deps.get(module_name, set())),
            "classification": classification,
            "reachable_from_core": sorted(reachable_from_core),
            "reachable_from_all": sorted(reachable_from_all)
        }

        analysis["modules"][module_name] = module_info

        # Update summary
        analysis["summary"][classification] += 1

    # Step 8: Output results
    output_file = "docs/architecture/module_classification.json"
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2, sort_keys=True)

    print("\nModule Classification Summary:")
    summary = analysis["summary"]
    print(f"Total modules: {summary['total_modules']}")
    print(f"Core reachable: {summary['core_reachable']}")
    print(f"Governance reachable: {summary['governance_reachable']}")
    print(f"Gate reachable: {summary['gate_reachable']}")
    print(f"Island modules: {summary['island']}")

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
        ][:10]
        print(f"{category_name}: {examples}")

    # Show some island modules if any exist
    if summary['island'] > 0:
        print(f"\nFirst 20 island modules:")
        islands = [
            name for name, info in analysis["modules"].items()
            if info["classification"] == "island"
        ][:20]
        for island in islands:
            deps = analysis["modules"][island]["dependencies"]
            print(f"  {island}: deps={deps}")

    print(f"\nResults written to {output_file}")
    return analysis

if __name__ == "__main__":
    analyze_modules()
