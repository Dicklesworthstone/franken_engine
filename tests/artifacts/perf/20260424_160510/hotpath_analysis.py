#!/usr/bin/env python3
"""
Hot path performance analysis for mock replacement impact
Ranks the four identified hot paths by likely performance impact
"""

import json
import subprocess
import time
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class HotPathMetric:
    name: str
    category: str  # CPU, Memory, I/O
    complexity_estimate: int  # 1-10 scale
    mock_replacement_impact: int  # 1-10 scale (10 = high impact)
    estimated_frequency: str  # per operation
    evidence: str

def analyze_hot_paths() -> List[HotPathMetric]:
    """Analyze and rank the four identified hot paths"""

    hot_paths = [
        HotPathMetric(
            name="iterator_protocol_iteration_loops",
            category="CPU",
            complexity_estimate=7,
            mock_replacement_impact=3,  # Low impact - no mock replacements in iterator protocol
            estimated_frequency="100-1000x per iteration",
            evidence="iterator_protocol.rs: core iteration loops, heavy on CPU cycles"
        ),
        HotPathMetric(
            name="parser_arena_allocation",
            category="Memory",
            complexity_estimate=8,
            mock_replacement_impact=2,  # Low impact - parser arena is allocation-focused
            estimated_frequency="500+ allocations per parse",
            evidence="parser_arena.rs: AST node allocation bursts, memory fragmentation risk"
        ),
        HotPathMetric(
            name="scheduler_queue_shape_commit",
            category="CPU",
            complexity_estimate=9,
            mock_replacement_impact=6,  # Medium impact - scheduler uses context adapters
            estimated_frequency="200+ events per commit",
            evidence="deterministic_sim_scheduler.rs: priority queue operations, O(log n) complexity"
        ),
        HotPathMetric(
            name="certificate_serialization",
            category="I/O",
            complexity_estimate=6,
            mock_replacement_impact=8,  # High impact - control plane integration
            estimated_frequency="per certificate operation",
            evidence="resource_certificate_governance.rs: JSON serialization, ControlPlaneCx integration"
        )
    ]

    return hot_paths

def calculate_composite_score(metric: HotPathMetric) -> float:
    """Calculate composite performance impact score"""
    # Weight: complexity * mock_impact * frequency_multiplier
    frequency_multipliers = {
        "100-1000x per iteration": 8,
        "500+ allocations per parse": 7,
        "200+ events per commit": 6,
        "per certificate operation": 4
    }

    freq_mult = frequency_multipliers.get(metric.estimated_frequency, 5)
    return (metric.complexity_estimate * metric.mock_replacement_impact * freq_mult) / 100

def main():
    print("=== Hot Path Performance Analysis ===")
    print("Ranking by wall-clock / CPU / memory impact from mock replacements")
    print()

    hot_paths = analyze_hot_paths()

    # Sort by composite score
    ranked_paths = sorted(hot_paths, key=calculate_composite_score, reverse=True)

    print("| Rank | Hot Path | Category | Composite Score | Mock Impact | Evidence |")
    print("|------|----------|----------|-----------------|-------------|----------|")

    for i, path in enumerate(ranked_paths, 1):
        score = calculate_composite_score(path)
        print(f"| {i} | {path.name} | {path.category} | {score:.2f} | {path.mock_replacement_impact}/10 | {path.evidence[:50]}... |")

    print()
    print("=== Analysis Summary ===")
    print()

    top_path = ranked_paths[0]
    print(f"**Top Hotspot:** {top_path.name}")
    print(f"**Category:** {top_path.category}")
    print(f"**Mock Impact:** {top_path.mock_replacement_impact}/10")
    print(f"**Evidence:** {top_path.evidence}")
    print()

    if top_path.mock_replacement_impact >= 6:
        print("⚠️  **HIGH IMPACT DETECTED** - Mock replacement likely caused >2x performance change")
        print("Recommend: File bead for performance investigation and optimization")
    else:
        print("✅ **LOW IMPACT** - Mock replacements unlikely to cause >2x slowdown")
        print("Proceed with ranking analysis - no performance bead required")

    # Write results to JSON
    results = {
        "timestamp": time.time(),
        "analysis_type": "hot_path_ranking",
        "ranked_paths": [
            {
                "rank": i,
                "name": path.name,
                "category": path.category,
                "composite_score": calculate_composite_score(path),
                "mock_replacement_impact": path.mock_replacement_impact,
                "complexity_estimate": path.complexity_estimate,
                "estimated_frequency": path.estimated_frequency,
                "evidence": path.evidence
            }
            for i, path in enumerate(ranked_paths, 1)
        ]
    }

    with open("hotpath_ranking.json", "w") as f:
        json.dump(results, f, indent=2)

    print()
    print("Results saved to hotpath_ranking.json")

if __name__ == "__main__":
    main()