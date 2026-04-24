#![forbid(unsafe_code)]

//! Hot path performance benchmarks
//!
//! Profiles the four critical hot paths identified for mock replacement impact analysis:
//! (a) iterator_protocol iteration loops
//! (b) parser_arena allocation
//! (c) scheduler queue-shape commit
//! (d) certificate serialization

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Simple micro-benchmark using only std to check for hot path performance
fn bench_hot_path_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_paths_simulation");

    // (a) Iterator protocol simulation - loop-intensive work
    group.bench_function("iterator_loops_1000", |b| {
        b.iter(|| {
            let data: Vec<i32> = (0..1000).collect();
            let mut sum: i32 = 0;

            // Simulate iterator protocol overhead with nested iteration
            for item in &data {
                for _ in 0..*item % 10 + 1 {
                    sum = black_box(sum.wrapping_add(*item));
                }
            }

            black_box(sum)
        });
    });

    // (b) Parser arena allocation simulation - memory allocation patterns
    group.bench_function("arena_allocation_burst", |b| {
        b.iter(|| {
            let mut arena = Vec::new();

            // Simulate AST node allocation bursts
            for i in 0..500 {
                let node = format!("node_{}_expr", i);
                arena.push(node);

                // Simulate nested allocations
                let sub_nodes: Vec<String> = (0..i % 10 + 1)
                    .map(|j| format!("subnode_{}_{}", i, j))
                    .collect();
                arena.extend(sub_nodes);
            }

            black_box(arena.len())
        });
    });

    // (c) Scheduler queue simulation - priority queue operations
    group.bench_function("scheduler_queue_operations", |b| {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        b.iter(|| {
            let mut queue = BinaryHeap::new();

            // Schedule events with mixed priorities
            for i in 0..200 {
                let priority = i % 4;
                let delay = i % 10;
                queue.push(Reverse((priority, delay, i)));
            }

            // Process queue (the hot commit path)
            let mut processed = 0;
            while let Some(Reverse((_, _, id))) = queue.pop() {
                processed += 1;

                // Simulate event processing overhead
                let work = (id * 17) % 1000;
                black_box(work);
            }

            black_box(processed)
        });
    });

    // (d) Certificate serialization simulation - JSON serialization patterns
    group.bench_function("certificate_serialization", |b| {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct MockCertificate {
            id: u64,
            metadata: Vec<String>,
            signature: Vec<u8>,
            policies: std::collections::HashMap<String, String>,
        }

        let cert = MockCertificate {
            id: 12345,
            metadata: (0..50).map(|i| format!("metadata_entry_{}", i)).collect(),
            signature: vec![0u8; 256],
            policies: (0..20)
                .map(|i| (format!("policy_{}", i), format!("value_{}", i)))
                .collect(),
        };

        b.iter(|| {
            let serialized = black_box(serde_json::to_string(&cert).unwrap());
            let deserialized: MockCertificate =
                black_box(serde_json::from_str(&serialized).unwrap());
            black_box(deserialized.id)
        });
    });

    group.finish();
}

criterion_group!(hot_paths, bench_hot_path_simulation);
criterion_main!(hot_paths);
