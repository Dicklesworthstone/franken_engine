// Macro-Benchmark Suite Index
// Orchestrates all macro-benchmarks for comprehensive performance testing

function loadBenchmarkModules() {
    return {
        jsonTransformation: require('./json_transformation.js'),
        treeTraversal: require('./tree_traversal.js'),
        recursiveAlgorithms: require('./recursive_algorithms.js'),
        textProcessing: require('./text_processing.js'),
        eventEmitterSimulation: require('./event_emitter_simulation.js')
    };
}

class BenchmarkSuite {
    constructor() {
        this.benchmarks = loadBenchmarkModules();
        this.results = new Map();
        this.startTime = null;
        this.endTime = null;
    }

    async runAll() {
        console.log("🚀 Starting Macro-Benchmark Suite");
        console.log("=====================================");

        this.startTime = Date.now();
        const allResults = {};

        // Run each benchmark
        for (const [name, benchmarkFn] of Object.entries(this.benchmarks)) {
            console.log(`\n📊 Running ${name} benchmark...`);
            console.log("-".repeat(50));

            try {
                if (typeof benchmarkFn !== 'function') {
                    throw new TypeError(`${name} benchmark module does not export a function`);
                }

                const benchmarkStart = Date.now();
                const result = await Promise.resolve(benchmarkFn());
                const benchmarkEnd = Date.now();
                const duration = benchmarkEnd - benchmarkStart;

                allResults[name] = {
                    ...result,
                    actualDuration: duration,
                    status: 'completed',
                    module: benchmarkFn.name || name
                };

                console.log(`✅ ${name} completed in ${duration}ms`);

            } catch (error) {
                console.error(`❌ ${name} failed:`, error.message);
                allResults[name] = {
                    status: 'failed',
                    error: error.message,
                    module: benchmarkFn && benchmarkFn.name ? benchmarkFn.name : name
                };
            }
        }

        this.endTime = Date.now();
        this.results = allResults;

        this.generateReport();
        return allResults;
    }

    generateReport() {
        console.log("\n📈 MACRO-BENCHMARK SUITE REPORT");
        console.log("=====================================");

        const totalDuration = this.endTime - this.startTime;
        const benchmarkCount = Object.keys(this.results).length;
        let completedCount = 0;
        let failedCount = 0;
        let totalOperations = 0;

        console.log(`Suite Duration: ${totalDuration}ms`);
        console.log(`Benchmarks Run: ${benchmarkCount}`);
        console.log("");

        // Individual benchmark summary
        for (const [name, result] of Object.entries(this.results)) {
            console.log(`📊 ${name}:`);

            if (result.status === 'completed') {
                completedCount++;
                console.log(`  ✅ Status: Completed (${result.duration || result.actualDuration}ms)`);

                if (result.operations) {
                    const opCount = Object.values(result.operations).reduce((sum, count) => {
                        return sum + (typeof count === 'number' ? count : 0);
                    }, 0);
                    totalOperations += opCount;
                    console.log(`  🔢 Operations: ${opCount.toLocaleString()}`);
                }

                // Highlight key metrics
                this.printKeyMetrics(name, result);

            } else {
                failedCount++;
                console.log(`  ❌ Status: Failed - ${result.error}`);
            }
            console.log("");
        }

        // Suite summary
        console.log("🎯 SUITE SUMMARY:");
        console.log(`  Total Duration: ${totalDuration}ms`);
        console.log(`  Completed: ${completedCount}/${benchmarkCount}`);
        console.log(`  Failed: ${failedCount}/${benchmarkCount}`);
        console.log(`  Total Operations: ${totalOperations.toLocaleString()}`);
        console.log(`  Avg Benchmark Duration: ${Math.round(totalDuration / benchmarkCount)}ms`);

        if (completedCount === benchmarkCount) {
            console.log("  🎉 All benchmarks completed successfully!");
        } else if (failedCount > 0) {
            console.log(`  ⚠️  ${failedCount} benchmark(s) failed`);
        }

        // Generate JSON report for automated processing
        this.saveJsonReport();
    }

    printKeyMetrics(benchmarkName, result) {
        switch (benchmarkName) {
            case 'jsonTransformation':
                console.log(`  📊 Data Size: ${result.dataSize?.users || 0} users, ${result.dataSize?.orders || 0} orders`);
                console.log(`  🔄 Array Operations: ${result.operations?.arrayMap + result.operations?.arrayFilter + result.operations?.arrayReduce || 0}`);
                break;

            case 'treeTraversal':
                console.log(`  🌳 Nodes Processed: ${result.nodesProcessed?.toLocaleString() || 0}`);
                console.log(`  📏 Tree Depth: ${result.treeDepth || 0}`);
                console.log(`  💾 Serialized Size: ${Math.round((result.serializedSize || 0) / 1024)}KB`);
                break;

            case 'recursiveAlgorithms':
                console.log(`  🔢 Fibonacci(35): ${result.results?.fibonacci?.memoized?.value?.toLocaleString() || 0}`);
                console.log(`  🗼 Hanoi Moves: ${result.results?.hanoi?.moves || 0}`);
                console.log(`  📊 QuickSort: ${result.results?.quicksort?.arraySize?.toLocaleString() || 0} elements`);
                break;

            case 'textProcessing':
                console.log(`  📝 Words Processed: ${result.results?.tokenization?.wordCount?.toLocaleString() || 0}`);
                console.log(`  🔍 Regex Patterns: ${result.results?.regex?.patterns?.length || 0}`);
                console.log(`  📊 Text Length: ${result.results?.analysis?.stats?.characters?.toLocaleString() || 0} chars`);
                break;

            case 'eventEmitterSimulation':
                console.log(`  ⚡ Events Emitted: ${result.results?.totalEventsEmitted?.toLocaleString() || 0}`);
                console.log(`  🔄 Async Tasks: ${result.results?.asyncTasksCompleted || 0}`);
                console.log(`  📈 Stress Cycles: ${result.results?.stressTestCycles?.toLocaleString() || 0}`);
                break;
        }
    }

    saveJsonReport() {
        const report = {
            schema_version: "franken-engine.macro-benchmark-suite.v1",
            timestamp: new Date().toISOString(),
            suite_duration_ms: this.endTime - this.startTime,
            benchmark_count: Object.keys(this.results).length,
            completed_count: Object.values(this.results).filter(r => r.status === 'completed').length,
            failed_count: Object.values(this.results).filter(r => r.status === 'failed').length,
            benchmarks: this.results
        };

        console.log(`\n💾 JSON Report Generated (${JSON.stringify(report).length} bytes)`);
        return report;
    }
}

// Main execution function
function runMacroBenchmarkSuite() {
    console.log("🎯 FrankenEngine Macro-Benchmark Suite");
    console.log("Comprehensive JavaScript Performance Testing");
    console.log("===========================================\n");

    const suite = new BenchmarkSuite();
    return suite.runAll();
}

// Export for module usage
if (typeof module !== 'undefined') {
    module.exports = {
        BenchmarkSuite,
        runMacroBenchmarkSuite,
        loadBenchmarkModules
    };
}

if (typeof require !== 'undefined' && require.main === module) {
    runMacroBenchmarkSuite().then(() => {
        console.log("\n🏁 Macro-Benchmark Suite Complete");
    }).catch(error => {
        console.error("\n💥 Suite Failed:", error);
        process.exitCode = 1;
    });
}
