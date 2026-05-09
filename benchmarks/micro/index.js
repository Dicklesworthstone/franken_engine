// Micro-Benchmark Suite Index
// Orchestrates all micro-benchmarks for detailed performance analysis

function loadMicroBenchmarkModules() {
    return {
        arithmeticLoop: require('./arithmetic_loop.js'),
        floatArithmetic: require('./float_arithmetic.js'),
        propertyAccess: require('./property_access.js'),
        functionCalls: require('./function_calls.js'),
        objectCreation: require('./object_creation.js'),
        arrayOperations: require('./array_operations.js'),
        stringOperations: require('./string_operations.js'),
        jsonOperations: require('./json_operations.js'),
        closureCapture: require('./closure_capture.js'),
        exceptionHandling: require('./exception_handling.js'),
        classInstantiation: require('./class_instantiation.js'),
        miscOperations: require('./misc_operations.js')
    };
}

class MicroBenchmarkSuite {
    constructor() {
        this.benchmarks = loadMicroBenchmarkModules();
        this.results = new Map();
        this.startTime = null;
        this.endTime = null;
    }

    async runAll() {
        console.log("🎯 Starting Micro-Benchmark Suite");
        console.log("===================================");

        this.startTime = Date.now();
        const allResults = {};

        // Run each benchmark
        for (const [name, benchmarkFn] of Object.entries(this.benchmarks)) {
            console.log(`\n⚡ Running ${name} benchmark...`);
            console.log("-".repeat(45));

            try {
                if (typeof benchmarkFn !== 'function') {
                    throw new TypeError(`${name} benchmark module does not export a function`);
                }

                const benchmarkStart = Date.now();
                const result = await Promise.resolve(benchmarkFn());
                const benchmarkEnd = Date.now();
                const actualDuration = benchmarkEnd - benchmarkStart;

                allResults[name] = {
                    ...result,
                    actualDuration,
                    status: 'completed',
                    module: benchmarkFn.name || name
                };

                console.log(`✅ ${name} completed in ${actualDuration}ms`);

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
        console.log("\n📊 MICRO-BENCHMARK SUITE REPORT");
        console.log("=================================");

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
            console.log(`⚡ ${name}:`);

            if (result.status === 'completed') {
                completedCount++;
                console.log(`  ✅ Status: Completed (${result.totalTime || result.actualDuration}ms)`);

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
            console.log("  🎉 All micro-benchmarks completed successfully!");
        } else if (failedCount > 0) {
            console.log(`  ⚠️  ${failedCount} benchmark(s) failed`);
        }

        // Generate JSON report for automated processing
        this.saveJsonReport();
    }

    printKeyMetrics(benchmarkName, result) {
        const getOpsPerSec = (category) => {
            return result.opsPerSecond && result.opsPerSecond[category]
                ? result.opsPerSecond[category].toLocaleString()
                : 'N/A';
        };

        switch (benchmarkName) {
            case 'arithmeticLoop':
                console.log(`  🔢 Addition: ${getOpsPerSec('addition')} ops/sec`);
                console.log(`  ✖️ Multiplication: ${getOpsPerSec('multiplication')} ops/sec`);
                console.log(`  ➗ Division: ${getOpsPerSec('division')} ops/sec`);
                break;

            case 'floatArithmetic':
                console.log(`  📊 Float Addition: ${getOpsPerSec('addition')} ops/sec`);
                console.log(`  📈 Transcendental: ${getOpsPerSec('transcendental')} ops/sec`);
                break;

            case 'propertyAccess':
                console.log(`  🔑 Small Object: ${getOpsPerSec('smallObject')} ops/sec`);
                console.log(`  🔗 Dynamic Access: ${getOpsPerSec('dynamicAccess')} ops/sec`);
                break;

            case 'functionCalls':
                console.log(`  📞 Simple Calls: ${getOpsPerSec('simpleCalls')} ops/sec`);
                console.log(`  🏹 Arrow Functions: ${getOpsPerSec('arrowCalls')} ops/sec`);
                break;

            case 'objectCreation':
                console.log(`  🏗️ Literal Objects: ${getOpsPerSec('literalObjects')} ops/sec`);
                console.log(`  🏛️ Class Objects: ${getOpsPerSec('classObjects')} ops/sec`);
                break;

            case 'arrayOperations':
                console.log(`  📥 Push/Pop: ${getOpsPerSec('pushPop')} ops/sec`);
                console.log(`  📊 Map/Filter: ${getOpsPerSec('map')} / ${getOpsPerSec('filter')} ops/sec`);
                break;

            case 'stringOperations':
                console.log(`  🔤 Concatenation: ${getOpsPerSec('concatenation')} ops/sec`);
                console.log(`  🔍 Character Access: ${getOpsPerSec('characterAccess')} ops/sec`);
                break;

            case 'jsonOperations':
                console.log(`  📄 Parse/Stringify: ${getOpsPerSec('simpleRoundtrip')} ops/sec`);
                console.log(`  📊 Object Roundtrip: ${getOpsPerSec('objectRoundtrip')} ops/sec`);
                break;

            case 'closureCapture':
                console.log(`  🔒 Single Capture: ${getOpsPerSec('singleCapture')} ops/sec`);
                console.log(`  🔗 Triple Capture: ${getOpsPerSec('tripleCapture')} ops/sec`);
                break;

            case 'exceptionHandling':
                if (result.overhead) {
                    console.log(`  ⚠️ Try/Catch Overhead: ${result.overhead.tryCatchPercent}%`);
                    console.log(`  💥 Throw Multiplier: ${result.overhead.throwMultiplier}x`);
                }
                break;

            case 'classInstantiation':
                console.log(`  🏭 Simple Classes: ${getOpsPerSec('simpleClass')} ops/sec`);
                console.log(`  🧬 Inheritance: ${getOpsPerSec('inheritance')} ops/sec`);
                break;

            case 'miscOperations':
                console.log(`  🧮 Math Operations: ${getOpsPerSec('mathOps')} ops/sec`);
                console.log(`  🏷️ Type Checking: ${getOpsPerSec('typeChecking')} ops/sec`);
                break;
        }
    }

    saveJsonReport() {
        const report = {
            schema_version: "franken-engine.micro-benchmark-suite.v1",
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
function runMicroBenchmarkSuite() {
    console.log("⚡ FrankenEngine Micro-Benchmark Suite");
    console.log("Detailed JavaScript Operation Performance Testing");
    console.log("===============================================\n");

    const suite = new MicroBenchmarkSuite();
    return suite.runAll();
}

// Export for module usage
if (typeof module !== 'undefined') {
    module.exports = {
        MicroBenchmarkSuite,
        runMicroBenchmarkSuite,
        loadMicroBenchmarkModules
    };
}

if (typeof require !== 'undefined' && require.main === module) {
    runMicroBenchmarkSuite().then(() => {
        console.log("\n🏁 Micro-Benchmark Suite Complete");
    }).catch(error => {
        console.error("\n💥 Suite Failed:", error);
        process.exitCode = 1;
    });
}
