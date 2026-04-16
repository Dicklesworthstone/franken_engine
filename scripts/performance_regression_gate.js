#!/usr/bin/env node
// Performance Regression Gate for FrankenEngine
// Ensures performance doesn't regress by more than 5% from baseline

const fs = require('fs');
const path = require('path');
const BaselineBenchmarkRunner = require('./run_baseline_benchmarks.js');

class PerformanceRegressionGate {
    constructor() {
        this.projectRoot = path.resolve(__dirname, '..');
        this.baselineDir = path.join(this.projectRoot, 'artifacts', 'performance_baselines');
        this.regressionThreshold = 0.05; // 5%
        this.criticalBenchmarks = [
            'arithmetic_loop.js',
            'function_calls.js',
            'object_creation.js',
            'array_operations.js',
            'json_operations.js'
        ];
    }

    async findLatestBaseline() {
        if (!fs.existsSync(this.baselineDir)) {
            throw new Error(`Baseline directory not found: ${this.baselineDir}`);
        }

        const runs = fs.readdirSync(this.baselineDir)
            .filter(dir => fs.statSync(path.join(this.baselineDir, dir)).isDirectory())
            .sort()
            .reverse();

        if (runs.length === 0) {
            throw new Error('No baseline performance data found');
        }

        const latestRun = runs[0];
        const baselinePath = path.join(this.baselineDir, latestRun, 'baseline_performance_results.json');

        if (!fs.existsSync(baselinePath)) {
            throw new Error(`Baseline results not found: ${baselinePath}`);
        }

        console.log(`📊 Using baseline from: ${latestRun}`);
        return JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    }

    async runCurrentBenchmarks() {
        console.log(`🔬 Running current benchmarks for regression check...`);
        const runner = new BaselineBenchmarkRunner();
        return await runner.run();
    }

    extractDurationFromOutput(output) {
        // Extract total time from benchmark output
        const match = output.match(/Total time: (\d+)ms/);
        return match ? parseInt(match[1]) : null;
    }

    comparePerformance(baseline, current) {
        const results = {
            regressions: [],
            improvements: [],
            stable: [],
            missing: [],
            summary: {
                totalChecked: 0,
                regressionCount: 0,
                gatePassed: true,
                maxRegression: 0
            }
        };

        console.log(`\n📈 Performance Comparison:`);
        console.log(`${'Benchmark'.padEnd(25)} ${'Baseline'.padEnd(12)} ${'Current'.padEnd(12)} ${'Change'.padEnd(12)} Status`);
        console.log('-'.repeat(80));

        for (const benchmark of this.criticalBenchmarks) {
            results.summary.totalChecked++;

            const baselineData = baseline.microBenchmarks[benchmark];
            const currentData = current.microBenchmarks[benchmark];

            if (!baselineData || baselineData.status !== 'completed') {
                results.missing.push({ benchmark, reason: 'No baseline data' });
                console.log(`${benchmark.padEnd(25)} ${'N/A'.padEnd(12)} ${'N/A'.padEnd(12)} ${'N/A'.padEnd(12)} ⚠️ MISSING`);
                continue;
            }

            if (!currentData || currentData.status !== 'completed') {
                results.missing.push({ benchmark, reason: 'Current benchmark failed' });
                console.log(`${benchmark.padEnd(25)} ${'N/A'.padEnd(12)} ${'FAILED'.padEnd(12)} ${'N/A'.padEnd(12)} ❌ FAILED`);
                continue;
            }

            const baselineDuration = this.extractDurationFromOutput(baselineData.output);
            const currentDuration = this.extractDurationFromOutput(currentData.output);

            if (!baselineDuration || !currentDuration) {
                results.missing.push({ benchmark, reason: 'Could not parse duration' });
                console.log(`${benchmark.padEnd(25)} ${'PARSE_ERR'.padEnd(12)} ${'PARSE_ERR'.padEnd(12)} ${'N/A'.padEnd(12)} ❌ PARSE_ERR`);
                continue;
            }

            const changeRatio = (currentDuration - baselineDuration) / baselineDuration;
            const changePercent = changeRatio * 100;
            const changeStr = changePercent >= 0 ? `+${changePercent.toFixed(1)}%` : `${changePercent.toFixed(1)}%`;

            results.summary.maxRegression = Math.max(results.summary.maxRegression, changeRatio);

            let status = '✅ OK';
            if (changeRatio > this.regressionThreshold) {
                results.regressions.push({
                    benchmark,
                    baselineDuration,
                    currentDuration,
                    changeRatio,
                    changePercent
                });
                results.summary.regressionCount++;
                results.summary.gatePassed = false;
                status = '🚫 REGRESS';
            } else if (changeRatio < -0.1) { // 10% improvement
                results.improvements.push({
                    benchmark,
                    baselineDuration,
                    currentDuration,
                    changeRatio,
                    changePercent
                });
                status = '🚀 IMPROVE';
            } else {
                results.stable.push({
                    benchmark,
                    baselineDuration,
                    currentDuration,
                    changeRatio,
                    changePercent
                });
            }

            console.log(`${benchmark.padEnd(25)} ${(baselineDuration + 'ms').padEnd(12)} ${(currentDuration + 'ms').padEnd(12)} ${changeStr.padEnd(12)} ${status}`);
        }

        return results;
    }

    generateReport(comparison, outputPath) {
        const report = {
            schema_version: "franken-engine.performance-regression-gate.v1",
            timestamp: new Date().toISOString(),
            threshold: this.regressionThreshold,
            gate_passed: comparison.summary.gatePassed,
            summary: comparison.summary,
            regressions: comparison.regressions,
            improvements: comparison.improvements,
            stable: comparison.stable,
            missing: comparison.missing
        };

        if (outputPath) {
            fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
            console.log(`\n📄 Regression report saved to: ${outputPath}`);
        }

        return report;
    }

    async run(outputDir = null) {
        try {
            console.log(`🚦 FrankenEngine Performance Regression Gate`);
            console.log(`⚠️ Threshold: ${(this.regressionThreshold * 100)}% performance regression\n`);

            const baseline = await this.findLatestBaseline();
            const current = await this.runCurrentBenchmarks();
            const comparison = this.comparePerformance(baseline, current);

            const reportPath = outputDir
                ? path.join(outputDir, 'regression_report.json')
                : null;
            const report = this.generateReport(comparison, reportPath);

            console.log(`\n📊 Regression Gate Summary:`);
            console.log(`  Benchmarks checked: ${comparison.summary.totalChecked}`);
            console.log(`  Regressions found: ${comparison.summary.regressionCount}`);
            console.log(`  Max regression: ${(comparison.summary.maxRegression * 100).toFixed(1)}%`);
            console.log(`  Gate status: ${comparison.summary.gatePassed ? '✅ PASSED' : '❌ FAILED'}`);

            if (!comparison.summary.gatePassed) {
                console.log(`\n🚫 Performance regressions detected:`);
                for (const regression of comparison.regressions) {
                    console.log(`  - ${regression.benchmark}: ${regression.changePercent.toFixed(1)}% slower`);
                    console.log(`    ${regression.baselineDuration}ms → ${regression.currentDuration}ms`);
                }
                console.log(`\nPerformance regressions exceed the ${(this.regressionThreshold * 100)}% threshold.`);
                console.log(`Please investigate and fix the performance issues before merging.`);
                process.exit(1);
            } else {
                console.log(`\n✅ No significant performance regressions detected.`);
                if (comparison.improvements.length > 0) {
                    console.log(`🚀 Performance improvements found:`);
                    for (const improvement of comparison.improvements) {
                        console.log(`  - ${improvement.benchmark}: ${Math.abs(improvement.changePercent).toFixed(1)}% faster`);
                    }
                }
                console.log(`Gate check passed!`);
            }

            return report;
        } catch (error) {
            console.error(`\n💥 Performance regression gate failed:`, error.message);
            console.error(`Please ensure baseline performance data exists and benchmarks are runnable.`);
            process.exit(1);
        }
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const outputDirIndex = args.indexOf('--output');
    const outputDir = outputDirIndex !== -1 && args[outputDirIndex + 1]
        ? args[outputDirIndex + 1]
        : null;

    const gate = new PerformanceRegressionGate();
    gate.run(outputDir);
}

module.exports = PerformanceRegressionGate;