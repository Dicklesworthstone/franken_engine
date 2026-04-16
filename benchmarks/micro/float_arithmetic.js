// Micro-Benchmark 2: Floating-Point Arithmetic
// Tests performance of floating-point arithmetic operations in tight loop

function benchmarkFloatArithmetic() {
    console.log("Starting Float Arithmetic benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M iterations
    let result = 0;

    // Float addition benchmark
    const addStart = Date.now();
    let addResult = 0.0;
    for (let i = 0; i < iterations; i++) {
        addResult += i * 0.5;
        addResult += 3.14159;
        addResult += Math.E;
    }
    const addTime = Date.now() - addStart;

    // Float multiplication benchmark
    const mulStart = Date.now();
    let mulResult = 1.0;
    for (let i = 1; i < iterations / 100; i++) {
        mulResult *= (i * 0.001);
        mulResult *= 1.618; // Golden ratio
        mulResult *= 0.707; // 1/sqrt(2)
        if (mulResult > 1000000) mulResult *= 0.000001; // Normalize
    }
    const mulTime = Date.now() - mulStart;

    // Float division benchmark
    const divStart = Date.now();
    let divResult = 1000000.0;
    for (let i = 1; i < iterations / 100; i++) {
        divResult /= (i % 100 + 1.5);
        if (divResult < 1.0) divResult = 1000000.0; // Reset
        divResult /= 3.33333;
        if (divResult < 1.0) divResult = 1000000.0;
    }
    const divTime = Date.now() - divStart;

    // Transcendental functions benchmark
    const transcStart = Date.now();
    let transcResult = 0.0;
    for (let i = 0; i < iterations / 100; i++) {
        const x = i * 0.01;
        transcResult += Math.sin(x);
        transcResult += Math.cos(x);
        transcResult += Math.sqrt(Math.abs(x) + 1);
        transcResult += Math.log(Math.abs(x) + 1);
    }
    const transcTime = Date.now() - transcStart;

    // Mixed float operations benchmark
    const mixedStart = Date.now();
    let mixedResult = 3.14159;
    for (let i = 0; i < iterations / 10; i++) {
        mixedResult += i * 0.1;
        mixedResult *= 1.01;
        mixedResult = Math.sqrt(mixedResult);
        mixedResult /= 1.1;
        if (mixedResult > 1000) mixedResult = 3.14159;
        if (mixedResult < 0.1) mixedResult = 3.14159;
    }
    const mixedTime = Date.now() - mixedStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Float Arithmetic benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Addition: ${addTime}ms (${iterations} operations)`);
    console.log(`Multiplication: ${mulTime}ms (${iterations / 100} operations)`);
    console.log(`Division: ${divTime}ms (${iterations / 100} operations)`);
    console.log(`Transcendental: ${transcTime}ms (${iterations / 100} operations)`);
    console.log(`Mixed: ${mixedTime}ms (${iterations / 10} operations)`);
    console.log(`Final results: add=${addResult.toFixed(2)}, mul=${mulResult.toFixed(2)}, div=${divResult.toFixed(2)}, transc=${transcResult.toFixed(2)}, mixed=${mixedResult.toFixed(2)}`);

    return {
        totalTime,
        iterations,
        operations: {
            addition: iterations,
            multiplication: iterations / 100,
            division: iterations / 100,
            transcendental: iterations / 100,
            mixed: iterations / 10
        },
        times: {
            addition: addTime,
            multiplication: mulTime,
            division: divTime,
            transcendental: transcTime,
            mixed: mixedTime
        },
        results: {
            addition: Math.round(addResult * 100) / 100,
            multiplication: Math.round(mulResult * 100) / 100,
            division: Math.round(divResult * 100) / 100,
            transcendental: Math.round(transcResult * 100) / 100,
            mixed: Math.round(mixedResult * 100) / 100
        },
        opsPerSecond: {
            addition: Math.round(iterations / (addTime / 1000)),
            multiplication: Math.round((iterations / 100) / (mulTime / 1000)),
            division: Math.round((iterations / 100) / (divTime / 1000)),
            transcendental: Math.round((iterations / 100) / (transcTime / 1000)),
            mixed: Math.round((iterations / 10) / (mixedTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkFloatArithmetic();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkFloatArithmetic;
}