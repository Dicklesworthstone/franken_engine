// Micro-Benchmark 1: Integer Arithmetic Loop
// Tests performance of basic integer arithmetic operations in tight loop

function benchmarkIntegerArithmetic() {
    console.log("Starting Integer Arithmetic benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M iterations
    let result = 0;

    // Addition benchmark
    const addStart = Date.now();
    let addResult = 0;
    for (let i = 0; i < iterations; i++) {
        addResult += i;
        addResult += 7;
        addResult += 23;
    }
    const addTime = Date.now() - addStart;

    // Multiplication benchmark
    const mulStart = Date.now();
    let mulResult = 1;
    for (let i = 1; i < iterations / 10; i++) {
        mulResult = (mulResult * i) % 1000000;
        mulResult = (mulResult * 3) % 1000000;
        mulResult = (mulResult * 7) % 1000000;
    }
    const mulTime = Date.now() - mulStart;

    // Division benchmark
    const divStart = Date.now();
    let divResult = 1000000;
    for (let i = 1; i < iterations / 10; i++) {
        divResult = Math.floor(divResult / (i % 100 + 1));
        if (divResult < 1000) divResult = 1000000; // Reset to avoid zero
        divResult = Math.floor(divResult / 3);
        if (divResult < 1000) divResult = 1000000;
    }
    const divTime = Date.now() - divStart;

    // Mixed arithmetic benchmark
    const mixedStart = Date.now();
    let mixedResult = 42;
    for (let i = 0; i < iterations; i++) {
        mixedResult += i;
        mixedResult *= 3;
        mixedResult %= 1000000;
        mixedResult -= 7;
        if (mixedResult < 0) mixedResult = 42;
    }
    const mixedTime = Date.now() - mixedStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Integer Arithmetic benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Addition: ${addTime}ms (${iterations} operations)`);
    console.log(`Multiplication: ${mulTime}ms (${iterations / 10} operations)`);
    console.log(`Division: ${divTime}ms (${iterations / 10} operations)`);
    console.log(`Mixed: ${mixedTime}ms (${iterations} operations)`);
    console.log(`Final results: add=${addResult}, mul=${mulResult}, div=${divResult}, mixed=${mixedResult}`);

    return {
        totalTime,
        iterations,
        operations: {
            addition: iterations,
            multiplication: iterations / 10,
            division: iterations / 10,
            mixed: iterations
        },
        times: {
            addition: addTime,
            multiplication: mulTime,
            division: divTime,
            mixed: mixedTime
        },
        results: {
            addition: addResult,
            multiplication: mulResult,
            division: divResult,
            mixed: mixedResult
        },
        opsPerSecond: {
            addition: Math.round(iterations / (addTime / 1000)),
            multiplication: Math.round((iterations / 10) / (mulTime / 1000)),
            division: Math.round((iterations / 10) / (divTime / 1000)),
            mixed: Math.round(iterations / (mixedTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkIntegerArithmetic();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkIntegerArithmetic;
}