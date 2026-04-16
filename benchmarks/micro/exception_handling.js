// Micro-Benchmark 10: Exception Handling
// Tests performance of try/catch overhead with and without throwing

function benchmarkExceptionHandling() {
    console.log("Starting Exception Handling benchmark...");
    const startTime = Date.now();

    const iterations = 100000; // 100K iterations (fewer due to exception overhead)

    // Control case: no try/catch
    const controlStart = Date.now();
    let controlSum = 0;
    for (let i = 0; i < iterations * 10; i++) {
        controlSum += i * 2;
    }
    const controlTime = Date.now() - controlStart;

    // Try/catch without throwing
    const noThrowStart = Date.now();
    let noThrowSum = 0;
    for (let i = 0; i < iterations * 10; i++) {
        try {
            noThrowSum += i * 2;
        } catch (e) {
            noThrowSum += 0;
        }
    }
    const noThrowTime = Date.now() - noThrowStart;

    // Try/catch with occasional throwing
    const occasionalThrowStart = Date.now();
    let occasionalSum = 0;
    let occasionalCaught = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            if (i % 1000 === 0 && i > 0) { // Throw every 1000 iterations
                throw new Error(`Test error at iteration ${i}`);
            }
            occasionalSum += i * 2;
        } catch (e) {
            occasionalCaught++;
            occasionalSum += 1; // Add something in catch block
        }
    }
    const occasionalThrowTime = Date.now() - occasionalThrowStart;

    // Try/catch with frequent throwing
    const frequentThrowStart = Date.now();
    let frequentSum = 0;
    let frequentCaught = 0;
    for (let i = 0; i < iterations / 10; i++) { // Fewer iterations
        try {
            if (i % 10 === 0) { // Throw every 10 iterations
                throw new Error(`Frequent error at iteration ${i}`);
            }
            frequentSum += i * 2;
        } catch (e) {
            frequentCaught++;
            frequentSum += 1;
        }
    }
    const frequentThrowTime = Date.now() - frequentThrowStart;

    // Try/catch/finally without throwing
    const finallyNoThrowStart = Date.now();
    let finallyNoThrowSum = 0;
    let finallyCount = 0;
    for (let i = 0; i < iterations; i++) {
        try {
            finallyNoThrowSum += i * 2;
        } catch (e) {
            finallyNoThrowSum += 0;
        } finally {
            finallyCount++;
        }
    }
    const finallyNoThrowTime = Date.now() - finallyNoThrowStart;

    // Try/catch/finally with throwing
    const finallyThrowStart = Date.now();
    let finallyThrowSum = 0;
    let finallyThrowCaught = 0;
    let finallyThrowFinally = 0;
    for (let i = 0; i < iterations / 10; i++) { // Fewer iterations
        try {
            if (i % 20 === 0 && i > 0) { // Throw every 20 iterations
                throw new Error(`Finally test error at iteration ${i}`);
            }
            finallyThrowSum += i * 2;
        } catch (e) {
            finallyThrowCaught++;
            finallyThrowSum += 1;
        } finally {
            finallyThrowFinally++;
        }
    }
    const finallyThrowTime = Date.now() - finallyThrowStart;

    // Nested try/catch
    const nestedStart = Date.now();
    let nestedSum = 0;
    let nestedCaught = 0;
    for (let i = 0; i < iterations / 10; i++) {
        try {
            try {
                if (i % 100 === 0 && i > 0) {
                    throw new Error(`Inner error at iteration ${i}`);
                }
                nestedSum += i * 2;
            } catch (innerE) {
                if (i % 200 === 0) {
                    throw new Error(`Outer error at iteration ${i}`);
                }
                nestedSum += 1;
            }
        } catch (outerE) {
            nestedCaught++;
            nestedSum += 2;
        }
    }
    const nestedTime = Date.now() - nestedStart;

    // Custom error types
    class CustomError extends Error {
        constructor(message, code) {
            super(message);
            this.name = 'CustomError';
            this.code = code;
        }
    }

    const customErrorStart = Date.now();
    let customSum = 0;
    let customCaught = 0;
    for (let i = 0; i < iterations / 10; i++) {
        try {
            if (i % 50 === 0 && i > 0) {
                throw new CustomError(`Custom error ${i}`, i);
            }
            customSum += i * 2;
        } catch (e) {
            if (e instanceof CustomError) {
                customCaught++;
                customSum += e.code;
            } else {
                customSum += 1;
            }
        }
    }
    const customErrorTime = Date.now() - customErrorStart;

    // Error with stack trace access
    const stackTraceStart = Date.now();
    let stackSum = 0;
    let stackCaught = 0;
    let stackTraces = [];
    for (let i = 0; i < iterations / 100; i++) { // Even fewer iterations
        try {
            if (i % 10 === 0 && i > 0) {
                throw new Error(`Stack trace error ${i}`);
            }
            stackSum += i * 2;
        } catch (e) {
            stackCaught++;
            stackTraces.push(e.stack ? e.stack.substring(0, 50) : 'no stack');
            stackSum += 1;
        }
    }
    const stackTraceTime = Date.now() - stackTraceStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Exception Handling benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Control (no try/catch): ${controlTime}ms (${iterations * 10} operations)`);
    console.log(`Try/catch no throw: ${noThrowTime}ms (${iterations * 10} operations)`);
    console.log(`Occasional throw: ${occasionalThrowTime}ms (${iterations} operations, ${occasionalCaught} caught)`);
    console.log(`Frequent throw: ${frequentThrowTime}ms (${iterations / 10} operations, ${frequentCaught} caught)`);
    console.log(`Finally no throw: ${finallyNoThrowTime}ms (${iterations} operations, ${finallyCount} finally blocks)`);
    console.log(`Finally with throw: ${finallyThrowTime}ms (${iterations / 10} operations, ${finallyThrowCaught} caught, ${finallyThrowFinally} finally blocks)`);
    console.log(`Nested try/catch: ${nestedTime}ms (${iterations / 10} operations, ${nestedCaught} outer caught)`);
    console.log(`Custom errors: ${customErrorTime}ms (${iterations / 10} operations, ${customCaught} caught)`);
    console.log(`Stack trace access: ${stackTraceTime}ms (${iterations / 100} operations, ${stackCaught} caught, ${stackTraces.length} traces)`);

    // Calculate overhead ratios
    const tryCatchOverhead = ((noThrowTime - controlTime) / controlTime * 100).toFixed(1);
    const throwOverhead = ((occasionalThrowTime / (iterations / 1000)) / (controlTime / (iterations * 10))).toFixed(1);

    console.log(`Try/catch overhead: ${tryCatchOverhead}% slower than control`);
    console.log(`Exception throw cost: ~${throwOverhead}x regular operation`);

    return {
        totalTime,
        iterations,
        operations: {
            control: iterations * 10,
            noThrow: iterations * 10,
            occasionalThrow: iterations,
            frequentThrow: iterations / 10,
            finallyNoThrow: iterations,
            finallyThrow: iterations / 10,
            nested: iterations / 10,
            customError: iterations / 10,
            stackTrace: iterations / 100
        },
        times: {
            control: controlTime,
            noThrow: noThrowTime,
            occasionalThrow: occasionalThrowTime,
            frequentThrow: frequentThrowTime,
            finallyNoThrow: finallyNoThrowTime,
            finallyThrow: finallyThrowTime,
            nested: nestedTime,
            customError: customErrorTime,
            stackTrace: stackTraceTime
        },
        results: {
            controlSum,
            noThrowSum,
            occasionalSum,
            occasionalCaught,
            frequentSum,
            frequentCaught,
            finallyNoThrowSum,
            finallyThrowSum,
            finallyThrowCaught,
            nestedSum,
            nestedCaught,
            customSum,
            customCaught,
            stackSum,
            stackCaught,
            stackTracesSample: stackTraces.slice(0, 3)
        },
        overhead: {
            tryCatchPercent: parseFloat(tryCatchOverhead),
            throwMultiplier: parseFloat(throwOverhead)
        },
        opsPerSecond: {
            control: Math.round((iterations * 10) / (controlTime / 1000)),
            noThrow: Math.round((iterations * 10) / (noThrowTime / 1000)),
            occasionalThrow: Math.round(iterations / (occasionalThrowTime / 1000)),
            frequentThrow: Math.round((iterations / 10) / (frequentThrowTime / 1000)),
            finallyNoThrow: Math.round(iterations / (finallyNoThrowTime / 1000)),
            finallyThrow: Math.round((iterations / 10) / (finallyThrowTime / 1000)),
            nested: Math.round((iterations / 10) / (nestedTime / 1000)),
            customError: Math.round((iterations / 10) / (customErrorTime / 1000)),
            stackTrace: Math.round((iterations / 100) / (stackTraceTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkExceptionHandling();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkExceptionHandling;
}