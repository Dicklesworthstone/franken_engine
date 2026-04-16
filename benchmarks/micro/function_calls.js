// Micro-Benchmark 4: Function Call Overhead
// Tests performance of function calls with various patterns

function benchmarkFunctionCalls() {
    console.log("Starting Function Calls benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M function calls

    // Simple function with no parameters
    function simpleFunction() {
        return 42;
    }

    // Function with parameters
    function addFunction(a, b) {
        return a + b;
    }

    // Function with multiple parameters
    function multiParamFunction(a, b, c, d, e) {
        return a + b + c + d + e;
    }

    // Function with conditional logic
    function conditionalFunction(x) {
        if (x > 0) {
            return x * 2;
        } else {
            return x * -1;
        }
    }

    // Recursive function
    function factorialFunction(n) {
        if (n <= 1) return 1;
        return n * factorialFunction(n - 1);
    }

    // Method on object
    const obj = {
        value: 10,
        getValue() {
            return this.value;
        },
        multiply(factor) {
            return this.value * factor;
        }
    };

    // Arrow function
    const arrowFunction = (x, y) => x * y;

    // Higher-order function
    function applyFunction(fn, value) {
        return fn(value);
    }

    // Simple function calls
    const simpleStart = Date.now();
    let simpleSum = 0;
    for (let i = 0; i < iterations; i++) {
        simpleSum += simpleFunction();
    }
    const simpleTime = Date.now() - simpleStart;

    // Function calls with parameters
    const paramStart = Date.now();
    let paramSum = 0;
    for (let i = 0; i < iterations; i++) {
        paramSum += addFunction(i, 10);
    }
    const paramTime = Date.now() - paramStart;

    // Multiple parameter function calls
    const multiStart = Date.now();
    let multiSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        multiSum += multiParamFunction(i, i + 1, i + 2, i + 3, i + 4);
    }
    const multiTime = Date.now() - multiStart;

    // Conditional function calls
    const condStart = Date.now();
    let condSum = 0;
    for (let i = 0; i < iterations; i++) {
        condSum += conditionalFunction(i - iterations / 2);
    }
    const condTime = Date.now() - condStart;

    // Recursive function calls (limited depth to avoid overflow)
    const recurStart = Date.now();
    let recurSum = 0;
    for (let i = 1; i <= 1000; i++) {
        recurSum += factorialFunction(i % 10);
    }
    const recurTime = Date.now() - recurStart;

    // Method calls
    const methodStart = Date.now();
    let methodSum = 0;
    for (let i = 0; i < iterations; i++) {
        methodSum += obj.getValue();
        methodSum += obj.multiply(2);
    }
    const methodTime = Date.now() - methodStart;

    // Arrow function calls
    const arrowStart = Date.now();
    let arrowSum = 0;
    for (let i = 0; i < iterations; i++) {
        arrowSum += arrowFunction(i, 3);
    }
    const arrowTime = Date.now() - arrowStart;

    // Higher-order function calls
    const higherStart = Date.now();
    let higherSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        higherSum += applyFunction(simpleFunction, i);
        higherSum += applyFunction(x => x * 2, i);
    }
    const higherTime = Date.now() - higherStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Function Calls benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Simple calls: ${simpleTime}ms (${iterations} calls)`);
    console.log(`Parameter calls: ${paramTime}ms (${iterations} calls)`);
    console.log(`Multi-param calls: ${multiTime}ms (${iterations / 10} calls)`);
    console.log(`Conditional calls: ${condTime}ms (${iterations} calls)`);
    console.log(`Recursive calls: ${recurTime}ms (1000 calls)`);
    console.log(`Method calls: ${methodTime}ms (${iterations * 2} calls)`);
    console.log(`Arrow calls: ${arrowTime}ms (${iterations} calls)`);
    console.log(`Higher-order calls: ${higherTime}ms (${iterations / 10 * 2} calls)`);
    console.log(`Final results: simple=${simpleSum}, param=${paramSum}, multi=${multiSum}, cond=${condSum}, recur=${recurSum}, method=${methodSum}, arrow=${arrowSum}, higher=${higherSum}`);

    return {
        totalTime,
        iterations,
        operations: {
            simpleCalls: iterations,
            paramCalls: iterations,
            multiParamCalls: iterations / 10,
            conditionalCalls: iterations,
            recursiveCalls: 1000,
            methodCalls: iterations * 2,
            arrowCalls: iterations,
            higherOrderCalls: iterations / 10 * 2
        },
        times: {
            simpleCalls: simpleTime,
            paramCalls: paramTime,
            multiParamCalls: multiTime,
            conditionalCalls: condTime,
            recursiveCalls: recurTime,
            methodCalls: methodTime,
            arrowCalls: arrowTime,
            higherOrderCalls: higherTime
        },
        results: {
            simpleSum,
            paramSum,
            multiSum,
            condSum,
            recurSum,
            methodSum,
            arrowSum,
            higherSum
        },
        opsPerSecond: {
            simpleCalls: Math.round(iterations / (simpleTime / 1000)),
            paramCalls: Math.round(iterations / (paramTime / 1000)),
            multiParamCalls: Math.round((iterations / 10) / (multiTime / 1000)),
            conditionalCalls: Math.round(iterations / (condTime / 1000)),
            recursiveCalls: Math.round(1000 / (recurTime / 1000)),
            methodCalls: Math.round((iterations * 2) / (methodTime / 1000)),
            arrowCalls: Math.round(iterations / (arrowTime / 1000)),
            higherOrderCalls: Math.round((iterations / 10 * 2) / (higherTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkFunctionCalls();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkFunctionCalls;
}