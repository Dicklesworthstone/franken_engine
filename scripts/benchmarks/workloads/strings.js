// String manipulation workload
function stringOperations() {
    let result = "hello";
    result = result.toUpperCase();
    result = result + " world";
    result = result.replace(/HELLO/, "goodbye");
    result = result.split(" ").join("-");
    result = result.slice(0, 10);
    return result.length;
}

// Benchmark: string operations
const start = Date.now();
let iterations = 0;
const duration = 1000; // Run for 1 second

while (Date.now() - start < duration) {
    stringOperations();
    iterations++;
}

const elapsed = Date.now() - start;
const opsPerSecond = Math.round((iterations * 1000) / elapsed);

console.log(JSON.stringify({
    workload: 'strings',
    iterations: iterations,
    duration_ms: elapsed,
    ops_per_second: opsPerSecond
}));