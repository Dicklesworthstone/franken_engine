// CPU-intensive computation workload
function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Benchmark: compute fibonacci numbers
const start = Date.now();
let iterations = 0;
const duration = 1000; // Run for 1 second

while (Date.now() - start < duration) {
    fibonacci(20);
    iterations++;
}

const elapsed = Date.now() - start;
const opsPerSecond = Math.round((iterations * 1000) / elapsed);

console.log(JSON.stringify({
    workload: 'fibonacci',
    iterations: iterations,
    duration_ms: elapsed,
    ops_per_second: opsPerSecond
}));