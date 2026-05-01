// Function calls workload
function add(a, b) { return a + b; }
function multiply(a, b) { return a * b; }
function compose(f, g) { return x => f(g(x)); }

function functionOperations() {
    let result = add(5, 3);
    result = multiply(result, 2);
    let composed = compose(x => x * 2, x => x + 1);
    result = composed(result);
    result = [1, 2, 3].reduce(add, result);
    return result;
}

// Benchmark: function operations
const start = Date.now();
let iterations = 0;
const duration = 1000; // Run for 1 second

while (Date.now() - start < duration) {
    functionOperations();
    iterations++;
}

const elapsed = Date.now() - start;
const opsPerSecond = Math.round((iterations * 1000) / elapsed);

console.log(JSON.stringify({
    workload: 'functions',
    iterations: iterations,
    duration_ms: elapsed,
    ops_per_second: opsPerSecond
}));