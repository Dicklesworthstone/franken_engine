// Array operations workload
function arrayOperations() {
    let arr = [1, 2, 3, 4, 5];
    arr = arr.map(x => x * 2);
    arr = arr.filter(x => x > 5);
    arr = arr.reduce((acc, x) => acc + x, 0);
    arr = [arr, arr, arr].flat();
    return arr.length;
}

// Benchmark: array operations
const start = Date.now();
let iterations = 0;
const duration = 1000; // Run for 1 second

while (Date.now() - start < duration) {
    arrayOperations();
    iterations++;
}

const elapsed = Date.now() - start;
const opsPerSecond = Math.round((iterations * 1000) / elapsed);

console.log(JSON.stringify({
    workload: 'arrays',
    iterations: iterations,
    duration_ms: elapsed,
    ops_per_second: opsPerSecond
}));