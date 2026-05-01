// Object property access workload
function objectOperations() {
    let obj = { a: 1, b: 2, c: 3, d: 4 };
    obj.e = obj.a + obj.b;
    obj.f = obj.c * obj.d;
    delete obj.a;
    obj.nested = { x: obj.e, y: obj.f };
    return Object.keys(obj).length;
}

// Benchmark: object operations
const start = Date.now();
let iterations = 0;
const duration = 1000; // Run for 1 second

while (Date.now() - start < duration) {
    objectOperations();
    iterations++;
}

const elapsed = Date.now() - start;
const opsPerSecond = Math.round((iterations * 1000) / elapsed);

console.log(JSON.stringify({
    workload: 'objects',
    iterations: iterations,
    duration_ms: elapsed,
    ops_per_second: opsPerSecond
}));