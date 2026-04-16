// Micro-Benchmark 6: Array Operations
// Tests performance of array push/pop and iteration operations

function benchmarkArrayOperations() {
    console.log("Starting Array Operations benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M push/pop operations
    const iterationSize = 10000; // 10K element arrays for iteration tests

    // Array push/pop benchmark
    const pushPopStart = Date.now();
    const arr = [];
    let pushPopSum = 0;

    // Push phase
    for (let i = 0; i < iterations; i++) {
        arr.push(i);
    }

    // Pop phase
    while (arr.length > 0) {
        pushPopSum += arr.pop();
    }
    const pushPopTime = Date.now() - pushPopStart;

    // Array unshift/shift benchmark
    const shiftStart = Date.now();
    const shiftArr = [];
    let shiftSum = 0;

    // Unshift phase (limited to avoid O(n²) performance)
    for (let i = 0; i < iterations / 100; i++) {
        shiftArr.unshift(i);
    }

    // Shift phase
    while (shiftArr.length > 0) {
        shiftSum += shiftArr.shift();
    }
    const shiftTime = Date.now() - shiftStart;

    // Array access by index
    const accessStart = Date.now();
    const accessArr = [];
    for (let i = 0; i < iterationSize; i++) {
        accessArr[i] = i * 2;
    }

    let accessSum = 0;
    for (let i = 0; i < iterations; i++) {
        const index = i % iterationSize;
        accessSum += accessArr[index];
    }
    const accessTime = Date.now() - accessStart;

    // Array map operation
    const mapStart = Date.now();
    const mapSource = [];
    for (let i = 0; i < iterationSize; i++) {
        mapSource[i] = i;
    }

    let mapResults = [];
    for (let i = 0; i < 100; i++) { // 100 iterations of map
        mapResults = mapSource.map(x => x * 2 + 1);
    }
    const mapTime = Date.now() - mapStart;

    // Array filter operation
    const filterStart = Date.now();
    const filterSource = [];
    for (let i = 0; i < iterationSize; i++) {
        filterSource[i] = i;
    }

    let filterResults = [];
    for (let i = 0; i < 100; i++) { // 100 iterations of filter
        filterResults = filterSource.filter(x => x % 2 === 0);
    }
    const filterTime = Date.now() - filterStart;

    // Array reduce operation
    const reduceStart = Date.now();
    const reduceSource = [];
    for (let i = 0; i < iterationSize; i++) {
        reduceSource[i] = i;
    }

    let reduceResults = 0;
    for (let i = 0; i < 100; i++) { // 100 iterations of reduce
        reduceResults = reduceSource.reduce((sum, x) => sum + x, 0);
    }
    const reduceTime = Date.now() - reduceStart;

    // Array forEach operation
    const forEachStart = Date.now();
    const forEachSource = [];
    for (let i = 0; i < iterationSize; i++) {
        forEachSource[i] = i;
    }

    let forEachSum = 0;
    for (let i = 0; i < 100; i++) { // 100 iterations of forEach
        let tempSum = 0;
        forEachSource.forEach(x => tempSum += x);
        forEachSum = tempSum;
    }
    const forEachTime = Date.now() - forEachStart;

    // Array sort operation
    const sortStart = Date.now();
    let sortResults = [];
    for (let i = 0; i < 10; i++) { // 10 iterations of sort
        const sortSource = [];
        for (let j = 0; j < iterationSize; j++) {
            sortSource[j] = Math.floor(Math.random() * 10000);
        }
        sortResults = sortSource.sort((a, b) => a - b);
    }
    const sortTime = Date.now() - sortStart;

    // Array concat operation
    const concatStart = Date.now();
    const concatBase = [];
    for (let i = 0; i < 1000; i++) {
        concatBase[i] = i;
    }

    let concatResults = [];
    for (let i = 0; i < 1000; i++) { // 1000 iterations of concat
        const tempArr = [i, i + 1, i + 2];
        concatResults = concatBase.concat(tempArr);
    }
    const concatTime = Date.now() - concatStart;

    // Array slice operation
    const sliceStart = Date.now();
    const sliceSource = [];
    for (let i = 0; i < iterationSize; i++) {
        sliceSource[i] = i;
    }

    let sliceResults = [];
    for (let i = 0; i < 10000; i++) { // 10K slice operations
        const start = i % (iterationSize - 100);
        sliceResults = sliceSource.slice(start, start + 100);
    }
    const sliceTime = Date.now() - sliceStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Array Operations benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Push/Pop: ${pushPopTime}ms (${iterations} operations each)`);
    console.log(`Unshift/Shift: ${shiftTime}ms (${iterations / 100} operations each)`);
    console.log(`Index Access: ${accessTime}ms (${iterations} accesses)`);
    console.log(`Map: ${mapTime}ms (100 × ${iterationSize} elements)`);
    console.log(`Filter: ${filterTime}ms (100 × ${iterationSize} elements)`);
    console.log(`Reduce: ${reduceTime}ms (100 × ${iterationSize} elements)`);
    console.log(`ForEach: ${forEachTime}ms (100 × ${iterationSize} elements)`);
    console.log(`Sort: ${sortTime}ms (10 × ${iterationSize} elements)`);
    console.log(`Concat: ${concatTime}ms (1000 operations)`);
    console.log(`Slice: ${sliceTime}ms (10000 operations)`);
    console.log(`Final results: pushPop=${pushPopSum}, shift=${shiftSum}, access=${accessSum}, map=${mapResults.length}, filter=${filterResults.length}, reduce=${reduceResults}, forEach=${forEachSum}, sort=${sortResults[0]}, concat=${concatResults.length}, slice=${sliceResults.length}`);

    return {
        totalTime,
        iterations,
        operations: {
            pushPop: iterations * 2, // push + pop
            unshiftShift: (iterations / 100) * 2, // unshift + shift
            indexAccess: iterations,
            map: 100 * iterationSize,
            filter: 100 * iterationSize,
            reduce: 100 * iterationSize,
            forEach: 100 * iterationSize,
            sort: 10 * iterationSize,
            concat: 1000,
            slice: 10000
        },
        times: {
            pushPop: pushPopTime,
            unshiftShift: shiftTime,
            indexAccess: accessTime,
            map: mapTime,
            filter: filterTime,
            reduce: reduceTime,
            forEach: forEachTime,
            sort: sortTime,
            concat: concatTime,
            slice: sliceTime
        },
        results: {
            pushPopSum,
            shiftSum,
            accessSum,
            mapLength: mapResults.length,
            filterLength: filterResults.length,
            reduceResult: reduceResults,
            forEachSum,
            sortFirst: sortResults[0] || 0,
            concatLength: concatResults.length,
            sliceLength: sliceResults.length
        },
        opsPerSecond: {
            pushPop: Math.round((iterations * 2) / (pushPopTime / 1000)),
            unshiftShift: Math.round(((iterations / 100) * 2) / (shiftTime / 1000)),
            indexAccess: Math.round(iterations / (accessTime / 1000)),
            map: Math.round((100 * iterationSize) / (mapTime / 1000)),
            filter: Math.round((100 * iterationSize) / (filterTime / 1000)),
            reduce: Math.round((100 * iterationSize) / (reduceTime / 1000)),
            forEach: Math.round((100 * iterationSize) / (forEachTime / 1000)),
            sort: Math.round((10 * iterationSize) / (sortTime / 1000)),
            concat: Math.round(1000 / (concatTime / 1000)),
            slice: Math.round(10000 / (sliceTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkArrayOperations();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkArrayOperations;
}