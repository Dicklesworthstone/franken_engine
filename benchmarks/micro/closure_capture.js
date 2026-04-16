// Micro-Benchmark 9: Closure Capture
// Tests performance of closures capturing various numbers of variables

function benchmarkClosureCapture() {
    console.log("Starting Closure Capture benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M calls through closures

    // Simple closure capturing one variable
    const singleStart = Date.now();
    function createSingleClosure(x) {
        return function() {
            return x * 2;
        };
    }

    const singleClosures = [];
    for (let i = 0; i < 1000; i++) {
        singleClosures.push(createSingleClosure(i));
    }

    let singleSum = 0;
    for (let i = 0; i < iterations; i++) {
        const closure = singleClosures[i % singleClosures.length];
        singleSum += closure();
    }
    const singleTime = Date.now() - singleStart;

    // Closure capturing three variables
    const tripleStart = Date.now();
    function createTripleClosure(x, y, z) {
        return function() {
            return x + y + z;
        };
    }

    const tripleClosures = [];
    for (let i = 0; i < 1000; i++) {
        tripleClosures.push(createTripleClosure(i, i + 1, i + 2));
    }

    let tripleSum = 0;
    for (let i = 0; i < iterations; i++) {
        const closure = tripleClosures[i % tripleClosures.length];
        tripleSum += closure();
    }
    const tripleTime = Date.now() - tripleStart;

    // Closure capturing many variables
    const manyStart = Date.now();
    function createManyClosure(a, b, c, d, e, f, g, h, i, j) {
        return function() {
            return a + b + c + d + e + f + g + h + i + j;
        };
    }

    const manyClosures = [];
    for (let i = 0; i < 1000; i++) {
        manyClosures.push(createManyClosure(i, i+1, i+2, i+3, i+4, i+5, i+6, i+7, i+8, i+9));
    }

    let manySum = 0;
    for (let i = 0; i < iterations / 10; i++) { // Fewer iterations for complex closures
        const closure = manyClosures[i % manyClosures.length];
        manySum += closure();
    }
    const manyTime = Date.now() - manyStart;

    // Nested closure creation
    const nestedStart = Date.now();
    function createNestedClosure(outer) {
        return function(middle) {
            return function(inner) {
                return outer + middle + inner;
            };
        };
    }

    const nestedClosures = [];
    for (let i = 0; i < 100; i++) {
        const level1 = createNestedClosure(i);
        const level2 = level1(i + 10);
        nestedClosures.push(level2);
    }

    let nestedSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        const closure = nestedClosures[i % nestedClosures.length];
        nestedSum += closure(i);
    }
    const nestedTime = Date.now() - nestedStart;

    // Closure with side effects
    const sideEffectStart = Date.now();
    function createSideEffectClosure() {
        let counter = 0;
        return function() {
            counter++;
            return counter;
        };
    }

    const sideEffectClosures = [];
    for (let i = 0; i < 100; i++) {
        sideEffectClosures.push(createSideEffectClosure());
    }

    let sideEffectSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        const closure = sideEffectClosures[i % sideEffectClosures.length];
        sideEffectSum += closure();
    }
    const sideEffectTime = Date.now() - sideEffectStart;

    // Arrow function closures
    const arrowStart = Date.now();
    const createArrowClosure = (x, y, z) => () => x + y + z;

    const arrowClosures = [];
    for (let i = 0; i < 1000; i++) {
        arrowClosures.push(createArrowClosure(i, i + 1, i + 2));
    }

    let arrowSum = 0;
    for (let i = 0; i < iterations; i++) {
        const closure = arrowClosures[i % arrowClosures.length];
        arrowSum += closure();
    }
    const arrowTime = Date.now() - arrowStart;

    // Closure returning closure (higher-order)
    const higherOrderStart = Date.now();
    function createHigherOrderClosure(multiplier) {
        return function(addend) {
            return function(value) {
                return (value * multiplier) + addend;
            };
        };
    }

    const higherOrderClosures = [];
    for (let i = 0; i < 100; i++) {
        const level1 = createHigherOrderClosure(i + 1);
        const level2 = level1(i * 2);
        higherOrderClosures.push(level2);
    }

    let higherOrderSum = 0;
    for (let i = 0; i < iterations / 100; i++) {
        const closure = higherOrderClosures[i % higherOrderClosures.length];
        higherOrderSum += closure(i);
    }
    const higherOrderTime = Date.now() - higherOrderStart;

    // Closure capturing object properties
    const objectStart = Date.now();
    function createObjectClosure(obj) {
        return function() {
            return obj.x + obj.y + obj.z;
        };
    }

    const objectClosures = [];
    for (let i = 0; i < 1000; i++) {
        const obj = { x: i, y: i + 1, z: i + 2 };
        objectClosures.push(createObjectClosure(obj));
    }

    let objectSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        const closure = objectClosures[i % objectClosures.length];
        objectSum += closure();
    }
    const objectTime = Date.now() - objectStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Closure Capture benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Single capture: ${singleTime}ms (${iterations} calls)`);
    console.log(`Triple capture: ${tripleTime}ms (${iterations} calls)`);
    console.log(`Many captures: ${manyTime}ms (${iterations / 10} calls)`);
    console.log(`Nested closures: ${nestedTime}ms (${iterations / 10} calls)`);
    console.log(`Side effects: ${sideEffectTime}ms (${iterations / 10} calls)`);
    console.log(`Arrow closures: ${arrowTime}ms (${iterations} calls)`);
    console.log(`Higher-order: ${higherOrderTime}ms (${iterations / 100} calls)`);
    console.log(`Object capture: ${objectTime}ms (${iterations / 10} calls)`);
    console.log(`Final results: single=${singleSum}, triple=${tripleSum}, many=${manySum}, nested=${nestedSum}, side=${sideEffectSum}, arrow=${arrowSum}, higher=${higherOrderSum}, object=${objectSum}`);

    return {
        totalTime,
        iterations,
        operations: {
            singleCapture: iterations,
            tripleCapture: iterations,
            manyCaptures: iterations / 10,
            nestedClosures: iterations / 10,
            sideEffects: iterations / 10,
            arrowClosures: iterations,
            higherOrder: iterations / 100,
            objectCapture: iterations / 10
        },
        times: {
            singleCapture: singleTime,
            tripleCapture: tripleTime,
            manyCaptures: manyTime,
            nestedClosures: nestedTime,
            sideEffects: sideEffectTime,
            arrowClosures: arrowTime,
            higherOrder: higherOrderTime,
            objectCapture: objectTime
        },
        results: {
            singleSum,
            tripleSum,
            manySum,
            nestedSum,
            sideEffectSum,
            arrowSum,
            higherOrderSum,
            objectSum
        },
        opsPerSecond: {
            singleCapture: Math.round(iterations / (singleTime / 1000)),
            tripleCapture: Math.round(iterations / (tripleTime / 1000)),
            manyCaptures: Math.round((iterations / 10) / (manyTime / 1000)),
            nestedClosures: Math.round((iterations / 10) / (nestedTime / 1000)),
            sideEffects: Math.round((iterations / 10) / (sideEffectTime / 1000)),
            arrowClosures: Math.round(iterations / (arrowTime / 1000)),
            higherOrder: Math.round((iterations / 100) / (higherOrderTime / 1000)),
            objectCapture: Math.round((iterations / 10) / (objectTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkClosureCapture();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkClosureCapture;
}