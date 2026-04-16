// Micro-Benchmark 3: Property Access
// Tests performance of property reads from objects of various sizes

function benchmarkPropertyAccess() {
    console.log("Starting Property Access benchmark...");
    const startTime = Date.now();

    const iterations = 1000000; // 1M property reads

    // Create objects of various sizes
    const smallObject = {
        a: 1, b: 2, c: 3
    };

    const mediumObject = {
        prop1: 'value1', prop2: 'value2', prop3: 'value3', prop4: 'value4', prop5: 'value5',
        prop6: 'value6', prop7: 'value7', prop8: 'value8', prop9: 'value9', prop10: 'value10',
        prop11: 'value11', prop12: 'value12', prop13: 'value13', prop14: 'value14', prop15: 'value15'
    };

    const largeObject = {};
    for (let i = 0; i < 100; i++) {
        largeObject[`property${i}`] = `value${i}`;
    }

    // Nested object
    const nestedObject = {
        level1: {
            level2: {
                level3: {
                    level4: {
                        finalValue: 42
                    }
                }
            }
        },
        otherProp: 'other'
    };

    // Small object property access
    const smallStart = Date.now();
    let smallSum = 0;
    for (let i = 0; i < iterations; i++) {
        smallSum += smallObject.a;
        smallSum += smallObject.b;
        smallSum += smallObject.c;
    }
    const smallTime = Date.now() - smallStart;

    // Medium object property access
    const mediumStart = Date.now();
    let mediumResult = '';
    const keys = Object.keys(mediumObject);
    for (let i = 0; i < iterations / 10; i++) {
        const key = keys[i % keys.length];
        mediumResult = mediumObject[key];
        mediumResult = mediumObject.prop1;
        mediumResult = mediumObject.prop8;
        mediumResult = mediumObject.prop15;
    }
    const mediumTime = Date.now() - mediumStart;

    // Large object property access
    const largeStart = Date.now();
    let largeResult = '';
    for (let i = 0; i < iterations / 100; i++) {
        const index = i % 100;
        largeResult = largeObject[`property${index}`];
        largeResult = largeObject.property0;
        largeResult = largeObject.property50;
        largeResult = largeObject.property99;
    }
    const largeTime = Date.now() - largeStart;

    // Nested property access
    const nestedStart = Date.now();
    let nestedResult = 0;
    for (let i = 0; i < iterations / 100; i++) {
        nestedResult += nestedObject.level1.level2.level3.level4.finalValue;
        nestedResult += nestedObject.level1.level2.level3.level4.finalValue;
        nestedResult += nestedObject.otherProp.length;
    }
    const nestedTime = Date.now() - nestedStart;

    // Dynamic property access
    const dynamicStart = Date.now();
    let dynamicResult = 0;
    const propertyNames = ['a', 'b', 'c'];
    for (let i = 0; i < iterations; i++) {
        const propName = propertyNames[i % propertyNames.length];
        dynamicResult += smallObject[propName];
    }
    const dynamicTime = Date.now() - dynamicStart;

    // Property existence checks
    const existenceStart = Date.now();
    let existenceCount = 0;
    for (let i = 0; i < iterations / 10; i++) {
        if ('a' in smallObject) existenceCount++;
        if ('z' in smallObject) existenceCount++;
        if (smallObject.hasOwnProperty('b')) existenceCount++;
        if (smallObject.hasOwnProperty('nonexistent')) existenceCount++;
    }
    const existenceTime = Date.now() - existenceStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Property Access benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Small object: ${smallTime}ms (${iterations} reads)`);
    console.log(`Medium object: ${mediumTime}ms (${iterations / 10} reads)`);
    console.log(`Large object: ${largeTime}ms (${iterations / 100} reads)`);
    console.log(`Nested access: ${nestedTime}ms (${iterations / 100} reads)`);
    console.log(`Dynamic access: ${dynamicTime}ms (${iterations} reads)`);
    console.log(`Existence checks: ${existenceTime}ms (${iterations / 10} checks)`);
    console.log(`Final results: small=${smallSum}, dynamic=${dynamicResult}, nested=${nestedResult}, existence=${existenceCount}`);

    return {
        totalTime,
        iterations,
        operations: {
            smallObject: iterations,
            mediumObject: iterations / 10,
            largeObject: iterations / 100,
            nestedAccess: iterations / 100,
            dynamicAccess: iterations,
            existenceChecks: iterations / 10
        },
        times: {
            smallObject: smallTime,
            mediumObject: mediumTime,
            largeObject: largeTime,
            nestedAccess: nestedTime,
            dynamicAccess: dynamicTime,
            existenceChecks: existenceTime
        },
        results: {
            smallSum,
            mediumResult: mediumResult ? mediumResult.substring(0, 10) : '',
            largeResult: largeResult ? largeResult.substring(0, 10) : '',
            nestedResult,
            dynamicResult,
            existenceCount
        },
        opsPerSecond: {
            smallObject: Math.round(iterations / (smallTime / 1000)),
            mediumObject: Math.round((iterations / 10) / (mediumTime / 1000)),
            largeObject: Math.round((iterations / 100) / (largeTime / 1000)),
            nestedAccess: Math.round((iterations / 100) / (nestedTime / 1000)),
            dynamicAccess: Math.round(iterations / (dynamicTime / 1000)),
            existenceChecks: Math.round((iterations / 10) / (existenceTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkPropertyAccess();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkPropertyAccess;
}