// Micro-Benchmark 12: Miscellaneous Operations
// Tests performance of various JavaScript operations and built-in functions

function benchmarkMiscOperations() {
    console.log("Starting Miscellaneous Operations benchmark...");
    const startTime = Date.now();

    const iterations = 100000; // Base iteration count

    // Math operations
    const mathStart = Date.now();
    let mathSum = 0;
    for (let i = 0; i < iterations; i++) {
        mathSum += Math.sin(i * 0.01);
        mathSum += Math.cos(i * 0.01);
        mathSum += Math.sqrt(i + 1);
        mathSum += Math.log(i + 1);
        mathSum += Math.exp(i * 0.001);
        mathSum += Math.abs(i - iterations / 2);
        mathSum += Math.floor(i * 1.5);
        mathSum += Math.ceil(i * 0.7);
        mathSum += Math.round(i * Math.PI);
        mathSum += Math.max(i, i - 1000);
        mathSum += Math.min(i, i + 1000);
        mathSum += Math.pow(i % 10, 2);
    }
    const mathTime = Date.now() - mathStart;

    // Type checking operations
    const typeCheckStart = Date.now();
    let typeCheckSum = 0;
    const testValues = [1, 'string', true, null, undefined, {}, [], function() {}];

    for (let i = 0; i < iterations; i++) {
        const value = testValues[i % testValues.length];

        if (typeof value === 'number') typeCheckSum++;
        if (typeof value === 'string') typeCheckSum++;
        if (typeof value === 'boolean') typeCheckSum++;
        if (typeof value === 'object') typeCheckSum++;
        if (typeof value === 'function') typeCheckSum++;
        if (value === null) typeCheckSum++;
        if (value === undefined) typeCheckSum++;
        if (Array.isArray(value)) typeCheckSum++;
        if (value instanceof Object) typeCheckSum++;
        if (value instanceof Array) typeCheckSum++;
    }
    const typeCheckTime = Date.now() - typeCheckStart;

    // Object property enumeration
    const enumerationStart = Date.now();
    const testObject = {};
    for (let i = 0; i < 100; i++) {
        testObject[`prop${i}`] = i;
    }

    let enumerationSum = 0;
    for (let i = 0; i < iterations / 100; i++) {
        // Object.keys
        const keys = Object.keys(testObject);
        enumerationSum += keys.length;

        // Object.values
        const values = Object.values(testObject);
        enumerationSum += values.length;

        // Object.entries
        const entries = Object.entries(testObject);
        enumerationSum += entries.length;

        // for...in loop
        for (const key in testObject) {
            if (testObject.hasOwnProperty(key)) {
                enumerationSum += 1;
            }
        }

        // Object.getOwnPropertyNames
        const propNames = Object.getOwnPropertyNames(testObject);
        enumerationSum += propNames.length;
    }
    const enumerationTime = Date.now() - enumerationStart;

    // Regular expression operations
    const regexStart = Date.now();
    const testText = 'The quick brown fox jumps over the lazy dog. 123-456-7890 email@example.com https://www.example.com';
    const patterns = [
        /the/gi,
        /\d+/g,
        /\w+@\w+\.\w+/g,
        /https?:\/\/[^\s]+/g,
        /\b\w{4,}\b/g,
        /[aeiou]/gi,
        /\d{3}-\d{3}-\d{4}/g
    ];

    let regexMatches = 0;
    for (let i = 0; i < iterations / 10; i++) {
        for (const pattern of patterns) {
            const matches = testText.match(pattern);
            if (matches) regexMatches += matches.length;

            pattern.lastIndex = 0; // Reset for global patterns
            let match;
            while ((match = pattern.exec(testText)) !== null) {
                regexMatches++;
                if (pattern.lastIndex === match.index) {
                    pattern.lastIndex++; // Prevent infinite loop
                }
            }
        }
    }
    const regexTime = Date.now() - regexStart;

    // Date operations
    const dateStart = Date.now();
    let dateSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        const now = Date.now();
        const date1 = new Date();
        const date2 = new Date(now + i * 1000);
        const date3 = new Date('2024-01-01');

        dateSum += date1.getTime();
        dateSum += date2.getTime() - date1.getTime();
        dateSum += date1.getFullYear();
        dateSum += date1.getMonth();
        dateSum += date1.getDate();
        dateSum += date1.getHours();
        dateSum += date1.getMinutes();
        dateSum += date1.getSeconds();
        dateSum += date1.getMilliseconds();
        dateSum += date3.getTime();
    }
    const dateTime = Date.now() - dateStart;

    // Number formatting and parsing
    const numberStart = Date.now();
    let numberSum = 0;
    for (let i = 0; i < iterations / 10; i++) {
        const num = i * 3.14159;

        // Number methods
        numberSum += Number(i);
        numberSum += parseInt(i.toString(), 10);
        numberSum += parseFloat(num.toString());
        numberSum += Number.isInteger(i) ? 1 : 0;
        numberSum += Number.isNaN(num) ? 1 : 0;
        numberSum += Number.isFinite(num) ? 1 : 0;

        // Number formatting
        const formatted = num.toFixed(2);
        const exponential = num.toExponential(2);
        const precision = num.toPrecision(4);

        numberSum += parseFloat(formatted);
        numberSum += parseFloat(exponential);
        numberSum += parseFloat(precision);
    }
    const numberTime = Date.now() - numberStart;

    // Boolean and logical operations
    const booleanStart = Date.now();
    let booleanSum = 0;
    for (let i = 0; i < iterations; i++) {
        const a = i % 2 === 0;
        const b = i % 3 === 0;
        const c = i % 5 === 0;

        if (a && b) booleanSum++;
        if (a || b) booleanSum++;
        if (!a) booleanSum++;
        if (a && (b || c)) booleanSum++;
        if ((a && b) || (a && c)) booleanSum++;
        if (a ? b : c) booleanSum++;

        // Truthy/falsy checks
        if (i) booleanSum++;
        if (i === 0) booleanSum++;
        if (Boolean(i)) booleanSum++;
        if (!!i) booleanSum++;
    }
    const booleanTime = Date.now() - booleanStart;

    // WeakMap and WeakSet operations (if supported)
    const weakStart = Date.now();
    let weakOperations = 0;
    try {
        const weakMap = new WeakMap();
        const weakSet = new WeakSet();
        const objects = [];

        // Create objects for weak references
        for (let i = 0; i < 1000; i++) {
            objects.push({ id: i });
        }

        for (let i = 0; i < iterations / 100; i++) {
            const obj = objects[i % objects.length];

            weakMap.set(obj, i);
            weakSet.add(obj);

            if (weakMap.has(obj)) weakOperations++;
            if (weakSet.has(obj)) weakOperations++;

            if (i % 100 === 99) { // Occasionally delete
                weakMap.delete(obj);
                weakSet.delete(obj);
            }
        }
    } catch (e) {
        // WeakMap/WeakSet not supported
        weakOperations = -1;
    }
    const weakTime = Date.now() - weakStart;

    // Proxy operations (if supported)
    const proxyStart = Date.now();
    let proxyOperations = 0;
    try {
        const target = { value: 0 };
        const handler = {
            get(target, prop) {
                proxyOperations++;
                return target[prop];
            },
            set(target, prop, value) {
                proxyOperations++;
                target[prop] = value;
                return true;
            }
        };

        const proxy = new Proxy(target, handler);

        for (let i = 0; i < iterations / 100; i++) {
            proxy.value = i;
            const value = proxy.value;
            proxy[`prop${i % 10}`] = i;
            const prop = proxy[`prop${i % 10}`];
        }
    } catch (e) {
        // Proxy not supported
        proxyOperations = -1;
    }
    const proxyTime = Date.now() - proxyStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Miscellaneous Operations benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Math operations: ${mathTime}ms (${iterations * 12} operations, sum=${mathSum.toFixed(2)})`);
    console.log(`Type checking: ${typeCheckTime}ms (${iterations * 10} checks, sum=${typeCheckSum})`);
    console.log(`Object enumeration: ${enumerationTime}ms (${iterations / 100} iterations, sum=${enumerationSum})`);
    console.log(`Regex operations: ${regexTime}ms (${iterations / 10} iterations, matches=${regexMatches})`);
    console.log(`Date operations: ${dateTime}ms (${iterations / 10} iterations, sum=${dateSum})`);
    console.log(`Number formatting: ${numberTime}ms (${iterations / 10} iterations, sum=${numberSum.toFixed(2)})`);
    console.log(`Boolean operations: ${booleanTime}ms (${iterations * 10} operations, sum=${booleanSum})`);

    if (weakOperations >= 0) {
        console.log(`WeakMap/Set operations: ${weakTime}ms (${iterations / 100} iterations, ops=${weakOperations})`);
    } else {
        console.log(`WeakMap/Set operations: Not supported`);
    }

    if (proxyOperations >= 0) {
        console.log(`Proxy operations: ${proxyTime}ms (${iterations / 100} iterations, ops=${proxyOperations})`);
    } else {
        console.log(`Proxy operations: Not supported`);
    }

    return {
        totalTime,
        iterations,
        operations: {
            mathOps: iterations * 12,
            typeChecking: iterations * 10,
            objectEnumeration: (iterations / 100) * 5,
            regexOps: (iterations / 10) * patterns.length,
            dateOps: (iterations / 10) * 10,
            numberFormatting: (iterations / 10) * 9,
            booleanOps: iterations * 10,
            weakCollections: weakOperations >= 0 ? iterations / 100 * 4 : 0,
            proxyOps: proxyOperations >= 0 ? iterations / 100 * 4 : 0
        },
        times: {
            mathOps: mathTime,
            typeChecking: typeCheckTime,
            objectEnumeration: enumerationTime,
            regexOps: regexTime,
            dateOps: dateTime,
            numberFormatting: numberTime,
            booleanOps: booleanTime,
            weakCollections: weakTime,
            proxyOps: proxyTime
        },
        results: {
            mathSum: Math.round(mathSum * 100) / 100,
            typeCheckSum,
            enumerationSum,
            regexMatches,
            dateSum,
            numberSum: Math.round(numberSum * 100) / 100,
            booleanSum,
            weakOperations,
            proxyOperations
        },
        opsPerSecond: {
            mathOps: Math.round((iterations * 12) / (mathTime / 1000)),
            typeChecking: Math.round((iterations * 10) / (typeCheckTime / 1000)),
            objectEnumeration: Math.round(((iterations / 100) * 5) / (enumerationTime / 1000)),
            regexOps: Math.round(((iterations / 10) * patterns.length) / (regexTime / 1000)),
            dateOps: Math.round(((iterations / 10) * 10) / (dateTime / 1000)),
            numberFormatting: Math.round(((iterations / 10) * 9) / (numberTime / 1000)),
            booleanOps: Math.round((iterations * 10) / (booleanTime / 1000)),
            weakCollections: weakOperations >= 0 ? Math.round(((iterations / 100) * 4) / (weakTime / 1000)) : 0,
            proxyOps: proxyOperations >= 0 ? Math.round(((iterations / 100) * 4) / (proxyTime / 1000)) : 0
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkMiscOperations();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkMiscOperations;
}