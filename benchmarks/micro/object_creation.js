// Micro-Benchmark 5: Object Creation
// Tests performance of creating objects with various patterns

function benchmarkObjectCreation() {
    console.log("Starting Object Creation benchmark...");
    const startTime = Date.now();

    const objectCount = 100000; // 100K objects
    const results = {};

    // Literal object creation
    const literalStart = Date.now();
    const literalObjects = [];
    for (let i = 0; i < objectCount; i++) {
        literalObjects.push({
            id: i,
            name: `Object${i}`,
            value: i * 2.5,
            active: i % 2 === 0,
            metadata: `meta${i}`
        });
    }
    const literalTime = Date.now() - literalStart;

    // Constructor function object creation
    function ObjectConstructor(id, name, value, active, metadata) {
        this.id = id;
        this.name = name;
        this.value = value;
        this.active = active;
        this.metadata = metadata;
    }

    const constructorStart = Date.now();
    const constructorObjects = [];
    for (let i = 0; i < objectCount; i++) {
        constructorObjects.push(new ObjectConstructor(
            i,
            `Object${i}`,
            i * 2.5,
            i % 2 === 0,
            `meta${i}`
        ));
    }
    const constructorTime = Date.now() - constructorStart;

    // ES6 Class object creation
    class ObjectClass {
        constructor(id, name, value, active, metadata) {
            this.id = id;
            this.name = name;
            this.value = value;
            this.active = active;
            this.metadata = metadata;
        }

        getValue() {
            return this.value;
        }

        isActive() {
            return this.active;
        }
    }

    const classStart = Date.now();
    const classObjects = [];
    for (let i = 0; i < objectCount; i++) {
        classObjects.push(new ObjectClass(
            i,
            `Object${i}`,
            i * 2.5,
            i % 2 === 0,
            `meta${i}`
        ));
    }
    const classTime = Date.now() - classStart;

    // Object.create() with prototype
    const prototypeObject = {
        getValue() {
            return this.value;
        },
        isActive() {
            return this.active;
        }
    };

    const createStart = Date.now();
    const createObjects = [];
    for (let i = 0; i < objectCount; i++) {
        const obj = Object.create(prototypeObject);
        obj.id = i;
        obj.name = `Object${i}`;
        obj.value = i * 2.5;
        obj.active = i % 2 === 0;
        obj.metadata = `meta${i}`;
        createObjects.push(obj);
    }
    const createTime = Date.now() - createStart;

    // Factory function object creation
    function createObject(id, name, value, active, metadata) {
        return {
            id,
            name,
            value,
            active,
            metadata,
            getValue() {
                return this.value;
            },
            isActive() {
                return this.active;
            }
        };
    }

    const factoryStart = Date.now();
    const factoryObjects = [];
    for (let i = 0; i < objectCount; i++) {
        factoryObjects.push(createObject(
            i,
            `Object${i}`,
            i * 2.5,
            i % 2 === 0,
            `meta${i}`
        ));
    }
    const factoryTime = Date.now() - factoryStart;

    // Empty object creation and property assignment
    const emptyStart = Date.now();
    const emptyObjects = [];
    for (let i = 0; i < objectCount; i++) {
        const obj = {};
        obj.id = i;
        obj.name = `Object${i}`;
        obj.value = i * 2.5;
        obj.active = i % 2 === 0;
        obj.metadata = `meta${i}`;
        emptyObjects.push(obj);
    }
    const emptyTime = Date.now() - emptyStart;

    // Nested object creation
    const nestedStart = Date.now();
    const nestedObjects = [];
    for (let i = 0; i < objectCount / 10; i++) { // Fewer nested objects
        nestedObjects.push({
            id: i,
            data: {
                name: `Object${i}`,
                details: {
                    value: i * 2.5,
                    metadata: {
                        active: i % 2 === 0,
                        description: `meta${i}`,
                        tags: [`tag${i % 5}`, `category${i % 3}`]
                    }
                }
            },
            config: {
                enabled: true,
                priority: i % 10,
                settings: {
                    timeout: 5000,
                    retries: 3
                }
            }
        });
    }
    const nestedTime = Date.now() - nestedStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    // Calculate memory usage estimates (rough)
    const sampleLiteral = literalObjects[0];
    const literalSize = JSON.stringify(sampleLiteral).length;
    const totalLiteralSize = literalSize * literalObjects.length;

    console.log("Object Creation benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Literal objects: ${literalTime}ms (${objectCount} objects)`);
    console.log(`Constructor objects: ${constructorTime}ms (${objectCount} objects)`);
    console.log(`Class objects: ${classTime}ms (${objectCount} objects)`);
    console.log(`Object.create: ${createTime}ms (${objectCount} objects)`);
    console.log(`Factory objects: ${factoryTime}ms (${objectCount} objects)`);
    console.log(`Empty + assign: ${emptyTime}ms (${objectCount} objects)`);
    console.log(`Nested objects: ${nestedTime}ms (${objectCount / 10} objects)`);
    console.log(`Estimated literal object size: ${Math.round(totalLiteralSize / 1024)}KB`);

    return {
        totalTime,
        objectCount,
        operations: {
            literalObjects: objectCount,
            constructorObjects: objectCount,
            classObjects: objectCount,
            createObjects: objectCount,
            factoryObjects: objectCount,
            emptyObjects: objectCount,
            nestedObjects: objectCount / 10
        },
        times: {
            literalObjects: literalTime,
            constructorObjects: constructorTime,
            classObjects: classTime,
            createObjects: createTime,
            factoryObjects: factoryTime,
            emptyObjects: emptyTime,
            nestedObjects: nestedTime
        },
        results: {
            literalCount: literalObjects.length,
            constructorCount: constructorObjects.length,
            classCount: classObjects.length,
            createCount: createObjects.length,
            factoryCount: factoryObjects.length,
            emptyCount: emptyObjects.length,
            nestedCount: nestedObjects.length,
            estimatedSizeKB: Math.round(totalLiteralSize / 1024)
        },
        opsPerSecond: {
            literalObjects: Math.round(objectCount / (literalTime / 1000)),
            constructorObjects: Math.round(objectCount / (constructorTime / 1000)),
            classObjects: Math.round(objectCount / (classTime / 1000)),
            createObjects: Math.round(objectCount / (createTime / 1000)),
            factoryObjects: Math.round(objectCount / (factoryTime / 1000)),
            emptyObjects: Math.round(objectCount / (emptyTime / 1000)),
            nestedObjects: Math.round((objectCount / 10) / (nestedTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkObjectCreation();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkObjectCreation;
}