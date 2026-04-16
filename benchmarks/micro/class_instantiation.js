// Micro-Benchmark 11: Class Instantiation
// Tests performance of creating class instances with constructors and methods

function benchmarkClassInstantiation() {
    console.log("Starting Class Instantiation benchmark...");
    const startTime = Date.now();

    const objectCount = 100000; // 100K instances
    const results = {};

    // Simple class with basic constructor
    class SimpleClass {
        constructor(id, value) {
            this.id = id;
            this.value = value;
        }

        getValue() {
            return this.value;
        }

        multiply(factor) {
            return this.value * factor;
        }
    }

    const simpleStart = Date.now();
    const simpleInstances = [];
    for (let i = 0; i < objectCount; i++) {
        simpleInstances.push(new SimpleClass(i, i * 2.5));
    }
    const simpleTime = Date.now() - simpleStart;

    // Class with complex constructor
    class ComplexClass {
        constructor(id, name, data, config) {
            this.id = id;
            this.name = name;
            this.data = data;
            this.config = config;
            this.created = Date.now();
            this.active = true;
            this.metadata = {
                version: '1.0.0',
                type: 'complex',
                index: id
            };
            this.initialize();
        }

        initialize() {
            this.computed = this.id * this.data.length;
            this.cached = {};
        }

        process() {
            return this.data.reduce((sum, val) => sum + val, 0);
        }

        getStatus() {
            return {
                id: this.id,
                name: this.name,
                active: this.active,
                created: this.created
            };
        }
    }

    const complexStart = Date.now();
    const complexInstances = [];
    for (let i = 0; i < objectCount / 10; i++) { // Fewer instances for complex class
        const data = Array.from({length: 5}, (_, j) => i + j);
        const config = { timeout: 5000, retries: 3 };
        complexInstances.push(new ComplexClass(i, `Item${i}`, data, config));
    }
    const complexTime = Date.now() - complexStart;

    // Class with inheritance
    class BaseClass {
        constructor(id) {
            this.id = id;
            this.baseValue = id * 10;
        }

        baseMethod() {
            return this.baseValue;
        }
    }

    class DerivedClass extends BaseClass {
        constructor(id, name, extra) {
            super(id);
            this.name = name;
            this.extra = extra;
            this.derivedValue = id * 20;
        }

        derivedMethod() {
            return this.baseValue + this.derivedValue;
        }

        overriddenMethod() {
            return super.baseMethod() + this.extra;
        }
    }

    const inheritanceStart = Date.now();
    const inheritanceInstances = [];
    for (let i = 0; i < objectCount / 2; i++) { // Half as many inheritance instances
        inheritanceInstances.push(new DerivedClass(i, `Derived${i}`, i * 3));
    }
    const inheritanceTime = Date.now() - inheritanceStart;

    // Class with static methods and properties
    class StaticClass {
        static count = 0;
        static instances = [];

        constructor(id, value) {
            this.id = id;
            this.value = value;
            StaticClass.count++;
            StaticClass.instances.push(this);
        }

        static getCount() {
            return StaticClass.count;
        }

        static findById(id) {
            return StaticClass.instances.find(inst => inst.id === id);
        }

        static reset() {
            StaticClass.count = 0;
            StaticClass.instances = [];
        }

        instanceMethod() {
            return this.value + StaticClass.count;
        }
    }

    // Reset static state
    StaticClass.reset();

    const staticStart = Date.now();
    const staticInstances = [];
    for (let i = 0; i < objectCount / 2; i++) {
        staticInstances.push(new StaticClass(i, i * 1.5));
    }
    const staticTime = Date.now() - staticStart;

    // Class with getters and setters
    class AccessorClass {
        constructor(initialValue) {
            this._value = initialValue;
            this._computedCache = null;
        }

        get value() {
            return this._value;
        }

        set value(newValue) {
            this._value = newValue;
            this._computedCache = null; // Invalidate cache
        }

        get computed() {
            if (this._computedCache === null) {
                this._computedCache = this._value * this._value + Math.sqrt(this._value);
            }
            return this._computedCache;
        }

        get description() {
            return `Value: ${this.value}, Computed: ${this.computed.toFixed(2)}`;
        }
    }

    const accessorStart = Date.now();
    const accessorInstances = [];
    for (let i = 0; i < objectCount / 5; i++) { // Fewer accessor instances
        accessorInstances.push(new AccessorClass(i + 1));
    }
    const accessorTime = Date.now() - accessorStart;

    // Class with private fields (simulated)
    class PrivateClass {
        #privateValue;
        #privateCounter = 0;

        constructor(id, value) {
            this.id = id;
            this.#privateValue = value;
        }

        getPrivateValue() {
            return this.#privateValue;
        }

        setPrivateValue(value) {
            this.#privateValue = value;
            this.#privateCounter++;
        }

        getCounter() {
            return this.#privateCounter;
        }

        process() {
            this.#privateCounter++;
            return this.#privateValue * this.#privateCounter;
        }
    }

    const privateStart = Date.now();
    const privateInstances = [];
    for (let i = 0; i < objectCount / 10; i++) { // Even fewer private instances
        privateInstances.push(new PrivateClass(i, i * 2));
    }
    const privateTime = Date.now() - privateStart;

    // Method call benchmarks on created instances
    const methodStart = Date.now();
    let methodSum = 0;
    for (let i = 0; i < Math.min(10000, simpleInstances.length); i++) {
        const instance = simpleInstances[i];
        methodSum += instance.getValue();
        methodSum += instance.multiply(2);
    }
    const methodTime = Date.now() - methodStart;

    // Inheritance method calls
    const inheritanceMethodStart = Date.now();
    let inheritanceMethodSum = 0;
    for (let i = 0; i < Math.min(5000, inheritanceInstances.length); i++) {
        const instance = inheritanceInstances[i];
        inheritanceMethodSum += instance.baseMethod();
        inheritanceMethodSum += instance.derivedMethod();
        inheritanceMethodSum += instance.overriddenMethod();
    }
    const inheritanceMethodTime = Date.now() - inheritanceMethodStart;

    const endTime = Date.now();
    const totalTime = endTime - startTime;

    console.log("Class Instantiation benchmark completed");
    console.log(`Total time: ${totalTime}ms`);
    console.log(`Simple class: ${simpleTime}ms (${objectCount} instances)`);
    console.log(`Complex class: ${complexTime}ms (${objectCount / 10} instances)`);
    console.log(`Inheritance: ${inheritanceTime}ms (${objectCount / 2} instances)`);
    console.log(`Static methods: ${staticTime}ms (${objectCount / 2} instances, final count: ${StaticClass.getCount()})`);
    console.log(`Accessor class: ${accessorTime}ms (${objectCount / 5} instances)`);
    console.log(`Private fields: ${privateTime}ms (${objectCount / 10} instances)`);
    console.log(`Method calls: ${methodTime}ms (${Math.min(10000, simpleInstances.length)} calls)`);
    console.log(`Inheritance methods: ${inheritanceMethodTime}ms (${Math.min(5000, inheritanceInstances.length)} calls)`);
    console.log(`Instance counts: simple=${simpleInstances.length}, complex=${complexInstances.length}, inheritance=${inheritanceInstances.length}, static=${staticInstances.length}, accessor=${accessorInstances.length}, private=${privateInstances.length}`);
    console.log(`Final sums: method=${methodSum}, inheritanceMethod=${inheritanceMethodSum}`);

    return {
        totalTime,
        objectCount,
        operations: {
            simpleClass: objectCount,
            complexClass: objectCount / 10,
            inheritance: objectCount / 2,
            staticMethods: objectCount / 2,
            accessorClass: objectCount / 5,
            privateFields: objectCount / 10,
            methodCalls: Math.min(10000, simpleInstances.length) * 2,
            inheritanceMethods: Math.min(5000, inheritanceInstances.length) * 3
        },
        times: {
            simpleClass: simpleTime,
            complexClass: complexTime,
            inheritance: inheritanceTime,
            staticMethods: staticTime,
            accessorClass: accessorTime,
            privateFields: privateTime,
            methodCalls: methodTime,
            inheritanceMethods: inheritanceMethodTime
        },
        results: {
            simpleCount: simpleInstances.length,
            complexCount: complexInstances.length,
            inheritanceCount: inheritanceInstances.length,
            staticCount: staticInstances.length,
            staticFinalCount: StaticClass.getCount(),
            accessorCount: accessorInstances.length,
            privateCount: privateInstances.length,
            methodSum,
            inheritanceMethodSum
        },
        opsPerSecond: {
            simpleClass: Math.round(objectCount / (simpleTime / 1000)),
            complexClass: Math.round((objectCount / 10) / (complexTime / 1000)),
            inheritance: Math.round((objectCount / 2) / (inheritanceTime / 1000)),
            staticMethods: Math.round((objectCount / 2) / (staticTime / 1000)),
            accessorClass: Math.round((objectCount / 5) / (accessorTime / 1000)),
            privateFields: Math.round((objectCount / 10) / (privateTime / 1000)),
            methodCalls: Math.round((Math.min(10000, simpleInstances.length) * 2) / (methodTime / 1000)),
            inheritanceMethods: Math.round((Math.min(5000, inheritanceInstances.length) * 3) / (inheritanceMethodTime / 1000))
        }
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkClassInstantiation();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkClassInstantiation;
}