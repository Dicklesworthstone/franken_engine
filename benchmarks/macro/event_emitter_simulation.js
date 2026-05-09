// Macro-Benchmark 5: Event Emitter Simulation
// Tests event-driven programming, callback management, and asynchronous patterns

class EventEmitter {
    constructor() {
        this.events = new Map();
        this.maxListeners = 10;
        this.listenerCount = 0;
        this.metadata = {
            created: Date.now(),
            eventsEmitted: 0,
            listenersAdded: 0,
            listenersRemoved: 0
        };
    }

    on(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error('Listener must be a function');
        }

        if (!this.events.has(event)) {
            this.events.set(event, []);
        }

        const listeners = this.events.get(event);
        if (listeners.length >= this.maxListeners) {
            console.warn(`MaxListenersExceeded: Event '${event}' has ${listeners.length} listeners`);
        }

        listeners.push({
            callback: listener,
            once: false,
            addedAt: Date.now(),
            callCount: 0
        });

        this.listenerCount++;
        this.metadata.listenersAdded++;
        return this;
    }

    once(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error('Listener must be a function');
        }

        if (!this.events.has(event)) {
            this.events.set(event, []);
        }

        this.events.get(event).push({
            callback: listener,
            once: true,
            addedAt: Date.now(),
            callCount: 0
        });

        this.listenerCount++;
        this.metadata.listenersAdded++;
        return this;
    }

    off(event, listener) {
        if (!this.events.has(event)) return this;

        const listeners = this.events.get(event);
        const index = listeners.findIndex(l => l.callback === listener);

        if (index !== -1) {
            listeners.splice(index, 1);
            this.listenerCount--;
            this.metadata.listenersRemoved++;

            if (listeners.length === 0) {
                this.events.delete(event);
            }
        }

        return this;
    }

    emit(event, ...args) {
        this.metadata.eventsEmitted++;

        if (!this.events.has(event)) {
            return false;
        }

        const listeners = this.events.get(event);
        const toRemove = [];

        // Call all listeners
        for (let i = 0; i < listeners.length; i++) {
            const listener = listeners[i];
            try {
                listener.callCount++;
                listener.callback.apply(this, args);

                if (listener.once) {
                    toRemove.push(i);
                }
            } catch (error) {
                // In a real implementation, this would emit an 'error' event
                console.error(`Error in event listener for '${event}':`, error.message);
            }
        }

        // Remove 'once' listeners (in reverse order to maintain indices)
        for (let i = toRemove.length - 1; i >= 0; i--) {
            listeners.splice(toRemove[i], 1);
            this.listenerCount--;
            this.metadata.listenersRemoved++;
        }

        if (listeners.length === 0) {
            this.events.delete(event);
        }

        return true;
    }

    listenerCount(event) {
        if (event) {
            return this.events.has(event) ? this.events.get(event).length : 0;
        }
        return this.listenerCount;
    }

    eventNames() {
        return Array.from(this.events.keys());
    }

    removeAllListeners(event) {
        if (event) {
            if (this.events.has(event)) {
                const count = this.events.get(event).length;
                this.events.delete(event);
                this.listenerCount -= count;
                this.metadata.listenersRemoved += count;
            }
        } else {
            const totalCount = this.listenerCount;
            this.events.clear();
            this.listenerCount = 0;
            this.metadata.listenersRemoved += totalCount;
        }
        return this;
    }

    setMaxListeners(n) {
        this.maxListeners = n;
        return this;
    }
}

class AsyncEventProcessor {
    constructor() {
        this.pendingTasks = [];
        this.completedTasks = [];
        this.errorCount = 0;
        this.processingTime = 0;
    }

    async processEvent(eventName, data, delay = 0) {
        const startTime = Date.now();
        const task = {
            id: Math.floor(Math.random() * 1000000),
            event: eventName,
            data: data,
            startTime: startTime,
            status: 'pending'
        };

        this.pendingTasks.push(task);

        try {
            // Simulate async processing
            if (delay > 0) {
                await this.delay(delay);
            }

            // Simulate some computational work
            let result = 0;
            for (let i = 0; i < 1000; i++) {
                result += Math.sqrt(i * data.value || i);
            }

            task.status = 'completed';
            task.endTime = Date.now();
            task.duration = task.endTime - task.startTime;
            task.result = result;

            this.completedTasks.push(task);
            this.processingTime += task.duration;

            return task;
        } catch (error) {
            task.status = 'error';
            task.error = error.message;
            task.endTime = Date.now();
            task.duration = task.endTime - task.startTime;
            this.errorCount++;
            throw error;
        } finally {
            const index = this.pendingTasks.findIndex(t => t.id === task.id);
            if (index !== -1) {
                this.pendingTasks.splice(index, 1);
            }
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getStats() {
        return {
            pendingTasks: this.pendingTasks.length,
            completedTasks: this.completedTasks.length,
            errorCount: this.errorCount,
            avgProcessingTime: this.completedTasks.length > 0
                ? this.processingTime / this.completedTasks.length
                : 0
        };
    }
}

function simulateComplexEventFlow() {
    const emitters = [];
    const processors = [];
    const eventCounts = {};
    const results = [];

    // Create multiple event emitters
    for (let i = 0; i < 5; i++) {
        const emitter = new EventEmitter();
        const processor = new AsyncEventProcessor();

        emitters.push(emitter);
        processors.push(processor);

        // Setup various event listeners
        emitter.on('data', async (data) => {
            try {
                const task = await processor.processEvent('data', data, Math.random() * 10);
                results.push({ emitter: i, task: task });
            } catch (error) {
                results.push({ emitter: i, error: error.message });
            }
        });

        emitter.on('compute', (input) => {
            eventCounts['compute'] = (eventCounts['compute'] || 0) + 1;

            // CPU-intensive computation
            let result = input.seed || 1;
            for (let j = 0; j < 10000; j++) {
                result = (result * 1.1 + j) % 1000000;
            }

            emitter.emit('computed', { original: input, result: result });
        });

        emitter.on('computed', (data) => {
            eventCounts['computed'] = (eventCounts['computed'] || 0) + 1;
        });

        emitter.once('init', () => {
            eventCounts['init'] = (eventCounts['init'] || 0) + 1;
        });

        // Error handling
        emitter.on('error', (error) => {
            eventCounts['error'] = (eventCounts['error'] || 0) + 1;
            console.error(`Emitter ${i} error:`, error);
        });
    }

    return { emitters, processors, eventCounts, results };
}

function benchmarkEventEmitterSimulation() {
    console.log("Starting Event Emitter Simulation benchmark...");
    const startTime = Date.now();

    // Step 1: Setup complex event flow
    console.log("Step 1: Setting up event emitters...");
    const { emitters, processors, eventCounts, results } = simulateComplexEventFlow();

    // Step 2: Generate events across all emitters
    console.log("Step 2: Generating events...");
    const eventGenerationStart = Date.now();

    for (let round = 0; round < 100; round++) {
        for (let i = 0; i < emitters.length; i++) {
            const emitter = emitters[i];

            // Emit init events (once each)
            if (round === 0) {
                emitter.emit('init', { emitter: i, round: round });
            }

            // Emit data events
            emitter.emit('data', {
                emitter: i,
                round: round,
                value: Math.floor(Math.random() * 1000),
                timestamp: Date.now()
            });

            // Emit compute events
            emitter.emit('compute', {
                seed: round * i + 1,
                complexity: round % 10
            });

            // Occasionally emit errors
            if (Math.random() < 0.05) {
                emitter.emit('error', new Error(`Simulated error in emitter ${i}, round ${round}`));
            }
        }
    }

    const eventGenerationTime = Date.now() - eventGenerationStart;

    // Step 3: Event listener management stress test
    console.log("Step 3: Event listener management...");
    const listenerManagementStart = Date.now();

    const managementEmitter = new EventEmitter();
    const dynamicListeners = [];

    // Add many listeners dynamically
    for (let i = 0; i < 1000; i++) {
        const listener = (data) => {
            return data.value * i;
        };

        if (i % 3 === 0) {
            managementEmitter.once(`dynamic_${i % 10}`, listener);
        } else {
            managementEmitter.on(`dynamic_${i % 10}`, listener);
        }

        dynamicListeners.push(listener);
    }

    // Emit events to trigger listeners
    for (let i = 0; i < 10; i++) {
        managementEmitter.emit(`dynamic_${i}`, { value: i * 10 });
    }

    // Remove half the listeners
    for (let i = 0; i < dynamicListeners.length; i += 2) {
        managementEmitter.off(`dynamic_${i % 10}`, dynamicListeners[i]);
    }

    // Emit again to test removal
    for (let i = 0; i < 10; i++) {
        managementEmitter.emit(`dynamic_${i}`, { value: i * 20 });
    }

    // Clear all listeners
    managementEmitter.removeAllListeners();

    const listenerManagementTime = Date.now() - listenerManagementStart;

    // Step 4: Memory and performance stress test
    console.log("Step 4: Memory stress test...");
    const memoryTestStart = Date.now();

    const stressEmitter = new EventEmitter();
    const stressResults = [];

    // Create many short-lived event/listener cycles
    for (let cycle = 0; cycle < 1000; cycle++) {
        const eventName = `stress_${cycle % 50}`;

        const listener = (data) => {
            stressResults.push({
                cycle: cycle,
                eventName: eventName,
                data: data,
                processedAt: Date.now()
            });
        };

        stressEmitter.on(eventName, listener);
        stressEmitter.emit(eventName, { cycle: cycle, random: Math.random() });

        // Occasionally clean up to test memory management
        if (cycle % 100 === 0) {
            stressEmitter.removeAllListeners(eventName);
        }
    }

    const memoryTestTime = Date.now() - memoryTestStart;

    // Step 5: Collect final statistics
    console.log("Step 5: Collecting statistics...");

    const totalEvents = Object.values(eventCounts).reduce((sum, count) => sum + count, 0);
    const processorStats = processors.map(p => p.getStats());

    const overallStats = {
        totalEventEmitters: emitters.length,
        totalEventsEmitted: totalEvents,
        eventBreakdown: eventCounts,
        asyncTasksCompleted: processorStats.reduce((sum, stats) => sum + stats.completedTasks, 0),
        asyncTaskErrors: processorStats.reduce((sum, stats) => sum + stats.errorCount, 0),
        avgAsyncProcessingTime: processorStats.reduce((sum, stats) => sum + stats.avgProcessingTime, 0) / processorStats.length,
        dynamicListenerOperations: 1000 + 500, // add + remove
        stressTestCycles: 1000,
        memoryStressResults: stressResults.length
    };

    const endTime = Date.now();
    const duration = endTime - startTime;

    console.log("Event Emitter Simulation benchmark completed");
    console.log(`Total duration: ${duration}ms`);
    console.log(`Event generation: ${eventGenerationTime}ms`);
    console.log(`Listener management: ${listenerManagementTime}ms`);
    console.log(`Memory stress test: ${memoryTestTime}ms`);
    console.log(`Total events emitted: ${totalEvents}`);
    console.log(`Async tasks completed: ${overallStats.asyncTasksCompleted}`);
    console.log(`Async task errors: ${overallStats.asyncTaskErrors}`);
    console.log(`Dynamic listener operations: ${overallStats.dynamicListenerOperations}`);
    console.log(`Memory stress cycles: ${overallStats.stressTestCycles}`);

    return {
        duration,
        operations: {
            eventEmitterCreation: emitters.length,
            eventEmission: totalEvents,
            listenerRegistration: overallStats.dynamicListenerOperations,
            asyncTaskProcessing: overallStats.asyncTasksCompleted,
            listenerRemoval: 500,
            memoryStressCycles: 1000
        },
        performance: {
            eventGenerationTime,
            listenerManagementTime,
            memoryTestTime,
            avgAsyncProcessingTime: Math.round(overallStats.avgAsyncProcessingTime * 100) / 100
        },
        results: overallStats
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkEventEmitterSimulation();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkEventEmitterSimulation;
}
