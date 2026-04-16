// Real-world program #3: Event Emitter System
// Features: ES2015 classes, Map, closures, spread operator, this binding, arrow functions

class EventEmitter {
    constructor() {
        this.listeners = new Map();
        this.maxListeners = 10;
        this.eventStats = new Map();
    }

    // Add event listener
    on(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error('Listener must be a function');
        }

        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }

        const eventListeners = this.listeners.get(event);

        if (eventListeners.length >= this.maxListeners) {
            console.warn(`Warning: More than ${this.maxListeners} listeners for event '${event}'`);
        }

        eventListeners.push({
            fn: listener,
            once: false,
            context: null,
            id: Math.random().toString(36).substr(2, 9)
        });

        return this;
    }

    // Add one-time event listener
    once(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error('Listener must be a function');
        }

        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }

        const eventListeners = this.listeners.get(event);
        eventListeners.push({
            fn: listener,
            once: true,
            context: null,
            id: Math.random().toString(36).substr(2, 9)
        });

        return this;
    }

    // Remove event listener
    off(event, listener) {
        if (!this.listeners.has(event)) {
            return this;
        }

        const eventListeners = this.listeners.get(event);
        const filteredListeners = eventListeners.filter(wrapper => wrapper.fn !== listener);

        if (filteredListeners.length === 0) {
            this.listeners.delete(event);
        } else {
            this.listeners.set(event, filteredListeners);
        }

        return this;
    }

    // Remove all listeners for event
    removeAllListeners(event) {
        if (event) {
            this.listeners.delete(event);
        } else {
            this.listeners.clear();
        }
        return this;
    }

    // Emit event with data
    emit(event, ...args) {
        // Update stats
        if (!this.eventStats.has(event)) {
            this.eventStats.set(event, { count: 0, lastEmitted: null });
        }

        const stats = this.eventStats.get(event);
        stats.count++;
        stats.lastEmitted = Date.now();

        if (!this.listeners.has(event)) {
            return false;
        }

        const eventListeners = this.listeners.get(event);
        const listenersToRemove = [];

        // Execute all listeners
        for (const wrapper of eventListeners) {
            try {
                // Call listener with provided arguments
                wrapper.fn.apply(wrapper.context, args);

                // Mark once listeners for removal
                if (wrapper.once) {
                    listenersToRemove.push(wrapper);
                }
            } catch (error) {
                console.error(`Error in event listener for '${event}':`, error.message);
            }
        }

        // Remove once listeners
        if (listenersToRemove.length > 0) {
            const remainingListeners = eventListeners.filter(
                wrapper => !listenersToRemove.includes(wrapper)
            );

            if (remainingListeners.length === 0) {
                this.listeners.delete(event);
            } else {
                this.listeners.set(event, remainingListeners);
            }
        }

        return true;
    }

    // Get listener count for event
    listenerCount(event) {
        return this.listeners.has(event) ? this.listeners.get(event).length : 0;
    }

    // Get all events that have listeners
    eventNames() {
        return Array.from(this.listeners.keys());
    }

    // Get event statistics
    getEventStats(event) {
        if (event) {
            return this.eventStats.get(event) || null;
        }
        return Object.fromEntries(this.eventStats);
    }

    // Set maximum listeners per event
    setMaxListeners(max) {
        this.maxListeners = Math.max(1, Math.floor(max));
        return this;
    }

    // Create event listener with context binding
    addListenerWithContext(event, listener, context) {
        if (typeof listener !== 'function') {
            throw new Error('Listener must be a function');
        }

        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }

        const eventListeners = this.listeners.get(event);
        eventListeners.push({
            fn: listener,
            once: false,
            context: context,
            id: Math.random().toString(36).substr(2, 9)
        });

        return this;
    }
}

// Helper class for creating typed events
class TypedEventEmitter extends EventEmitter {
    constructor(eventTypes = []) {
        super();
        this.eventTypes = new Set(eventTypes);
        this.strict = false;
    }

    setStrict(strict) {
        this.strict = strict;
        return this;
    }

    emit(event, ...args) {
        if (this.strict && !this.eventTypes.has(event)) {
            throw new Error(`Unknown event type: ${event}`);
        }
        return super.emit(event, ...args);
    }

    on(event, listener) {
        if (this.strict && !this.eventTypes.has(event)) {
            throw new Error(`Unknown event type: ${event}`);
        }
        return super.on(event, listener);
    }
}

// Test the event emitter system
function testEventEmitter() {
    console.log('Testing Event Emitter System...');

    const emitter = new EventEmitter();
    const results = [];

    // Test basic event emission
    let basicCounter = 0;
    emitter.on('test', (data) => {
        basicCounter++;
        console.log('Basic event received:', data);
        results.push({ type: 'basic', data, counter: basicCounter });
    });

    emitter.emit('test', 'hello world');
    emitter.emit('test', { message: 'object data', value: 42 });

    // Test once listeners
    let onceCounter = 0;
    emitter.once('onceEvent', (value) => {
        onceCounter++;
        console.log('Once event received:', value);
        results.push({ type: 'once', value, counter: onceCounter });
    });

    emitter.emit('onceEvent', 'first call');
    emitter.emit('onceEvent', 'second call'); // Should not trigger

    // Test multiple listeners on same event
    const multiListeners = [];
    for (let i = 0; i < 3; i++) {
        emitter.on('multiEvent', ((index) => {
            return (data) => {
                multiListeners.push({ index, data });
                console.log(`Listener ${index} received:`, data);
            };
        })(i));
    }

    emitter.emit('multiEvent', 'broadcast message');

    // Test context binding
    const contextObj = {
        name: 'TestContext',
        value: 100,
        handler: function(multiplier) {
            console.log(`${this.name}: ${this.value * multiplier}`);
            results.push({
                type: 'context',
                name: this.name,
                result: this.value * multiplier
            });
        }
    };

    emitter.addListenerWithContext('contextEvent', contextObj.handler, contextObj);
    emitter.emit('contextEvent', 2);

    // Test listener removal
    const tempListener = (data) => {
        console.log('Temporary listener:', data);
    };

    emitter.on('tempEvent', tempListener);
    emitter.emit('tempEvent', 'before removal');

    emitter.off('tempEvent', tempListener);
    emitter.emit('tempEvent', 'after removal'); // Should not trigger

    // Test error handling
    emitter.on('errorEvent', () => {
        throw new Error('Listener error');
    });

    emitter.on('errorEvent', (data) => {
        console.log('This listener should still work despite the error above');
        results.push({ type: 'errorTest', data });
    });

    emitter.emit('errorEvent', 'error test data');

    // Test typed event emitter
    const typedEmitter = new TypedEventEmitter(['user:login', 'user:logout', 'data:update']);

    typedEmitter.on('user:login', (user) => {
        console.log('User logged in:', user);
        results.push({ type: 'typed', event: 'user:login', user });
    });

    typedEmitter.emit('user:login', { id: 1, name: 'Alice' });

    // Get final statistics
    const stats = {
        totalEvents: emitter.eventNames().length,
        eventNames: emitter.eventNames(),
        listenerCounts: {},
        eventStats: emitter.getEventStats()
    };

    for (const eventName of emitter.eventNames()) {
        stats.listenerCounts[eventName] = emitter.listenerCount(eventName);
    }

    return {
        basicCounter,
        onceCounter,
        multiListeners: multiListeners.length,
        results,
        stats
    };
}

// Execute the test
const result = testEventEmitter();
console.log('\nFinal result:', JSON.stringify(result, null, 2));

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = { EventEmitter, TypedEventEmitter };
}