// Real-world program #1: Linked List with Iterator Protocol
// Features: ES2015 classes, Symbol.iterator, generators, for..of loops

class ListNode {
    constructor(value, next = null) {
        this.value = value;
        this.next = next;
    }
}

class LinkedList {
    constructor() {
        this.head = null;
        this.size = 0;
    }

    // Add element to the beginning
    prepend(value) {
        this.head = new ListNode(value, this.head);
        this.size++;
        return this;
    }

    // Add element to the end
    append(value) {
        if (!this.head) {
            return this.prepend(value);
        }

        let current = this.head;
        while (current.next) {
            current = current.next;
        }

        current.next = new ListNode(value);
        this.size++;
        return this;
    }

    // Remove first occurrence of value
    remove(value) {
        if (!this.head) return false;

        if (this.head.value === value) {
            this.head = this.head.next;
            this.size--;
            return true;
        }

        let current = this.head;
        while (current.next && current.next.value !== value) {
            current = current.next;
        }

        if (current.next) {
            current.next = current.next.next;
            this.size--;
            return true;
        }

        return false;
    }

    // Find element
    find(value) {
        let current = this.head;
        let index = 0;

        while (current) {
            if (current.value === value) {
                return { value: current.value, index };
            }
            current = current.next;
            index++;
        }

        return null;
    }

    // Convert to array
    toArray() {
        const result = [];
        let current = this.head;

        while (current) {
            result.push(current.value);
            current = current.next;
        }

        return result;
    }

    // Iterator protocol implementation
    *[Symbol.iterator]() {
        let current = this.head;

        while (current) {
            yield current.value;
            current = current.next;
        }
    }

    // Generator-based reverse iteration
    *reverse() {
        const values = this.toArray();
        for (let i = values.length - 1; i >= 0; i--) {
            yield values[i];
        }
    }

    // Filter with generator
    *filter(predicate) {
        for (const value of this) {
            if (predicate(value)) {
                yield value;
            }
        }
    }

    // Map with generator
    *map(transform) {
        for (const value of this) {
            yield transform(value);
        }
    }

    // String representation
    toString() {
        return '[' + this.toArray().join(' -> ') + ']';
    }
}

// Test the linked list implementation
function testLinkedList() {
    console.log('Testing LinkedList implementation...');

    const list = new LinkedList();

    // Test append and prepend
    list.append(1).append(2).append(3);
    list.prepend(0);

    console.log('List after operations:', list.toString());
    console.log('Size:', list.size);

    // Test iteration with for..of
    console.log('Iterating with for..of:');
    for (const value of list) {
        console.log('  Value:', value);
    }

    // Test find
    const found = list.find(2);
    console.log('Find 2:', found);

    // Test filter with generator
    console.log('Even numbers:');
    for (const even of list.filter(x => x % 2 === 0)) {
        console.log('  Even:', even);
    }

    // Test map with generator
    console.log('Squared values:');
    for (const squared of list.map(x => x * x)) {
        console.log('  Squared:', squared);
    }

    // Test reverse iteration
    console.log('Reverse iteration:');
    for (const value of list.reverse()) {
        console.log('  Reverse:', value);
    }

    // Test remove
    const removed = list.remove(2);
    console.log('Removed 2:', removed);
    console.log('List after removal:', list.toString());

    return {
        size: list.size,
        array: list.toArray(),
        hasIterator: typeof list[Symbol.iterator] === 'function'
    };
}

// Execute the test
const result = testLinkedList();
console.log('Final result:', JSON.stringify(result));

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = { LinkedList, ListNode };
}