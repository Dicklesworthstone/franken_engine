export const offset = 40;
export function add(value) { return value + offset; }
export function apply(callback, value) { return callback(value) + 1; }
export function fail() { throw 17; }
export function makeCounter() {
    let count = 0;
    return function () { count += 1; return count; };
}
export class Counter {
    constructor(value) { this.value = value; }
    next() { this.value += 1; return this.value; }
}
export function* values(start) {
    yield start;
    yield add(start);
    return 99;
}
export async function resolved(value) { return add(value); }
