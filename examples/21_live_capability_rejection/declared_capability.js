// Example with properly declared capability (conceptual)
// This demonstrates what SHOULD work when capabilities are properly granted

console.log("Pure computation works fine:");
console.log("Math operations: 40 + 2 =", 40 + 2);
console.log("String operations:", "capability".toUpperCase());
// Use Array.from because direct array-literal `.map` is not yet statically
// recognized as an engine-owned finite method in the IFC layer.
console.log("Array operations:", Array.from([1, 2, 3], x => x * 2));