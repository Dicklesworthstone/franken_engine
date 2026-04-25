# Certified Rewrite Demo: Proof-Carrying Optimization

**Impossible-by-Default Security Property #5**

This demo showcases FrankenEngine's proof-carrying adaptive optimization with translation validation and auto-rollback - a capability that is fundamentally **impossible by default** in V8/Node.js and other incumbent JavaScript runtimes.

## What This Demo Shows

The demo takes a simple JavaScript function with an optimization opportunity:
```javascript
function compute(x) { return (2 * 3) + x; }
```

And demonstrates the complete certified optimization pipeline:
1. **Parse & Lower**: Generate intermediate representation (IR)
2. **Optimize**: Apply constant folding (2 * 3 → 6) 
3. **Validate**: Generate formal equivalence proof
4. **Certify**: Create cryptographic governance certificate
5. **Monitor**: Enable automatic rollback if performance degrades

## Why This Is Impossible in V8/Node.js

### V8's Fundamental Design Problem

**V8 optimizes without proof of correctness:**

- **TurboFan compiler**: Applies hundreds of optimization passes with zero formal verification
- **Speculative optimization**: Makes aggressive assumptions based on runtime feedback with no mathematical guarantees  
- **Trust-based approach**: Relies entirely on compiler testing, not formal methods
- **No equivalence checking**: When optimizations introduce bugs (they do - see CVE database), there's no systematic detection

### Real-World Consequences

V8 optimization bugs have caused:
- Memory corruption vulnerabilities
- Type confusion exploits  
- Silent correctness violations
- Unpredictable performance cliffs

**Example**: When V8's constant folding has bugs, your `2 * 3` might not equal `6` under certain edge conditions. There's no proof it will work correctly.

### Why V8 Can't Add This Capability

1. **Performance Requirements**: V8 prioritizes compilation speed over verification. Adding translation validation would slow optimization by orders of magnitude.

2. **Legacy Compatibility**: Billions of lines of JavaScript code depend on V8's current (unverified) optimization behavior. Formal verification might expose semantic differences.

3. **Architectural Constraints**: V8 has no SAT solver integration, no theorem proving infrastructure, and no formal semantics for JavaScript.

4. **Optimization Complexity**: V8's optimization pipeline is too complex and underdefined to retrofit with mathematical verification.

## FrankenEngine's Approach

**Every optimization requires a mathematical proof:**

- **Translation validation**: Formal proof that optimized code is semantically equivalent
- **Cryptographic receipts**: All optimizations are signed and independently verifiable
- **Automatic rollback**: Performance regressions trigger immediate revert to proven-safe code
- **Audit trail**: Complete provenance of every optimization decision

This is **impossible to retrofit** into existing runtimes - it requires fundamental architectural changes from the ground up.

## Demo Files

- `demo.sh`: Interactive demonstration of the certified optimization process
- `sample_proof_artifact.json`: Example proof artifact with before/after IR + translation validation evidence  
- `verify.sh`: Script that validates the proof artifact and asserts proof_status=valid

## Running the Demo

```bash
./demo.sh
./verify.sh
```

The demo proves that FrankenEngine can provide mathematical guarantees about optimization correctness - something that would require complete architectural redesign of incumbent JavaScript runtimes.