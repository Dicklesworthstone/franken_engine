# Revocation-First Execution Gates with Degraded-Mode Policy Proofs

**Impossible-by-Default Security Property #8**

This example demonstrates FrankenEngine's revocation-first execution gates - a security capability that is impossible to achieve safely in incumbent JavaScript runtimes.

## The Problem with Incumbent Runtimes

### Node.js, Deno, and Browser Revocation Gaps

Current JavaScript execution environments have fundamental architectural limitations that make revocation-first security impossible:

1. **No Cryptographic Revocation Integration**: When a package or extension is discovered to be compromised, there's no built-in mechanism to cryptographically revoke execution privileges across all instances.

2. **Graceful Degradation Anti-Pattern**: Incumbent runtimes default to "graceful degradation" - if security checks fail, they often fallback to reduced functionality rather than fail-closed. This creates attack surface.

3. **Post-Install Revocation Blindness**: Once code is installed locally, most runtimes have no mechanism to receive and enforce revocation decisions from upstream trust authorities.

4. **Capability Escalation via Error Paths**: When security enforcement fails, error handling paths often preserve dangerous capabilities rather than revoking them.

### Why This Matters

Consider a supply chain compromise scenario:
- Malicious code is discovered in a widely-used utility library
- Security teams issue revocation notices
- **Incumbent behavior**: Existing instances continue running with degraded features
- **Attack vector**: Malicious code exploits "degraded mode" to escalate privileges

## FrankenEngine's Revocation-First Approach

### Cryptographic Policy Proofs

FrankenEngine requires explicit cryptographic proof for any execution decision post-revocation:

```json
{
  "policy_decision": "fail-closed",
  "degraded_mode_proof": {
    "signature_hex": "a7b9c8d2e3f456789...",
    "denied_capabilities": ["read", "write", "exec"],
    "explanation": "Extension revoked due to supply chain compromise"
  }
}
```

### Key Security Properties

1. **No Silent Degradation**: Revoked extensions cannot silently continue with reduced capabilities
2. **Cryptographic Enforcement**: Every post-revocation decision requires valid cryptographic proof
3. **Capability Revocation**: Specific capabilities (read, write, exec) are explicitly denied and cannot be recovered
4. **Audit Trail**: Every revocation decision is logged with explanation and proof signature

### Impossible in Incumbent Runtimes

This approach is architecturally impossible in existing runtimes because:

- **No Trust Chain Integration**: They lack built-in PKI integration for code provenance
- **Runtime Modification Resistance**: Core security checks cannot be updated without full runtime restart
- **Capability Model Absence**: No fine-grained capability system to selectively revoke permissions
- **Backwards Compatibility Constraints**: Cannot break existing deployment patterns

## Demo Files

- `before_revocation.json`: Normal execution state with valid trust chain
- `after_revocation.json`: Post-revocation state with fail-closed policy and cryptographic proof  
- `demo.sh`: Simple demonstration of the state transition
- `verify.sh`: Validation script ensuring proper fail-closed enforcement

## Verification

Run `./verify.sh` to confirm:
- Policy decision is strictly "fail-closed" (not "degraded" or "limited")
- Degraded mode proof contains valid signature format
- All dangerous capabilities are explicitly denied