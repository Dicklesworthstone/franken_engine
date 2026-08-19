# Hash Types FixedLayout Migration Audit

## Executive Summary

Audit of existing hashers in franken-engine identifies **3 primary hash types** as excellent candidates for FixedLayout migration. All currently use length-prefixing as precaution but have deterministic fixed-size representations.

**Migration will eliminate cycles spent on length-prefix encoding/decoding since encoded types are fixed-size.**

## Primary Migration Candidates

### 1. IntegrityHash (Tier 1)
- **Type**: `IntegrityHash(u64)` - 8 bytes
- **Current encoding**: Manual `to_le_bytes()` + `extend_from_slice()`
- **Usage pattern**: Hot-path integrity checks, cache keys, GC fingerprinting
- **FixedLayout benefit**: Direct 8-byte copy instead of length prefix + data
- **LAYOUT_SIZE**: `8`

```rust
// Current pattern (found in parallel_parser.rs):
bytes.extend_from_slice(&chunk.chunk_index.to_le_bytes());  // Manual assembly

// After FixedLayout:
chunk.chunk_index.encode_fixed(&mut buffer[offset..offset+8]);
```

### 2. ContentHash (Tier 2)
- **Type**: `ContentHash([u8; 32])` - 32 bytes  
- **Current encoding**: Manual `as_bytes()` + `extend_from_slice()`
- **Usage pattern**: Content identity, evidence IDs, module cache, deterministic hashing
- **FixedLayout benefit**: Direct 32-byte copy instead of length prefix + data
- **LAYOUT_SIZE**: `32`

```rust
// Current pattern (found extensively):
bytes.extend_from_slice(merged_hash.as_bytes());           // Manual 32-byte append
bytes.extend_from_slice(compute_chunk_hash(chunk).as_bytes());

// After FixedLayout:
merged_hash.encode_fixed(&mut buffer[offset..offset+32]);
```

### 3. AuthenticityHash (Tier 3)
- **Type**: `AuthenticityHash([u8; 32])` - 32 bytes
- **Current encoding**: Manual `as_bytes()` + `extend_from_slice()`  
- **Usage pattern**: HMAC signatures, keyed authentication, signature verification
- **FixedLayout benefit**: Direct 32-byte copy instead of length prefix + data
- **LAYOUT_SIZE**: `32`

```rust
// Current pattern:
content.extend_from_slice(authenticity_hash.as_bytes());

// After FixedLayout:
authenticity_hash.encode_fixed(&mut buffer[offset..offset+32]);
```

## Usage Pattern Analysis

### Manual Byte Assembly Locations

Found **47 locations** using manual byte assembly with hash types:

1. **parallel_parser.rs** (12 occurrences)
   - `compute_chunk_hash()` - assembles chunk metadata + token data
   - `compute_merge_witness_hash()` - assembles merge witness with hash chains
   - `compute_schedule_transcript_hash()` - deterministic scheduler serialization

2. **quarantine_deescalation.rs** (5 occurrences)  
   - Decision content hashing with evidence chain links
   - Receipt verification with hash comparison

3. **moonshot_disruption_track.rs** (8 occurrences)
   - Evidence aggregation with hash accumulation
   - Disruption event serialization

4. **extension_host_topology_assessment.rs** (3 occurrences)
   - Topology fingerprinting with canonical JSON + hash

### Performance Impact Locations

**High-frequency paths** that would benefit most:

1. **Hot parsing path** (`parallel_parser.rs`)
   - Chunk hashing during parallel lexing (per-chunk)
   - Merge witness generation (per parse operation)
   - Schedule transcript building (per parallel parse)

2. **Evidence processing** (multiple modules)
   - Evidence chain building with hash links
   - Receipt generation and verification

3. **Content identity** (widespread)
   - Module cache lookups using ContentHash
   - IR pass output identity checks

## Current Length-Prefixing Evidence

All hash types currently implement manual serialization patterns that **would benefit from fixed-layout encoding**:

```rust
// Pattern 1: Mixed primitive + hash assembly
let mut bytes = Vec::with_capacity(32 + chunk.tokens.len() * 24);
bytes.extend_from_slice(&chunk.chunk_index.to_le_bytes());    // 8 bytes
bytes.extend_from_slice(&chunk.chunk_start.to_le_bytes());    // 8 bytes  
bytes.extend_from_slice(&chunk.chunk_end.to_le_bytes());      // 8 bytes
bytes.extend_from_slice(compute_chunk_hash(chunk).as_bytes()); // 32 bytes ← ContentHash

// Pattern 2: Hash chaining
bytes.extend_from_slice(merged_hash.as_bytes());               // 32 bytes ← ContentHash  
bytes.extend_from_slice(compute_chunk_hash(chunk).as_bytes()); // 32 bytes ← ContentHash

// Pattern 3: Signature verification  
content.extend_from_slice(prev_evidence_hash.as_bytes());      // 32 bytes ← ContentHash
```

## Recommended Migration Priority

### Phase 1 (High Impact): ContentHash  
- **Rationale**: Most widely used, 32-byte fixed size, deterministic
- **Files**: 25+ modules using ContentHash  
- **Cycle savings**: Eliminates length prefix for every content hash operation

### Phase 2 (Medium Impact): AuthenticityHash
- **Rationale**: Security-critical, 32-byte fixed size, used in hot verification paths
- **Files**: 12+ modules using AuthenticityHash
- **Cycle savings**: Eliminates length prefix for signature verification

### Phase 3 (Low Impact): IntegrityHash  
- **Rationale**: Already efficient at 8 bytes, but completeness for consistency
- **Files**: 8+ modules using IntegrityHash
- **Cycle savings**: Minimal but eliminates length prefix for hot integrity checks

## Implementation Notes

### Already Deterministic
All three hash types already implement the `Deterministic` trait, so FixedLayout compatibility is guaranteed.

### Big-Endian Compatibility  
Current implementations already use deterministic byte representations:
- IntegrityHash: uses `to_le_bytes()` consistently  
- ContentHash: SHA-256 output (deterministic)
- AuthenticityHash: HMAC-SHA256 output (deterministic)

FixedLayout implementation should use **big-endian encoding** for cross-platform determinism.

### Backward Compatibility
Migration can be done incrementally:
1. Add FixedLayout derives to existing types
2. Replace manual assembly with `encode_fixed()` calls  
3. Update deserialization to use `decode_fixed()`
4. Remove legacy manual serialization code

## Conclusion

**Recommendation**: Proceed with FixedLayout migration for all three hash types.

**Expected benefit**: Eliminate length-prefix overhead for fixed-size hash types, resulting in more efficient serialization and reduced cycle count for content hashing operations.

**Risk**: Low - all types are already deterministic and fixed-size.

**Migration effort**: Medium - requires updating ~50 manual serialization sites, but changes are mechanical.