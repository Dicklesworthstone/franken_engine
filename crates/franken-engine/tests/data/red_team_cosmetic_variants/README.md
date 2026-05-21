# Red Team Cosmetic Variants Test Fixtures

## Purpose
Test fixtures for red team attack detection that contain cosmetic variants that should NOT be counted as novel attacks. Referenced by:
- U.5 negative test (refuse to count cosmetic-variant attacks as novel)

## Contents
- `variant_001_variable_rename.js`: Same attack with different variable names
- `variant_002_whitespace_change.js`: Same attack with different whitespace/formatting
- `variant_003_comment_insertion.js`: Same attack with added comments
- `variant_004_equivalent_syntax.js`: Same attack using equivalent syntax forms
- `variant_005_string_encoding.js`: Same attack with different string encoding

## Generation
These variants are hand-crafted examples of the same underlying attack vector with cosmetic differences.
The red team system should recognize these as the same attack, not count them as separate novel attacks.

## Attack Pattern
All variants implement the same basic privilege escalation attack:
1. Extension requests compute-only capability
2. Extension attempts to access hidden hostcall interface
3. Extension tries to escalate to filesystem write capability

The cosmetic differences should not fool the detection system into thinking these are different attacks.

## Validation
Content hashes are recorded in `fixture_manifest.json`.
The attack detection system must classify all variants as the same attack family.

## Testing Strategy
Load all variants and verify:
1. They are all recognized as attacks (not false negatives)
2. They are all classified as the same attack family
3. Only ONE novel attack is recorded, not five