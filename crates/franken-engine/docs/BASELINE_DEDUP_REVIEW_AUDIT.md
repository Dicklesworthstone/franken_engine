# Baseline Dedup Review Audit

Date: 2026-04-20
Reviewer: VioletSwan
Scope: `crates/franken-engine/src/baseline_interpreter.rs` dedup chain for commits `2f84f9a9`, `574ab531`, `46cf7513`, `1e41dc42`, `dc384af8`, `37b832b8`, `0637d3ac`, `985aa545`, `89a3077d`, `06ab43b2`, and `b6d98f01`.

## Summary

The reviewed builtin ID map still routes the audited IDs to the expected capability strings, but several capability strings still have multiple match arms in `dispatch_builtin_hostcall`. In Rust match order, only the first arm for a duplicated string literal is reachable. The later arms are therefore dead dispatch paths even when recent commit messages claim deduplication.

Memory ownership risk is low for the audited string paths: the file uses safe Rust, no raw string ownership APIs, and no leak primitives were found in non-test code. The remaining risk is semantic drift, not double-free or leaked `String` allocations.

## Unreachable Dedup Arms

| Capability | Current arms | Impact |
| --- | ---: | --- |
| `builtin:StringPrototypeSubstring` | `7934`, `16314` | IDs `32` and `345` both route to the first arm; the later byte-length/char-iteration variant is unreachable. |
| `builtin:ArrayPrototypeReduce` | `9312`, `13020`, `16364` | IDs `27`, `241`, and `346` all route to the first arm; two later reduce implementations are unreachable. |
| `builtin:NumberPrototypeToString` | `11323`, `16291` | IDs `196` and `343` route to the first arm; the later copy is unreachable even though it currently uses the same helper path. |
| `builtin:StringPrototypeToLowerCase` | `8088`, `14606`, `16068` | IDs `34`, `293`, and `330` route to the first arm; two later copies are unreachable. |
| `builtin:StringPrototypeToUpperCase` | `8101`, `14700`, `16076` | IDs `35`, `297`, and `331` route to the first arm; two later copies are unreachable. |
| `builtin:ArrayPrototypeFind` | `9033`, `12570`, `16794` | IDs `25`, `225`, and `367` route to the first arm; later simplified callback variants are unreachable. |
| `builtin:ArrayPrototypeFindIndex` | `10893`, `13764`, `16834` | IDs `183`, `271`, and `368` route to the first arm; later simplified callback variants are unreachable. |

The commits `0637d3ac` and `89a3077d` do not modify `crates/franken-engine/src/baseline_interpreter.rs` in this repository, despite commit subjects referencing `ArrayPrototypeSort` and `Array.prototype.find/findIndex` deduplication.

## Cleared Dedup Checks

The following reviewed capabilities currently have a single dispatch arm and their known duplicate IDs map to that single capability string:

| Capability | IDs reviewed | Current arm |
| --- | --- | ---: |
| `builtin:StringPrototypeSplit` | `36`, `356` | `16455` |
| `builtin:MathCeil` | `51`, `354` | `8156` |
| `builtin:MathFloor` | `52`, `353` | `8177` |
| `builtin:MathRound` | `53`, `355` | `8198` |
| `builtin:MathLog` | `61`, `388` | `9187` |
| `builtin:StringPrototypeReplace` | `41`, `235`, `360` | `9128` |
| `builtin:ArrayPrototypeMap` | `23`, `237`, `357` | `16541` |
| `builtin:MathSqrt` | `58`, `358` | `8867` |
| `builtin:MathPow` | `57`, `240`, `359` | `8719` |
| `builtin:MathRandom` | `56`, `361` | `8326` |
| `builtin:ArrayPrototypeSort` | `28`, `248`, `385` | `9466` |
| `builtin:ArrayPrototypeEvery` | `204`, `255`, `341` | `16252` |
| `builtin:ArrayPrototypeSome` | `203`, `259`, `340` | `10116` |
| `builtin:EncodeURIComponent` | `373` | `16914` |
| `builtin:DecodeURIComponent` | `374` | `16927` |
| `builtin:ConsoleInfo` | `384` | `17203` |

## Builtin ID Routing

The map function still maps audited IDs to the intended capability names. The dispatch risk is not an ID-map failure; it is that duplicated match arms hide later implementations behind the first matching string literal.

Priority for follow-up cleanup:

1. Remove or consolidate the unreachable `ArrayPrototypeFind` and `ArrayPrototypeFindIndex` arms because the variants encode different callback fallbacks.
2. Remove or consolidate the unreachable `ArrayPrototypeReduce` arms because three variants remain and callback behavior differs.
3. Remove duplicate `StringPrototypeSubstring`, `NumberPrototypeToString`, and string case-conversion arms to prevent future edits from landing in dead code.

## String Allocation Review

Searches for `String::leak`, `Box::leak`, `mem::forget`, `ManuallyDrop`, `into_raw`, and unsafe code did not find string leak or double-free mechanisms in the runtime implementation. `ObjectId::from_raw` occurrences are test-only constructors, not raw pointer ownership. The audited string paths allocate owned `String` values and move them into `Value::Str`, or clone existing heap values before mutation; those ownership flows are handled by Rust drop semantics.

Conclusion: no double-free or intentional `String` leak pattern was found. Remaining issues are unreachable dispatch code and semantic drift risk.

## Evidence Commands

- `rg -n '"builtin:<name>" =>' crates/franken-engine/src/baseline_interpreter.rs`
- `sed -n '17396,17745p' crates/franken-engine/src/baseline_interpreter.rs`
- `git show --name-status --oneline 0637d3ac`
- `git show --name-status --oneline 89a3077d`
- `rg -n 'String::leak|Box::leak|mem::forget|ManuallyDrop|into_raw|from_raw|unsafe' crates/franken-engine/src/baseline_interpreter.rs`
