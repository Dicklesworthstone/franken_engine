#![no_main]
//! SWAR-vs-scalar lexer differential, shaped at word-width boundaries.
//!
//! BRIDGE-18.10 scope item 5: "Fuzzing that specifically targets ISA-path
//! boundaries: input lengths around vector-width boundaries, unaligned starts,
//! and tail handling, which is where `bd-2noh9`-class bugs live."
//!
//! Before this target there was no fuzz coverage of `simd_lexer` at all --
//! neither fuzz tree mentioned it. The adjacent `parallel_parser` target reaches
//! the lexer transitively but drives only the SWAR path, so it cannot observe a
//! divergence: with nothing to compare against, a wrong answer is just an answer.
//!
//! `bd-2noh9` was exactly this failure -- the SWAR lexer disagreed with the
//! scalar lexer on token output -- and it shipped. The in-tree parity control
//! that survived that fix compares only whole `u64` words, never slices, so it
//! covers no length, no tail, and no alignment.
//!
//! What this target does differently
//! ---------------------------------
//! Two things, both about reaching the boundary rather than merely reaching the
//! code:
//!
//! 1. **`swar_min_input_bytes = 0`.** The default 64-byte threshold means the
//!    word loop is never entered below 64 bytes, so a naive fuzzer spends most
//!    of its budget comparing the scalar path against itself. Forcing SWAR on is
//!    what makes short inputs -- where every byte is a tail byte -- reachable.
//!
//! 2. **Length and phase are derived from the input, not left to chance.** The
//!    first two bytes choose a truncation and a leading pad, so the corpus walks
//!    lengths and alignments systematically instead of waiting for libFuzzer to
//!    stumble onto `len % 8 == 7`.
//!
//! Comparison is over the whole `LexerOutput`, not just tokens: the in-tree
//! `find_mismatch` looks at tokens alone, so a divergence in `bytes_scanned` or
//! `token_count` would pass a parity check while still being a divergence.
//!
//! Known-divergence carve-out
//! --------------------------
//! `0x0B` (vertical tab) is a *deliberate* SWAR/scalar difference: the SWAR
//! whitespace mask includes it, `u8::is_ascii_whitespace` does not, and the
//! repository asserts that divergence in
//! `simd_lexer_integration.rs::enrichment_differential_parity_mixed_whitespace_types`.
//! It is filtered here rather than allowlisted after the fact, so this target
//! fails only on divergences nobody has decided about. Narrowing it to a single
//! byte value keeps the carve-out auditable -- a broad "ignore whitespace
//! mismatches" filter would have hidden `bd-2noh9` itself.
//!
//! Run:
//!   cargo +nightly fuzz run --fuzz-dir crates/franken-engine/fuzz \
//!       swar_scalar_boundary_differential

use frankenengine_engine::simd_lexer::{LexerConfig, LexerMode, ScalarLexer, SwarLexer};
use libfuzzer_sys::fuzz_target;

/// Mirrors the private `SWAR_WIDTH`. Kept as a literal because the constant is
/// crate-private; the assertions below do not depend on it being right, only the
/// usefulness of the shaping does.
const SWAR_WIDTH: usize = 8;

/// Vertical tab. See the module note -- this is the one known, asserted,
/// intentional divergence between the two paths.
const KNOWN_DIVERGENT_BYTE: u8 = 0x0B;

fuzz_target!(|data: &[u8]| {
    // Two shaping bytes plus at least one payload byte.
    if data.len() < 3 {
        return;
    }
    let (shape, payload) = data.split_at(2);

    // Bound the payload so a huge input does not spend the whole iteration in
    // the scalar reference; boundary bugs live in the first few words anyway.
    let payload = &payload[..payload.len().min(4096)];
    if payload.contains(&KNOWN_DIVERGENT_BYTE) {
        return;
    }

    // Phase: 0..=2*width leading spaces, so every token in the payload starts at
    // every offset modulo the word width across the corpus.
    let pad = usize::from(shape[0]) % (2 * SWAR_WIDTH + 1);
    // Tail: trim 0..width bytes so the final word is ragged at every remainder.
    let trim = usize::from(shape[1]) % (SWAR_WIDTH + 1);

    let keep = payload.len().saturating_sub(trim);
    if keep == 0 {
        return;
    }

    let mut source = vec![b' '; pad];
    source.extend_from_slice(&payload[..keep]);

    // `swar_min_input_bytes: 0` is the load-bearing line: without it nothing
    // under 64 bytes reaches the word loop and the differential is vacuous.
    // `emit_tokens: true` because a count-only run cannot witness a span bug.
    let config = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        emit_tokens: true,
        ..LexerConfig::default()
    };

    let swar = match SwarLexer::lex(&source, &config) {
        Ok(output) => output,
        // A budget/limit refusal is a legitimate outcome; it just is not a
        // comparison. Requiring the scalar side to refuse identically is a
        // separate property from token equality, checked below only when both
        // sides produced output.
        Err(_) => return,
    };
    let scalar = match ScalarLexer::lex(&source, &config) {
        Ok(output) => output,
        Err(_) => return,
    };

    assert_eq!(
        swar.tokens, scalar.tokens,
        "SWAR/scalar token divergence: pad={pad} trim={trim} len={} source={:?}",
        source.len(),
        source
    );
    assert_eq!(
        swar.token_count, scalar.token_count,
        "SWAR/scalar token_count divergence: pad={pad} trim={trim} source={:?}",
        source
    );
    assert_eq!(
        swar.bytes_scanned, scalar.bytes_scanned,
        "SWAR/scalar bytes_scanned divergence: pad={pad} trim={trim} source={:?}",
        source
    );

    // Structural invariants, lifted from the `parallel_parser` target. These hold
    // of each path independently, so they catch a shape error that happens to be
    // symmetric and would therefore survive the equality checks above.
    let source_len = source.len() as u64;
    for output in [&swar, &scalar] {
        assert_eq!(
            output.token_count,
            output.tokens.len() as u64,
            "token_count disagrees with the token vector"
        );
        let mut previous_end = 0u64;
        for token in &output.tokens {
            assert!(token.start <= token.end, "token start exceeds end: {token:?}");
            assert!(
                token.end <= source_len,
                "token end {} exceeds source length {source_len}",
                token.end
            );
            assert!(
                previous_end <= token.start,
                "tokens must stay source-ordered and non-overlapping: {token:?}"
            );
            previous_end = token.end;
        }
    }
});
