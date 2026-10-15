//! Bounded fallible galloping over a sorted run's winning prefix.
//!
//! Each predicate uses the caller's ordinary comparison/work/provenance gate.
//! Search at most 256 indices before returning to the merger: copying a huge
//! proven run must not introduce an unbounded cancellation-polling gap.

pub(super) const AFTER_WINS: usize = 7;
pub(super) const MAX_SPAN: usize = 256;

/// `wins` is true on a prefix, false on the remainder. Probe exponentially
/// before binary refinement so a short streak does not search the entire run.
/// The cap bounds both comparisons and the subsequent memmove. A refusal
/// propagates before any part of this span is copied by the caller.
pub(super) fn winning_span<E>(
    count: usize,
    mut wins: impl FnMut(usize) -> Result<bool, E>,
) -> Result<usize, E> {
    let count = count.min(MAX_SPAN);
    if count == 0 {
        return Ok(0);
    }
    let mut accepted = 0;
    let mut probe = 1;
    loop {
        if wins(probe - 1)? {
            accepted = probe;
            if accepted == count {
                return Ok(count);
            }
            probe = (probe * 2).min(count);
        } else {
            let mut end = probe - 1;
            while accepted < end {
                let middle = accepted + (end - accepted) / 2;
                if wins(middle)? {
                    accepted = middle + 1;
                } else {
                    end = middle;
                }
            }
            return Ok(accepted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_prefix_lengths_and_capped_windows_match_linear_search() {
        for count in 0..=2 * MAX_SPAN + 1 {
            for prefix in 0..=count {
                let mut calls = 0;
                let actual = winning_span(count, |index| {
                    calls += 1;
                    assert!(index < count.min(MAX_SPAN));
                    Ok::<_, ()>(index < prefix)
                }).unwrap();
                assert_eq!(actual, prefix.min(MAX_SPAN));
                assert!(calls <= 16, "{calls} comparisons for {count}/{prefix}");
                if prefix == 0 && count != 0 {
                    assert_eq!(calls, 1, "a stopped streak gets one comparison");
                }
            }
        }
    }

    #[test]
    fn refusal_propagates_at_each_exponential_and_binary_probe() {
        for count in [0, 1, 2, 7, 15, 16, 31, 255, 256, usize::MAX] {
            for prefix in 0..=count.min(MAX_SPAN) {
                let mut calls = 0;
                winning_span(count, |index| {
                    calls += 1;
                    Ok::<_, usize>(index < prefix)
                }).unwrap();
                for fail_at in 1..=calls {
                    let mut seen = 0;
                    let result = winning_span(count, |index| {
                        seen += 1;
                        if seen == fail_at { Err(seen) } else { Ok(index < prefix) }
                    });
                    assert_eq!(result, Err(fail_at));
                    assert_eq!(seen, fail_at);
                }
            }
        }
    }
}
