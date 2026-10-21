//! Stable natural-run sorting for immutable primitive keys only.
//!
//! Guest comparators and observable ToString remain on the original recursive
//! merger. This path moves only private indices, uses the caller's half-size
//! scratch, and performs every comparison through its fallible work meter.

use std::cmp::Ordering;

mod gallop;
use gallop::{AFTER_WINS, prefix_boundary, winning_span};

// Avoid adding boundary probes to short merges. Above one bulk-copy window,
// trimming can avoid copying an otherwise settled prefix or suffix into
// scratch; no payload or index needs to move while proving those bounds.
const MIN_TRIM_LENGTH: usize = gallop::MAX_SPAN;
// Whole-input proofs avoid a setup cost on short arrays. The bitset fits in
// the existing half-size scratch on every supported usize width.
const MIN_WHOLE_DESCENDING_LENGTH: usize = gallop::MAX_SPAN;
const BOUNDARY_WORD_BITS: usize = usize::BITS as usize;

#[derive(Clone, Copy, Default)]
struct Run {
    start: usize,
    len: usize,
}

impl Run {
    fn level(self) -> u32 {
        debug_assert!(self.len != 0);
        usize::BITS - 1 - self.len.leading_zeros()
    }
}

/// Keep strictly decreasing binary length classes on a fixed stack. Each
/// push may temporarily add one class; collapsing adjacent top runs restores
/// the invariant. There are at most usize::BITS nonempty length classes, so
/// input chosen by the guest cannot grow native recursion or allocate a run
/// list. Neither run detection nor merging retains a Value or a string key.
pub(super) fn sort<E>(
    order: &mut [usize],
    scratch: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    if order.len() < 2 {
        return Ok(());
    }
    debug_assert!(scratch.len() >= order.len() / 2);
    let mut runs = [Run::default(); usize::BITS as usize + 1];
    let mut pending = 0;
    let mut start = 0;
    while start < order.len() {
        let len = if start == 0 {
            normalize_first_run(order, scratch, compare)?
        } else {
            normalize_run(&mut order[start..], compare)?
        };
        runs[pending] = Run { start, len };
        pending += 1;
        start += len;
        while pending >= 2 && runs[pending - 2].level() <= runs[pending - 1].level() {
            merge_top(order, scratch, &mut runs, &mut pending, compare)?;
        }
        debug_assert!(runs[..pending].windows(2).all(|pair| pair[0].level() > pair[1].level()));
    }
    while pending > 1 {
        merge_top(order, scratch, &mut runs, &mut pending, compare)?;
    }
    Ok(())
}

/// Equal keys belong only to ascending runs. Reversing a descending run with
/// a tie would reverse equal original identities and violate sort stability.
/// Do not reverse until detection succeeds: a refused comparison leaves this
/// run alone, and the caller never publishes indices after any sort error.
fn normalize_run<E>(
    order: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<usize, E> {
    if order.len() < 2 {
        return Ok(order.len());
    }
    let descending = compare(order[0], order[1])? == Ordering::Greater;
    finish_run(order, descending, 2, compare)
}

/// Continue the original strict-descending/nondecreasing run detector after
/// comparisons the first-run probe has already performed. A rejected probe
/// must not change the run partition or add any index movement on fallback.
fn finish_run<E>(
    order: &mut [usize],
    descending: bool,
    mut end: usize,
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<usize, E> {
    while end < order.len() {
        let ordering = compare(order[end - 1], order[end])?;
        if (ordering == Ordering::Greater) != descending {
            break;
        }
        end += 1;
    }
    if descending {
        order[..end].reverse();
    }
    Ok(end)
}

/// A whole nonincreasing input with ties need not be split into equal-key
/// runs and merged. Prove it once, without changing any index. The caller's
/// initial identity order lets us emit the reversed GROUP order directly,
/// preserving source order within each group rather than reversing it twice.
/// Check that identity explicitly so arbitrary input permutations still work.
///
/// Strict boundaries occupy one bit per adjacent pair in the existing paid
/// scratch, not a new allocation. Before the first changed comparison every
/// word is uniform and can be reconstructed; all-equal and strictly descending
/// inputs therefore retain their original comparison and scratch-write counts.
/// Only the first run gets this probe. A miss resumes the original detector
/// without rescanning its known prefix or changing its original run boundary.
fn normalize_first_run<E>(
    order: &mut [usize],
    scratch: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<usize, E> {
    if order.len() < MIN_WHOLE_DESCENDING_LENGTH || order[0] != 0 || order[1] != 1 {
        return normalize_run(order, compare);
    }
    let first = compare(0, 1)?;
    let descending = first == Ordering::Greater;
    if first == Ordering::Less {
        return finish_run(order, false, 2, compare);
    }
    let mut original_end = None;
    let mut saved_from = None;
    let mut bits = usize::from(descending);
    for end in 2..order.len() {
        if order[end] != end {
            let Some(original_end) = original_end else {
                return finish_run(order, descending, end, compare);
            };
            if descending {
                order[..original_end].reverse();
            }
            return Ok(original_end);
        }
        let ordering = compare(end - 1, end)?;
        if original_end.is_none() && (ordering == Ordering::Greater) != descending {
            original_end = Some(end);
        }
        if ordering == Ordering::Less {
            let Some(original_end) = original_end else {
                return finish_run(order, false, end + 1, compare);
            };
            if descending {
                order[..original_end].reverse();
            }
            return Ok(original_end);
        }
        let edge = end - 1;
        let word = edge / BOUNDARY_WORD_BITS;
        if ordering != first && saved_from.is_none() {
            saved_from = Some(word);
        }
        if ordering == Ordering::Greater {
            bits |= 1_usize << (edge % BOUNDARY_WORD_BITS);
        }
        if (edge + 1).is_multiple_of(BOUNDARY_WORD_BITS) {
            if saved_from.is_some() {
                scratch[word] = bits;
            }
            bits = 0;
        }
    }
    let Some(saved_from) = saved_from else {
        if descending {
            order.reverse();
        }
        return Ok(order.len());
    };
    let last_edge = order.len() - 2;
    if !(last_edge + 1).is_multiple_of(BOUNDARY_WORD_BITS) {
        scratch[last_edge / BOUNDARY_WORD_BITS] = bits;
    }
    emit_descending_groups(order, scratch, saved_from, descending, compare)?;
    Ok(order.len())
}

/// Find groups from the right using the boundary bitmap, then write their
/// original source indices from left to right. No Value is cloned or moved.
/// On a refusal the private index buffer may be unfinished, exactly as after
/// a failed merge; sort_captured_values never applies it to the payloads.
fn emit_descending_groups<E>(
    order: &mut [usize],
    boundaries: &[usize],
    saved_from: usize,
    initial_descending: bool,
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    let uniform = if initial_descending { usize::MAX } else { 0 };
    let mut remaining = 0;
    let mut output = 0;
    let mut end = order.len();
    while end != 0 {
        let mut before = end - 1;
        let mut start = 0;
        while before != 0 {
            descending_checkpoint(&mut remaining, end - 1, compare)?;
            let word = (before - 1) / BOUNDARY_WORD_BITS;
            let used = (before - 1) % BOUNDARY_WORD_BITS + 1;
            let bits = if word < saved_from { uniform } else { boundaries[word] };
            let bits = bits & (usize::MAX >> (BOUNDARY_WORD_BITS - used));
            if bits != 0 {
                start = word * BOUNDARY_WORD_BITS
                    + (BOUNDARY_WORD_BITS - bits.leading_zeros() as usize);
                break;
            }
            before = word * BOUNDARY_WORD_BITS;
        }
        for source in start..end {
            descending_checkpoint(&mut remaining, source, compare)?;
            order[output] = source;
            output += 1;
        }
        end = start;
    }
    debug_assert_eq!(output, order.len());
    Ok(())
}

/// Bitmap probes and index emission must not create an unmetered O(n) tail
/// after the order proof. A self-comparison goes through the SAME fallible
/// work/provenance gate at most 256 operations apart. Keys are immutable
/// primitives here: this cannot invoke guest code, and its result is unused.
/// The source is an original item index, not an entry in the rewriting order.
fn descending_checkpoint<E>(
    remaining: &mut usize,
    source: usize,
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    if *remaining == 0 {
        compare(source, source)?;
        *remaining = gallop::MAX_SPAN;
    }
    *remaining -= 1;
    Ok(())
}

fn merge_top<E>(
    order: &mut [usize],
    scratch: &mut [usize],
    runs: &mut [Run],
    pending: &mut usize,
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    let left = runs[*pending - 2];
    let right = runs[*pending - 1];
    debug_assert_eq!(left.start + left.len, right.start);
    let end = right.start + right.len;
    merge(&mut order[left.start..end], left.len, scratch, compare)?;
    runs[*pending - 2].len += right.len;
    *pending -= 1;
    Ok(())
}

/// The caller has proved that the last left key exceeds the first right key.
/// Leave the left <= first-right prefix and the right >= last-left suffix in
/// place. Left ties precede every right tie; right ties follow every left tie.
///
/// Exclude the already-proven crossing endpoints from each search, keeping
/// both active runs nonempty. Only immutable primitive comparisons reach
/// this function. Every probe is fallible and metered; neither search writes
/// indices or scratch, allocates storage, or skips a bulk-copy checkpoint.
fn overlap_bounds<E>(
    order: &[usize],
    middle: usize,
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(usize, usize), E> {
    let first_right = order[middle];
    let last_left = order[middle - 1];
    let prefix = prefix_boundary(middle - 1, |offset| {
        compare(order[offset], first_right).map(|ordering| ordering != Ordering::Greater)
    })?;
    let suffix = prefix_boundary(order.len() - middle - 1, |offset| {
        compare(last_left, order[order.len() - 1 - offset])
            .map(|ordering| ordering != Ordering::Greater)
    })?;
    Ok((prefix, order.len() - suffix))
}

/// Save the SMALLER run, not invariably the left half: natural run lengths
/// need not be balanced. Trim settled ends first so a small overlap does not
/// copy an entire run. The existing floor(n/2) scratch is always enough.
/// Forward ties take the earlier left identity; backward ties take the later
/// right identity first, placing it at the higher output position.
fn merge<E>(
    order: &mut [usize],
    middle: usize,
    scratch: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    debug_assert!(middle != 0 && middle < order.len());
    if compare(order[middle - 1], order[middle])? != Ordering::Greater {
        return Ok(());
    }
    let (start, end) = if order.len() >= MIN_TRIM_LENGTH {
        overlap_bounds(order, middle, compare)?
    } else {
        (0, order.len())
    };
    let middle = middle - start;
    let order = &mut order[start..end];
    let right_len = order.len() - middle;
    if middle <= right_len {
        scratch[..middle].copy_from_slice(&order[..middle]);
        let (mut left, mut right, mut output) = (0, middle, 0);
        let (mut left_wins, mut right_wins) = (0, 0);
        while left < middle && right < order.len() {
            if compare(scratch[left], order[right])? == Ordering::Greater {
                order[output] = order[right];
                right += 1;
                right_wins += 1;
                left_wins = 0;
            } else {
                order[output] = scratch[left];
                left += 1;
                left_wins += 1;
                right_wins = 0;
            }
            output += 1;
            if left == middle || right == order.len() {
                break;
            }
            if left_wins >= AFTER_WINS {
                // Forward ties take the original left run. Search only its
                // <= prefix; the other run's pivot is not moved by this span.
                let pivot = order[right];
                let span = winning_span(middle - left, |offset| {
                    compare(scratch[left + offset], pivot).map(|order| order != Ordering::Greater)
                })?;
                order[output..output + span].copy_from_slice(&scratch[left..left + span]);
                left += span;
                output += span;
                left_wins = 0;
            } else if right_wins >= AFTER_WINS {
                let pivot = scratch[left];
                let span = winning_span(order.len() - right, |offset| {
                    compare(pivot, order[right + offset]).map(|order| order == Ordering::Greater)
                })?;
                // Source/destination may overlap; no allocation or key clone.
                order.copy_within(right..right + span, output);
                right += span;
                output += span;
                right_wins = 0;
            }
        }
        order[output..right].copy_from_slice(&scratch[left..middle]);
    } else {
        scratch[..right_len].copy_from_slice(&order[middle..]);
        let (mut left, mut right, mut output) = (middle, right_len, order.len());
        let (mut left_wins, mut right_wins) = (0, 0);
        while left != 0 && right != 0 {
            output -= 1;
            if compare(order[left - 1], scratch[right - 1])? == Ordering::Greater {
                left -= 1;
                order[output] = order[left];
                left_wins += 1;
                right_wins = 0;
            } else {
                right -= 1;
                order[output] = scratch[right];
                right_wins += 1;
                left_wins = 0;
            }
            if left == 0 || right == 0 {
                break;
            }
            if left_wins >= AFTER_WINS {
                let pivot = scratch[right - 1];
                let span = winning_span(left, |offset| {
                    compare(order[left - 1 - offset], pivot).map(|order| order == Ordering::Greater)
                })?;
                order.copy_within(left - span..left, output - span);
                left -= span;
                output -= span;
                left_wins = 0;
            } else if right_wins >= AFTER_WINS {
                // Backward ties take the original right run so they occupy
                // higher output positions. Its winning suffix is >= pivot.
                let pivot = order[left - 1];
                let span = winning_span(right, |offset| {
                    compare(pivot, scratch[right - 1 - offset]).map(|order| order != Ordering::Greater)
                })?;
                order[output - span..output].copy_from_slice(&scratch[right - span..right]);
                right -= span;
                output -= span;
                right_wins = 0;
            }
        }
        order[left..output].copy_from_slice(&scratch[..right]);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod descending_tests;
