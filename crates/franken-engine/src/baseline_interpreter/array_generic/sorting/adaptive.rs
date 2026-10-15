//! Stable natural-run sorting for immutable primitive keys only.
//!
//! Guest comparators and observable ToString remain on the original recursive
//! merger. This path moves only private indices, uses the caller's half-size
//! scratch, and performs every comparison through its fallible work meter.

use std::cmp::Ordering;

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
        let len = normalize_run(&mut order[start..], compare)?;
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
    let mut end = 2;
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

/// Save the SMALLER run, not invariably the left half: natural run lengths
/// need not be balanced. The existing floor(n/2) scratch is always enough.
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
    let right_len = order.len() - middle;
    if middle <= right_len {
        scratch[..middle].copy_from_slice(&order[..middle]);
        let (mut left, mut right, mut output) = (0, middle, 0);
        while left < middle && right < order.len() {
            if compare(scratch[left], order[right])? == Ordering::Greater {
                order[output] = order[right];
                right += 1;
            } else {
                order[output] = scratch[left];
                left += 1;
            }
            output += 1;
        }
        order[output..right].copy_from_slice(&scratch[left..middle]);
    } else {
        scratch[..right_len].copy_from_slice(&order[middle..]);
        let (mut left, mut right, mut output) = (middle, right_len, order.len());
        while left != 0 && right != 0 {
            output -= 1;
            if compare(order[left - 1], scratch[right - 1])? == Ordering::Greater {
                left -= 1;
                order[output] = order[left];
            } else {
                right -= 1;
                order[output] = scratch[right];
            }
        }
        order[left..output].copy_from_slice(&scratch[..right]);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
