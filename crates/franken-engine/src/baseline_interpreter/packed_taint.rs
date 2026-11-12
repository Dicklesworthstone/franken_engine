//! Zero-overhead packed taint bitsets for register-frame IFC propagation (`g2vrp.15`).
//!
//! Canonical 3-bit SWAR encoding (`SLOTS_PER_WORD = 21` registers per `u64`):
//! - `0b000` (`0`): `Label::Public` (canonical zero so lazy `all_public -> tainted`
//!   materialization is an `O(words)` zeroed allocation with zero register scans)
//! - `0b001` (`1`): `Label::Internal`
//! - `0b010` (`2`): `Label::Confidential`
//! - `0b011` (`3`): `Label::Secret`
//! - `0b100` (`4`): `Label::TopSecret`
//! - `0b111` (`7`): `CustomSpill` (`Label::Custom { name, level }` stored in a cold side table)

use std::collections::BTreeMap;

use crate::ifc_artifacts::Label;

/// Number of 3-bit register taint slots packed into a single `u64` word (`21 * 3 = 63` bits).
pub const SLOTS_PER_WORD: usize = 21;

const SLOT_MASK: u64 = 0b111;
const PUBLIC_SLOT: u8 = 0b000;
const INTERNAL_SLOT: u8 = 0b001;
const CONFIDENTIAL_SLOT: u8 = 0b010;
const SECRET_SLOT: u8 = 0b011;
const TOP_SECRET_SLOT: u8 = 0b100;
const CUSTOM_SPILL_SLOT: u8 = 0b111;

#[inline(always)]
pub const fn words_for_registers(num_regs: usize) -> usize {
    num_regs.div_ceil(SLOTS_PER_WORD)
}

#[inline(always)]
const fn encode_label_slot(label: &Label) -> u8 {
    match label {
        Label::Public => PUBLIC_SLOT,
        Label::Internal => INTERNAL_SLOT,
        Label::Confidential => CONFIDENTIAL_SLOT,
        Label::Secret => SECRET_SLOT,
        Label::TopSecret => TOP_SECRET_SLOT,
        Label::Custom { .. } => CUSTOM_SPILL_SLOT,
    }
}

#[inline(always)]
const fn decode_builtin_slot(slot: u8) -> Option<Label> {
    match slot {
        PUBLIC_SLOT => Some(Label::Public),
        INTERNAL_SLOT => Some(Label::Internal),
        CONFIDENTIAL_SLOT => Some(Label::Confidential),
        SECRET_SLOT => Some(Label::Secret),
        TOP_SECRET_SLOT => Some(Label::TopSecret),
        _ => None,
    }
}

/// Compact IFC header for a shared lexical upvalue (`EnvCell`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedEnvCell {
    slot: u8,
    custom_spill: Option<Label>,
}

impl Default for PackedEnvCell {
    fn default() -> Self {
        Self::public()
    }
}

impl PackedEnvCell {
    #[inline(always)]
    pub const fn public() -> Self {
        Self {
            slot: PUBLIC_SLOT,
            custom_spill: None,
        }
    }

    #[inline]
    pub fn from_label(label: Label) -> Self {
        let slot = encode_label_slot(&label);
        let custom_spill = if slot == CUSTOM_SPILL_SLOT {
            Some(label)
        } else {
            None
        };
        Self { slot, custom_spill }
    }

    #[inline(always)]
    pub const fn is_public(&self) -> bool {
        self.slot == PUBLIC_SLOT
    }

    #[inline]
    pub fn to_label(&self) -> Label {
        if let Some(builtin) = decode_builtin_slot(self.slot) {
            builtin
        } else {
            self.custom_spill.clone().unwrap_or(Label::Public)
        }
    }
}

/// Packed SWAR taint state for one VM register frame.
///
/// While `frame_is_all_public` is `true`, `taint_words` and `custom_spill` remain
/// empty and pure-Public compute executes zero word loads/stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedFrameTaint {
    frame_is_all_public: bool,
    num_regs: usize,
    taint_words: Vec<u64>,
    custom_spill: BTreeMap<u32, Label>,
}

impl PackedFrameTaint {
    /// Construct a fresh all-`Public` frame with zero heap allocation.
    #[inline(always)]
    pub const fn new(num_regs: usize) -> Self {
        Self {
            frame_is_all_public: true,
            num_regs,
            taint_words: Vec::new(),
            custom_spill: BTreeMap::new(),
        }
    }

    /// Construct from an existing `Label` slice, preserving the `all_public` fast path
    /// when every register is `Label::Public`.
    pub fn from_labels(labels: &[Label]) -> Self {
        let mut frame = Self::new(labels.len());
        for (idx, label) in labels.iter().enumerate() {
            if !matches!(label, Label::Public) {
                frame.set(idx as u32, label.clone());
            }
        }
        frame
    }

    #[inline(always)]
    pub const fn is_all_public(&self) -> bool {
        self.frame_is_all_public
    }

    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.num_regs
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.num_regs == 0
    }

    #[inline(always)]
    pub fn word_count(&self) -> usize {
        self.taint_words.len()
    }

    /// Reset all registers in `0..clear_width` to `Label::Public`.
    pub fn clear_prefix(&mut self, clear_width: usize) {
        if self.frame_is_all_public {
            return;
        }
        let limit = clear_width.min(self.num_regs);
        if limit == self.num_regs {
            self.taint_words.fill(0);
            self.custom_spill.clear();
            self.frame_is_all_public = true;
            return;
        }
        for reg in 0..limit {
            self.write_slot_raw(reg as u32, PUBLIC_SLOT);
            self.custom_spill.remove(&(reg as u32));
        }
        self.refresh_all_public_flag();
    }

    /// Resize the logical register window, initializing new slots to `Label::Public`.
    pub fn resize(&mut self, new_num_regs: usize) {
        if new_num_regs < self.num_regs && !self.frame_is_all_public {
            for reg in new_num_regs..self.num_regs {
                self.write_slot_raw(reg as u32, PUBLIC_SLOT);
                self.custom_spill.remove(&(reg as u32));
            }
            self.taint_words.truncate(words_for_registers(new_num_regs));
            self.num_regs = new_num_regs;
            self.refresh_all_public_flag();
            return;
        }
        self.num_regs = new_num_regs;
        if !self.frame_is_all_public {
            let needed_words = words_for_registers(new_num_regs);
            if self.taint_words.len() < needed_words {
                self.taint_words.resize(needed_words, 0);
            }
        }
    }

    #[inline]
    fn materialize_words(&mut self) {
        if self.frame_is_all_public {
            self.taint_words = vec![0u64; words_for_registers(self.num_regs)];
            self.frame_is_all_public = false;
        } else {
            let needed = words_for_registers(self.num_regs);
            if self.taint_words.len() < needed {
                self.taint_words.resize(needed, 0);
            }
        }
    }

    #[inline(always)]
    fn read_slot_raw(&self, reg: u32) -> u8 {
        if self.frame_is_all_public {
            return PUBLIC_SLOT;
        }
        let idx = reg as usize;
        let word_idx = idx / SLOTS_PER_WORD;
        let bit_shift = (idx % SLOTS_PER_WORD) * 3;
        self.taint_words
            .get(word_idx)
            .map_or(PUBLIC_SLOT, |word| ((word >> bit_shift) & SLOT_MASK) as u8)
    }

    #[inline(always)]
    fn write_slot_raw(&mut self, reg: u32, slot: u8) {
        let idx = reg as usize;
        let word_idx = idx / SLOTS_PER_WORD;
        let bit_shift = (idx % SLOTS_PER_WORD) * 3;
        if let Some(word) = self.taint_words.get_mut(word_idx) {
            *word = (*word & !(SLOT_MASK << bit_shift)) | (u64::from(slot) << bit_shift);
        }
    }

    fn refresh_all_public_flag(&mut self) {
        if self.custom_spill.is_empty() && self.taint_words.iter().all(|&word| word == 0) {
            self.frame_is_all_public = true;
        }
    }

    /// Read the exact `Label` of register `reg`.
    #[inline]
    pub fn get(&self, reg: u32) -> Label {
        if self.frame_is_all_public || (reg as usize) >= self.num_regs {
            return Label::Public;
        }
        let slot = self.read_slot_raw(reg);
        if let Some(builtin) = decode_builtin_slot(slot) {
            builtin
        } else {
            self.custom_spill
                .get(&reg)
                .cloned()
                .unwrap_or(Label::Public)
        }
    }

    /// Write `label` into register `reg`, lazily materializing SWAR taint words
    /// only when a non-`Public` label enters an `all_public` frame.
    #[inline]
    pub fn set(&mut self, reg: u32, label: Label) {
        let idx = reg as usize;
        if idx >= self.num_regs {
            self.resize(idx + 1);
        }
        let slot = encode_label_slot(&label);
        if self.frame_is_all_public {
            if slot == PUBLIC_SLOT {
                return;
            }
            self.materialize_words();
        }
        self.write_slot_raw(reg, slot);
        if slot == CUSTOM_SPILL_SLOT {
            self.custom_spill.insert(reg, label);
        } else {
            self.custom_spill.remove(&reg);
            if slot == PUBLIC_SLOT {
                self.refresh_all_public_flag();
            }
        }
    }

    /// Branchless SWAR join of two register labels (`max(slot_a, slot_b)` on built-in classes,
    /// exact `Label::join` when either slot is `CustomSpill`).
    #[inline(always)]
    pub fn join_regs(&self, lhs: u32, rhs: u32) -> Label {
        if self.frame_is_all_public {
            return Label::Public;
        }
        let slot_a = self.read_slot_raw(lhs);
        let slot_b = self.read_slot_raw(rhs);
        let max_slot = slot_a.max(slot_b);
        if max_slot != CUSTOM_SPILL_SLOT
            && let Some(builtin) = decode_builtin_slot(max_slot)
        {
            return builtin;
        }
        self.get(lhs).join(&self.get(rhs))
    }

    /// Transition hook (a): normal `Return` from callee into `dst` on caller frame.
    #[inline]
    pub fn apply_callee_return(
        &mut self,
        dst: u32,
        callee_return_label: Label,
        caller_pc_label: &Label,
    ) {
        let effective = callee_return_label.join(caller_pc_label);
        if self.frame_is_all_public && matches!(effective, Label::Public) {
            return;
        }
        self.set(dst, effective);
    }

    /// Transition hook (b): `Throw` unwinding across `N` frames into `catch_reg` on target frame.
    /// Joins `thrown_label` with every unwound frame's `active_pc_label` plus the handler's PC label.
    pub fn apply_exception_unwind(
        &mut self,
        catch_reg: u32,
        thrown_label: Label,
        unwound_pc_labels: &[Label],
        catch_frame_pc_label: &Label,
    ) -> Label {
        let mut effective = thrown_label.join(catch_frame_pc_label);
        for pc_label in unwound_pc_labels {
            effective = effective.join(pc_label);
        }
        if !(self.frame_is_all_public && matches!(effective, Label::Public)) {
            self.set(catch_reg, effective.clone());
        }
        effective
    }

    /// Transition hook (c): `LoadScoped` from a shared lexical `PackedEnvCell` into `dst`.
    #[inline]
    pub fn load_from_env_cell(&mut self, dst: u32, cell: &PackedEnvCell, active_pc_label: &Label) {
        if self.frame_is_all_public && cell.is_public() && matches!(active_pc_label, Label::Public)
        {
            return;
        }
        let effective = cell.to_label().join(active_pc_label);
        self.set(dst, effective);
    }

    /// Transition hook (c): `StoreScoped` from register `src` into a shared lexical `PackedEnvCell`.
    #[inline]
    pub fn store_to_env_cell(&self, src: u32, active_pc_label: &Label) -> PackedEnvCell {
        if self.frame_is_all_public && matches!(active_pc_label, Label::Public) {
            return PackedEnvCell::public();
        }
        PackedEnvCell::from_label(self.get(src).join(active_pc_label))
    }

    /// Export full `Vec<Label>` snapshot for diagnostics/replay parity checks.
    pub fn to_label_vec(&self) -> Vec<Label> {
        if self.frame_is_all_public {
            return vec![Label::Public; self.num_regs];
        }
        (0..self.num_regs).map(|idx| self.get(idx as u32)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_label(seed: u64) -> Label {
        match seed % 8 {
            0..=2 => Label::Public,
            3 => Label::Internal,
            4 => Label::Confidential,
            5 => Label::Secret,
            6 => Label::TopSecret,
            _ => Label::Custom {
                name: format!("tenant_{}", seed % 5),
                level: ((seed / 8) % 6) as u32,
            },
        }
    }

    #[test]
    fn public_frame_allocates_zero_words_until_first_tainted_write() {
        let mut frame = PackedFrameTaint::new(64);
        assert!(frame.is_all_public());
        assert_eq!(frame.word_count(), 0);
        assert_eq!(frame.join_regs(0, 63), Label::Public);

        frame.set(17, Label::Public);
        assert!(frame.is_all_public());
        assert_eq!(frame.word_count(), 0);

        frame.set(42, Label::Secret);
        assert!(!frame.is_all_public());
        assert_eq!(frame.word_count(), 4); // ceil(64 / 21) == 4
        assert_eq!(frame.get(42), Label::Secret);
        assert_eq!(frame.get(41), Label::Public);
        assert_eq!(frame.join_regs(41, 42), Label::Secret);

        // Overwriting the sole tainted register back to Public restores the fast path.
        frame.set(42, Label::Public);
        assert!(frame.is_all_public());
    }

    #[test]
    fn return_unwind_and_env_cell_transitions_preserve_exact_labels() {
        let mut caller = PackedFrameTaint::new(32);
        assert!(caller.is_all_public());

        // (a) Public return keeps caller all_public.
        caller.apply_callee_return(3, Label::Public, &Label::Public);
        assert!(caller.is_all_public());

        // Non-Public return lazily materializes caller taint words.
        caller.apply_callee_return(3, Label::Confidential, &Label::Public);
        assert!(!caller.is_all_public());
        assert_eq!(caller.get(3), Label::Confidential);

        // (b) Exception unwind across all_public frames carrying secret PC taint.
        let mut catch_frame = PackedFrameTaint::new(25);
        let caught = catch_frame.apply_exception_unwind(
            22, // crosses into second 21-slot SWAR word
            Label::Internal,
            &[Label::Public, Label::Secret, Label::Confidential],
            &Label::Public,
        );
        assert_eq!(caught, Label::Secret);
        assert!(!catch_frame.is_all_public());
        assert_eq!(catch_frame.get(22), Label::Secret);
        assert_eq!(catch_frame.get(21), Label::Public);

        // (c) Shared EnvCell taint into fresh sibling frame.
        let custom = Label::Custom {
            name: "pii".to_string(),
            level: 3,
        };
        catch_frame.set(5, custom.clone());
        let env_cell = catch_frame.store_to_env_cell(5, &Label::Public);
        let mut sibling = PackedFrameTaint::new(16);
        assert!(sibling.is_all_public());
        sibling.load_from_env_cell(9, &env_cell, &Label::Public);
        assert!(!sibling.is_all_public());
        assert_eq!(sibling.get(9), custom);
    }

    #[test]
    fn ten_thousand_step_trace_matches_reference_label_join_exactly() {
        const NUM_REGS: usize = 50; // spans 3 u64 SWAR words (21 + 21 + 8)
        const NUM_CELLS: usize = 8;
        let mut packed = PackedFrameTaint::new(NUM_REGS);
        let mut reference = vec![Label::Public; NUM_REGS];
        let mut packed_cells = vec![PackedEnvCell::public(); NUM_CELLS];
        let mut ref_cells = vec![Label::Public; NUM_CELLS];

        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next_u64 = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for step in 0..10_000usize {
            let op = next_u64() % 6;
            let dst = (next_u64() as usize % NUM_REGS) as u32;
            let lhs = (next_u64() as usize % NUM_REGS) as u32;
            let rhs = (next_u64() as usize % NUM_REGS) as u32;
            let pc = if next_u64().is_multiple_of(5) {
                sample_label(next_u64())
            } else {
                Label::Public
            };

            match op {
                0 => {
                    let lbl = sample_label(next_u64());
                    packed.set(dst, lbl.clone());
                    reference[dst as usize] = lbl;
                }
                1 => {
                    let p_join = packed.join_regs(lhs, rhs);
                    let r_join = reference[lhs as usize].join(&reference[rhs as usize]);
                    assert_eq!(p_join, r_join, "join mismatch at step {step}");
                    packed.set(dst, p_join);
                    reference[dst as usize] = r_join;
                }
                2 => {
                    let ret = sample_label(next_u64());
                    packed.apply_callee_return(dst, ret.clone(), &pc);
                    reference[dst as usize] = ret.join(&pc);
                }
                3 => {
                    let thrown = sample_label(next_u64());
                    let unwound = [sample_label(next_u64()), sample_label(next_u64())];
                    let p_caught =
                        packed.apply_exception_unwind(dst, thrown.clone(), &unwound, &pc);
                    let r_caught = thrown.join(&pc).join(&unwound[0]).join(&unwound[1]);
                    assert_eq!(p_caught, r_caught, "unwind mismatch at step {step}");
                    reference[dst as usize] = r_caught;
                }
                4 => {
                    let cell_idx = next_u64() as usize % NUM_CELLS;
                    packed_cells[cell_idx] = packed.store_to_env_cell(lhs, &pc);
                    ref_cells[cell_idx] = reference[lhs as usize].join(&pc);
                    packed.load_from_env_cell(dst, &packed_cells[cell_idx], &pc);
                    reference[dst as usize] = ref_cells[cell_idx].join(&pc);
                }
                _ => {
                    let clear_w = if next_u64().is_multiple_of(3) {
                        NUM_REGS
                    } else {
                        next_u64() as usize % NUM_REGS
                    };
                    packed.clear_prefix(clear_w);
                    for slot in reference.iter_mut().take(clear_w) {
                        *slot = Label::Public;
                    }
                }
            }

            if step.is_multiple_of(250) {
                assert_eq!(
                    packed.to_label_vec(),
                    reference,
                    "full frame drift at step {step}"
                );
                assert_eq!(
                    packed.is_all_public(),
                    reference.iter().all(|lbl| matches!(lbl, Label::Public)),
                    "all_public flag drift at step {step}"
                );
            }
        }
        assert_eq!(packed.to_label_vec(), reference);
    }
}
