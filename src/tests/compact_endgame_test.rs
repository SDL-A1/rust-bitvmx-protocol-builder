//! The endgame of Compact BitVMX II: a leaf is a four-byte word.
//!
//! Replaces the trace-tree suite. The figures here are pinned to
//! `compact2/python`, which is what the paper's tables are produced by.
#[cfg(test)]
mod tests {
    use crate::compact::memory::{
        step_message_bytes, touched_words, MerkleMemory, Pattern, NODE, REG_SLOTS, REG_WORDS, SLOT,
        SLOT_LEVELS, WORD, WORD_LEVELS,
    };
    use std::collections::HashMap;

    fn empty_tree(levels: u32) -> MerkleMemory {
        MerkleMemory::new(levels, &HashMap::new())
    }

    // --- the two granularities ------------------------------------------

    #[test]
    fn a_word_tree_covers_the_same_memory_as_a_slot_tree() {
        assert_eq!(SLOT * (1usize << SLOT_LEVELS), 1 << 20);
        assert_eq!(WORD * (1usize << WORD_LEVELS), 1 << 20);
    }

    #[test]
    fn the_register_block_is_four_slots_or_thirty_two_words() {
        assert_eq!(32 * 4 / SLOT, REG_SLOTS);
        assert_eq!(32 * 4 / WORD, REG_WORDS);
    }

    // --- the access model, both granularities ----------------------------

    #[test]
    fn an_instruction_touches_at_most_four_words() {
        // RISC-V is load/store: nothing both touches memory and names
        // three registers.
        let regs = [0usize, 7, 31];
        for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
            let t = touched_words(p, 65_536, 196_607, regs);
            assert!(t.len() <= 4, "{:?} touches {}", p, t.len());
        }
    }

    #[test]
    fn registers_are_always_distinct_leaves_at_word_granularity() {
        // At slot granularity rs1, rs2 and rd may share one leaf; at word
        // granularity they cannot, which is why the word multiproof is
        // slightly larger and not smaller.
        let t = touched_words(Pattern::Alu, 65_536, 0, [0, 7, 31]);
        assert_eq!(t.len(), 4, "fetch plus three distinct register words");
    }

    #[test]
    fn nothing_straddles_at_either_granularity() {
        let regs = [0usize, 7, 31];
        for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
            let t = touched_words(p, 65_536, 196_607, regs);
            let strays = t
                .windows(2)
                .filter(|w| w[1] == w[0] + 1 && w[0] >= REG_WORDS)
                .count();
            assert_eq!(strays, 0, "{:?} built a straddling pair: {:?}", p, t);
        }
    }

    // --- the step message ------------------------------------------------

    #[test]
    fn tau_is_eighty_bytes_on_words_and_two_twenty_eight_on_five_slots() {
        // python: WordEndgame(4).core_bytes == 80
        assert_eq!(step_message_bytes(WORD, 4), 80);
        // the companion paper budgets five slots: 2(20) + 4 + 4 + 5(4+32)
        assert_eq!(step_message_bytes(SLOT, 5), 228);
        // and four slots, which is the repaired bound, would be 192
        assert_eq!(step_message_bytes(SLOT, 4), 192);
    }

    #[test]
    fn the_message_is_two_roots_a_pc_an_instruction_and_the_pairs() {
        assert_eq!(
            step_message_bytes(WORD, 4),
            2 * NODE + 4 + 4 + 4 * (4 + WORD)
        );
    }

    // --- the multiproof ---------------------------------------------------

    #[test]
    fn the_word_tree_worst_case_multiproof_is_1040_bytes() {
        // python: memory.word_worst_case_bytes() == 1040 on
        // [0, 31, 65536, 196607] -- two register words, a fetch and a
        // data word, maximally separated.
        let m = empty_tree(WORD_LEVELS);
        let got = m.multiproof_bytes(&[0, 31, 65_536, 196_607]);
        assert_eq!(got, 1_040);
    }

    #[test]
    fn the_slot_tree_worst_case_is_800_and_the_deeper_tree_costs_240() {
        // python: memory.worst_case_proof_bytes(15) == 800
        let m = empty_tree(SLOT_LEVELS);
        let slot = m.multiproof_bytes(&[0, 3, 8_192, 24_575]);
        assert_eq!(slot, 800);
        assert_eq!(1_040 - slot, 240, "three extra levels, four leaves");
    }

    #[test]
    fn forty_siblings_pack_into_sixteen_elements_and_fifty_two_into_thirty_two() {
        // The published file is what rounds, not the raw proof.
        let els = |bytes: usize| {
            let blocks = bytes.div_ceil(64);
            blocks.next_power_of_two().max(4)
        };
        assert_eq!(800 / 20, 40);
        assert_eq!(1_040 / 20, 52);
        assert_eq!(els(800), 16);
        assert_eq!(els(1_040), 32);
    }
}
