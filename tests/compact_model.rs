//! The Rust compact module, checked against the paper's Python model.
//!
//! `compact2/python` carries 108 checks and `compact/python` 2,304, and
//! between them they are the specification every figure in both papers is
//! produced by.  This file pins the Rust to the same numbers, so that the
//! two cannot drift the way the papers' own tables did.
//!
//! The suite in `src/tests/` exercises the modules; what was missing was
//! anything tying them to the model, which is a different job.  That gap
//! is how the M4 predicate came to implement one of its four cases, and
//! how `memory.rs` came to model a machine that rejects unaligned access
//! as though it straddled slots.

use protocol_builder::compact::{annex, commitment, flatmerkle, memory};

// --- FlatMerkle file sizes -------------------------------------------------
// python: fmref.total_raw_len(n)

#[test]
fn flatmerkle_file_sizes_match_the_model() {
    assert_eq!(flatmerkle::total_raw_len(16), 1_920);
    assert_eq!(flatmerkle::total_raw_len(32), 3_968);
    assert_eq!(flatmerkle::total_raw_len(64), 8_064);
}

#[test]
fn a_file_is_64_times_two_n_minus_two() {
    for n in [4usize, 8, 16, 32, 64, 128] {
        assert_eq!(flatmerkle::total_raw_len(n), 64 * (2 * n - 2));
    }
}

// --- the checkpoint publication -------------------------------------------
// python: checkpoints.publication_bytes(192) / annex_bytes / publication_wu

#[test]
fn a_192_way_dissection_publishes_in_64_elements() {
    // 191 interior states, three to a 64-byte element.
    let elements = (191 + 2) / 3;
    assert_eq!(elements, 64, "191 hashes pack into 64 elements");
    assert_eq!(flatmerkle::total_raw_len(elements), 8_064);
}

#[test]
fn the_annex_that_carries_it_is_8125_bytes() {
    // annex_len takes the element count, not the byte length.
    assert_eq!(annex::annex_len(64), 8_125);
}

// --- the signature-hash profile -------------------------------------------
// python: sighash.PROTOCOL_BITCOUNT and the window offsets

#[test]
fn the_profile_is_222_bytes_and_1776_bits() {
    assert_eq!(commitment::PROFILE_LEN, 222);
    assert_eq!(commitment::PROFILE_BITCOUNT, 1_776);
}

#[test]
fn the_window_is_the_last_30_bytes_before_the_padding() {
    assert_eq!(commitment::WINDOW_START, 192);
    assert_eq!(commitment::WINDOW_LEN, 30);
    assert_eq!(
        commitment::WINDOW_START + commitment::WINDOW_LEN,
        commitment::PROFILE_LEN,
        "the window ends where the message does"
    );
}

// --- the memory access model ----------------------------------------------
// python: memory.pattern / worst_case_slots, repaired for audit C07

#[test]
fn nothing_straddles_a_slot() {
    // BitVMX-CPU rejects UnalignedRead/Write/Jump, so no touched set may
    // contain an adjacent pair put there by a straddle.
    let regs = [0usize, 1, 3];
    for p in [
        memory::Pattern::Worst,
        memory::Pattern::Alu,
        memory::Pattern::Load,
        memory::Pattern::Store,
    ] {
        let t = memory::touched(p, 8_192, 24_575, regs);
        assert!(
            !t.windows(2).any(|w| w[1] == w[0] + 1 && w[0] >= memory::REG_SLOTS),
            "a straddling pair outside the register block: {:?}",
            t
        );
    }
}

#[test]
fn an_instruction_touches_at_most_four_slots() {
    // RISC-V is load/store: nothing both touches memory and names three
    // registers.  Four, not the five an earlier version claimed.
    let regs = [0usize, 1, 3];
    for p in [
        memory::Pattern::Worst,
        memory::Pattern::Alu,
        memory::Pattern::Load,
        memory::Pattern::Store,
    ] {
        let t = memory::touched(p, 8_192, 24_575, regs);
        assert!(t.len() <= 4, "{:?} touches {} slots", p, t.len());
    }
}

#[test]
fn the_register_block_is_four_slots() {
    // 32 registers of four bytes are 128 bytes, which is four 32-byte slots.
    assert_eq!(memory::REG_SLOTS, 4);
    assert_eq!(32 * 4 / memory::SLOT, memory::REG_SLOTS);
}

#[test]
fn a_node_is_twenty_bytes() {
    assert_eq!(memory::NODE, 20);
    assert_eq!(memory::SLOT, 32);
}
