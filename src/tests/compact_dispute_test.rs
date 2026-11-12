//! The publication disputes of the interval construction.
//!
//! Replaces the trace-tree suite. Two of its subjects are gone -- the
//! wrong-node option and the equal-vector stall -- and one case was never
//! implemented at all: the empty annex, which the November 2026 audit
//! found as C09.
#[cfg(test)]
mod tests {
    use crate::compact::checkpoints::{self, NODE_BYTES, PER_ELEMENT};
    use crate::compact::commitment::{DIGEST_WINDOW_OFFSET, WINDOW_LEN};
    use crate::compact::dispute::{empty_annex_window, evidence_for, MCode, MCODE_BITS};

    // --- the option set ------------------------------------------------

    /// The whole option set, written out.  Adding a code without adding
    /// it here fails to compile, which is the point.
    const ALL: [MCode; 4] = [
        MCode::Malformed,
        MCode::BadProfile,
        MCode::DanglingReference,
        MCode::DivergentReference,
    ];

    #[test]
    fn every_option_names_evidence_its_own_disputer_holds() {
        for c in ALL {
            assert!(!evidence_for(c).is_empty(), "{:?} has no evidence", c);
        }
    }

    #[test]
    fn four_options_fit_a_two_bit_field_exactly() {
        assert_eq!(ALL.len(), 4);
        assert_eq!(ALL.len(), 1 << MCODE_BITS, "the field is full");
        assert_eq!(MCODE_BITS, 2, "the tree spent three bits on five codes");
    }

    /// Two of the tree's five options do not survive the interval, and a
    /// third was never an option.
    #[test]
    fn the_options_the_interval_does_not_have() {
        // WrongNode policed a parent-child relation an interval lacks.
        // SelfContradiction compared a machine-state hash to the digest
        // of a file of state hashes; the tree identified those two
        // objects and an interval does not, so the comparison means
        // nothing here.
        // FalseOpening was never refutable at all: an opening is checked
        // against a digest the publisher's own signature committed to.
        assert_eq!(ALL.len(), 4, "the tree had five");

        // Each surviving option's evidence is something the disputer
        // already holds, and none of it is a comparison of two values of
        // different kinds -- which is what SelfContradiction had become.
        for c in ALL {
            let e = evidence_for(c);
            assert!(
                !e.contains("20-byte values"),
                "{c:?} still names the tree's comparison: {e}"
            );
        }

        // And the codes are dense from zero, so the two-bit field is
        // fully used rather than merely sufficient.
        let mut codes: Vec<u8> = ALL.iter().map(|c| *c as u8).collect();
        codes.sort_unstable();
        assert_eq!(codes, vec![0, 1, 2, 3]);
    }

    // --- M6: the reference points at a diverged instance ---------------

    /// The predicate deduplication needs, and the cheapest one in the
    /// paper: two instances hold the same interval exactly when their
    /// selection digits agree, so the negation is one differing pair.
    #[test]
    fn a_divergent_reference_is_witnessed_by_one_pair_of_digits() {
        use crate::compact::dispute::divergent_reference;

        // Agreeing instances: nothing to exhibit, so the option cannot be
        // formed against an honest reference.
        assert_eq!(divergent_reference(&[3, 7, 2], &[3, 7, 2]), None);

        // Diverged at stage 2: that is the witness, and the first one.
        assert_eq!(divergent_reference(&[3, 7, 2], &[3, 9, 2]), Some(2));
        assert_eq!(divergent_reference(&[1, 7, 2], &[3, 9, 4]), Some(1),
                   "the earliest divergence, not any of them");
    }

    /// The witness is two digits, so it costs two digits.  Compare M1,
    /// whose evidence is 222 bytes, and M4, whose binding is 160.
    #[test]
    fn m6_is_two_orders_cheaper_than_the_options_it_joins() {
        use crate::compact::checkpoints::selection_bits;
        let digit_bits = selection_bits(192);
        assert_eq!(digit_bits, 8);
        // Two eight-bit digits against 222 bytes of M1 evidence.
        assert!(2 * digit_bits as usize / 8 * 100 < 222,
                "two digits must be far under M1's evidence");
    }

    /// And it needs no garbled circuit: Script already verifies digits.
    #[test]
    fn m6_names_evidence_that_is_already_on_chain() {
        use crate::compact::dispute::{evidence_for, MCode};
        let e = evidence_for(MCode::DivergentReference);
        assert!(e.contains("already on chain"), "{e}");
        assert!(!e.contains("proof"), "no proof is published for M6: {e}");
    }

    // --- C09: the empty annex ------------------------------------------

    #[test]
    fn the_empty_annex_window_is_the_published_constant() {
        // E = SHA256(0x01 || 0x50)[2..32].  Pinned here so the Rust and
        // the Python model cannot disagree about it.
        let w = empty_annex_window();
        assert_eq!(w.len(), 30);
        assert_eq!(
            hex::encode(w),
            "213288f0988543a76512fab09684131809d98baa8b93c2cd8a03a0e31d41"
        );
    }

    #[test]
    fn the_empty_annex_window_is_not_all_zero_or_trivial() {
        let w = empty_annex_window();
        assert!(w.iter().any(|&b| b != 0));
        assert_ne!(w, [0xffu8; 30]);
    }

    // --- the packing the publication uses -------------------------------

    #[test]
    fn states_pack_three_to_an_element() {
        assert_eq!(PER_ELEMENT, 3);
        assert_eq!(NODE_BYTES, 20);
        // The digest window, which is what the number two is really
        // about: the 222-byte profile commits to D[2..31].  It is not an
        // offset inside an element, and `packed_position` once added it
        // to one.
        assert_eq!(DIGEST_WINDOW_OFFSET, 2);
        assert_eq!(DIGEST_WINDOW_OFFSET + WINDOW_LEN, 32, "to the end of the digest");
        assert!(PER_ELEMENT * NODE_BYTES <= 64, "and three states fit a block");
    }

    #[test]
    fn packed_positions_do_not_overlap() {
        let mut seen: Vec<(usize, usize)> = Vec::new();
        for t in 0..12 {
            let (elem, off) = checkpoints::packed_position(t);
            for &(e2, o2) in &seen {
                if e2 == elem {
                    assert!(
                        off + NODE_BYTES <= o2 || o2 + NODE_BYTES <= off,
                        "state {} overlaps another in element {}",
                        t,
                        elem
                    );
                }
            }
            seen.push((elem, off));
        }
    }

    /// The check that was missing, and whose absence let `packed_position`
    /// disagree with the packing for as long as there was no packing.
    #[test]
    fn pack_round_trips_through_packed_position() {
        let states: Vec<checkpoints::Node> =
            (0..11u8).map(|i| [i.wrapping_mul(17); NODE_BYTES]).collect();
        let elements = checkpoints::pack(&states);

        assert_eq!(elements.len(), 11usize.div_ceil(PER_ELEMENT));
        for e in &elements {
            assert_eq!(e.len(), 64, "every element is one block");
        }

        assert_eq!(checkpoints::unpack(&elements, states.len()), states);

        // And the position the dispute reads an opening at is where the
        // packing put it.
        for (t, want) in states.iter().enumerate() {
            let (elem, off) = checkpoints::packed_position(t);
            assert_eq!(
                &elements[elem][off..off + NODE_BYTES],
                &want[..],
                "state {} is not where packed_position says",
                t
            );
        }
    }

    /// The states fit a block with room to spare, and the spare is zero.
    #[test]
    fn a_full_element_pads_with_four_zero_bytes() {
        let states: Vec<checkpoints::Node> = (0..3u8).map(|i| [i + 1; NODE_BYTES]).collect();
        let e = &checkpoints::pack(&states)[0];
        assert_eq!(&e[60..], &[0u8; 4], "four spare bytes, zeroed");
    }

    /// A short last element is padded the same way, which is the ordinary
    /// case now that a stage publishes `b - 1` states rather than `b`.
    #[test]
    fn a_short_last_element_is_zero_padded() {
        let states: Vec<checkpoints::Node> = (0..4u8).map(|i| [i + 1; NODE_BYTES]).collect();
        let els = checkpoints::pack(&states);
        assert_eq!(els.len(), 2);
        assert_eq!(&els[1][..NODE_BYTES], &[4u8; NODE_BYTES]);
        assert_eq!(&els[1][NODE_BYTES..], &[0u8; 64 - NODE_BYTES]);
    }

    #[test]
    fn a_192_way_dissection_fills_64_elements() {
        assert_eq!(checkpoints::interior_states(192), 191);
        assert_eq!(checkpoints::elements_for(192), 64);
        assert!(checkpoints::feasible(192));
        assert_eq!(checkpoints::publication_bytes(192), 8_064);
    }

    #[test]
    fn b_minus_one_only_has_to_fill_the_count_so_the_ladder_is_wider() {
        // The tree needed b/3 to be a power of two, so exactly 3 * 2^k.
        for b in [191usize, 192, 193] {
            assert!(checkpoints::feasible(b), "b = {} should be admissible", b);
        }
        assert_ne!(191 % 3, 0, "and 191 is not a multiple of three");
    }

    #[test]
    fn four_levels_and_an_eight_bit_digit_at_192() {
        assert_eq!(checkpoints::levels(192usize.pow(4), 192), 4);
        assert_eq!(checkpoints::selection_bits(192), 8);
    }
}
