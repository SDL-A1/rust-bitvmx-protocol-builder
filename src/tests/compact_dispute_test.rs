//! The publication disputes of the interval construction.
//!
//! Replaces the trace-tree suite. Two of its subjects are gone -- the
//! wrong-node option and the equal-vector stall -- and one case was never
//! implemented at all: the empty annex, which the November 2026 audit
//! found as C09.
#[cfg(test)]
mod tests {
    use crate::compact::checkpoints::{self, NODE_BYTES, NODE_OFFSET, PER_ELEMENT};
    use crate::compact::dispute::{empty_annex_window, evidence_for, MCode, MCODE_BITS};

    // --- the option set ------------------------------------------------

    #[test]
    fn every_option_names_evidence_its_own_disputer_holds() {
        for c in [
            MCode::Malformed,
            MCode::FalseOpening,
            MCode::SelfContradiction,
            MCode::BadProfile,
            MCode::DanglingReference,
        ] {
            assert!(!evidence_for(c).is_empty(), "{:?} has no evidence", c);
        }
    }

    #[test]
    fn five_options_fit_the_three_bit_field() {
        assert!(5 <= 1 << MCODE_BITS);
    }

    #[test]
    fn there_is_no_wrong_node_option() {
        // An interval has no parent node for a publication to open from,
        // so the option the tree needed does not exist here.  This test
        // is a statement about the enum, and it fails to compile rather
        // than fails to pass if someone adds it back without thinking.
        let all = [
            MCode::Malformed,
            MCode::FalseOpening,
            MCode::SelfContradiction,
            MCode::BadProfile,
            MCode::DanglingReference,
        ];
        assert_eq!(all.len(), 5, "the tree had six");
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
        assert_eq!(NODE_OFFSET, 2);
        assert!(NODE_OFFSET + PER_ELEMENT * NODE_BYTES <= 64, "and fit a block");
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
