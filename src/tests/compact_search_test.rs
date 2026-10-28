//! The search, end to end, against traces that diverge at a known step.
//!
//! This is the property the whole construction exists to deliver: given
//! two executions that agree up to step `f - 1` and differ at `f`, the
//! search must name exactly `f`, in `L + 1` transactions, whatever `f`
//! is.  Nothing here is asserted from the algebra -- every run builds two
//! real trace trees over real FlatMerkle publications and descends them.

#[cfg(test)]
mod tests {
    use crate::compact::search::*;
    use crate::compact::tracetree::*;
    use bitcoin::hashes::{sha256, Hash};

    /// A toy execution: state `i + 1` is the hash of state `i` and the
    /// step number, so a trace is deterministic from its seed and any
    /// divergence propagates to the end.
    fn trace(seed: u8, steps: usize, divergence: Option<usize>) -> Vec<Node> {
        let mut out = Vec::with_capacity(steps);
        let mut st = [seed; NODE_BYTES];
        out.push(st);
        for j in 1..steps {
            let mut pre = st.to_vec();
            pre.extend_from_slice(&(j as u64).to_be_bytes());
            if divergence == Some(j) {
                pre.push(0xFF); // the one step that is computed wrong
            }
            let h = sha256::Hash::hash(&pre).to_byte_array();
            st = h[..NODE_BYTES].try_into().unwrap();
            out.push(st);
        }
        out
    }

    fn tree(b: usize, levels: u32, leaves: Vec<Node>) -> TraceTree {
        TraceTree::from_leaves(b, levels, leaves)
    }

    // ------------------------------------------------- the tree itself

    #[test]
    fn only_some_branching_factors_are_usable() {
        for b in [12usize, 24, 48, 96, 192, 384] {
            assert!(feasible(b), "b = {b}");
        }
        for b in [1usize, 2, 3, 6, 9, 10, 20, 36, 100, 193] {
            assert!(!feasible(b), "b = {b} should be rejected");
        }
    }

    #[test]
    fn a_node_value_lies_inside_the_commitment_window() {
        let children: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
        let sf = publication(&children);
        let v = node_value(&sf);
        // the window a 222-byte signature commits to is digest[2..32]
        assert_eq!(v[..], sf.digest[2..22]);
        let window = &sf.digest[2..32];
        assert_eq!(&v[..], &window[..NODE_BYTES]);
    }

    #[test]
    fn children_round_trip_through_a_publication() {
        for b in [12usize, 24, 48] {
            let children: Vec<Node> = (0..b).map(|i| [(i * 5 + 1) as u8; NODE_BYTES]).collect();
            let sf = publication(&children);
            assert_eq!(unpack(&sf.elements, b), children);
            assert_eq!(sf.elements.len(), elements_for(b));
        }
    }

    #[test]
    fn a_child_sits_where_the_paper_says() {
        // "Child t lives at offset t mod 3 of element floor(t/3)."
        for t in [0usize, 1, 2, 3, 11, 47] {
            let (elem, off) = child_position(t);
            assert_eq!(elem, t / 3);
            assert_eq!(off, (t % 3) * NODE_BYTES);
        }
        let b = 48;
        let children: Vec<Node> = (0..b).map(|i| [(i * 3 + 7) as u8; NODE_BYTES]).collect();
        let sf = publication(&children);
        for t in 0..b {
            let (elem, off) = child_position(t);
            assert_eq!(&sf.elements[elem][off..off + NODE_BYTES], &children[t][..]);
        }
    }

    #[test]
    fn levels_for_matches_the_paper() {
        // 2^29 steps at b = 192 is four levels
        assert_eq!(levels_for(1u128 << 29, 192), 4);
        assert_eq!(levels_for(1u128 << 29, 96), 5);
        assert_eq!(levels_for(1u128 << 29, 12), 9);
        assert_eq!(levels_for(1u128 << 29, 1536), 3);
    }

    // ------------------------------------------------------- the search

    #[test]
    fn the_search_names_the_first_divergent_step() {
        let (b, l) = (12usize, 2u32); // 144 steps
        let steps = b.pow(l);
        for f in 1..steps {
            let honest = trace(1, steps, None);
            let wrong = trace(1, steps, Some(f));
            assert_eq!(honest[..f], wrong[..f], "they must agree before f = {f}");
            assert_ne!(honest[f], wrong[f]);

            let p = tree(b, l, honest);
            let c = tree(b, l, wrong);
            let (stages, out) = run(&p, &c).expect("a dispute");
            assert_eq!(out.step, f, "the search must name f = {f}");
            assert_eq!(stages.len(), l as usize + 1, "L + 1 transactions");
        }
    }

    #[test]
    fn it_works_at_three_levels_too() {
        let (b, l) = (12usize, 3u32); // 1,728 steps
        let steps = b.pow(l);
        for f in [1usize, 2, 11, 12, 13, 143, 144, 500, 1000, 1726, 1727] {
            let p = tree(b, l, trace(2, steps, None));
            let c = tree(b, l, trace(2, steps, Some(f)));
            let (stages, out) = run(&p, &c).expect("a dispute");
            assert_eq!(out.step, f);
            assert_eq!(stages.len(), 4);
        }
    }

    #[test]
    fn the_digits_spell_the_step_in_base_b() {
        let (b, l) = (12usize, 3u32);
        let steps = b.pow(l);
        let f = 977usize;
        let p = tree(b, l, trace(3, steps, None));
        let c = tree(b, l, trace(3, steps, Some(f)));
        let (_, out) = run(&p, &c).unwrap();
        assert_eq!(out.digits.len(), l as usize);
        let mut v = 0usize;
        for k in &out.digits {
            assert!(*k < b, "a digit is in range");
            v = v * b + k;
        }
        assert_eq!(v, out.step);
        assert_eq!(v, f);
    }

    #[test]
    fn the_boundary_is_an_agreed_state_followed_by_a_disagreed_one() {
        let (b, l) = (12usize, 2u32);
        let steps = b.pow(l);
        for f in [1usize, 7, 12, 60, 143] {
            let p = tree(b, l, trace(4, steps, None));
            let c = tree(b, l, trace(4, steps, Some(f)));
            let (_, out) = run(&p, &c).unwrap();
            let bd = boundary(&p, &c, &out);
            assert_eq!(bd.step, f);
            assert_eq!(p.leaves()[f - 1], c.leaves()[f - 1], "pre-state agreed");
            assert_ne!(bd.prover_post, bd.challenger_post, "post-state disputed");
        }
    }

    // -------------------------------------------- the shape of a stage

    #[test]
    fn stage_one_selects_nothing_and_the_last_publishes_nothing() {
        let (b, l) = (12usize, 3u32);
        let steps = b.pow(l);
        let p = tree(b, l, trace(5, steps, None));
        let c = tree(b, l, trace(5, steps, Some(42)));
        let (stages, _) = run(&p, &c).unwrap();

        assert!(
            stages[0].selection.is_none(),
            "stage 1 carries no selection"
        );
        assert!(stages[0].publication.is_some());
        let last = stages.last().unwrap();
        assert!(last.selection.is_some());
        assert!(
            last.publication.is_none(),
            "stage L+1 names a leaf, so it publishes nothing"
        );
        for s in &stages[1..stages.len() - 1] {
            assert!(s.selection.is_some() && s.publication.is_some());
        }
    }

    #[test]
    fn the_parties_alternate_starting_with_the_prover() {
        let (b, l) = (12usize, 3u32);
        let steps = b.pow(l);
        let p = tree(b, l, trace(6, steps, None));
        let c = tree(b, l, trace(6, steps, Some(99)));
        let (stages, _) = run(&p, &c).unwrap();
        for (n, s) in stages.iter().enumerate() {
            assert_eq!(s.index, n + 1);
            assert_eq!(s.sender, Party::of_stage(n + 1));
        }
        assert_eq!(stages[0].sender, Party::Prover);
        assert_eq!(stages[1].sender, Party::Challenger);
        // L even and the prover first means the trailing selection is
        // hers: the party on trial makes the last move.
        assert_eq!(stages.last().unwrap().sender, Party::Challenger);
    }

    #[test]
    fn a_publication_is_the_children_of_the_node_the_digits_name() {
        let (b, l) = (12usize, 3u32);
        let steps = b.pow(l);
        let p = tree(b, l, trace(7, steps, None));
        let c = tree(b, l, trace(7, steps, Some(617)));
        let (stages, out) = run(&p, &c).unwrap();

        let mut j = 0usize;
        for (n, s) in stages.iter().enumerate() {
            if let Some(k) = s.selection {
                j = j * b + k;
                let d = n as u32; // after n selections we are at level n
                assert_eq!(s.node.map(|x| x.1), if d < l { Some(j) } else { None });
                if let Some((nd, nj)) = s.node {
                    assert_eq!((nd, nj), (d, j));
                    let owner = match s.sender {
                        Party::Prover => &p,
                        Party::Challenger => &c,
                    };
                    let sf = s.publication.as_ref().unwrap();
                    assert_eq!(unpack(&sf.elements, b), owner.children(nd, nj));
                }
            }
        }
        assert_eq!(j, out.step);
    }

    // ------------------------------------------------------ edge cases

    #[test]
    fn identical_traces_are_not_a_dispute() {
        let (b, l) = (12usize, 2u32);
        let steps = b.pow(l);
        let p = tree(b, l, trace(8, steps, None));
        let c = tree(b, l, trace(8, steps, None));
        assert_eq!(p.root(), c.root());
        assert!(matches!(run(&p, &c), Err(SearchError::RootsAgree)));
    }

    #[test]
    fn the_selection_rule_is_total_when_the_vectors_differ() {
        let a: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
        let mut b2 = a.clone();
        assert_eq!(
            select(&a, &b2),
            None,
            "equal vectors have nothing to select"
        );
        b2[7][3] ^= 1;
        assert_eq!(select(&a, &b2), Some(7));
        b2[2][0] ^= 1;
        assert_eq!(select(&a, &b2), Some(2), "the *least* differing index");
    }

    /// Divergence at the very last step is the awkward case: the padding
    /// repeats the halting state, so the last leaves must still differ.
    #[test]
    fn divergence_at_the_last_step_is_found() {
        let (b, l) = (12usize, 2u32);
        let steps = b.pow(l);
        let f = steps - 1;
        let p = tree(b, l, trace(9, steps, None));
        let c = tree(b, l, trace(9, steps, Some(f)));
        let (_, out) = run(&p, &c).unwrap();
        assert_eq!(out.step, f);
    }
}
