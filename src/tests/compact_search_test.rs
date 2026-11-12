//! The interval search of Compact BitVMX II.
//!
//! Replaces the trace-tree suite of the same name.  The cases that matter
//! are the ones the tree could not handle: equal interior vectors, and a
//! disagreement that falls in the last subinterval.
#[cfg(test)]
mod tests {
    use crate::compact::search::{
        boundary, levels, published_states, run, select, Interval, Outcome, Party,
        SearchError, State,
    };

    fn st(n: u8) -> State {
        [n; 20]
    }

    /// A trace of `steps + 1` states that diverges from `honest` at
    /// `from`: every state at or after `from` differs.
    fn trace(steps: usize, from: usize, tag: u8) -> Vec<State> {
        (0..=steps)
            .map(|j| if j >= from { st(tag) } else { st(j as u8) })
            .collect()
    }

    fn honest(steps: usize) -> Vec<State> {
        (0..=steps).map(|j| st(j as u8)).collect()
    }

    // --- the interval itself ------------------------------------------

    #[test]
    fn a_dissection_has_b_minus_one_interior_points() {
        let iv = Interval { lo: 0, hi: 16 };
        assert_eq!(iv.points(4), vec![4, 8, 12]);
        assert_eq!(iv.points(4).len(), 3, "b - 1 points, not b");
    }

    #[test]
    fn the_endpoints_are_never_published() {
        let iv = Interval { lo: 8, hi: 24 };
        let p = iv.points(4);
        assert!(!p.contains(&iv.lo), "lo is inherited, not published");
        assert!(!p.contains(&iv.hi), "hi is inherited, not published");
    }

    #[test]
    fn subintervals_tile_the_interval() {
        let iv = Interval { lo: 0, hi: 64 };
        let b = 8;
        let mut cur = iv.lo;
        for k in 0..b {
            let s = iv.subinterval(b, k);
            assert_eq!(s.lo, cur, "subinterval {} starts where the last ended", k);
            cur = s.hi;
        }
        assert_eq!(cur, iv.hi, "and the last ends at hi");
    }

    // --- the selection rule, which is the point ------------------------

    #[test]
    fn select_finds_the_first_difference() {
        let published = vec![st(1), st(2), st(9), st(4)];
        let own = vec![st(1), st(2), st(3), st(4)];
        assert_eq!(select(&published, &own), 2);
    }

    #[test]
    fn equal_vectors_select_the_last_subinterval_and_do_not_stall() {
        // The trace-tree version returned NothingToSelect here and needed
        // a dispute option to punish the publisher.  An interval inherits
        // a disagreeing upper endpoint, so the answer is the last one.
        let v = vec![st(1), st(2), st(3)];
        assert_eq!(select(&v, &v), 3, "b - 1 = 3, so subinterval 3 of 0..4");
    }

    #[test]
    fn select_is_total_over_every_vector_pair() {
        // There is no input on which the rule has no answer.
        for first_diff in 0..=3usize {
            let own = vec![st(1), st(2), st(3)];
            let mut published = own.clone();
            if first_diff < 3 {
                published[first_diff] = st(99);
            }
            let k = select(&published, &own);
            assert!(k <= 3, "always names a subinterval");
            assert_eq!(k, first_diff);
        }
    }

    // --- whole searches ------------------------------------------------

    #[test]
    fn a_search_isolates_the_first_divergent_step() {
        let steps = 64;
        let p = honest(steps);
        let c = trace(steps, 37, 200);
        let (stages, out) = run(&p, &c, 8).expect("a dispute");
        assert_eq!(out.step, 36, "the step whose post-state first differs");
        assert_eq!(stages.len(), levels(steps, 8) as usize);
    }

    #[test]
    fn divergence_in_the_last_subinterval_is_found() {
        // The case the equal-vector rule exists for: every interior
        // checkpoint agrees at the top level and only the end differs.
        let steps = 64;
        let p = honest(steps);
        let c = trace(steps, 64, 200);
        let (_, out) = run(&p, &c, 8).expect("a dispute");
        assert_eq!(out.step, 63, "the very last step");
    }

    #[test]
    fn divergence_at_the_first_step_is_found() {
        let steps = 64;
        let p = honest(steps);
        let c = trace(steps, 1, 200);
        let (_, out) = run(&p, &c, 8).expect("a dispute");
        assert_eq!(out.step, 0);
    }

    #[test]
    fn every_divergence_point_is_located_exactly() {
        let steps = 64;
        let p = honest(steps);
        for from in 1..=steps {
            let c = trace(steps, from, 200);
            let (_, out) = run(&p, &c, 8).expect("a dispute");
            assert_eq!(out.step, from - 1, "diverging at {} isolates step {}", from, from - 1);
        }
    }

    #[test]
    fn the_boundary_pre_state_is_the_agreed_endpoint() {
        let steps = 64;
        let p = honest(steps);
        let c = trace(steps, 37, 200);
        let (_, out) = run(&p, &c, 8).expect("a dispute");
        let bd = boundary(&p, &c, &out);
        assert_eq!(bd.pre_state, p[bd.step], "and needs no sibling subtree");
        assert_eq!(bd.pre_state, c[bd.step], "the parties agree on it");
        assert_ne!(bd.prover_post, bd.challenger_post, "and differ after it");
    }

    #[test]
    fn stages_alternate_from_the_prover() {
        let steps = 64;
        let (stages, _) = run(&honest(steps), &trace(steps, 37, 200), 8).unwrap();
        assert_eq!(stages[0].sender, Party::Prover);
        for w in stages.windows(2) {
            assert_ne!(w[0].sender, w[1].sender, "stages alternate");
        }
    }

    // --- the publication layer, which the selection is taken against ---

    /// The reason `run` builds the file rather than leaving it to the
    /// caller: a selection is only sound if it is taken against the bytes
    /// the stage committed to, not against states recomputed alongside.
    ///
    /// So the states read back out of the published file must be the
    /// sender's own states at the interior points -- and this is the only
    /// place that round trip is closed, from a trace through `pack`,
    /// FlatMerkle and back.
    #[test]
    fn a_stage_publishes_the_states_the_counterparty_selects_against() {
        let steps = 64;
        let b = 8;
        let p = honest(steps);
        let c = trace(steps, 37, 0xEE);
        let (stages, _) = run(&p, &c, b).expect("a dispute");

        for st in &stages {
            let own = match st.sender {
                Party::Prover => &p,
                Party::Challenger => &c,
            };
            let want: Vec<State> =
                st.interval.points(b).iter().map(|&t| own[t]).collect();
            assert_eq!(
                published_states(st, b),
                want,
                "stage {} published something other than its own interior states",
                st.index
            );
        }
    }

    /// And the file is a real FlatMerkle commitment, not a container: its
    /// digest moves when any published state does.
    #[test]
    fn the_digest_binds_every_published_state() {
        let steps = 64;
        let b = 8;
        let p = honest(steps);
        let c = trace(steps, 37, 0xEE);
        let (stages, _) = run(&p, &c, b).expect("a dispute");

        let base = stages[0].publication.digest;
        let states = published_states(&stages[0], b);
        assert_eq!(states.len(), b - 1, "the interior states, and only those");

        for i in 0..states.len() {
            let mut altered = states.clone();
            altered[i][0] ^= 1;
            let moved = crate::compact::checkpoints::publication(&altered).digest;
            assert_ne!(
                moved, base,
                "flipping state {i} left the digest alone, so it is not bound"
            );
        }
    }

    #[test]
    fn agreeing_results_are_not_a_dispute() {
        let p = honest(64);
        // Stage holds a StructuredFile, which is not PartialEq, so match
        // on the error rather than comparing the whole Result.
        match run(&p, &p, 8) {
            Err(SearchError::ResultsAgree) => {}
            other => panic!("expected ResultsAgree, got {:?}", other.map(|(s, o)| (s.len(), o))),
        }
    }

    #[test]
    fn four_levels_cover_a_192_ary_search_of_2_to_the_30() {
        assert_eq!(levels(192usize.pow(4), 192), 4);
        assert!(192usize.pow(4) >= 1 << 30);
    }

    #[test]
    fn an_outcome_names_one_digit_per_level_plus_the_trailing_one() {
        let steps = 64;
        let (_, out): (_, Outcome) =
            run(&honest(steps), &trace(steps, 37, 200), 8).unwrap();
        assert_eq!(out.digits.len(), levels(steps, 8) as usize);
    }
}
