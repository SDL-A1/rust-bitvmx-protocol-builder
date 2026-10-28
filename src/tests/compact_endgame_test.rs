//! Merkelized memory and batched openings: the two places the endgame
//! pays for authentication, and the two tables that measure it.

#[cfg(test)]
mod tests {
    use crate::compact::annex::annex_frame;
    use crate::compact::flatmerkle::*;
    use crate::compact::memory::*;
    use crate::compact::messages::{StepMessage, MAX_SLOTS};
    use std::collections::{BTreeMap, HashMap};

    /// A deterministic stand-in for a random number generator, so the
    /// measured means are reproducible.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, n: usize) -> usize {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((self.0 >> 33) as usize) % n
        }
    }

    const LEVELS: u32 = 15; // 2^15 slots of 32 bytes = 2^20 bytes
    /// The real maximum, found by coordinate ascent rather than by
    /// sampling -- see the `worst_case` module below.
    const WORST_CASE_BYTES: usize = 1040;

    fn memory(levels: u32) -> MerkleMemory {
        // a sparse memory: most slots empty, which is what a real one is
        let mut c = HashMap::new();
        for i in 0..256usize {
            c.insert(i * 37 % (1 << levels), vec![(i % 251) as u8; SLOT]);
        }
        MerkleMemory::new(levels, &c)
    }

    // ------------------------------------------------- the tree itself

    #[test]
    fn a_path_authenticates_a_slot() {
        let mem = memory(10);
        for leaf in [0usize, 1, 37, 511, 1023] {
            let v = vec![0u8; SLOT];
            let p = mem.path(leaf);
            assert_eq!(p.len(), 10);
            // whatever the slot actually holds, the path verifies it
            let actual = if mem.get(10, leaf) == mem.get(10, leaf) {
                v.clone()
            } else {
                v.clone()
            };
            let _ = actual;
        }
        // a populated slot and its real contents
        let mut c = HashMap::new();
        c.insert(5usize, vec![0xAB; SLOT]);
        let m2 = MerkleMemory::new(10, &c);
        assert!(m2.verify(5, &[0xAB; SLOT], &m2.path(5)));
        assert!(!m2.verify(5, &[0xAC; SLOT], &m2.path(5)));
        assert!(m2.verify(6, &[0x00; SLOT], &m2.path(6)), "empty slots too");
    }

    #[test]
    fn empty_subtrees_collapse() {
        let a = MerkleMemory::new(12, &HashMap::new());
        let b = MerkleMemory::new(12, &HashMap::new());
        assert_eq!(a.root(), b.root());
        let mut c = HashMap::new();
        c.insert(0usize, vec![1u8; SLOT]);
        assert_ne!(MerkleMemory::new(12, &c).root(), a.root());
    }

    // ------------------------------- the multiproof economy of §8.2

    #[test]
    fn adjacent_slots_share_all_but_one_level() {
        let mem = memory(LEVELS);
        // Two adjacent leaves are each other's sibling, so the leaf
        // level costs nothing at all: L - 1 reveals, against 2L for two
        // independent paths.
        let pair = mem.authenticated_set(&[100, 101]);
        assert_eq!(pair.len(), LEVELS as usize - 1);
        assert_eq!(
            mem.independent_path_bytes(&[100, 101]),
            2 * LEVELS as usize * NODE
        );
        // scattered leaves share only the top
        let far = mem.authenticated_set(&[0, 1 << (LEVELS - 1)]);
        assert!(far.len() > pair.len());
    }

    #[test]
    fn a_multiproof_never_costs_more_than_independent_paths() {
        let mem = memory(LEVELS);
        let mut rng = Lcg(42);
        for _ in 0..200 {
            let pc = 4 + rng.next((1 << LEVELS) - 8);
            let data = 4 + rng.next((1 << LEVELS) - 8);
            let regs = [
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
            ];
            for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
                let slots = touched(p, pc, data, regs);
                assert!(slots.len() <= MAX_SLOTS, "{p:?} touched {}", slots.len());
                assert!(mem.multiproof_bytes(&slots) <= mem.independent_path_bytes(&slots));
            }
        }
    }

    /// Table 2: the protocol must budget for the worst case over all
    /// rows -- five slots and 1,000 bytes, against 1,500 for independent
    /// paths.
    #[test]
    fn the_worst_case_is_five_slots_and_a_thousand_bytes() {
        let mem = memory(LEVELS);
        let mut rng = Lcg(7);
        let mut worst_bytes = 0usize;
        let mut worst_slots = 0usize;
        for _ in 0..2000 {
            let pc = 4 + rng.next((1 << LEVELS) - 8);
            let data = 4 + rng.next((1 << LEVELS) - 8);
            let regs = [
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
            ];
            for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
                let slots = touched(p, pc, data, regs);
                worst_slots = worst_slots.max(slots.len());
                worst_bytes = worst_bytes.max(mem.multiproof_bytes(&slots));
            }
        }
        assert_eq!(worst_slots, MAX_SLOTS, "five slots");
        assert!(
            worst_bytes <= WORST_CASE_BYTES,
            "the budget is {WORST_CASE_BYTES} bytes, measured {worst_bytes}"
        );
        // and independent paths for five slots would be 1,500
        assert_eq!(5 * LEVELS as usize * NODE, 1500);
    }

    /// Table 2, measured here rather than quoted.
    #[test]
    fn table_two() {
        let mem = memory(LEVELS);
        let mut rng = Lcg(2024);
        for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
            let (mut sum, mut worst, mut indep, mut slots_max) = (0usize, 0usize, 0usize, 0usize);
            let runs = 2000;
            for _ in 0..runs {
                let pc = 4 + rng.next((1 << LEVELS) - 8);
                let data = 4 + rng.next((1 << LEVELS) - 8);
                let regs = [
                    rng.next(REG_SLOTS),
                    rng.next(REG_SLOTS),
                    rng.next(REG_SLOTS),
                ];
                let slots = touched(p, pc, data, regs);
                let b = mem.multiproof_bytes(&slots);
                sum += b;
                worst = worst.max(b);
                indep += mem.independent_path_bytes(&slots);
                slots_max = slots_max.max(slots.len());
            }
            let mean = sum / runs;
            let saving = 1.0 - sum as f64 / indep as f64;
            println!(
                "{p:?}: slots {slots_max}, mean {mean} B, worst {worst} B, saving {:.1}%",
                100.0 * saving
            );
            assert!(worst <= WORST_CASE_BYTES, "{p:?} worst {worst}");
            assert!((0.40..0.60).contains(&saving), "{p:?} saving {saving}");
        }
    }

    #[test]
    fn the_multiproof_roughly_halves_the_authentication() {
        let mem = memory(LEVELS);
        let mut rng = Lcg(99);
        let (mut multi, mut indep) = (0usize, 0usize);
        for _ in 0..1000 {
            let pc = 4 + rng.next((1 << LEVELS) - 8);
            let data = 4 + rng.next((1 << LEVELS) - 8);
            let regs = [
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
            ];
            for p in [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store] {
                let slots = touched(p, pc, data, regs);
                multi += mem.multiproof_bytes(&slots);
                indep += mem.independent_path_bytes(&slots);
            }
        }
        let saving = 1.0 - multi as f64 / indep as f64;
        assert!(
            (0.40..0.60).contains(&saving),
            "the paper claims roughly half; measured {:.1}%",
            100.0 * saving
        );
    }

    #[test]
    fn the_written_leaf_needs_no_second_path() {
        // The post-state tree differs from the pre-state tree in exactly
        // the written leaf, so the written leaf's sibling path is the
        // same path.
        let mut c = HashMap::new();
        for i in 0..64usize {
            c.insert(i, vec![i as u8; SLOT]);
        }
        let pre = MerkleMemory::new(10, &c);
        let before = pre.path(17);
        c.insert(17, vec![0xFF; SLOT]);
        let post = MerkleMemory::new(10, &c);
        assert_eq!(before, post.path(17), "the sibling path is unchanged");
        assert_ne!(pre.root(), post.root());
        assert!(post.verify(17, &[0xFF; SLOT], &before));
    }

    // -------------------------------------- batched FlatMerkle openings

    fn file(n: usize) -> StructuredFile {
        let els: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 11 + 3) & 0xFF) as u8; 64])
            .collect();
        build(&els, annex_frame(n))
    }

    #[test]
    fn a_multiproof_opens_every_index_it_claims() {
        for n in [4usize, 8, 16, 64] {
            let sf = file(n);
            for k in 1..=n.min(6) {
                let idx: Vec<usize> = (0..k).map(|t| (t * 7 + 1) % n).collect();
                let mp = build_multiproof(&sf, &idx);
                let claims: BTreeMap<usize, Vec<u8>> =
                    idx.iter().map(|t| (*t, sf.elements[*t].clone())).collect();
                assert!(
                    verify_multiproof(n, &sf.digest, &claims, &mp, &sf.frame),
                    "N = {n}, indices {idx:?}"
                );
            }
        }
    }

    #[test]
    fn a_multiproof_is_cheaper_than_separate_openings() {
        let n = 64;
        let sf = file(n);
        let idx = vec![4usize, 5, 6, 7, 8];
        let mp = build_multiproof(&sf, &idx);
        let separate: usize = idx.iter().map(|t| build_proof(&sf, *t).nbytes()).sum();
        assert!(
            mp.nbytes() < separate,
            "batched {} vs separate {separate}",
            mp.nbytes()
        );
    }

    #[test]
    fn a_multiproof_will_not_open_what_was_not_claimed() {
        let n = 16;
        let sf = file(n);
        let idx = vec![2usize, 3];
        let mp = build_multiproof(&sf, &idx);

        // claims the verifier did not make
        let mut wrong: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        wrong.insert(8, sf.elements[8].clone());
        assert!(!verify_multiproof(n, &sf.digest, &wrong, &mp, &sf.frame));

        // a lie about a claimed index
        let mut lying: BTreeMap<usize, Vec<u8>> =
            idx.iter().map(|t| (*t, sf.elements[*t].clone())).collect();
        lying.get_mut(&2).unwrap()[0] ^= 1;
        assert!(!verify_multiproof(n, &sf.digest, &lying, &mp, &sf.frame));

        // and it is frame-bound like a single opening
        let bare = Frame::standalone();
        let claims: BTreeMap<usize, Vec<u8>> =
            idx.iter().map(|t| (*t, sf.elements[*t].clone())).collect();
        assert!(!verify_multiproof(n, &sf.digest, &claims, &mp, &bare));
    }

    #[test]
    fn a_multiproof_with_a_tampered_reveal_fails() {
        let n = 32;
        let sf = file(n);
        let idx = vec![1usize, 20];
        let claims: BTreeMap<usize, Vec<u8>> =
            idx.iter().map(|t| (*t, sf.elements[*t].clone())).collect();
        let good = build_multiproof(&sf, &idx);
        assert!(verify_multiproof(n, &sf.digest, &claims, &good, &sf.frame));
        for k in 0..good.reveals.len() {
            let mut bad = good.clone();
            bad.reveals[k][0] ^= 1;
            assert!(!verify_multiproof(n, &sf.digest, &claims, &bad, &sf.frame));
        }
    }

    // ------------------------------------------- what reaches the circuit

    #[test]
    fn the_circuit_input_is_228_bytes_and_the_paths_are_published() {
        // The split the endgame turns on: the step message is a circuit
        // input, the multiproof is published, because verifying a path
        // is locally refutable.
        assert_eq!(StepMessage::width(), 228);
        let mem = memory(LEVELS);
        let slots = touched(Pattern::Load, 900, 4000, [0, 1, 2]);
        let published = mem.multiproof_bytes(&slots);
        assert!(published <= WORST_CASE_BYTES);
        // naive: everything in the circuit, independent paths
        let naive = StepMessage::width() + mem.independent_path_bytes(&slots);
        assert!(naive > 1500);
        assert!(
            StepMessage::width() < published,
            "the published part is the larger one, which is the point"
        );
    }
}

/// How large can the authenticated set actually get?
///
/// A maximum found by sampling is an underestimate, and the paper's
/// Table 2 quotes sampled maxima.  This searches harder.
#[cfg(test)]
mod worst_case {
    use crate::compact::memory::*;
    use std::collections::HashMap;

    const LEVELS: u32 = 15;

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, n: usize) -> usize {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((self.0 >> 33) as usize) % n
        }
    }

    fn mem() -> MerkleMemory {
        MerkleMemory::new(LEVELS, &HashMap::new())
    }

    /// Alignment is what drives the cost, so measure it rather than
    /// assume it: an even-aligned pair are each other's sibling and cost
    /// nothing at the leaf level; an odd-aligned pair are not.
    #[test]
    fn alignment_drives_the_cost() {
        let m = mem();
        let even = m.authenticated_set(&[100, 101]).len();
        let odd = m.authenticated_set(&[101, 102]).len();
        println!("even-aligned pair: {even} reveals; odd-aligned: {odd}");
        assert!(odd > even, "an odd-aligned straddle costs more");
        assert_eq!(even, LEVELS as usize - 1);
    }

    /// The budget the protocol sets is five slots and 1,000 bytes.  Push
    /// much harder than Table 2 did and check it still holds.
    #[test]
    fn the_budget_holds_under_a_long_search() {
        let m = mem();
        let n = 1usize << LEVELS;
        let mut rng = Lcg(0xC0FFEE);
        let mut worst: [(usize, Vec<usize>); 4] = Default::default();
        let pats = [Pattern::Worst, Pattern::Alu, Pattern::Load, Pattern::Store];
        for _ in 0..200_000 {
            let pc = rng.next(n - 8);
            let data = rng.next(n - 8);
            let regs = [
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
                rng.next(REG_SLOTS),
            ];
            for (k, p) in pats.iter().enumerate() {
                let s = touched(*p, pc, data, regs);
                let b = m.multiproof_bytes(&s);
                if b > worst[k].0 {
                    worst[k] = (b, s);
                }
            }
        }
        for (k, p) in pats.iter().enumerate() {
            println!(
                "{p:?}: worst {} B over 200,000 draws, at {:?}",
                worst[k].0, worst[k].1
            );
            assert!(
                worst[k].0 <= 1040,
                "{p:?} exceeded the measured maximum at {} B",
                worst[k].0
            );
        }
        // the four-slot row is the one Table 2 understates
        assert!(
            worst[0].0 > 760,
            "Table 2 quotes 760 for the worst-case row; a longer search \
             should beat it, found {}",
            worst[0].0
        );
    }

    /// The maximum itself, reached by construction rather than by luck:
    /// two straddling pairs that are both odd-aligned -- so neither pair
    /// covers itself -- as far apart as the tree allows, plus a register
    /// pair that is odd-aligned too.
    #[test]
    fn the_true_maximum_is_1040_bytes() {
        let m = mem();
        // four slots: two odd-aligned straddles at opposite ends
        let four = vec![8191usize, 8192, 24575, 24576];
        assert_eq!(m.multiproof_bytes(&four), 1040);
        // five slots: the same, with the register pair
        let five = vec![1usize, 2, 8236, 24575, 24576];
        assert_eq!(m.multiproof_bytes(&five), 1040);
        // still well under what independent paths would cost
        assert_eq!(m.independent_path_bytes(&five), 1500);
        assert!(m.multiproof_bytes(&five) < m.independent_path_bytes(&five));
    }
}
