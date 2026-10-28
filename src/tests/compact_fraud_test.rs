//! M1: proving that a published file is not a canonical FlatMerkle file.
//!
//! The guarantee is two-sided and both sides are tested here: a corrupt
//! file is always refutable, and a canonical file is never falsely
//! refutable.  The second is the one with the sharp edges.

#[cfg(test)]
mod tests {
    use crate::compact::annex::annex_frame;
    use crate::compact::flatmerkle::*;
    use crate::compact::fraud::*;
    use crate::compact::sha256_core::{BLOCK_SIZE, STATE_SIZE};
    use std::collections::BTreeSet;

    fn file(n: usize) -> StructuredFile {
        let els: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 29 + 7) & 0xFF) as u8; 64])
            .collect();
        build(&els, annex_frame(n))
    }

    /// Corrupt the MID block at `(a, k)` in a file's raw bytes.
    fn corrupt(sf: &StructuredFile, a: usize, k: u32, byte: u8) -> Vec<u8> {
        let items = layout(sf.n);
        let pos = items
            .iter()
            .find_map(|it| match it {
                Item::Mid { pos, a: aa, k: kk } if *aa == a && *kk == k => Some(*pos),
                _ => None,
            })
            .expect("that MID exists");
        let mut raw = sf.raw_bytes.clone();
        raw[pos * BLOCK_SIZE] ^= byte;
        raw
    }

    // --------------------------------------------------- the structure

    #[test]
    fn the_layout_matches_the_file_the_builder_emits() {
        for n in [4usize, 8, 16, 64] {
            let sf = file(n);
            let items = layout(n);
            assert_eq!(items.len(), 2 * n - 2);
            assert_eq!(items.len() * BLOCK_SIZE, sf.raw_bytes.len());
            // positions are 0..M in order
            for (i, it) in items.iter().enumerate() {
                assert_eq!(it.pos(), i);
            }
            // every element appears exactly once as data
            let data: BTreeSet<usize> = items
                .iter()
                .filter_map(|it| match it {
                    Item::Data { i, .. } => Some(*i),
                    _ => None,
                })
                .collect();
            assert_eq!(data.len(), n);
        }
    }

    #[test]
    fn a_canonical_file_has_no_violations() {
        for n in [4usize, 8, 16, 64] {
            let sf = file(n);
            let scan = scan_for_violations(n, &sf.raw_bytes, &sf.frame).expect("scan");
            assert!(scan.violations.is_empty(), "N = {n}");
            assert!(pick_provable_target(&scan).is_none());
            // and the scan reproduces the digest the builder computed
            assert_eq!(scan.state_after.last().copied().unwrap(), sf.raw_state);
        }
    }

    #[test]
    fn self_positions_are_the_targets_own_containing_blocks() {
        let n = 64usize;
        let l = n.trailing_zeros();
        for target in [0usize, 1, 17, 32, 63] {
            let ps = self_positions(l, target);
            assert_eq!(ps.len(), l as usize - 1);
            for (a, k) in ps {
                assert!(a <= target && target < a + (1usize << k), "({a},{k})");
            }
        }
    }

    // ------------------------------------------- corruption is refutable

    #[test]
    fn every_single_corruption_is_refutable() {
        for n in [4usize, 8, 16, 32] {
            let sf = file(n);
            let items = layout(n);
            for it in &items {
                let (a, k) = match it {
                    Item::Mid { a, k, .. } => (*a, *k),
                    _ => continue,
                };
                let raw = corrupt(&sf, a, k, 0x5A);
                let scan = scan_for_violations(n, &raw, &sf.frame).expect("scan");
                assert!(!scan.violations.is_empty(), "N={n} ({a},{k})");

                // the digest of the corrupt file is what a publisher would
                // have committed to
                let bad_digest = {
                    let mut s = scan.state_after.last().copied().unwrap();
                    let pad =
                        crate::compact::sha256_core::length_padding_blocks(sf.frame.hashed_len(n));
                    for blk in pad.chunks(BLOCK_SIZE) {
                        s = crate::compact::sha256_core::compress(&s, blk);
                    }
                    s
                };

                let target = pick_provable_target(&scan).expect("a target");
                let provable = provable_set(&scan, target);
                assert!(!provable.is_empty(), "N={n} ({a},{k})");
                let fp = build_fraud_proof(&scan, target, &provable).expect("a proof");
                assert!(
                    verify_fraud_proof(n, &bad_digest, &fp, &sf.frame, true),
                    "N={n}, corrupted ({a},{k}), target {target}"
                );
            }
        }
    }

    #[test]
    fn several_independent_corruptions_do_not_mask_each_other() {
        let n = 32usize;
        let sf = file(n);
        let mut raw = sf.raw_bytes.clone();
        for (a, k) in [(0usize, 1u32), (8, 2), (16, 1)] {
            let c = corrupt(
                &StructuredFile {
                    raw_bytes: raw.clone(),
                    ..sf.clone()
                },
                a,
                k,
                0x33,
            );
            raw = c;
        }
        let scan = scan_for_violations(n, &raw, &sf.frame).expect("scan");
        assert!(
            scan.violations.len() >= 3,
            "found {}",
            scan.violations.len()
        );
    }

    #[test]
    fn a_proof_is_logarithmic() {
        for n in [8usize, 16, 32, 64, 128] {
            let sf = file(n);
            let raw = corrupt(&sf, 0, 1, 0x11);
            let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
            let target = pick_provable_target(&scan).unwrap();
            let fp = build_fraud_proof(&scan, target, &provable_set(&scan, target)).unwrap();
            let l = n.trailing_zeros() as usize;
            assert_eq!(fp.reveals.len(), l - 1);
            assert!(
                fp.nbytes() <= 2 * BLOCK_SIZE + (l - 1) * STATE_SIZE + (l - 1) * BLOCK_SIZE,
                "N = {n}"
            );
        }
    }

    // ------------------------------- a canonical file is not refutable

    /// The sharp edge: a dishonest claim against a perfectly good file
    /// must fail, including the claim that invents a corruption where
    /// there is none.
    #[test]
    fn a_canonical_file_cannot_be_falsely_refuted() {
        let n = 32usize;
        let sf = file(n);
        let scan = scan_for_violations(n, &sf.raw_bytes, &sf.frame).unwrap();
        for target in [0usize, 1, 7, 16, 31] {
            for (a, k) in self_positions(n.trailing_zeros(), target) {
                // claim this level is violated when it is not
                let fp = build_fraud_proof(&scan, target, &[(a, k)]).expect("built");
                assert!(
                    !verify_fraud_proof(n, &sf.digest, &fp, &sf.frame, true),
                    "a canonical file was refuted at target {target}, ({a},{k})"
                );
            }
        }
    }

    #[test]
    fn a_claim_about_a_level_off_the_targets_path_is_rejected() {
        let n = 32usize;
        let sf = file(n);
        let raw = corrupt(&sf, 0, 1, 0x77);
        let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
        // (0,1) is not one of target 31's own containing blocks
        assert!(build_fraud_proof(&scan, 31, &[(0u32 as usize, 1u32)]).is_none());
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let n = 32usize;
        let sf = file(n);
        let raw = corrupt(&sf, 4, 1, 0x2A);
        let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
        let bad_digest = {
            let mut s = scan.state_after.last().copied().unwrap();
            let pad = crate::compact::sha256_core::length_padding_blocks(sf.frame.hashed_len(n));
            for blk in pad.chunks(BLOCK_SIZE) {
                s = crate::compact::sha256_core::compress(&s, blk);
            }
            s
        };
        let target = pick_provable_target(&scan).unwrap();
        let good = build_fraud_proof(&scan, target, &provable_set(&scan, target)).unwrap();
        assert!(verify_fraud_proof(n, &bad_digest, &good, &sf.frame, true));

        // Not every reveal is load-bearing: where the proof substitutes
        // a closing block, the value that reveal fed is overridden, so
        // altering it changes nothing.  At least one always is, and the
        // reference implementation behaves the same way -- see
        // `a_valid_proof_is_malleable_in_its_masked_reveals` below.
        let rejected = (0..good.reveals.len())
            .filter(|i| {
                let mut bad = good.clone();
                bad.reveals[*i][0] ^= 1;
                !verify_fraud_proof(n, &bad_digest, &bad, &sf.frame, true)
            })
            .count();
        assert!(rejected >= 1, "no reveal was load-bearing");
        // the wrong number of reveals
        let mut short = good.clone();
        short.reveals.pop();
        assert!(!verify_fraud_proof(n, &bad_digest, &short, &sf.frame, true));
        // a byte string that is not the file's
        let mut lying = good.clone();
        for v in lying.actual_mid_bytes.values_mut() {
            v[0] ^= 1;
        }
        assert!(!verify_fraud_proof(n, &bad_digest, &lying, &sf.frame, true));
        // the wrong digest
        assert!(!verify_fraud_proof(n, &sf.digest, &good, &sf.frame, true));
    }

    /// And it is frame-bound, like every other proof in the construction.
    #[test]
    fn a_fraud_proof_does_not_transfer_between_frames() {
        let n = 32usize;
        let sf = file(n);
        let raw = corrupt(&sf, 4, 1, 0x13);
        let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
        let bad_digest = {
            let mut s = scan.state_after.last().copied().unwrap();
            let pad = crate::compact::sha256_core::length_padding_blocks(sf.frame.hashed_len(n));
            for blk in pad.chunks(BLOCK_SIZE) {
                s = crate::compact::sha256_core::compress(&s, blk);
            }
            s
        };
        let target = pick_provable_target(&scan).unwrap();
        let fp = build_fraud_proof(&scan, target, &provable_set(&scan, target)).unwrap();
        assert!(verify_fraud_proof(n, &bad_digest, &fp, &sf.frame, true));
        assert!(!verify_fraud_proof(
            n,
            &bad_digest,
            &fp,
            &Frame::standalone(),
            true
        ));
    }

    /// Either an inclusion or a malformation, for every string: there is
    /// no publication that is hard to prove anything about.
    #[test]
    fn every_string_is_provable_one_way_or_the_other() {
        let n = 16usize;
        let sf = file(n);
        for seed in 0..40u8 {
            let mut raw = sf.raw_bytes.clone();
            // a scattering of arbitrary edits
            for t in 0..4 {
                let at = ((seed as usize * 37 + t * 211) * 7) % raw.len();
                raw[at] ^= seed.wrapping_add(t as u8).wrapping_add(1);
            }
            let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
            let digest = {
                let mut s = scan.state_after.last().copied().unwrap();
                let pad =
                    crate::compact::sha256_core::length_padding_blocks(sf.frame.hashed_len(n));
                for blk in pad.chunks(BLOCK_SIZE) {
                    s = crate::compact::sha256_core::compress(&s, blk);
                }
                s
            };
            match pick_provable_target(&scan) {
                Some(target) => {
                    let pv = provable_set(&scan, target);
                    assert!(!pv.is_empty(), "seed {seed}");
                    let fp = build_fraud_proof(&scan, target, &pv).unwrap();
                    assert!(
                        verify_fraud_proof(n, &digest, &fp, &sf.frame, true),
                        "seed {seed}: malformation not provable"
                    );
                }
                None => {
                    // no MID was touched, so the file is still canonical
                    // in structure and every element opens
                    for i in 0..n {
                        let els: Vec<Vec<u8>> = (0..n)
                            .map(|j| {
                                raw[scan.data_pos[&j] * BLOCK_SIZE
                                    ..scan.data_pos[&j] * BLOCK_SIZE + BLOCK_SIZE]
                                    .to_vec()
                            })
                            .collect();
                        let rebuilt = build(&els, sf.frame.clone());
                        let pf = build_proof(&rebuilt, i);
                        assert!(
                            verify_proof(n, &rebuilt.digest, i, &els[i], &pf, &sf.frame),
                            "seed {seed}: inclusion not provable at {i}"
                        );
                    }
                }
            }
        }
    }

    /// A valid fraud proof can be altered in the reveals its own
    /// substitutions mask, and still verify.
    ///
    /// This is not unsoundness: verification still requires the fold to
    /// reach the real digest *and* a genuine mismatch at an anchored
    /// level, so a canonical file stays unrefutable either way.  It is
    /// malleability, and it is worth pinning down because the obvious
    /// test -- "change any byte, expect rejection" -- fails against it.
    /// The reference implementation does exactly the same.
    #[test]
    fn a_valid_proof_is_malleable_in_its_masked_reveals() {
        let n = 32usize;
        let sf = file(n);
        let raw = corrupt(&sf, 4, 1, 0x2A);
        let scan = scan_for_violations(n, &raw, &sf.frame).unwrap();
        let bad_digest = {
            let mut s = scan.state_after.last().copied().unwrap();
            let pad = crate::compact::sha256_core::length_padding_blocks(sf.frame.hashed_len(n));
            for blk in pad.chunks(BLOCK_SIZE) {
                s = crate::compact::sha256_core::compress(&s, blk);
            }
            s
        };
        let target = pick_provable_target(&scan).unwrap();
        let violated = provable_set(&scan, target);
        let fp = build_fraud_proof(&scan, target, &violated).unwrap();

        // one physical corruption cascades: the scan walks on with the
        // real bytes, so every later checkpoint disagrees too
        assert!(
            violated.len() > 1,
            "a single edit is reported at several levels"
        );

        let tolerant = (0..fp.reveals.len())
            .filter(|i| {
                let mut bad = fp.clone();
                bad.reveals[*i][0] ^= 1;
                verify_fraud_proof(n, &bad_digest, &bad, &sf.frame, true)
            })
            .count();
        assert!(tolerant > 0, "this configuration should mask some reveals");
        assert!(tolerant < fp.reveals.len(), "but not all of them");

        // what malleability does not buy: refuting a good file
        let clean = scan_for_violations(n, &sf.raw_bytes, &sf.frame).unwrap();
        for t in [0usize, 5, 17, 31] {
            for lvl in self_positions(n.trailing_zeros(), t) {
                let forged = build_fraud_proof(&clean, t, &[lvl]).unwrap();
                assert!(!verify_fraud_proof(n, &sf.digest, &forged, &sf.frame, true));
            }
        }
    }
}
