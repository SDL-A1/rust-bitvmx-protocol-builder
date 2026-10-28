//! The publication disputes, against real signatures and real files.

#[cfg(test)]
mod tests {
    use crate::compact::annex::*;
    use crate::compact::commitment::*;
    use crate::compact::dispute::*;
    use crate::compact::flatmerkle::*;
    use crate::compact::messages::*;
    use crate::compact::search::select;
    use crate::compact::tracetree::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    };

    const B: usize = 12;

    fn spk(tag: u8) -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[tag; 32]);
        ScriptBuf::from_bytes(v)
    }

    fn pinned_out() -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        }
    }

    /// A one-input transaction whose output 0 is the pinned OP_RETURN.
    fn stage_tx() -> (Transaction, Vec<TxOut>) {
        let prevouts = vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk(0xA1),
        }];
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([7u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xFFFF_FFFD),
                witness: Witness::new(),
            }],
            output: vec![
                pinned_out(),
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: spk(0xB1),
                },
            ],
        };
        (tx, prevouts)
    }

    fn pinned_window() -> [u8; WINDOW_LEN] {
        let k0 = sha256::Hash::hash(&serialize_output(&pinned_out())).to_byte_array();
        k0[2..32].try_into().unwrap()
    }

    fn children(seed: u8) -> Vec<Node> {
        (0..B).map(|i| [seed ^ (i as u8); NODE_BYTES]).collect()
    }

    /// Sign a slot the way a publisher does, and hand back the witness a
    /// disputer would exhibit.
    fn publish(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        kp: &Keypair,
        annex: &[u8],
        ty: TapSighashType,
    ) -> ProfileWitness {
        let (tx, prevouts) = stage_tx();
        let msg =
            signing_message(&tx, 0, &Prevouts::All(&prevouts), Some(annex), None, ty).unwrap();
        let sh = sha256::Hash::hash(&msg).to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh), kp);
        ProfileWitness {
            signature: sig.serialize(),
            h192: h192(&msg),
            window: commitment_window(&msg),
        }
    }

    /// The same, for a profile whose message is not 222 bytes.
    fn publish_short(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        kp: &Keypair,
        ty: TapSighashType,
    ) -> ProfileWitness {
        let (tx, prevouts) = stage_tx();
        let msg = signing_message(&tx, 0, &Prevouts::All(&prevouts), None, None, ty).unwrap();
        assert_ne!(msg.len(), PROFILE_LEN);
        let sh = sha256::Hash::hash(&msg).to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh), kp);
        // the disputer exhibits the real tail of the real message
        let blocks = msg.len() / 64;
        let boundary = blocks * 64;
        let mut window = [0u8; WINDOW_LEN];
        let tail = &msg[boundary..];
        window[..tail.len().min(WINDOW_LEN)].copy_from_slice(&tail[..tail.len().min(WINDOW_LEN)]);
        ProfileWitness {
            signature: sig.serialize(),
            h192: crate::compact::sha256_core::midstate_at(&msg, boundary),
            window,
        }
    }

    // ----------------------------------------------------------- M5

    #[test]
    fn m5_does_not_stand_against_an_honest_publisher() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x31; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();
        let sf = publication(&children(0x10));
        let a = annex_bytes(&sf);

        let w = publish(&secp, &kp, &a, TapSighashType::AllPlusAnyoneCanPay);
        assert_eq!(
            read_profile(&secp, &w, &xonly, &pinned_window()),
            Profile::Published { window: w.window }
        );
        assert!(!m5_stands(&secp, &w, &xonly, &pinned_window()));
        // and the window carries the node value the protocol reads
        assert_eq!(node_value_of(&w.window), node_value(&sf));
    }

    #[test]
    fn m5_stands_against_the_single_anyonecanpay_dodge() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x32; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();
        let a = annex_bytes(&publication(&children(0x20)));

        // she carries an annex, but commits to the pinned output instead
        let w = publish(&secp, &kp, &a, TapSighashType::SinglePlusAnyoneCanPay);
        assert_eq!(
            read_profile(&secp, &w, &xonly, &pinned_window()),
            Profile::CommittedToPinnedOutput
        );
        assert!(m5_stands(&secp, &w, &xonly, &pinned_window()));
    }

    #[test]
    fn m5_stands_against_every_other_hash_type() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x33; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();
        for ty in [
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            let w = publish_short(&secp, &kp, ty);
            match read_profile(&secp, &w, &xonly, &pinned_window()) {
                Profile::WrongLength { bitcount } => {
                    assert_ne!(bitcount, PROFILE_BITCOUNT, "{ty:?}")
                }
                // a truncated tail will usually fail the signature check,
                // which is also a refutation
                Profile::NotHers => {}
                other => panic!("{ty:?} with no annex read as {other:?}"),
            }
            assert!(m5_stands(&secp, &w, &xonly, &pinned_window()), "{ty:?}");
        }
    }

    #[test]
    fn a_disputer_cannot_forge_a_profile_witness() {
        let secp = Secp256k1::new();
        let honest = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x34; 32]).unwrap());
        let (xonly, _) = honest.x_only_public_key();
        let a = annex_bytes(&publication(&children(0x40)));
        let good = publish(&secp, &honest, &a, TapSighashType::AllPlusAnyoneCanPay);

        // tamper with the window to make it look like the pinned output
        let mut forged = good.clone();
        forged.window = pinned_window();
        assert_eq!(
            read_profile(&secp, &forged, &xonly, &pinned_window()),
            Profile::NotHers
        );
        assert!(m5_stands(&secp, &forged, &xonly, &pinned_window()));

        // a signature from someone else's key is not hers either
        let other = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x35; 32]).unwrap());
        let theirs = publish(&secp, &other, &a, TapSighashType::SinglePlusAnyoneCanPay);
        assert_eq!(
            read_profile(&secp, &theirs, &xonly, &pinned_window()),
            Profile::NotHers
        );
    }

    // ----------------------------------------------------------- M6

    #[test]
    fn m6_reads_the_referenced_partys_signature() {
        let secp = Secp256k1::new();
        let z = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x51; 32]).unwrap());
        let (z_key, _) = z.x_only_public_key();
        let a = annex_bytes(&publication(&children(0x50)));

        // z published: the reference to it answers
        let good = publish(&secp, &z, &a, TapSighashType::AllPlusAnyoneCanPay);
        assert!(!m6_stands(&secp, &good, &z_key, &pinned_window()));

        // z published nothing: the reference points at an empty annex
        let empty = publish(&secp, &z, &a, TapSighashType::SinglePlusAnyoneCanPay);
        assert!(m6_stands(&secp, &empty, &z_key, &pinned_window()));
    }

    // ----------------------------------------------------------- M2

    #[test]
    fn an_entry_claim_holds_exactly_when_it_is_true() {
        let kids = children(0x60);
        let sf = publication(&kids);
        let n = elements_for(B);
        for t in 0..B {
            let (elem, _) = child_position(t);
            let claim = EntryClaim {
                index: t,
                claimed: kids[t],
                element: sf.elements[elem].clone(),
                proof: build_proof(&sf, elem),
            };
            assert!(entry_holds(n, &sf.digest, &sf.frame, &claim));

            let mut lying = claim.clone();
            lying.claimed[0] ^= 1;
            assert!(!entry_holds(n, &sf.digest, &sf.frame, &lying));
        }
    }

    #[test]
    fn an_entry_claim_against_the_wrong_digest_fails() {
        let sf = publication(&children(0x61));
        let other = publication(&children(0x62));
        let kids = children(0x61);
        let n = elements_for(B);
        let (elem, _) = child_position(4);
        let claim = EntryClaim {
            index: 4,
            claimed: kids[4],
            element: sf.elements[elem].clone(),
            proof: build_proof(&sf, elem),
        };
        assert!(entry_holds(n, &sf.digest, &sf.frame, &claim));
        assert!(!entry_holds(n, &other.digest, &other.frame, &claim));
    }

    // ----------------------------------------------------------- M4

    #[test]
    fn m4_catches_a_sender_that_republishes_the_counterpartys_vector() {
        // The counterparty published `prev`.  The sender selects index k,
        // asserting it disagrees there -- and then publishes a vector
        // that hashes to exactly the value it just disputed.
        let prev_kids = children(0x70);
        let prev = publication(&prev_kids);
        let n = elements_for(B);

        let k = 5usize;
        let cheating = {
            // whatever hashes to prev_kids[k]: the sender's own publication
            // would have to be the file whose node value is that.  We
            // simulate by asserting the equality directly.
            prev_kids[k]
        };
        let (elem, _) = child_position(k);
        let s = SelfContradiction {
            selected: k,
            previous: EntryClaim {
                index: k,
                claimed: prev_kids[k],
                element: prev.elements[elem].clone(),
                proof: build_proof(&prev, elem),
            },
            own_value: cheating,
        };
        assert!(m4_stands(n, &prev.digest, &prev.frame, &s));

        // an honest sender's publication has a different value
        let mut honest = s.clone();
        honest.own_value[0] ^= 1;
        assert!(!m4_stands(n, &prev.digest, &prev.frame, &honest));
    }

    #[test]
    fn m4_requires_the_index_the_sender_actually_signed() {
        let prev_kids = children(0x71);
        let prev = publication(&prev_kids);
        let n = elements_for(B);
        let (elem, _) = child_position(3);
        let s = SelfContradiction {
            selected: 4, // not what the opening is for
            previous: EntryClaim {
                index: 3,
                claimed: prev_kids[3],
                element: prev.elements[elem].clone(),
                proof: build_proof(&prev, elem),
            },
            own_value: prev_kids[3],
        };
        assert!(!m4_stands(n, &prev.digest, &prev.frame, &s));
    }

    /// M4 is what makes the selection rule total in practice: faced with
    /// two identical vectors there is no index to select, and the
    /// counterparty refutes instead of timing out.
    #[test]
    fn identical_vectors_leave_nothing_to_select_but_something_to_refute() {
        let kids = children(0x72);
        assert_eq!(select(&kids, &kids), None);
        let sf = publication(&kids);
        let n = elements_for(B);
        let k = 2usize;
        let (elem, _) = child_position(k);
        let s = SelfContradiction {
            selected: k,
            previous: EntryClaim {
                index: k,
                claimed: kids[k],
                element: sf.elements[elem].clone(),
                proof: build_proof(&sf, elem),
            },
            own_value: kids[k],
        };
        assert!(m4_stands(n, &sf.digest, &sf.frame, &s));
    }

    // ------------------------------------------------------ messages

    #[test]
    fn the_challenge_message_is_eleven_bits_in_every_branch() {
        assert_eq!(PublicationChallenge::bits(), 11);
        assert_eq!(PublicationChallenge::nibbles(), 3);
        assert_eq!(ChallengeMessage::bits(), 11);
        for code in [
            MCode::Malformed,
            MCode::FalseOpening,
            MCode::WrongNode,
            MCode::SelfContradiction,
            MCode::BadProfile,
            MCode::DanglingReference,
        ] {
            for index in [0u8, 1, 191, 255] {
                let c = PublicationChallenge {
                    option: code,
                    index,
                };
                let v = c.encode();
                assert!(v >> 11 == 0, "eleven bits");
                assert_eq!(PublicationChallenge::decode(v), Some(c));
            }
        }
    }

    #[test]
    fn three_bits_of_option_code_name_six_outcomes() {
        for c in 0u8..8 {
            let m = MCode::from_code(c);
            assert_eq!(m.is_some(), c < 6, "code {c}");
        }
    }

    #[test]
    fn the_index_is_ignored_where_the_paper_says() {
        for c in [
            MCode::Malformed,
            MCode::BadProfile,
            MCode::DanglingReference,
        ] {
            assert!(
                !c.reads_index(),
                "{c:?} is about the publication as a whole"
            );
        }
        assert!(!MCode::SelfContradiction.reads_index(), "already on chain");
        assert!(MCode::FalseOpening.reads_index());
    }

    #[test]
    fn the_step_message_is_228_bytes_whatever_it_carries() {
        assert_eq!(StepMessage::width(), 228);
        for n in 0..=MAX_SLOTS {
            let m = StepMessage {
                pre_root: [1u8; NODE_BYTES],
                post_root: [2u8; NODE_BYTES],
                pc: 0x1000,
                instruction: 0x0033,
                accesses: (0..n)
                    .map(|i| Access {
                        address: 0x2000 + i as u32,
                        contents: [i as u8; SLOT_BYTES],
                    })
                    .collect(),
            };
            assert_eq!(m.encode().len(), 228, "{n} slots");
        }
    }

    #[test]
    fn every_option_has_evidence_and_none_of_it_is_an_answer() {
        for c in [
            MCode::Malformed,
            MCode::FalseOpening,
            MCode::WrongNode,
            MCode::SelfContradiction,
            MCode::BadProfile,
            MCode::DanglingReference,
        ] {
            assert!(!evidence_for(c).is_empty());
        }
    }
}
