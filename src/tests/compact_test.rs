//! Checking the compact-BitVMX publication commitment against real
//! transactions, real BIP341 signing messages and real SHA-256.
//!
//! The arithmetic in the paper is only worth anything if it survives the
//! library that actually builds the transaction, so nothing here is
//! asserted from a formula: every message is produced by
//! `rust-bitcoin`'s own sighash code and then measured.

#[cfg(test)]
mod tests {
    use crate::compact::annex::*;
    use crate::compact::commitment::*;
    use crate::compact::flatmerkle::*;
    use crate::compact::sha256_core::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    };

    // ----------------------------------------------------------------- fixtures

    fn spk(tag: u8) -> ScriptBuf {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[tag; 32]);
        ScriptBuf::from_bytes(v)
    }

    /// Two inputs, two outputs: the shape a stage transaction has.
    fn demo_tx() -> (Transaction, Vec<TxOut>) {
        let prevouts: Vec<TxOut> = (0..2)
            .map(|k| TxOut {
                value: Amount::from_sat(100_000 + k as u64),
                script_pubkey: spk(0xA0 + k),
            })
            .collect();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..2)
                .map(|k| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([k as u8 + 1; 32]),
                        vout: k as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(0xFFFF_FFFD),
                    witness: Witness::new(),
                })
                .collect(),
            output: (0..2)
                .map(|k| TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: spk(0xB0 + k),
                })
                .collect(),
        };
        (tx, prevouts)
    }

    /// A publication of `n` 20-byte node values, three to a 64-byte element.
    fn publication(n_elements: usize) -> StructuredFile {
        let elements: Vec<Vec<u8>> = (0..n_elements)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        build(&elements, annex_frame(n_elements))
    }

    const HASH_TYPES: [(TapSighashType, &str); 7] = [
        (TapSighashType::Default, "DEFAULT"),
        (TapSighashType::All, "ALL"),
        (TapSighashType::None, "NONE"),
        (TapSighashType::Single, "SINGLE"),
        (TapSighashType::AllPlusAnyoneCanPay, "ALL|ACP"),
        (TapSighashType::NonePlusAnyoneCanPay, "NONE|ACP"),
        (TapSighashType::SinglePlusAnyoneCanPay, "SINGLE|ACP"),
    ];

    fn message_len(ty: TapSighashType, annex: Option<&[u8]>) -> usize {
        let (tx, prevouts) = demo_tx();
        signing_message(&tx, 0, &Prevouts::All(&prevouts), annex, None, ty)
            .expect("sighash")
            .len()
    }

    // ------------------------------------------------- the profile table (Table 7)

    #[test]
    fn profile_lengths_match_the_paper() {
        let a = annex_bytes(&publication(8));
        // (hash type, B without annex, B with annex)
        let expected = [
            ("DEFAULT", 239, 271),
            ("ALL", 239, 271),
            ("NONE", 207, 239),
            ("SINGLE", 239, 271),
            ("ALL|ACP", 190, 222),
            ("NONE|ACP", 158, 190),
            ("SINGLE|ACP", 190, 222),
        ];
        for (ty, name) in HASH_TYPES {
            let (_, no, yes) = expected.iter().find(|e| e.0 == name).unwrap();
            assert_eq!(message_len(ty, None), *no, "{name}, no annex");
            assert_eq!(message_len(ty, Some(&a)), *yes, "{name}, annex");
        }
    }

    #[test]
    fn exactly_two_profiles_reach_222_and_both_carry_an_annex() {
        let a = annex_bytes(&publication(8));
        let mut hits = Vec::new();
        for (ty, name) in HASH_TYPES {
            if message_len(ty, None) == PROFILE_LEN {
                hits.push((name, "no annex"));
            }
            if message_len(ty, Some(&a)) == PROFILE_LEN {
                hits.push((name, "annex"));
            }
        }
        assert_eq!(hits, vec![("ALL|ACP", "annex"), ("SINGLE|ACP", "annex")]);
    }

    #[test]
    fn the_length_field_is_1776() {
        let a = annex_bytes(&publication(8));
        let msg = signing_message(
            &demo_tx().0,
            0,
            &Prevouts::All(&demo_tx().1),
            Some(&a),
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();
        let blk = final_block(&commitment_window(&msg));
        let field = u64::from_be_bytes(blk[56..64].try_into().unwrap());
        assert_eq!(field, PROFILE_BITCOUNT);
        assert_eq!(field, 1776);
        assert_eq!(field, 8 * msg.len() as u64);
    }

    // ------------------------------------------- where the annex hash lands

    #[test]
    fn the_annex_hash_straddles_the_block_boundary_at_192() {
        let sf = publication(64);
        let a = annex_bytes(&sf);
        let (tx, prevouts) = demo_tx();
        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            Some(&a),
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();
        let sa = sha_annex(&a);
        // the whole 32-byte hash occupies bytes 190..222 ...
        assert_eq!(&msg[190..222], &sa[..]);
        // ... so its last 30 bytes begin exactly on the boundary at 192
        assert_eq!(commitment_window(&msg)[..], sa[2..32]);
    }

    // ------------------------------------------ the one-compression identity

    #[test]
    fn one_compression_reproduces_the_signature_hash() {
        for n in [4usize, 8, 16, 32, 64, 128] {
            let a = annex_bytes(&publication(n));
            let (tx, prevouts) = demo_tx();
            for ty in [
                TapSighashType::AllPlusAnyoneCanPay,
                TapSighashType::SinglePlusAnyoneCanPay,
            ] {
                let msg =
                    signing_message(&tx, 0, &Prevouts::All(&prevouts), Some(&a), None, ty).unwrap();
                assert_eq!(msg.len(), PROFILE_LEN, "N = {n}");
                let direct = sha256::Hash::hash(&msg).to_byte_array();
                let via = sighash_from_commitment(&h192(&msg), &commitment_window(&msg));
                assert_eq!(direct, via, "N = {n}, one compression must suffice");
            }
        }
    }

    #[test]
    fn the_final_block_is_the_window_plus_fixed_padding() {
        let a = annex_bytes(&publication(16));
        let (tx, prevouts) = demo_tx();
        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            Some(&a),
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();
        let blk = final_block(&commitment_window(&msg));
        assert_eq!(&blk[..30], &msg[192..222]);
        assert_eq!(blk[30], 0x80);
        assert!(blk[31..56].iter().all(|b| *b == 0));
    }

    // --------------------------------- the identity the construction rests on

    #[test]
    fn the_framed_digest_is_exactly_bip341s_sha_annex() {
        for n in [4usize, 8, 16, 32, 64, 128, 256] {
            let sf = publication(n);
            let a = annex_bytes(&sf);
            assert_eq!(
                sf.digest,
                sha_annex(&a),
                "N = {n}: the publication's digest must be what Bitcoin commits to"
            );
        }
    }

    #[test]
    fn without_the_frame_the_identity_fails() {
        // The trap: `SHA256(file)` is not `sha_annex`.  BIP341 hashes
        // compact_size(len) || 0x50 || .. in front of the file, which moves
        // every block boundary inside it.
        let n = 64;
        let elements: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        let bare = build(&elements, Frame::standalone());
        let framed = build(&elements, annex_frame(n));
        let a = annex_bytes(&framed);
        assert_eq!(framed.digest, sha_annex(&a));
        assert_ne!(bare.digest, sha_annex(&a));
        // and the bare digest is the plain hash of the file, as paper 1 has it
        assert_eq!(
            bare.digest,
            sha256::Hash::hash(&bare.raw_bytes).to_byte_array()
        );
    }

    #[test]
    fn the_frame_prefix_is_one_block_and_a_public_function_of_n() {
        for n in [4usize, 64, 256, 1024] {
            let pre = annex_prefix(n);
            assert_eq!(pre.len(), BLOCK_SIZE);
            assert_eq!(pre[compact_size(annex_len(n)).len()], ANNEX_PREFIX_BYTE);
            // the derived iv is C(IV, prefix): no publisher input anywhere
            assert_eq!(annex_frame(n).iv(), compress(&iv_std(), &pre));
            // and the compact size in the prefix is the real annex length
            assert_eq!(
                &pre[..compact_size(annex_len(n)).len()],
                &compact_size(annex_len(n))[..]
            );
        }
    }

    #[test]
    fn the_alignment_header_costs_61_bytes_at_b_192() {
        let n = 64; // 192 children, three to a 64-byte element
        assert_eq!(total_raw_len(n), 8064);
        assert_eq!(annex_len(n), 8125);
        assert_eq!(annex_len(n) - total_raw_len(n), 61);
    }

    // ------------------------------------------- cross-check with the reference

    #[test]
    fn matches_the_python_reference_vector() {
        // loglink_annex.build(64 elements, annex_frame(64)) in the
        // FlatMerkle reference implementation.
        let sf = publication(64);
        assert_eq!(
            hex::encode(sf.digest),
            "249346f6f47e35293fd36778336c77b811ee5a9d2ae40eb36c27f04da9efb716"
        );
        assert_eq!(hex::encode(&annex_prefix(64)[..6]), "fdbd1f500000");
        assert_eq!(sf.raw_bytes.len(), 8064);
    }

    // ------------------------------------------------------- tamper resistance

    #[test]
    fn a_single_flipped_byte_moves_the_commitment() {
        let n = 64;
        let mut elements: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        let before = build(&elements, annex_frame(n)).digest;
        elements[31][0] ^= 1;
        let after = build(&elements, annex_frame(n)).digest;
        assert_ne!(before, after);
    }

    #[test]
    fn a_signature_is_checkable_from_the_commitment_alone() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x42; 32]).unwrap());
        let (xonly, _) = kp.x_only_public_key();

        let a = annex_bytes(&publication(64));
        let (tx, prevouts) = demo_tx();
        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            Some(&a),
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();

        let digest = sha256::Hash::hash(&msg).to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp);

        // the verifier never sees the transaction: only H192 and the window
        let recomputed = sighash_from_commitment(&h192(&msg), &commitment_window(&msg));
        assert!(secp
            .verify_schnorr(&sig, &Message::from_digest(recomputed), &xonly)
            .is_ok());

        // a different window is a different signature hash
        let mut bad = commitment_window(&msg);
        bad[0] ^= 1;
        let wrong = sighash_from_commitment(&h192(&msg), &bad);
        assert!(secp
            .verify_schnorr(&sig, &Message::from_digest(wrong), &xonly)
            .is_err());
    }

    // ------------------------------------------- the pinned SIGHASH_SINGLE output

    #[test]
    fn a_bare_op_return_output_hashes_to_the_constant_in_the_paper() {
        let out = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        };
        let ser = serialize_output(&out);
        assert_eq!(ser.len(), 10);
        assert_eq!(hex::encode(&ser), "0000000000000000016a");
        assert_eq!(
            hex::encode(sha256::Hash::hash(&ser).to_byte_array()),
            "cd496407aff71ffb5742f4f51efeac926c9f84eb51c391b5f2049bd74d9b4a02"
        );
    }

    #[test]
    fn single_anyonecanpay_commits_to_the_output_not_the_annex() {
        // The second 222-byte profile ends on sha_single_output, so the
        // window it yields is the pinned output's hash, not the annex's.
        let sf = publication(64);
        let a = annex_bytes(&sf);
        let (mut tx, prevouts) = demo_tx();
        tx.output[0] = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
        };
        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            Some(&a),
            None,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .unwrap();
        assert_eq!(msg.len(), PROFILE_LEN);
        let k0 = sha256::Hash::hash(&serialize_output(&tx.output[0])).to_byte_array();
        assert_eq!(commitment_window(&msg)[..], k0[2..32]);
        assert_ne!(commitment_window(&msg)[..], sha_annex(&a)[2..32]);
    }

    // --------------------------------------------------------- sanity on the core

    #[test]
    fn compress_and_padding_agree_with_hashlib() {
        for len in [0usize, 1, 55, 56, 63, 64, 65, 191, 192, 222, 8125] {
            let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut buf = msg.clone();
            buf.extend_from_slice(&length_padding_blocks(len));
            let mut state = iv_std();
            for blk in buf.chunks(BLOCK_SIZE) {
                state = compress(&state, blk);
            }
            assert_eq!(state, sha256::Hash::hash(&msg).to_byte_array(), "len {len}");
        }
    }

    #[test]
    #[should_panic(expected = "at least")]
    fn two_elements_is_below_the_floor() {
        // Not a port artefact: the reference implementation raises here too.
        // The recursion bottoms out at block(a, 1), so the top call needs
        // L - 1 >= 1, i.e. N >= 4 -- which is b >= 12.
        let _ = publication(2);
    }

    #[test]
    fn the_file_is_two_n_minus_two_blocks() {
        for n in [4usize, 8, 16, 64, 256] {
            let sf = publication(n);
            assert_eq!(sf.raw_bytes.len(), (2 * n - 2) * BLOCK_SIZE);
            assert_eq!(sf.raw_bytes.len(), total_raw_len(n));
        }
    }
}

/// The witness estimator against the bytes `rust-bitcoin` actually
/// serializes.  An estimate that is merely self-consistent is no use: the
/// annex has to be paid for at the real rate, or every weight in the paper
/// is fiction.
#[cfg(test)]
mod witness_accounting {
    use crate::compact::annex::*;
    use crate::compact::flatmerkle::build;
    use bitcoin::Witness;

    fn publication_annex(n: usize) -> Vec<u8> {
        let elements: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        annex_bytes(&build(&elements, annex_frame(n)))
    }

    /// What one more witness item of `len` bytes adds to the serialized
    /// witness, measured rather than derived.
    fn delta_for_annex(n: usize) -> usize {
        let a = publication_annex(n);
        let sig = vec![0u8; 64];

        let mut without = Witness::new();
        without.push(&sig);

        let mut with = Witness::new();
        with.push(&sig);
        with.push(&a);

        with.size() - without.size()
    }

    #[test]
    fn an_annex_costs_its_length_plus_its_own_length_prefix() {
        for n in [4usize, 64, 256] {
            let a = publication_annex(n);
            let expected = a.len() + compact_size(a.len()).len();
            assert_eq!(
                delta_for_annex(n),
                expected,
                "N = {n}: the item count's compact size does not grow too"
            );
        }
    }

    #[test]
    fn the_b_192_publication_costs_8128_witness_bytes() {
        // 8,064 bytes of file, 61 bytes of alignment header and prefix
        // byte, 3 bytes of compact size for the item.
        let n = 64;
        assert_eq!(annex_len(n), 8125);
        assert_eq!(delta_for_annex(n), 8128);
    }

    #[test]
    fn a_witness_round_trips_through_consensus_encoding() {
        use bitcoin::consensus::{deserialize, serialize};
        let a = publication_annex(64);
        let mut w = Witness::new();
        w.push(vec![0u8; 64]);
        w.push(&a);
        let bytes = serialize(&w);
        let back: Witness = deserialize(&bytes).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back.last().unwrap(), &a[..]);
        // rust-bitcoin recognises it as an annex, by the 0x50 prefix
        assert_eq!(back.taproot_annex(), Some(&a[..]));
    }
}

/// Opening one entry of a publication.  This is the part of the dispute
/// that actually runs, and the part where the frame has to be threaded
/// through verification as well as construction.
#[cfg(test)]
mod openings {
    use crate::compact::annex::*;
    use crate::compact::flatmerkle::*;
    use crate::compact::sha256_core::*;
    use bitcoin::hashes::{sha256, Hash};

    fn publication(n: usize) -> StructuredFile {
        let elements: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        build(&elements, annex_frame(n))
    }

    #[test]
    fn every_element_opens() {
        for n in [4usize, 8, 16, 64] {
            let sf = publication(n);
            for i in 0..n {
                let pf = build_proof(&sf, i);
                assert!(
                    verify_proof(n, &sf.digest, i, &sf.elements[i], &pf, &sf.frame),
                    "N = {n}, index {i}"
                );
            }
        }
    }

    #[test]
    fn an_opening_is_288_bytes_at_b_192() {
        // 64 elements, so six levels: two 64-byte data blocks and five
        // 32-byte state reveals.
        let sf = publication(64);
        let pf = build_proof(&sf, 17);
        assert_eq!(pf.reveals.len(), 5);
        assert_eq!(pf.nbytes(), 2 * 64 + 5 * 32);
        assert_eq!(pf.nbytes(), 288);
    }

    #[test]
    fn opening_cost_is_96_plus_32_log2_n() {
        for n in [4usize, 8, 16, 32, 64, 128, 256] {
            let sf = publication(n);
            let pf = build_proof(&sf, 1);
            // the paper quotes 96 + 32 log2 N for a standalone file; here
            // the pair of data blocks is carried in full, so it is
            // 128 + 32 (log2 N - 1)
            assert_eq!(pf.nbytes(), 128 + 32 * (n.trailing_zeros() as usize - 1));
        }
    }

    #[test]
    fn a_wrong_value_does_not_open() {
        let n = 64;
        let sf = publication(n);
        for i in [0usize, 1, 17, 63] {
            let pf = build_proof(&sf, i);
            let mut wrong = sf.elements[i].clone();
            wrong[0] ^= 1;
            assert!(!verify_proof(n, &sf.digest, i, &wrong, &pf, &sf.frame));
        }
    }

    #[test]
    fn a_tampered_reveal_does_not_open() {
        let n = 64;
        let sf = publication(n);
        for k in 0..5 {
            let mut pf = build_proof(&sf, 17);
            pf.reveals[k][0] ^= 1;
            assert!(!verify_proof(
                n,
                &sf.digest,
                17,
                &sf.elements[17],
                &pf,
                &sf.frame
            ));
        }
    }

    #[test]
    fn a_proof_for_one_index_does_not_open_another() {
        let n = 64;
        let sf = publication(n);
        let pf = build_proof(&sf, 17);
        assert!(!verify_proof(
            n,
            &sf.digest,
            18,
            &sf.elements[18],
            &pf,
            &sf.frame
        ));
    }

    #[test]
    fn a_malformed_proof_is_rejected_rather_than_acted_on() {
        let n = 64;
        let sf = publication(n);
        let good = build_proof(&sf, 17);

        let mut short = good.clone();
        short.reveals.pop();
        assert!(!verify_proof(
            n,
            &sf.digest,
            17,
            &sf.elements[17],
            &short,
            &sf.frame
        ));

        let mut long = good.clone();
        long.reveals.push([0u8; 32]);
        assert!(!verify_proof(
            n,
            &sf.digest,
            17,
            &sf.elements[17],
            &long,
            &sf.frame
        ));

        let mut stunted = good.clone();
        stunted.d0.truncate(32);
        assert!(!verify_proof(
            n,
            &sf.digest,
            17,
            &sf.elements[17],
            &stunted,
            &sf.frame
        ));

        // out of domain
        assert!(!verify_proof(
            n,
            &sf.digest,
            n,
            &sf.elements[0],
            &good,
            &sf.frame
        ));
        assert!(!verify_proof(
            3,
            &sf.digest,
            1,
            &sf.elements[0],
            &good,
            &sf.frame
        ));
    }

    /// The frame is not decoration.  A proof built in the annex frame must
    /// not verify against a standalone digest, or the commitment would not
    /// bind the file to the transaction that published it.
    #[test]
    fn an_opening_does_not_transfer_between_frames() {
        let n = 64;
        let elements: Vec<Vec<u8>> = (0..n)
            .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
            .collect();
        let framed = build(&elements, annex_frame(n));
        let bare = build(&elements, Frame::standalone());
        let pf = build_proof(&framed, 17);

        assert!(verify_proof(
            n,
            &framed.digest,
            17,
            &elements[17],
            &pf,
            &framed.frame
        ));
        // right proof, right file, wrong frame
        assert!(!verify_proof(
            n,
            &framed.digest,
            17,
            &elements[17],
            &pf,
            &bare.frame
        ));
        // and the two digests are different objects
        assert_ne!(framed.digest, bare.digest);
    }

    /// End to end: the challenger holds only the signature and the
    /// commitment window, and opens one child out of it.
    #[test]
    fn a_child_opens_from_the_commitment_window_alone() {
        let n = 64;
        let sf = publication(n);
        let a = annex_bytes(&sf);

        // what a verifier recovers from the signature
        let window = &sha_annex(&a)[2..32];

        // it reconstructs the full digest only if it also knows the two
        // leading bytes -- which it does not, so it compares windows
        let pf = build_proof(&sf, 17);
        assert!(verify_proof(
            n,
            &sf.digest,
            17,
            &sf.elements[17],
            &pf,
            &sf.frame
        ));
        assert_eq!(&sf.digest[2..32], window);

        // the node value the protocol reads is the first 20 of those 30
        let node_value = &window[..20];
        assert_eq!(node_value, &sf.digest[2..22]);
        assert_eq!(node_value.len(), 20);
    }

    #[test]
    fn the_digest_is_the_hash_of_the_framed_string() {
        for n in [4usize, 8, 64] {
            let sf = publication(n);
            let mut framed = sf.frame.prefix.clone();
            framed.extend_from_slice(&sf.raw_bytes);
            assert_eq!(sf.digest, sha256::Hash::hash(&framed).to_byte_array());
            assert_eq!(framed.len(), sf.frame.hashed_len(n));
            assert_eq!(framed.len() % BLOCK_SIZE, 0);
        }
    }
}
