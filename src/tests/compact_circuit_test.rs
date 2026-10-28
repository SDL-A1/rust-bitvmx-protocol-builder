//! The endgame's circuit, wired: loaded, garbled, committed, released.
//!
//! The fixture is option A3's own circuit, 3,437 AND gates, with vectors
//! from the model it was translated from.  A disagreement here is a
//! disagreement with that model.

#[cfg(test)]
mod tests {
    use crate::compact::bristol::{Circuit, Gate, ParseError};
    use crate::compact::endgame::{adjudicate, Endgame, Outcome};
    use crate::compact::garble::{colour, evaluate, xor, Garbled, Label, LABEL_LEN};
    use crate::compact::graph::{Graph, Leaf, Params, Role};
    use crate::compact::release::{
        commit_inputs, open_inputs, pad, BitCommitment, Release, A3_TWEAK, COMPRESSION_TWEAK,
    };
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    const A3: &str = include_str!("fixtures/rv32i_verdict.bristol");
    const A3_VECTORS: &str = include_str!("fixtures/rv32i_verdict.vectors");

    /// A deterministic label source.  Tests must not be flaky, and a
    /// garbling is a function of its randomness.
    fn labels_from(seed: u8) -> impl FnMut() -> Label {
        let mut n: u64 = 0;
        move || {
            n += 1;
            let mut m = [0u8; 9];
            m[0] = seed;
            m[1..].copy_from_slice(&n.to_le_bytes());
            let d = sha256::Hash::hash(&m).to_byte_array();
            let mut l = [0u8; LABEL_LEN];
            l.copy_from_slice(&d[..LABEL_LEN]);
            l
        }
    }

    fn a3() -> Circuit {
        Circuit::parse(A3).expect("the A3 fixture parses")
    }

    fn vectors() -> Vec<(String, Vec<bool>, bool)> {
        A3_VECTORS
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let name = it.next().unwrap().to_string();
                let ins = it.next().unwrap().bytes().map(|b| b == b'1').collect();
                let out = it.next().unwrap() == "1";
                (name, ins, out)
            })
            .collect()
    }

    // -- the format -----------------------------------------------------

    /// Two inputs, `a AND NOT b`, one output.  Small enough to read.
    const TINY: &str = "2 4\n1 2\n1 1\n\n1 1 1 2 INV\n2 1 0 2 3 AND\n";

    #[test]
    fn a_small_circuit_parses_and_computes() {
        let c = Circuit::parse(TINY).unwrap();
        assert_eq!((c.n_inputs, c.n_outputs, c.and_count()), (2, 1, 1));
        assert_eq!(c.gates.len(), 2);
        assert_eq!(c.gates[0], Gate::Inv { a: 1, out: 2 });
        for (a, b, want) in [
            (false, false, false),
            (false, true, false),
            (true, false, true),
            (true, true, false),
        ] {
            let w = c.eval(&[a, b]);
            assert_eq!(c.outputs(&w), vec![want], "{a} AND NOT {b}");
        }
    }

    #[test]
    fn the_first_output_is_the_top_wire() {
        let c = a3();
        assert_eq!(c.output_wire(0), c.n_wires - 1);
        // the convention the loader depends on, stated as a test rather
        // than left in a comment
        assert!(matches!(
            Circuit::parse("1 3\n1 2\n1 1\n\n2 1 0 1 2 XOR\n"),
            Ok(_)
        ));
        assert!(matches!(
            // the last gate does not write the top wire
            Circuit::parse("1 4\n1 2\n1 1\n\n2 1 0 1 2 XOR\n"),
            Err(ParseError::OutputsNotOnTop)
        ));
    }

    #[test]
    fn malformed_files_are_rejected_rather_than_guessed_at() {
        for (why, s) in [
            ("no header", ""),
            (
                "a gate count that does not match",
                "9 5\n1 2\n1 1\n\n2 1 0 1 2 XOR\n",
            ),
            (
                "a wire beyond the declared count",
                "1 3\n1 2\n1 1\n\n2 1 0 9 2 XOR\n",
            ),
            ("an unknown gate", "1 3\n1 2\n1 1\n\n2 1 0 1 2 NAND\n"),
            (
                "an arity that does not match",
                "1 3\n1 2\n1 1\n\n3 1 0 1 2 XOR\n",
            ),
            (
                "input sizes that do not count",
                "1 3\n2 2\n1 1\n\n2 1 0 1 2 XOR\n",
            ),
        ] {
            assert!(Circuit::parse(s).is_err(), "accepted {why}");
        }
    }

    #[test]
    fn the_fixture_is_the_circuit_the_paper_measures() {
        let c = a3();
        assert_eq!(c.n_inputs, 450, "289 bits of step, 161 of claim");
        assert_eq!(c.n_outputs, 1, "a verdict, not a state");
        assert_eq!(c.gates.len(), 11_317);
        assert_eq!(c.and_count(), 3_437);
    }

    #[test]
    fn plain_evaluation_agrees_with_the_model() {
        let c = a3();
        let v = vectors();
        assert_eq!(v.len(), 128);
        let mut lies = 0;
        for (name, ins, want) in &v {
            assert_eq!(c.outputs(&c.eval(ins))[0], *want, "{name}");
            lies += usize::from(*want);
        }
        assert_eq!(lies, 64, "half the vectors are lies");
    }

    // -- the garbling ---------------------------------------------------

    #[test]
    fn a_garbled_evaluation_agrees_wire_for_wire() {
        let c = a3();
        let g = Garbled::new(&c, labels_from(7));
        for (name, ins, _) in vectors().iter().take(6) {
            let plain = c.eval(ins);
            let wires = evaluate(&c, g.tables(), &g.encode(&c, ins));
            for w in 0..c.n_wires {
                assert_eq!(g.decode(w, &wires[w]), Some(plain[w]), "{name} wire {w}");
            }
        }
    }

    #[test]
    fn free_xor_holds_and_the_table_is_two_ciphertexts_an_and_gate() {
        let c = a3();
        let g = Garbled::new(&c, labels_from(11));
        let delta = xor(&g.label(0, false), &g.label(0, true));
        for w in 0..c.n_wires {
            assert_eq!(
                xor(&g.label(w, false), &g.label(w, true)),
                delta,
                "wire {w}"
            );
        }
        assert_eq!(g.tables().len(), c.and_count());
        assert_eq!(g.tables().size(), c.and_count() * 2 * LABEL_LEN);
        // point-and-permute needs the offset's colour bit set
        assert!(colour(&delta));
    }

    // -- the commitment -------------------------------------------------

    #[test]
    fn a_commitment_opens_to_one_bit_and_a_foreign_label_to_neither() {
        let c = a3();
        let g = Garbled::new(&c, labels_from(13));
        let labels = g.input_labels(&c);
        let commits = commit_inputs(&labels);
        assert_eq!(commits.len(), 450);
        for (w, b) in commits.iter().zip(&labels) {
            assert_eq!(w.opens(&b[0]), Some(false));
            assert_eq!(w.opens(&b[1]), Some(true));
            assert_eq!(w.opens(&[0xab; LABEL_LEN]), None);
        }
        // a different garbling's labels do not open this one's commitments
        let other = Garbled::new(&c, labels_from(14));
        assert!(open_inputs(&commits, &other.encode(&c, &[false; 450])).is_none());
    }

    // -- the release ----------------------------------------------------

    #[test]
    fn the_pad_covers_the_whole_secret() {
        // SHA256 of a 16-byte label is 16 bytes; a secret masked with
        // that would keep half of itself in the clear.
        let p = pad(A3_TWEAK, &[0x5a; LABEL_LEN]);
        assert_eq!(p.len(), 32);
        assert!(p[16..].iter().any(|b| *b != 0), "the tail is not padding");
    }

    #[test]
    fn a_release_opens_under_one_label_and_not_the_other() {
        let secret = [0x42u8; 32];
        let (l0, l1) = ([1u8; LABEL_LEN], [2u8; LABEL_LEN]);
        let r = Release::seal(A3_TWEAK, &l1, &secret);
        assert_eq!(r.open(A3_TWEAK, &l1), Some(secret));
        assert_eq!(r.open(A3_TWEAK, &l0), None);
        // and not under another option's tweak
        assert_eq!(r.open(COMPRESSION_TWEAK, &l1), None);
        assert_eq!(r.h_b, sha256::Hash::hash(&secret).to_byte_array());
    }

    // -- the exchange ---------------------------------------------------

    #[test]
    fn a_lie_releases_the_secret_and_an_honest_claim_does_not() {
        let secret = [0x7fu8; 32];
        let e = Endgame::setup(a3(), A3_TWEAK, &secret, labels_from(17));
        let p = e.published();
        let c = a3();

        let (mut refuted, mut stood) = (0, 0);
        for (name, ins, lying) in vectors() {
            let opened = e.open(&ins);
            assert_eq!(e.verdict(&ins), lying, "{name}");
            match adjudicate(&c, p, A3_TWEAK, &opened) {
                Outcome::Refuted(got) => {
                    assert!(lying, "{name} was honest and still released");
                    assert_eq!(got, secret, "{name}");
                    refuted += 1;
                }
                Outcome::Stands => {
                    assert!(!lying, "{name} was a lie and released nothing");
                    stood += 1;
                }
                Outcome::NotAnOpening => panic!("{name}: the prover's own opening"),
            }
        }
        assert_eq!((refuted, stood), (64, 64));
    }

    #[test]
    fn a_forged_opening_refutes_nothing() {
        let secret = [0x01u8; 32];
        let e = Endgame::setup(a3(), A3_TWEAK, &secret, labels_from(19));
        let c = a3();
        let (_, lie, _) = vectors()
            .into_iter()
            .find(|(n, _, _)| n.ends_with("lie"))
            .unwrap();
        let honest = e.open(&lie);
        assert!(matches!(
            adjudicate(&c, e.published(), A3_TWEAK, &honest),
            Outcome::Refuted(_)
        ));

        // a label the prover never committed to
        let mut forged = honest.clone();
        forged[0] = [0xff; LABEL_LEN];
        assert_eq!(
            adjudicate(&c, e.published(), A3_TWEAK, &forged),
            Outcome::NotAnOpening
        );
        // the wrong width
        assert_eq!(
            adjudicate(&c, e.published(), A3_TWEAK, &honest[..449]),
            Outcome::NotAnOpening
        );
        // the right labels under the wrong option's tweak
        assert_eq!(
            adjudicate(&c, e.published(), COMPRESSION_TWEAK, &honest),
            Outcome::Stands
        );
    }

    #[test]
    fn the_published_material_is_what_the_paper_says() {
        let e = Endgame::setup(a3(), A3_TWEAK, &[0u8; 32], labels_from(23));
        let p = e.published();
        assert_eq!(p.tables.size(), 3_437 * 32, "two ciphertexts an AND gate");
        assert_eq!(p.commitments.len(), 450);
        // 110 kB of table, and 32 bytes of ct
        assert_eq!(p.tables.size(), 109_984);
        assert_eq!(p.size(), 109_984 + 450 * 64 + 32);
    }

    // -- the spend ------------------------------------------------------

    #[test]
    fn the_stake_carries_the_release_leaf_and_the_secret_satisfies_it() {
        let secret = [0x99u8; 32];
        let e = Endgame::setup(a3(), A3_TWEAK, &secret, labels_from(29));
        let h_b = e.published().release.h_b;

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let g = Graph::build(&secp, &key, Params::default().with_release(h_b));

        let stake = g
            .nodes
            .iter()
            .flat_map(|n| &n.outputs)
            .find(|o| o.role == Role::Stake)
            .expect("a stake output");
        let leaf = stake
            .leaves
            .iter()
            .find_map(|l| match l {
                Leaf::PreimageRelease { h_b } => Some(*h_b),
                _ => None,
            })
            .expect("a release leaf");
        assert_eq!(
            leaf, h_b,
            "the leaf commits to the secret the circuit gates"
        );
        assert_eq!(
            sha256::Hash::hash(&secret).to_byte_array(),
            leaf,
            "what the script checks is what the release hands over"
        );
    }

    #[test]
    fn a_different_secret_moves_the_stakes_script_pubkey() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x12; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let spk = |h: [u8; 32]| {
            Graph::build(&secp, &key, Params::default().with_release(h))
                .nodes
                .iter()
                .flat_map(|n| n.outputs.clone())
                .find(|o| o.role == Role::Stake)
                .unwrap()
                .script_pubkey(&secp, &key)
        };
        assert_ne!(spk([0xaa; 32]), spk([0xbb; 32]));
    }

    #[test]
    fn a_bit_commitment_is_one_time_in_the_shape_that_matters() {
        // Two labels of one wire are two preimages of two hashes.  The
        // commitment binds each separately; what it cannot do by itself
        // is stop a prover revealing both, which is why the protocol
        // gives her one opening and the graph gives it one spend.
        let l = [[3u8; LABEL_LEN], [4u8; LABEL_LEN]];
        let c = BitCommitment::of(&l);
        assert_eq!(c.opens(&l[0]), Some(false));
        assert_eq!(c.opens(&l[1]), Some(true));
        assert_ne!(c.h[0], c.h[1]);
    }
}

/// The leaf is a script, so run it.
///
/// Everything above says the circuit releases `P_b`.  This says what
/// `P_b` is good for: a script-path spend of the stake, executed by a
/// real interpreter, with a real BIP341 signature over a real
/// transaction.  Without it the wiring would stop one step short of the
/// chain.
#[cfg(test)]
mod spending_the_release {
    use crate::compact::bristol::Circuit;
    use crate::compact::commitment::signing_message;
    use crate::compact::endgame::{adjudicate, Endgame, Outcome};
    use crate::compact::garble::{Label, LABEL_LEN};
    use crate::compact::graph::{Graph, Leaf, Params, Role};
    use crate::compact::release::A3_TWEAK;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    const A3: &str = include_str!("fixtures/rv32i_verdict.bristol");
    const A3_VECTORS: &str = include_str!("fixtures/rv32i_verdict.vectors");

    fn labels_from(seed: u8) -> impl FnMut() -> Label {
        let mut n: u64 = 0;
        move || {
            n += 1;
            let mut m = [0u8; 9];
            m[0] = seed;
            m[1..].copy_from_slice(&n.to_le_bytes());
            let d = sha256::Hash::hash(&m).to_byte_array();
            let mut l = [0u8; LABEL_LEN];
            l.copy_from_slice(&d[..LABEL_LEN]);
            l
        }
    }

    /// Run the release leaf with the given preimage on the stack.
    fn runs(preimage: &[u8]) -> bool {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x21; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();

        // the secret the circuit would release, and the dispute that gates it
        let secret = [0x5cu8; 32];
        let circuit = Circuit::parse(A3).unwrap();
        let e = Endgame::setup(circuit, A3_TWEAK, &secret, labels_from(31));
        let h_b = e.published().release.h_b;

        // a challenger that evaluates a lie really does hold it
        let (_, lie) = A3_VECTORS
            .lines()
            .find(|l| l.split_whitespace().next().unwrap().ends_with("lie"))
            .map(|l| {
                let mut it = l.split_whitespace();
                (
                    it.next().unwrap().to_string(),
                    it.next()
                        .unwrap()
                        .bytes()
                        .map(|b| b == b'1')
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        let held = match adjudicate(
            &Circuit::parse(A3).unwrap(),
            e.published(),
            A3_TWEAK,
            &e.open(&lie),
        ) {
            Outcome::Refuted(s) => s,
            other => panic!("a lie should refute, got {other:?}"),
        };
        assert_eq!(
            held, secret,
            "the challenger holds the secret the leaf wants"
        );

        // the stake output, with its release leaf
        let g = Graph::build(&secp, &key, Params::default().with_release(h_b));
        let stake = g
            .nodes
            .iter()
            .flat_map(|n| &n.outputs)
            .find(|o| o.role == Role::Stake)
            .unwrap()
            .clone();
        let info = stake.spend_info(&secp, &key).expect("a taptree");
        let script = stake
            .leaves
            .iter()
            .filter(|l| **l != Leaf::KeyPathPublication)
            .find_map(|l| match l {
                Leaf::PreimageRelease { .. } => {
                    Some(crate::compact::graph::Output::release_script(l, &key))
                }
                _ => None,
            })
            .expect("the release leaf's script");
        let control = info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("the leaf is in the tree");

        // a transaction that spends it
        let prevout = TxOut {
            value: Amount::from_sat(stake.value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        };
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(stake.value - 1_000),
                script_pubkey: prevout.script_pubkey.clone(),
            }],
        };
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        let prevouts = [prevout.clone()];
        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            None,
            Some((leaf_hash, 0xFFFF_FFFF)),
            TapSighashType::Default,
        )
        .expect("the tapscript signing message");
        let sighash = sha256::Hash::hash(&msg).to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp);

        // bottom of the stack first: OP_SHA256 reads the preimage, so it
        // must be on top, and OP_CHECKSIG reads the signature under it
        let stack = vec![sig.serialize().to_vec(), preimage.to_vec()];
        let mut w = Witness::new();
        for item in &stack {
            w.push(item);
        }
        w.push(script.as_bytes());
        w.push(control.serialize());
        tx.input[0].witness = w;

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx,
                prevouts: vec![prevout],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((leaf_hash, None)),
            },
            script,
            stack,
        )
        .expect("the interpreter accepts the script");
        loop {
            if exec.exec_next().is_err() {
                break;
            }
        }
        exec.result().expect("a result").success
    }

    #[test]
    fn the_released_secret_spends_the_stake() {
        assert!(runs(&[0x5cu8; 32]), "P_b should spend the release leaf");
    }

    #[test]
    fn any_other_preimage_does_not() {
        assert!(!runs(&[0x5du8; 32]), "a wrong secret must not spend it");
        assert!(!runs(&[]), "nor an empty one");
        assert!(!runs(&[0x5cu8; 31]), "nor a truncated one");
    }
}
