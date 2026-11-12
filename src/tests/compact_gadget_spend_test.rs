//! C04's resolution, end to end: the evaluator of a garbled circuit
//! produces a signature that Bitcoin's script interpreter accepts.
//!
//! `compact_gsig_test` checks the gadget against libsecp256k1's
//! `verify_schnorr`, which is the right verifier but not the right
//! setting.  What the protocol needs is that the scalar the evaluation
//! telescopes to spends a real output, under a real sighash, through a
//! real interpreter -- and that it spends *that* output and no other.
//!
//! The ordering matters and is the reason this works at all.  A BIP341
//! sighash does not cover the witness of the input it signs, so the
//! message is fixed before the signature exists.  The circuit can
//! therefore compute the challenge for a transaction that does not yet
//! have a witness, which is exactly the shape the dispute needs: the
//! payout transaction is known at setup, and only the question of whether
//! it gets signed is decided at dispute time.

#[cfg(test)]
mod tests {
    use crate::compact::bristol::{Circuit, Gate};
    use crate::compact::commitment::signing_message;
    use crate::compact::garble::{evaluate as geval, Garbled, Label, LABEL_LEN};
    use crate::compact::graph::{Graph, Leaf, Output, Params, Role};
    use crate::compact::gsig::{self, Signer, M4_SIG_TWEAK, MSG_BITS};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

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

    /// A circuit carrying 256 message wires, routed through one free XOR
    /// so the gadget sits on garbled wires rather than on input labels.
    ///
    /// The real M4 circuit computes the challenge from the sighash in one
    /// SHA-256 compression and multiplexes it against a dud.  Neither
    /// changes what is tested here, which is the hand-off from the
    /// evaluation to the interpreter.
    fn carrier() -> (Circuit, Vec<usize>) {
        let n_inputs = MSG_BITS + 1;
        let mut gates = Vec::new();
        let mut wires = Vec::new();
        for i in 0..MSG_BITS {
            let out = n_inputs + i;
            gates.push(Gate::Xor { a: i, b: MSG_BITS, out });
            wires.push(out);
        }
        (
            Circuit {
                n_wires: n_inputs + MSG_BITS,
                n_inputs,
                n_outputs: MSG_BITS,
                gates,
            },
            wires,
        )
    }

    /// Everything the spend needs, assembled once.
    struct Fixture {
        tx: Transaction,
        prevout: TxOut,
        script: ScriptBuf,
        control: Vec<u8>,
        leaf_hash: TapLeafHash,
        sighash: [u8; 32],
        signer: Signer,
    }

    fn fixture() -> Fixture {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x21; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();

        // The gadget's key is its own, and is never used to sign anything
        // directly in this test -- only the circuit produces signatures
        // under it.
        let signer = Signer::new(&[0x9Au8; 32]);
        let gadget_key =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&signer.p_x).expect("x-only");

        let g = Graph::build(&secp, &key, Params::default().with_gadget(gadget_key));
        let stake = g
            .nodes
            .iter()
            .flat_map(|n| &n.outputs)
            .find(|o| o.role == Role::Stake)
            .expect("a stake")
            .clone();
        let info = stake.spend_info(&secp, &key).expect("a taptree");
        let script = stake
            .leaves
            .iter()
            .find_map(|l| match l {
                Leaf::GadgetRelease { .. } => Some(Output::release_script(l, &key)),
                _ => None,
            })
            .expect("the gadget's release leaf");
        let control = info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("the leaf is in the tree")
            .serialize();

        let prevout = TxOut {
            value: Amount::from_sat(stake.value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        };
        let tx = Transaction {
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

        Fixture {
            tx,
            prevout,
            script,
            control,
            leaf_hash,
            sighash: sha256::Hash::hash(&msg).to_byte_array(),
            signer,
        }
    }

    /// Garble, evaluate on the bits of `e`, and return the 64-byte
    /// signature the evaluation telescopes to.
    fn evaluate_to_signature(signer: &Signer, nonce: &[u8; 32], msg: &[u8; 32]) -> [u8; 64] {
        let key = signer.affine(nonce);
        let e = signer.challenge(&key.r_x, msg);

        let (c, wires) = carrier();
        let g = Garbled::new(&c, labels_from(44));
        let sig = gsig::garble(M4_SIG_TWEAK, &g, &wires, &key);

        let mut inputs = gsig::scalar_bits(&e);
        inputs.push(false);
        let out = geval(&c, g.tables(), &g.encode(&c, &inputs));
        let held: Vec<Label> = wires.iter().map(|&w| out[w]).collect();

        gsig::evaluate(M4_SIG_TWEAK, &sig, &held).sig
    }

    /// Run the gadget's release leaf with `sig` on the stack.
    fn runs(f: &Fixture, sig: &[u8]) -> bool {
        let stack = vec![sig.to_vec()];
        let mut w = Witness::new();
        w.push(sig);
        w.push(f.script.as_bytes());
        w.push(&f.control);
        let mut tx = f.tx.clone();
        tx.input[0].witness = w;

        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx,
                prevouts: vec![f.prevout.clone()],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((f.leaf_hash, None)),
            },
            f.script.clone(),
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

    /// The whole claim, in one assertion: nobody signed this.  The scalar
    /// came out of a garbled evaluation, and Bitcoin took it.
    #[test]
    fn a_garbled_evaluation_spends_the_stake() {
        let f = fixture();
        let sig = evaluate_to_signature(&f.signer, &[0x31; 32], &f.sighash);
        assert!(
            runs(&f, &sig),
            "the signature the circuit produced must spend the gadget leaf"
        );
    }

    /// And it spends only this transaction.  The evaluation is bound to
    /// the sighash the circuit was given, so a signature produced for a
    /// different message is worthless here -- which is what makes the
    /// multiplexer a decision and not a formality.
    #[test]
    fn an_evaluation_for_another_message_does_not() {
        let f = fixture();
        let mut other = f.sighash;
        other[0] ^= 1;
        let sig = evaluate_to_signature(&f.signer, &[0x31; 32], &other);
        assert!(
            !runs(&f, &sig),
            "a signature on another sighash must not spend this output"
        );
    }

    /// A garbling fed the wrong message bits yields a scalar, not an
    /// error.  That is by design -- the evaluator cannot tell a bad
    /// garbling from a good one before it spends -- and the interpreter
    /// is where it is caught.
    #[test]
    fn a_wrong_assignment_yields_a_scalar_that_simply_fails() {
        let f = fixture();
        let key = f.signer.affine(&[0x31; 32]);

        let (c, wires) = carrier();
        let g = Garbled::new(&c, labels_from(44));
        let sig = gsig::garble(M4_SIG_TWEAK, &g, &wires, &key);

        // the bits of a challenge for nothing in particular
        let mut inputs = gsig::scalar_bits(&[0x77u8; 32]);
        inputs.push(false);
        let out = geval(&c, g.tables(), &g.encode(&c, &inputs));
        let held: Vec<Label> = wires.iter().map(|&w| out[w]).collect();
        let ev = gsig::evaluate(M4_SIG_TWEAK, &sig, &held);

        assert_eq!(ev.sig.len(), 64, "it is a scalar, not an error");
        assert!(!runs(&f, &ev.sig), "and it does not spend anything");
    }

    #[test]
    fn a_truncated_or_empty_signature_does_not_spend() {
        let f = fixture();
        let sig = evaluate_to_signature(&f.signer, &[0x31; 32], &f.sighash);
        assert!(!runs(&f, &sig[..63]), "a truncated signature");
        assert!(!runs(&f, &[]), "nor an empty one");
    }

    /// The witness the paper prices: one signature, the script, the
    /// control block, and no preimage.
    #[test]
    fn the_witness_is_the_one_the_paper_prices() {
        let f = fixture();
        let sig = evaluate_to_signature(&f.signer, &[0x31; 32], &f.sighash);
        let mut w = Witness::new();
        w.push(sig);
        w.push(f.script.as_bytes());
        w.push(&f.control);

        assert_eq!(f.script.as_bytes().len(), 34, "<P_g> CHECKSIG");
        // The stake carries two leaves -- Cooperative and the release --
        // so the control block carries one sibling hash.  An earlier
        // hand count assumed a bare 33-byte block, which would mean a
        // one-leaf tree the stake does not have.
        assert_eq!(f.control.len(), 33 + 32, "internal key, and one sibling");
        assert_eq!(w.len(), 3, "a signature, a script, a control block");
        assert_eq!(w.size(), 1 + 65 + 35 + 66);
        assert_eq!(w.size(), 167, "the figure the cost note quotes");
    }
}
