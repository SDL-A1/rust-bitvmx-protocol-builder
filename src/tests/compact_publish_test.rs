//! Publishing a dissection in an output, end to end at script level.
//!
//! The medium's claim is that a stage's dissection can reach the chain
//! as data rather than as commitments Script reads, and still be bound
//! to its publisher in one compression. These check both halves against
//! real sighash code and a real interpreter: that the committing
//! signature's message carries the publication's own digest, and that
//! the slot it spends actually spends.

#[cfg(test)]
mod tests {
    use crate::compact::checkpoints::{
        publication, publication_framed, FramedFor, Node, NODE_BYTES,
    };
    use crate::compact::commitment::signing_message;
    use crate::compact::output::{
        self, COMMITTING_INPUT, PINNING_INPUT, PUBLICATION_VOUT,
    };
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::key::Keypair;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, TapSighashType, Transaction, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    /// A dissection of twelve interior states: the smallest feasible
    /// publication, four FlatMerkle elements.
    fn dissection() -> Vec<Node> {
        (0..12u8).map(|i| [i.wrapping_mul(31); NODE_BYTES]).collect()
    }

    fn keys(byte: u8) -> (Secp256k1<bitcoin::secp256k1::All>, Keypair) {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap());
        (secp, kp)
    }

    #[test]
    fn the_publication_sits_where_sighash_single_signs() {
        let sf = publication_framed(&dissection(), FramedFor::Output);
        let tx = output::data_transaction(OutPoint::null(), OutPoint::null(), &sf);

        assert_eq!(tx.input.len(), 2, "one to commit, one to pin");
        assert_eq!(tx.output.len(), 1);
        assert_eq!(COMMITTING_INPUT, 0);
        assert_eq!(PINNING_INPUT, 1);
        assert_eq!(
            PUBLICATION_VOUT, COMMITTING_INPUT,
            "SIGHASH_SINGLE signs the output at the signing input's index"
        );
        assert_eq!(tx.output[PUBLICATION_VOUT], output::txout_for(&sf));
    }

    /// The point of the frame: the serialized output's own digest *is*
    /// the FlatMerkle digest of the file inside it, so one compression
    /// of the signature's final block reaches the publication.
    /// And a file framed for the annex does not publish in an output.
    /// The two headers differ, so the digest the signature reaches is
    /// not the file's.
    #[test]
    fn an_annex_framed_file_does_not_publish_in_an_output() {
        let for_output = publication_framed(&dissection(), FramedFor::Output);
        let for_annex = publication(&dissection());
        assert_ne!(
            for_output.digest, for_annex.digest,
            "the medium is part of what is committed"
        );

        let txout = output::txout_for(&for_annex);
        let mut serialized = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(&txout, &mut serialized).unwrap();
        assert_ne!(
            sha256::Hash::hash(&serialized).to_byte_array(),
            for_annex.digest,
            "an annex-framed file in an output commits to nothing openable"
        );
    }

    #[test]
    fn the_outputs_digest_is_the_publications_digest() {
        let sf = publication_framed(&dissection(), FramedFor::Output);
        let txout = output::txout_for(&sf);

        let mut serialized = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(&txout, &mut serialized).unwrap();
        let digest = sha256::Hash::hash(&serialized).to_byte_array();

        assert_eq!(
            digest, sf.digest,
            "the framed output must hash to the file's own digest"
        );
    }

    /// And the slot spends. The publisher signs input 0 with
    /// SIGHASH_SINGLE under its own key, and a real interpreter accepts
    /// the leaf.
    #[test]
    fn the_publisher_spends_its_slot() {
        let (secp, kp) = keys(0x4d);
        let (publisher, _) = kp.x_only_public_key();
        let sf = publication_framed(&dissection(), FramedFor::Output);

        // The slot: a taproot output whose leaf 0 is the publisher's.
        let leaf = ScriptBuf::builder()
            .push_x_only_key(&publisher)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, publisher)
            .unwrap();
        let slot = TxOut {
            value: Amount::from_sat(600),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        };
        let fee = slot.clone();

        let mut tx = output::data_transaction(OutPoint::null(), OutPoint::null(), &sf);
        let prevouts = [slot.clone(), fee.clone()];
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);

        // SIGHASH_SINGLE on the committing input: it signs output 0,
        // which is the publication.
        let msg = signing_message(
            &tx,
            COMMITTING_INPUT,
            &Prevouts::All(&prevouts),
            None,
            Some((leaf_hash, 0xFFFF_FFFF)),
            TapSighashType::Single,
        )
        .expect("the tapscript signing message");
        let sighash = sha256::Hash::hash(&msg).to_byte_array();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp);

        // A SIGHASH_SINGLE signature is 65 bytes: the hash type is appended.
        let mut sig_bytes = sig.serialize().to_vec();
        sig_bytes.push(TapSighashType::Single as u8);

        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        let stack = vec![sig_bytes.clone()];
        let mut w = Witness::new();
        w.push(&sig_bytes);
        w.push(leaf.as_bytes());
        w.push(&control);
        tx.input[COMMITTING_INPUT].witness = w;

        assert!(
            run(tx, prevouts.to_vec(), leaf, leaf_hash, stack),
            "the publisher must be able to spend its own slot"
        );
    }

    fn run(
        tx: Transaction,
        prevouts: Vec<TxOut>,
        script: ScriptBuf,
        leaf_hash: TapLeafHash,
        stack: Vec<Vec<u8>>,
    ) -> bool {
        let mut exec = Exec::new(
            ExecCtx::Tapscript,
            Options::default(),
            TxTemplate {
                tx,
                prevouts,
                input_idx: COMMITTING_INPUT,
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

    // --- the counterparty's side: reading the dissection back ---------

    use crate::compact::checkpoints::{unpack, PER_ELEMENT};
    use crate::compact::flatmerkle::{elements_from_raw, item_is_data, total_raw_len};

    /// The whole round trip, which is what the medium has to deliver:
    /// the states a stage dissected come back out of the transaction
    /// that carried them, byte for byte, with nothing shared between the
    /// two parties but the chain.
    #[test]
    fn a_dissection_survives_the_round_trip_through_a_transaction() {
        let states = dissection();
        let sf = publication_framed(&states, FramedFor::Output);
        let tx = output::data_transaction(OutPoint::null(), OutPoint::null(), &sf);

        let body = output::body_from_transaction(&tx).expect("a publication");
        assert_eq!(body, sf.raw_bytes, "the file comes back whole");

        // And the states come back out of the file. The reader knows
        // only N, which the protocol fixes; everything else it works out
        // from the layout.
        let elements = elements_from_raw(&body, sf.n).expect("a file of N elements");
        assert_eq!(elements, sf.elements, "the data elements, and only those");
        let recovered = unpack(&elements, states.len());
        assert_eq!(recovered, states, "every state, in order");
    }

    /// A reader accepts the layout this protocol lays down and nothing
    /// else. What a publisher put somewhere else is a publication that
    /// did not happen, which the profile dispute decides rather than a
    /// lenient parser.
    #[test]
    fn a_reader_accepts_only_the_protocols_layout() {
        let sf = publication_framed(&dissection(), FramedFor::Output);
        let good = output::txout_for(&sf);

        // Not an OP_RETURN at all.
        let mut t = good.clone();
        t.script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(output::body_from_spk(&t.script_pubkey).is_none());

        // An OP_RETURN with the right body but no frame, so the file
        // would not start on a block boundary.
        let bare = ScriptBuf::from_bytes(
            [vec![0x6a, 0x4e], (sf.raw_bytes.len() as u32).to_le_bytes().to_vec(),
             sf.raw_bytes.clone()].concat(),
        );
        assert!(
            output::body_from_spk(&bare).is_none(),
            "an unframed body is not a publication"
        );

        // A length that does not match the bytes present.
        let mut truncated = good.script_pubkey.as_bytes().to_vec();
        truncated.pop();
        assert!(output::body_from_spk(&ScriptBuf::from_bytes(truncated)).is_none());

        // Filler that is not filler.
        let mut dirty = good.script_pubkey.as_bytes().to_vec();
        dirty[1] = 0x01;
        assert!(output::body_from_spk(&ScriptBuf::from_bytes(dirty)).is_none());
    }

    #[test]
    fn a_publication_must_carry_no_value_and_sit_at_the_signed_index() {
        let sf = publication_framed(&dissection(), FramedFor::Output);
        let mut tx = output::data_transaction(OutPoint::null(), OutPoint::null(), &sf);
        assert!(output::body_from_transaction(&tx).is_some());

        // Value in the publication output would make it spendable-looking
        // and is not what the frame's zero amount hashes.
        tx.output[PUBLICATION_VOUT].value = Amount::from_sat(1);
        assert!(output::body_from_transaction(&tx).is_none());

        // And a transaction with no outputs publishes nothing.
        let empty = Transaction { output: vec![], ..tx.clone() };
        assert!(output::body_from_transaction(&empty).is_none());
    }

    /// Three states to a sixty-four byte element, which is what makes
    /// 191 of them fill exactly 64 elements at the branching factor the
    /// construction is for.
    #[test]
    fn the_packing_is_what_the_branching_factor_rests_on() {
        assert_eq!(PER_ELEMENT, 3);
        assert_eq!(NODE_BYTES, 20);
        assert_eq!(191usize.div_ceil(PER_ELEMENT), 64);
    }

    /// The file is data elements interleaved with MID blocks, and which
    /// is which is a function of N alone.
    #[test]
    fn the_layout_is_known_from_n_alone() {
        for n in [4usize, 8, 16, 32, 64] {
            let kinds = item_is_data(n);
            assert_eq!(kinds.len(), 2 * n - 2, "N = {n}: 2N - 2 items");
            assert_eq!(
                kinds.iter().filter(|d| **d).count(),
                n,
                "N = {n}: N of them are data"
            );
            assert_eq!(kinds.len() * 64, total_raw_len(n));
        }
    }

    /// A reader given the wrong N, or bytes that are not a file, gets
    /// nothing rather than a plausible-looking answer.
    #[test]
    fn a_reader_refuses_what_is_not_a_file_of_n_elements() {
        let sf = publication_framed(&dissection(), FramedFor::Output);
        assert!(elements_from_raw(&sf.raw_bytes, sf.n).is_some());

        assert!(elements_from_raw(&sf.raw_bytes, sf.n * 2).is_none(), "wrong N");
        assert!(elements_from_raw(&sf.raw_bytes, 3).is_none(), "N not a power of two");
        assert!(elements_from_raw(&sf.raw_bytes, 2).is_none(), "N below the minimum");
        assert!(
            elements_from_raw(&sf.raw_bytes[..sf.raw_bytes.len() - 1], sf.n).is_none(),
            "a truncated file is not a file"
        );
    }

    /// At the branching factor the construction is for.
    #[test]
    fn a_192_ary_dissection_round_trips() {
        let states: Vec<Node> = (0..191u32)
            .map(|i| {
                let mut h = [0u8; NODE_BYTES];
                h[..4].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        let sf = publication_framed(&states, FramedFor::Output);
        assert_eq!(sf.n, 64, "191 states fill 64 elements");

        let tx = output::data_transaction(OutPoint::null(), OutPoint::null(), &sf);
        let body = output::body_from_transaction(&tx).expect("a publication");
        let elements = elements_from_raw(&body, sf.n).expect("a file");
        assert_eq!(unpack(&elements, states.len()), states);
    }
}
