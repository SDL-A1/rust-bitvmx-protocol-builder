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
}
