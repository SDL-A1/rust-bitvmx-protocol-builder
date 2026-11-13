//! The annex is signed data, and the builder now signs it.
//!
//! BIP341 strips the annex before the stack a script runs on is formed,
//! which is what makes a published dissection cost no stack at all. What
//! makes it *binding* is that its hash is in the signature-hash message.
//! An input that carries an annex and signs without one commits to
//! nothing, and the two signatures differ, which is what these check.

#[cfg(test)]
mod tests {
    use crate::compact::annex::annex_bytes;
    use crate::compact::checkpoints::{publication, Node, NODE_BYTES};
    use crate::compact::commitment::{commitment_window, signing_message, PROFILE_LEN};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::sighash::{Annex, Prevouts, SighashCache};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Witness,
    };

    fn dissection() -> Vec<Node> {
        (0..12u8).map(|i| [i.wrapping_mul(7); NODE_BYTES]).collect()
    }

    fn spending(prevout: &TxOut) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: prevout.script_pubkey.clone(),
            }],
        }
    }

    fn prevout() -> TxOut {
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![
                0x51, 0x20, // OP_1 <32 bytes>
                0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
                0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            ]),
        }
    }

    /// Signing with the annex and signing without it give different
    /// messages. If they did not, publishing in an annex would bind
    /// nothing.
    #[test]
    fn an_annex_changes_what_is_signed() {
        let out = prevout();
        let tx = spending(&out);
        let prevouts = [out.clone()];
        let annex = annex_bytes(&publication(&dissection()));

        let with = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                Some(Annex::new(&annex).unwrap()),
                None,
                TapSighashType::AllPlusAnyoneCanPay,
            )
            .unwrap();
        let without = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                None,
                None,
                TapSighashType::AllPlusAnyoneCanPay,
            )
            .unwrap();

        assert_ne!(
            with.to_byte_array(),
            without.to_byte_array(),
            "the annex must be inside the signature-hash message"
        );
    }

    /// And a different publication gives a different message, so the
    /// signature is over the dissection and not merely over the fact
    /// that some annex was present.
    #[test]
    fn the_signature_follows_the_publication() {
        let out = prevout();
        let tx = spending(&out);
        let prevouts = [out.clone()];

        let mut other = dissection();
        other[5][0] ^= 1;

        let hash = |states: &[Node]| {
            let a = annex_bytes(&publication(states));
            SighashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    Some(Annex::new(&a).unwrap()),
                    None,
                    TapSighashType::AllPlusAnyoneCanPay,
                )
                .unwrap()
                .to_byte_array()
        };

        assert_ne!(
            hash(&dissection()),
            hash(&other),
            "one flipped bit of one state must move the signature"
        );
    }

    /// The profile the whole construction rests on: with an annex and
    /// `ALL|ANYONECANPAY`, the message is 222 bytes and its last thirty
    /// are the publication's own digest, one compression from the
    /// signature.
    #[test]
    fn the_protocols_profile_is_222_bytes_and_one_compression() {
        let out = prevout();
        let tx = spending(&out);
        let prevouts = [out.clone()];
        let sf = publication(&dissection());
        let annex = annex_bytes(&sf);

        let msg = signing_message(
            &tx,
            0,
            &Prevouts::All(&prevouts),
            Some(&annex),
            None,
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .expect("a signing message");

        assert_eq!(msg.len(), PROFILE_LEN, "the 222-byte profile");
        assert_eq!(
            8 * msg.len(),
            1776,
            "which SHA-256 writes into the block being signed"
        );
        assert_eq!(
            commitment_window(&msg)[..],
            sf.digest[2..32],
            "the last thirty bytes are the publication's digest"
        );
    }

    /// An annex must begin with 0x50 or it is not an annex, and the
    /// builder rejects it rather than signing something else.
    #[test]
    fn an_annex_must_begin_with_0x50() {
        assert!(Annex::new(&[0x50, 0x00, 0x01]).is_ok());
        assert!(Annex::new(&[0x51, 0x00]).is_err());
        assert!(Annex::new(&[]).is_err());

        // What the protocol publishes does.
        let a = annex_bytes(&publication(&dissection()));
        assert_eq!(a.first(), Some(&0x50));
        assert!(Annex::new(&a).is_ok());
    }

    /// And the hash the message carries is the annex's, prefixed by its
    /// length exactly as BIP341 specifies -- which is why the file needs
    /// the frame at all.
    #[test]
    fn the_message_carries_sha_annex_and_not_the_raw_file() {
        let sf = publication(&dissection());
        let a = annex_bytes(&sf);

        let mut prefixed = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(
            &bitcoin::consensus::encode::VarInt(a.len() as u64),
            &mut prefixed,
        )
        .unwrap();
        prefixed.extend_from_slice(&a);

        assert_eq!(
            sha256::Hash::hash(&prefixed).to_byte_array(),
            sf.digest,
            "sha_annex is the framed file's own digest"
        );
        assert_ne!(
            sha256::Hash::hash(&a).to_byte_array(),
            sf.digest,
            "and not the hash of the annex alone"
        );
    }

    // --- and onto the wire --------------------------------------------

    /// BIP341 takes the last witness element as the annex when there are
    /// at least two and it begins with 0x50, so that is where it has to
    /// sit and nowhere else.
    #[test]
    fn the_annex_is_the_last_witness_element() {
        let a = annex_bytes(&publication(&dissection()));

        // A script-path witness: signature, script, control block, annex.
        let mut w = Witness::new();
        w.push([0u8; 64]);
        w.push([0x51u8]);
        w.push([0u8; 33]);
        w.push(&a);

        assert_eq!(w.len(), 4);
        assert_eq!(w.last().unwrap(), &a[..], "the annex is last");
        assert_eq!(
            w.taproot_annex(),
            Some(&a[..]),
            "and BIP341 reads it as the annex"
        );
        assert_eq!(
            w.taproot_control_block().map(|c| c.len()),
            Some(33),
            "with the control block still found underneath it"
        );
    }

    /// And it survives the wire. A node receives the transaction as
    /// bytes, so the annex has to come back out of them unchanged.
    #[test]
    fn the_annex_survives_consensus_serialisation() {
        let out = prevout();
        let mut tx = spending(&out);
        let sf = publication(&dissection());
        let a = annex_bytes(&sf);

        let mut w = Witness::new();
        w.push([0u8; 64]);
        w.push(&a);
        tx.input[0].witness = w;

        let bytes = bitcoin::consensus::serialize(&tx);
        let back: Transaction = bitcoin::consensus::deserialize(&bytes).expect("a transaction");

        assert_eq!(
            back.input[0].witness.taproot_annex(),
            Some(&a[..]),
            "the annex comes back off the wire"
        );
        assert_eq!(
            back.compute_txid(),
            tx.compute_txid(),
            "and does not move the txid, which is what lets the graph be pre-signed"
        );
    }

    /// The property the whole pre-signed graph rests on: a segwit txid
    /// does not cover the witness, so a stage's identity is fixed before
    /// anyone knows what it will publish.
    #[test]
    fn what_a_stage_publishes_does_not_move_its_txid() {
        let out = prevout();
        let base = spending(&out);

        let mut first = base.clone();
        first.input[0].witness = {
            let mut w = Witness::new();
            w.push([0u8; 64]);
            w.push(annex_bytes(&publication(&dissection())));
            w
        };

        let mut other_states = dissection();
        other_states[0][0] ^= 0xff;
        let mut second = base.clone();
        second.input[0].witness = {
            let mut w = Witness::new();
            w.push([0u8; 64]);
            w.push(annex_bytes(&publication(&other_states)));
            w
        };

        assert_ne!(
            first.input[0].witness.taproot_annex(),
            second.input[0].witness.taproot_annex(),
            "two different dissections"
        );
        assert_eq!(
            first.compute_txid(),
            second.compute_txid(),
            "but one txid, which is why the chain can be pre-signed"
        );
        assert_ne!(
            first.compute_wtxid(),
            second.compute_wtxid(),
            "though the wtxid does move, as it must"
        );
    }
}
