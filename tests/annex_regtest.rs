//! Does a real node accept a publication in a Taproot annex?
//!
//! The paper assumes two different things about the annex and they are
//! worth separating, because only one of them is a limitation:
//!
//!   * **consensus** must accept the spend, or the construction is dead;
//!   * **policy** need not relay it, because a dispute that has to reach
//!     the chain can go to a miner directly -- but if policy rejects it,
//!     the paper has to say so.
//!
//! This drives a real `bitcoind` in regtest.  The node is built without
//! wallet or generating RPCs, so the test mines its own blocks: a regtest
//! target is trivial to hit and `submitblock` is all that is needed.
//!
//! Ignored by default.  Run with a node listening on $BITCOIN_RPC_URL:
//!   cargo test --test annex_regtest -- --ignored --nocapture --test-threads=1
//!
//! Serially: every test here mines its own blocks against one chain, so
//! two of them in parallel race for the tip.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::block::{Block, Header, Version as BlockVersion};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::Prevouts;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, WitnessMerkleNode,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use protocol_builder::compact::annex::{annex_bytes, annex_frame, sha_annex};
use protocol_builder::compact::commitment::{
    commitment_window, h192, sighash_from_commitment, signing_message, PROFILE_LEN,
};
use protocol_builder::compact::flatmerkle::build;

const COINBASE_MATURITY: u64 = 100;
/// Regtest halves every 150 blocks, and this test mines several hundred.
const HALVING_INTERVAL: u64 = 150;

fn subsidy(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        0
    } else {
        (50 * 100_000_000u64) >> halvings
    }
}

fn rpc() -> Client {
    let url =
        std::env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:19445".to_string());
    let user = std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "annex".into());
    let pass = std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "annex".into());
    Client::new(&url, Auth::UserPass(user, pass)).expect("connect to bitcoind")
}

/// A key-path-only P2TR output we control.
fn taproot_spk(secp: &Secp256k1<bitcoin::secp256k1::All>, kp: &Keypair) -> ScriptBuf {
    let (xonly, _) = kp.x_only_public_key();
    ScriptBuf::new_p2tr(secp, xonly, None)
}

fn coinbase(height: u64, spk: &ScriptBuf, value: u64) -> Transaction {
    // BIP34: the height, minimally encoded, first in the scriptSig.
    let mut script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .into_script()
        .to_bytes();
    script_sig.push(0x00); // arbitrary extra nonce, keeps coinbases distinct
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32].as_slice()]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk.clone(),
        }],
    }
}

fn witness_commitment_output(txs: &[Transaction]) -> TxOut {
    let witness_root: WitnessMerkleNode = {
        let hashes = std::iter::once(Txid::all_zeros().to_raw_hash())
            .chain(txs[1..].iter().map(|t| t.compute_wtxid().to_raw_hash()));
        WitnessMerkleNode::from_raw_hash(
            bitcoin::merkle_tree::calculate_root(hashes).expect("non-empty"),
        )
    };
    let commitment = Block::compute_witness_commitment(&witness_root, &[0u8; 32]);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&commitment.to_byte_array());
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    }
}

/// Assemble a block, grind the regtest target, and submit it.
fn mine(client: &Client, spk: &ScriptBuf, mut txs: Vec<Transaction>, fees: u64) -> Block {
    let tip = client.get_best_block_hash().expect("tip");
    let height = client.get_block_count().expect("height") + 1;

    let mut cb = coinbase(height, spk, subsidy(height) + fees);
    txs.insert(0, cb.clone());
    cb.output.push(witness_commitment_output(&txs));
    txs[0] = cb;

    let merkle_root: TxMerkleNode = TxMerkleNode::from_raw_hash(
        bitcoin::merkle_tree::calculate_root(txs.iter().map(|t| t.compute_txid().to_raw_hash()))
            .expect("non-empty"),
    );

    let mut header = Header {
        version: BlockVersion::from_consensus(0x2000_0000),
        prev_blockhash: tip,
        merkle_root,
        // must exceed the median time past of the last eleven blocks, so
        // it cannot simply be "now" when we mine a hundred in a second
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
            + height as u32,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }

    let block = Block {
        header,
        txdata: txs,
    };
    client.submit_block(&block).expect("submitblock");
    assert_ne!(
        client.get_best_block_hash().expect("tip"),
        tip,
        "block was not accepted: {}",
        serialize_hex(&block.header)
    );
    block
}

#[test]
#[ignore = "needs a regtest bitcoind"]
fn a_real_node_on_an_annex_publication() {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let spk = taproot_spk(&secp, &kp);
    let client = rpc();

    // ---- mine to maturity, paying ourselves --------------------------
    let start = client.get_block_count().expect("height");
    let mut funding: Option<(OutPoint, TxOut)> = None;
    for i in 0..=COINBASE_MATURITY {
        let b = mine(&client, &spk, vec![], 0);
        if i == 0 {
            funding = Some((
                OutPoint {
                    txid: b.txdata[0].compute_txid(),
                    vout: 0,
                },
                b.txdata[0].output[0].clone(),
            ));
        }
    }
    let (outpoint, prevout) = funding.expect("funded");
    println!(
        "mined {} blocks (height {} -> {})",
        COINBASE_MATURITY + 1,
        start,
        client.get_block_count().unwrap()
    );

    // ---- the publication ---------------------------------------------
    let n = 64; // b = 192 children, three to a 64-byte element
    let elements: Vec<Vec<u8>> = (0..n)
        .map(|i| vec![((i * 7 + 1) & 0xFF) as u8; 64])
        .collect();
    let sf = build(&elements, annex_frame(n));
    let annex = annex_bytes(&sf);
    assert_eq!(sf.digest, sha_annex(&annex));
    println!(
        "publication: {} byte file, {} byte annex",
        sf.raw_bytes.len(),
        annex.len()
    );

    // ---- the stage transaction ---------------------------------------
    let fee = 50_000u64;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prevout.value - Amount::from_sat(fee),
            script_pubkey: spk.clone(),
        }],
    };

    let prevouts = vec![prevout.clone()];
    let ty = TapSighashType::AllPlusAnyoneCanPay;
    let msg = signing_message(&tx, 0, &Prevouts::All(&prevouts), Some(&annex), None, ty)
        .expect("signing message");
    assert_eq!(msg.len(), PROFILE_LEN, "the 222-byte profile");
    println!(
        "signing message: {} bytes, bitcount {}",
        msg.len(),
        8 * msg.len()
    );

    // the commitment the protocol reads, recomputed in one compression
    let digest = sha256d::Hash::from_byte_array({
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&msg).to_byte_array()
    });
    let one_compression = sighash_from_commitment(&h192(&msg), &commitment_window(&msg));
    assert_eq!(digest.to_byte_array(), one_compression);
    println!("one compression reproduces the sighash: ok");

    let tweaked = kp.tap_tweak(&secp, None);
    let sig = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(one_compression),
        &tweaked.to_keypair(),
    );
    let mut w = Witness::new();
    let mut sigbytes = sig.serialize().to_vec();
    sigbytes.push(ty as u8); // 0x81, so the signature is 65 bytes
    w.push(&sigbytes);
    w.push(&annex);
    tx.input[0].witness = w;

    println!(
        "stage tx: {} bytes serialized, {} vbytes, {} WU",
        tx.total_size(),
        tx.vsize(),
        tx.weight().to_wu()
    );

    // ---- what does POLICY say? ---------------------------------------
    let accept = client
        .test_mempool_accept(&[&tx])
        .expect("testmempoolaccept");
    println!("\n--- policy ---");
    println!("{:?}", accept[0]);

    // ---- what does CONSENSUS say? ------------------------------------
    println!("\n--- consensus ---");
    let before = client.get_block_count().unwrap();
    let block = mine(&client, &spk, vec![tx.clone()], fee);
    let after = client.get_block_count().unwrap();
    assert_eq!(
        after,
        before + 1,
        "the block carrying the annex was rejected"
    );
    let txid = tx.compute_txid();
    let confirmed = client
        .get_raw_transaction_info(&txid, Some(&block.block_hash()))
        .expect("the annex spend is in the chain");
    println!(
        "confirmed in block {} at height {}: {} confirmations",
        block.block_hash(),
        after,
        confirmed.confirmations.unwrap_or(0)
    );

    // and the annex survived the round trip through consensus
    let fetched: Transaction = client
        .get_raw_transaction(&txid, Some(&block.block_hash()))
        .expect("fetch");
    assert_eq!(
        fetched.input[0].witness.taproot_annex(),
        Some(&annex[..]),
        "the annex came back byte for byte"
    );
    println!(
        "annex round-tripped through the chain: {} bytes",
        annex.len()
    );

    // ---- the other 222-byte profile, and the pinned output -----------
    //
    // SINGLE|ANYONECANPAY also reaches 222 bytes, but ends on
    // sha_single_output.  The graph pins that output so its hash is a
    // constant; here we check a node really does accept the spend, since
    // M5's reading of the window depends on it.
    println!("\n--- SINGLE|ANYONECANPAY with a pinned OP_RETURN ---");
    let b2 = mine(&client, &spk, vec![], 0);
    let op2 = OutPoint {
        txid: b2.txdata[0].compute_txid(),
        vout: 0,
    };
    for _ in 0..COINBASE_MATURITY {
        mine(&client, &spk, vec![], 0);
    }
    let prev2 = b2.txdata[0].output[0].clone();
    let mut tx2 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op2,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            // index 0: the output SIGHASH_SINGLE commits to, pinned
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            },
            TxOut {
                value: prev2.value - Amount::from_sat(fee),
                script_pubkey: spk.clone(),
            },
        ],
    };
    let pre2 = vec![prev2.clone()];
    let ty2 = TapSighashType::SinglePlusAnyoneCanPay;
    let msg2 = signing_message(&tx2, 0, &Prevouts::All(&pre2), Some(&annex), None, ty2).unwrap();
    assert_eq!(msg2.len(), PROFILE_LEN);
    {
        use bitcoin::hashes::sha256;
        let k0 = sha256::Hash::hash(&protocol_builder::compact::commitment::serialize_output(
            &tx2.output[0],
        ))
        .to_byte_array();
        assert_eq!(commitment_window(&msg2)[..], k0[2..32]);
        println!("the window is the pinned output's hash, not the annex's: ok");
        let sh2 = sighash_from_commitment(&h192(&msg2), &commitment_window(&msg2));
        let sig2 = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sh2),
            &kp.tap_tweak(&secp, None).to_keypair(),
        );
        let mut w2 = Witness::new();
        let mut sb2 = sig2.serialize().to_vec();
        sb2.push(ty2 as u8);
        w2.push(&sb2);
        w2.push(&annex);
        tx2.input[0].witness = w2;
    }
    let before2 = client.get_block_count().unwrap();
    mine(&client, &spk, vec![tx2.clone()], fee);
    assert_eq!(client.get_block_count().unwrap(), before2 + 1);
    println!("0x83 with an annex also confirms");

    // ---- how big an annex will consensus take? -----------------------
    //
    // The branching-factor table goes to b = 3072, a 131 kB publication.
    // There is no explicit consensus limit on annex size, but "no
    // explicit limit" is worth checking rather than assuming.
    println!("\n--- large publications ---");
    for n_elem in [512usize, 1024] {
        let b3 = mine(&client, &spk, vec![], 0);
        let op3 = OutPoint {
            txid: b3.txdata[0].compute_txid(),
            vout: 0,
        };
        for _ in 0..COINBASE_MATURITY {
            mine(&client, &spk, vec![], 0);
        }
        let prev3 = b3.txdata[0].output[0].clone();
        let els: Vec<Vec<u8>> = (0..n_elem)
            .map(|i| vec![((i * 13 + 5) & 0xFF) as u8; 64])
            .collect();
        let sf3 = build(&els, annex_frame(n_elem));
        let a3 = annex_bytes(&sf3);
        assert_eq!(sf3.digest, sha_annex(&a3));
        let mut tx3 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op3,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: prev3.value - Amount::from_sat(fee),
                script_pubkey: spk.clone(),
            }],
        };
        let pre3 = vec![prev3.clone()];
        let m3 = signing_message(&tx3, 0, &Prevouts::All(&pre3), Some(&a3), None, ty).unwrap();
        assert_eq!(
            m3.len(),
            PROFILE_LEN,
            "the profile does not depend on annex size"
        );
        let sh3 = sighash_from_commitment(&h192(&m3), &commitment_window(&m3));
        let sig3 = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sh3),
            &kp.tap_tweak(&secp, None).to_keypair(),
        );
        let mut w3 = Witness::new();
        let mut sb3 = sig3.serialize().to_vec();
        sb3.push(ty as u8);
        w3.push(&sb3);
        w3.push(&a3);
        tx3.input[0].witness = w3;
        let before3 = client.get_block_count().unwrap();
        mine(&client, &spk, vec![tx3.clone()], fee);
        assert_eq!(
            client.get_block_count().unwrap(),
            before3 + 1,
            "a {}-byte annex was rejected",
            a3.len()
        );
        println!(
            "N = {:>4}: {:>7} byte annex, tx {:>6} WU -- confirmed",
            n_elem,
            a3.len(),
            tx3.weight().to_wu()
        );
    }
}

/// Does a real node accept a publication in an `OP_RETURN`?
///
/// The annex test above separates consensus from policy because the
/// annex fails the second.  Here the question is the reverse, and it is
/// the reason the output mode exists: the whole point of paying four
/// weight units a byte instead of one is that the transaction *relays*.
/// So `testmempoolaccept` is the assertion, not a printout.
///
/// Everything else is Section 11: two inputs under two keys, one signed
/// `SIGHASH_SINGLE` so that the commitment is `sha_single_output`, one
/// signed `SIGHASH_ALL` so that the transaction is not malleable, and
/// the `OP_RETURN` at the index of the first.
#[test]
#[ignore = "needs a regtest bitcoind"]
fn a_real_node_on_an_output_publication() {
    use protocol_builder::compact::commitment::{OUTPUT_PROFILE_LEN, SPEND_TYPE_OFFSET};
    use protocol_builder::compact::dispute::{read_output_profile, OutputProfile, ProfileWitness};
    use protocol_builder::compact::output::{output_frame, spk_for};

    let secp = Secp256k1::new();
    // two keys of the same party: A makes the commitment, B pins the tx
    let ka = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x21; 32]).unwrap());
    let kb = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32]).unwrap());
    let spk_a = taproot_spk(&secp, &ka);
    let spk_b = taproot_spk(&secp, &kb);
    let client = rpc();

    // ---- fund one output for each key --------------------------------
    let mut data_out: Option<(OutPoint, TxOut)> = None;
    let mut data_fee: Option<(OutPoint, TxOut)> = None;
    for i in 0..=COINBASE_MATURITY + 1 {
        let to = if i == 1 { &spk_b } else { &spk_a };
        let b = mine(&client, to, vec![], 0);
        let op = OutPoint {
            txid: b.txdata[0].compute_txid(),
            vout: 0,
        };
        if i == 0 {
            data_out = Some((op, b.txdata[0].output[0].clone()));
        } else if i == 1 {
            data_fee = Some((op, b.txdata[0].output[0].clone()));
        }
    }
    let (out_point, out_prev) = data_out.expect("data_out");
    let (fee_point, fee_prev) = data_fee.expect("data_fee");

    // ---- the publication, framed for an output -----------------------
    let n = 64;
    let elements: Vec<Vec<u8>> = (0..n)
        .map(|i| vec![((i * 11 + 3) & 0xFF) as u8; 64])
        .collect();
    let sf = build(&elements, output_frame(n));
    println!(
        "publication: {} byte file in an OP_RETURN",
        sf.raw_bytes.len()
    );
    // The frame's whole purpose: the file's FlatMerkle digest IS
    // sha_single_output of the output carrying it.  Without the OP_0
    // fillers that put the file on a block boundary this fails, which is
    // the same mistake Definition 4.1 made for the annex.
    let framed_out = TxOut {
        value: Amount::ZERO,
        script_pubkey: spk_for(&sf.raw_bytes),
    };
    let sso_expected = {
        use bitcoin::hashes::sha256;
        let mut ser = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(&framed_out, &mut ser).unwrap();
        sha256::Hash::hash(&ser).to_byte_array()
    };
    assert_eq!(
        sf.digest, sso_expected,
        "the framed file's digest is sha_single_output"
    );
    println!("the file's digest IS sha_single_output of the output carrying it");

    // ---- StageData: two inputs, the OP_RETURN at input 0's index -----
    let fee = 50_000u64;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: out_point,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: fee_point,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: spk_for(&sf.raw_bytes),
            },
            TxOut {
                value: out_prev.value + fee_prev.value - Amount::from_sat(fee),
                script_pubkey: spk_a.clone(),
            },
        ],
    };
    let prevouts = vec![out_prev.clone(), fee_prev.clone()];

    // input 0, SIGHASH_SINGLE: this is the commitment
    let msg = signing_message(
        &tx,
        0,
        &Prevouts::All(&prevouts),
        None,
        None,
        TapSighashType::Single,
    )
    .expect("signing message");
    assert_eq!(msg.len(), OUTPUT_PROFILE_LEN, "the 239-byte profile");
    assert_eq!(msg[SPEND_TYPE_OFFSET], 0, "a bare key-path spend");
    println!(
        "signing message: {} bytes, bitcount {}",
        msg.len(),
        8 * msg.len()
    );

    let sighash_a = {
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&msg).to_byte_array()
    };
    let tweak_a = ka.tap_tweak(&secp, None);
    let sig_a =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash_a), &tweak_a.to_keypair());
    let mut wa = Witness::new();
    let mut ser_a = sig_a.serialize().to_vec();
    ser_a.push(TapSighashType::Single as u8); // 0x03, a 65-byte signature
    wa.push(&ser_a);
    tx.input[0].witness = wa;

    // input 1, SIGHASH_ALL: this is what pins the transaction
    let msg_b = signing_message(
        &tx,
        1,
        &Prevouts::All(&prevouts),
        None,
        None,
        TapSighashType::All,
    )
    .expect("signing message");
    let sighash_b = {
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&msg_b).to_byte_array()
    };
    let tweak_b = kb.tap_tweak(&secp, None);
    let sig_b =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash_b), &tweak_b.to_keypair());
    let mut wb = Witness::new();
    let mut ser_b = sig_b.serialize().to_vec();
    ser_b.push(TapSighashType::All as u8);
    wb.push(&ser_b);
    tx.input[1].witness = wb;

    println!(
        "StageData: {} bytes, {} WU, OP_RETURN of {} bytes",
        tx.total_size(),
        tx.weight().to_wu(),
        sf.raw_bytes.len()
    );

    // ---- POLICY.  This is the claim the mode is for. -----------------
    println!("\n--- policy ---");
    let accept = client
        .test_mempool_accept(&[&tx])
        .expect("testmempoolaccept");
    println!("{:?}", accept[0]);
    assert!(
        accept[0].allowed,
        "an OP_RETURN publication must relay -- that is the whole point \
         of paying four weight units a byte: {:?}",
        accept[0].reject_reason
    );
    let in_mempool = client
        .send_raw_transaction(&tx)
        .expect("sendrawtransaction");
    println!("accepted into the mempool: {in_mempool}");

    // ---- consensus ---------------------------------------------------
    println!("\n--- consensus ---");
    let before = client.get_block_count().unwrap();
    let block = mine(&client, &spk_a, vec![tx.clone()], fee);
    assert_eq!(client.get_block_count().unwrap(), before + 1);
    let txid = tx.compute_txid();
    let fetched: Transaction = client
        .get_raw_transaction(&txid, Some(&block.block_hash()))
        .expect("fetch");
    assert_eq!(
        fetched.output[0].script_pubkey.as_bytes(),
        spk_for(&sf.raw_bytes).as_bytes(),
        "the file came back byte for byte"
    );
    println!("confirmed, and the OP_RETURN round-tripped");

    // ---- and M5 reads it ---------------------------------------------
    println!("\n--- M5 ---");
    let (xonly_a, _) = tweak_a.to_keypair().x_only_public_key();
    let w = ProfileWitness::for_message(sig_a.serialize(), &msg);
    let mut ser = Vec::new();
    bitcoin::consensus::Encodable::consensus_encode(&fetched.output[0], &mut ser).unwrap();
    let sso = {
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&ser).to_byte_array()
    };
    match read_output_profile(&secp, &w, &xonly_a) {
        OutputProfile::Published { window } => {
            assert_eq!(
                window[..],
                sso[2..32],
                "the window is sha_single_output of the confirmed output"
            );
            println!("reads as a publication, window = sha_single_output[2..32]");
        }
        other => panic!("the honest publication read as {other:?}"),
    }

    // the same transaction signed ALL instead would be convicted
    let msg_all = signing_message(
        &tx,
        0,
        &Prevouts::All(&prevouts),
        None,
        None,
        TapSighashType::All,
    )
    .unwrap();
    let sighash_all = {
        use bitcoin::hashes::sha256;
        sha256::Hash::hash(&msg_all).to_byte_array()
    };
    let sig_all =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash_all), &tweak_a.to_keypair());
    let w_all = ProfileWitness::for_message(sig_all.serialize(), &msg_all);
    assert_eq!(
        read_output_profile(&secp, &w_all, &xonly_a),
        OutputProfile::CommittedToEveryOutput,
        "signing ALL over the same transaction must be caught"
    );
    println!("and the same spend signed ALL is caught by the five bytes");
}
