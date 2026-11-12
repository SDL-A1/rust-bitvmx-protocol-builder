//! The transaction graph: the claims that make the chain pre-signable.

#[cfg(test)]
mod tests {
    use crate::compact::annex::annex_bytes;
    use crate::compact::commitment::{serialize_output, signing_message, PROFILE_LEN};
    use crate::compact::graph::{is_pinned, Graph, Leaf, Params, Role, TxNode};
    use crate::compact::checkpoints::{publication, Node, NODE_BYTES};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::{TapSighashType, Witness};
    use std::collections::{HashMap, HashSet};

    fn graph() -> (Graph, Secp256k1<bitcoin::secp256k1::All>, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let g = Graph::build(&secp, &key, Params::default());
        (g, secp, key)
    }

    fn stage_names(levels: u32) -> Vec<String> {
        let stages = levels as usize + 1;
        (1..=stages)
            .map(|i| match i {
                1 => "Claim".to_string(),
                2 => "Challenge".to_string(),
                n if n == stages => "Endgame".to_string(),
                n => format!("Stage{n}"),
            })
            .collect()
    }

    // ------------------------------------------------- it is a real DAG

    #[test]
    fn every_input_points_at_an_output_that_exists() {
        let (g, _, _) = graph();
        let by_name: HashMap<&str, &TxNode> =
            g.nodes.iter().map(|n| (n.name.as_str(), n)).collect();
        for n in &g.nodes {
            for (parent, vout) in &n.spends {
                let p = by_name
                    .get(parent.as_str())
                    .unwrap_or_else(|| panic!("{} spends unknown {parent}", n.name));
                assert!(
                    *vout < p.outputs.len(),
                    "{} spends {parent}:{vout}, which has {} outputs",
                    n.name,
                    p.outputs.len()
                );
                // and the real transaction agrees with the model
                assert!(n.tx.input.iter().any(|i| i.previous_output.txid == p.txid()
                    && i.previous_output.vout == *vout as u32));
            }
        }
    }

    #[test]
    fn the_graph_is_acyclic_and_topologically_ordered() {
        let (g, _, _) = graph();
        let mut seen: HashSet<&str> = HashSet::new();
        for n in &g.nodes {
            for (parent, _) in &n.spends {
                assert!(
                    seen.contains(parent.as_str()),
                    "{} spends {parent}, which comes later",
                    n.name
                );
            }
            seen.insert(n.name.as_str());
        }
    }

    #[test]
    fn the_spine_is_a_chain_not_a_fan() {
        let (g, _, _) = graph();
        let names = stage_names(g.params.levels);
        for w in names.windows(2) {
            let (prev, next) = (&w[0], &w[1]);
            let n = g.get(next);
            assert!(
                n.spends.iter().all(|(p, _)| p == prev),
                "{next} should spend only {prev}, spends {:?}",
                n.spends
            );
        }
        // nothing after Claim spends Setup
        for n in &g.nodes {
            if n.name != "Claim" {
                assert!(
                    !n.spends.iter().any(|(p, _)| p == "Setup"),
                    "{} spends Setup: that is a fan",
                    n.name
                );
            }
        }
    }

    // ------------------------------------- the shape is fixed at setup

    /// The claim the chain rests on: a stage's txid does not depend on
    /// what it publishes, because the annex is witness data.
    #[test]
    fn a_stages_txid_does_not_move_when_it_publishes() {
        let (g, _, _) = graph();
        for name in stage_names(g.params.levels) {
            let n = g.get(&name);
            let bare = n.txid();

            // publish something in the annex
            // Twelve interior states: the dissection of a b = 13 interval, which
            // is the smallest feasible one (four elements, a power of two).
            let states: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
            let sf = publication(&states);
            let a = annex_bytes(&sf);
            let mut with = n.tx.clone();
            let mut w = Witness::new();
            w.push(vec![0u8; 65]);
            w.push(&a);
            with.input[n.slot_input.expect("a slot input")].witness = w;

            assert_eq!(
                bare,
                with.compute_txid(),
                "{name}: the annex moved the txid"
            );
            assert_ne!(
                with.compute_wtxid(),
                n.tx.compute_wtxid(),
                "{name}: but the wtxid must move"
            );
        }
    }

    /// And it does not depend on whether the party deduplicates: the
    /// outputs are the same either way, including the Dedup set, which
    /// is what makes the dangling reference of M6 possible at all.
    #[test]
    fn a_deduplicating_stage_has_the_same_shape() {
        let (g, _, _) = graph();
        for name in stage_names(g.params.levels) {
            let n = g.get(&name);
            let publishing = n.tx.clone();

            let mut deduplicating = n.tx.clone();
            let mut w = Witness::new();
            w.push(vec![0u8; 65]); // signed with no annex
            deduplicating.input[n.slot_input.unwrap()].witness = w;

            assert_eq!(publishing.compute_txid(), deduplicating.compute_txid());
            assert_eq!(publishing.output, deduplicating.output);
            assert!(
                n.outputs
                    .iter()
                    .any(|o| matches!(o.role, Role::Dedup { .. })),
                "{name} emits its Dedup outputs whatever it does"
            );
        }
    }

    // ------------------------------------------------ outputs and leaves

    #[test]
    fn every_selection_output_carries_three_leaves_except_the_last() {
        let (g, _, _) = graph();
        let stages = g.params.levels as usize + 1;
        let mut seen_last = false;
        for n in &g.nodes {
            for o in &n.outputs {
                if let Role::Selection(i) = o.role {
                    if i > stages {
                        assert_eq!(
                            o.leaves,
                            vec![Leaf::Dispute, Leaf::Timeout(g.params.delta)],
                            "the last link has no stage left to select"
                        );
                        seen_last = true;
                    } else {
                        assert_eq!(
                            o.leaves,
                            vec![
                                Leaf::Selection,
                                Leaf::Dispute,
                                Leaf::Timeout(g.params.delta)
                            ],
                            "K_{i}"
                        );
                    }
                }
            }
        }
        assert!(seen_last, "the endgame creates one more selection output");
    }

    #[test]
    fn every_lock_in_the_graph_is_one_delta() {
        let (g, _, _) = graph();
        let mut locks = HashSet::new();
        for n in &g.nodes {
            for o in &n.outputs {
                for l in &o.leaves {
                    if let Leaf::Timeout(d) = l {
                        locks.insert(*d);
                    }
                }
            }
        }
        assert_eq!(
            locks,
            HashSet::from([g.params.delta]),
            "a chain has no schedule to stagger"
        );
    }

    #[test]
    fn a_publication_slot_is_key_path_only() {
        let (g, secp, key) = graph();
        for n in &g.nodes {
            for o in &n.outputs {
                if matches!(o.role, Role::Slot(_)) {
                    assert_eq!(o.leaves, vec![Leaf::KeyPathPublication]);
                    assert!(
                        o.spend_info(&secp, &key).is_none(),
                        "a slot has no script tree: a pre-signature would fix the annex"
                    );
                }
            }
        }
    }

    /// `SIGHASH_SINGLE` commits to the output at the signed input's
    /// index, so the graph has to put a fixed output there.
    #[test]
    fn the_pinned_output_sits_at_the_slot_inputs_index() {
        let (g, _, _) = graph();
        for name in stage_names(g.params.levels) {
            let n = g.get(&name);
            let idx = n.slot_input.expect("a slot input");
            assert!(idx < n.outputs.len(), "{name}: no output at the slot index");
            assert!(
                is_pinned(&n.outputs[idx]),
                "{name}: output {idx} is {:?}, not the pinned OP_RETURN",
                n.outputs[idx].role
            );
            assert_eq!(n.tx.output[idx].value.to_sat(), 0);
            assert_eq!(n.tx.output[idx].script_pubkey.as_bytes(), &[0x6a]);
        }
    }

    #[test]
    fn the_pinned_outputs_hash_is_a_constant_known_at_setup() {
        use bitcoin::hashes::sha256;
        let (g, _, _) = graph();
        let mut windows = HashSet::new();
        for name in stage_names(g.params.levels) {
            let n = g.get(&name);
            let idx = n.slot_input.unwrap();
            let k0 = sha256::Hash::hash(&serialize_output(&n.tx.output[idx])).to_byte_array();
            windows.insert(hex::encode(&k0[2..32]));
        }
        assert_eq!(windows.len(), 1, "the same constant at every stage");
        assert!(windows
            .iter()
            .next()
            .unwrap()
            .starts_with("6407aff71ffb5742"));
    }

    // -------------------------------------- the dispute branch's shape

    #[test]
    fn a_publication_dispute_consumes_s_out_and_is_terminal() {
        let (g, _, _) = graph();
        for i in 1..=(g.params.levels as usize + 1) {
            let d = g.get(&format!("StageDispute{i}"));
            assert_eq!(d.spends.len(), 2, "the selection leaf and s_out");
            let parent = &d.spends[0].0;
            let p = g.get(parent);
            assert!(matches!(p.outputs[d.spends[1].1].role, Role::SOut(_)));
            // terminal: nothing in the graph spends it
            assert!(
                !g.nodes
                    .iter()
                    .any(|n| n.spends.iter().any(|(q, _)| q == &d.name)),
                "StageDispute{i} should be terminal"
            );
        }
    }

    /// Deduplicating and disputing compete for the same output, which is
    /// what makes "no reference was made" readable without anyone
    /// asserting it.
    #[test]
    fn stagedup_and_the_m5_dispute_contend_for_s_out() {
        let (g, _, _) = graph();
        for i in 1..=(g.params.levels as usize + 1) {
            let dup = g.get(&format!("StageDup{i}"));
            let disp = g.get(&format!("StageDispute{i}"));
            let dup_sout = dup
                .spends
                .iter()
                .find(|(p, v)| matches!(g.get(p).outputs[*v].role, Role::SOut(_)));
            let disp_sout = disp
                .spends
                .iter()
                .find(|(p, v)| matches!(g.get(p).outputs[*v].role, Role::SOut(_)));
            assert_eq!(
                dup_sout, disp_sout,
                "both spend the same s_out, so only one can"
            );
        }
    }

    #[test]
    fn only_the_endgame_dispute_takes_a_second_message() {
        let (g, _, _) = graph();
        let disp = g.get("Dispute");
        assert_eq!(disp.outputs.len(), 1);
        assert!(matches!(disp.outputs[0].role, Role::AnswerSlot));
        for n in [g.get("Answer"), g.get("MissingAnswer")] {
            assert_eq!(n.spends, vec![("Dispute".to_string(), 0)]);
        }
        // the publication disputes create nothing
        for i in 1..=(g.params.levels as usize + 1) {
            assert!(g.get(&format!("StageDispute{i}")).outputs.len() <= 1);
        }
    }

    // ----------------------------------- the profile the slot must use

    #[test]
    fn signing_a_real_slot_input_gives_the_222_byte_profile() {
        let (g, secp, key) = graph();
        let states: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
        let a = annex_bytes(&publication(&states));

        for name in stage_names(g.params.levels) {
            let n = g.get(&name);
            let idx = n.slot_input.unwrap();
            // the prevout is the slot the previous transaction created
            let (parent, vout) = &n.spends[idx];
            let prev = g.get(parent).tx.output[*vout].clone();
            let prevouts = vec![prev; n.tx.input.len()];
            for ty in [
                TapSighashType::AllPlusAnyoneCanPay,
                TapSighashType::SinglePlusAnyoneCanPay,
            ] {
                let msg =
                    signing_message(&n.tx, idx, &Prevouts::All(&prevouts), Some(&a), None, ty)
                        .expect("signing message");
                assert_eq!(msg.len(), PROFILE_LEN, "{name} under {ty:?}");
            }
            let _ = (&secp, &key);
        }
    }

    // ------------------------------- the single-evaluation invariant (gsig)

    /// All the transactions that spend a given outpoint.  Any two of them
    /// conflict, so at most one can ever confirm.
    fn spenders<'a>(g: &'a Graph, tx: &str, vout: usize) -> Vec<&'a str> {
        let target = g.get(tx).txid();
        g.nodes
            .iter()
            .filter(|n| {
                n.tx.input.iter().any(|i| {
                    i.previous_output.txid == target
                        && i.previous_output.vout == vout as u32
                })
            })
            .map(|n| n.name.as_str())
            .collect()
    }

    /// `gsig::SINGLE_EVALUATION`, discharged against this graph as far as
    /// the graph can discharge it.
    ///
    /// The argument is a UTXO argument and it is short. The accuser's
    /// `Dispute` transaction is what opens the one-time commitments and so
    /// delivers one label per input wire: one transaction, one assignment.
    /// It creates exactly one output. Every transaction that could consume
    /// that output spends the same outpoint, so any two of them conflict
    /// and at most one confirms. One garbling, one feeding, one evaluation.
    ///
    /// What makes this worth asserting rather than asserting in prose is
    /// that it is a property of the *shape*, and the shape is what a later
    /// edit would change silently.
    #[test]
    fn the_gadget_is_fed_once_because_its_labels_come_from_one_outpoint() {
        let (g, _, _) = graph();

        // One feeding. The accuser's Dispute carries the opened labels,
        // and it is a single node of the graph.
        let disputes: Vec<&str> = g
            .nodes
            .iter()
            .filter(|n| n.name == "Dispute")
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(disputes.len(), 1, "a second Dispute would be a second feeding");

        // It offers exactly one output for the evaluation to consume.
        let d = g.get("Dispute");
        assert_eq!(d.tx.output.len(), 1);
        assert_eq!(d.outputs[0].role, Role::AnswerSlot);

        // Every consumer spends that one outpoint, so they are mutually
        // exclusive by construction rather than by any rule of ours.
        let consumers = spenders(&g, "Dispute", 0);
        assert_eq!(
            consumers.len(),
            2,
            "the answer and its timeout, and nothing else: {consumers:?}"
        );
        assert!(consumers.contains(&"Answer"));
        assert!(consumers.contains(&"MissingAnswer"));

        let outpoints: HashSet<_> = consumers
            .iter()
            .map(|n| g.get(n).tx.input[0].previous_output)
            .collect();
        assert_eq!(
            outpoints.len(),
            1,
            "they must conflict, not merely be alternatives"
        );
    }

    /// And the part this graph does *not* discharge, stated so that it is
    /// not mistaken for covered.
    ///
    /// With more than two parties the endgame still has a single `Dispute`,
    /// so the invariant holds here only because the concurrent case is not
    /// modelled. A graph that gave each challenger its own endgame would
    /// need a garbling each -- sharing one across challengers is exactly
    /// the two-evaluation failure, and it hands over the key rather than
    /// degrading. Deduplication shares *publications*, never garblings.
    #[test]
    fn concurrent_challengers_do_not_share_an_endgame_yet() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();

        for parties in [2usize, 3, 5] {
            let g = Graph::build(
                &secp,
                &key,
                Params {
                    parties,
                    ..Params::default()
                },
            );
            let n = g.nodes.iter().filter(|x| x.name == "Dispute").count();
            assert_eq!(
                n, 1,
                "{parties} parties still share one endgame, so the                  single-evaluation question has not been asked yet"
            );
        }
    }

    // ------------------------------------------- the gadget's release leaf

    fn gadget_params() -> (Params, XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x5A; 32]).unwrap());
        let (gk, _) = kp.x_only_public_key();
        (Params::default().with_gadget(gk), gk)
    }

    /// The choice of release does not reshape the graph.  One leaf either
    /// way, same outputs, same txids downstream.
    #[test]
    fn the_gadget_release_does_not_move_the_graph() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let (gp, gk) = gadget_params();

        let a = Graph::build(&secp, &key, Params::default());
        let b = Graph::build(&secp, &key, gp);

        assert_eq!(a.nodes.len(), b.nodes.len());
        for (x, y) in a.nodes.iter().zip(&b.nodes) {
            assert_eq!(x.name, y.name);
            assert_eq!(
                x.tx.output.len(),
                y.tx.output.len(),
                "{} changed shape",
                x.name
            );
        }

        // The stake still carries exactly two leaves, and the release one
        // is now the gadget's.
        let stake = b
            .get("Setup")
            .outputs
            .iter()
            .find(|o| o.role == Role::Stake)
            .expect("a stake");
        assert_eq!(stake.leaves.len(), 2);
        assert!(stake.leaves.contains(&Leaf::Cooperative));
        assert!(stake.leaves.contains(&Leaf::GadgetRelease { key: gk }));
        assert!(!stake
            .leaves
            .iter()
            .any(|l| matches!(l, Leaf::PreimageRelease { .. })));
    }

    /// The gadget's key is its own.  Reusing the protocol key would let
    /// one signature serve two purposes.
    #[test]
    fn the_gadget_leaf_checks_its_own_key() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let (_, gk) = gadget_params();
        assert_ne!(key, gk, "the fixture is only meaningful with two keys");

        let script = crate::compact::graph::Output::release_script(
            &Leaf::GadgetRelease { key: gk },
            &key,
        );
        let bytes = script.as_bytes();
        assert_eq!(bytes.len(), 34, "<32-byte key> CHECKSIG");
        assert_eq!(bytes[0], 32, "a 32-byte push");
        assert_eq!(&bytes[1..33], &gk.serialize()[..], "the gadget's key");
        assert!(
            !script.to_bytes().windows(32).any(|w| w == key.serialize()),
            "the protocol key must not appear in the gadget leaf"
        );
    }

    /// What C04's resolution costs on chain.  The companion note declined
    /// to claim this -- "probably a small saving; not measured" -- so here
    /// it is measured.
    #[test]
    fn what_the_gadget_release_saves_on_chain() {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x77; 32]).unwrap());
        let (key, _) = kp.x_only_public_key();
        let (_, gk) = gadget_params();

        // Taken from the graph's own stake, so the leaf really is in the
        // tree whose control block is measured below.
        let (g, _, _) = graph();
        let stake = g
            .nodes
            .iter()
            .flat_map(|n| &n.outputs)
            .find(|o| o.role == Role::Stake)
            .expect("a stake");
        let preimage = stake
            .leaves
            .iter()
            .find_map(|l| match l {
                Leaf::PreimageRelease { .. } => {
                    Some(crate::compact::graph::Output::release_script(l, &key))
                }
                _ => None,
            })
            .expect("the default graph releases by preimage");
        let gadget = crate::compact::graph::Output::release_script(
            &Leaf::GadgetRelease { key: gk },
            &key,
        );
        assert_eq!(preimage.as_bytes().len(), 69, "SHA256 <h_b> EQUALVERIFY <P> CHECKSIG");
        assert_eq!(gadget.as_bytes().len(), 34, "<P_g> CHECKSIG");

        // The witness each is spent with.  Both take one 64-byte Schnorr
        // signature and a control block; the preimage leaf additionally
        // pushes the 32-byte secret, and carries a 35-byte longer script.
        //
        // The control block is taken from the real taptree, not assumed.
        // The stake carries two leaves, so it has a sibling hash and is
        // 65 bytes -- a first hand count said 33, which would have been a
        // one-leaf tree the stake does not have.  It is the same either
        // way, so the *difference* was right and the absolutes were not.
        let info = stake.spend_info(&secp, &key).expect("a taptree");
        let control = info
            .control_block(&(preimage.clone(), LeafVersion::TapScript))
            .expect("the release leaf is in the tree")
            .serialize();
        assert_eq!(control.len(), 65, "internal key, and one sibling");
        let mut w_pre = Witness::new();
        w_pre.push([0u8; 64]);
        w_pre.push([0u8; 32]);
        w_pre.push(preimage.as_bytes());
        w_pre.push(&control);

        let mut w_gad = Witness::new();
        w_gad.push([0u8; 64]);
        w_gad.push(gadget.as_bytes());
        w_gad.push(&control);

        assert_eq!(w_pre.size(), 235);
        assert_eq!(w_gad.size(), 167);
        let saved = w_pre.size() - w_gad.size();
        // 33 for the pushed preimage and its length byte, plus 35 for the
        // shorter script.  The item count stays one byte at three items or
        // four, so it contributes nothing.
        assert_eq!(saved, 33 + 35);
        assert_eq!(saved, 68, "witness bytes, so 68 WU");
        println!(
            "preimage release {} witness bytes, gadget {} -- {saved} WU saved",
            w_pre.size(),
            w_gad.size()
        );
    }
}

/// Publishing in an output instead of the annex.
///
/// The choice is made at setup because it changes the graph: an annex
/// rides in the witness of the stage transaction, an output needs a
/// transaction of its own, a penalization against it, and two outputs on
/// the stage to fund both.
#[cfg(test)]
mod publishing_in_an_output {
    use crate::compact::commitment::{signing_message, OUTPUT_PROFILE_LEN, SPEND_TYPE_OFFSET};
    use crate::compact::dispute::{read_output_profile, OutputProfile, ProfileWitness};
    use crate::compact::graph::*;
    use crate::compact::output::spk_for;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::Prevouts;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::{Amount, TapSighashType, TxOut};

    fn keys() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair) {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x41; 32]).unwrap());
        (secp, kp)
    }

    fn graphs() -> (Graph, Graph) {
        let (secp, kp) = keys();
        let (key, _) = kp.x_only_public_key();
        (
            Graph::build(&secp, &key, Params::default()),
            Graph::build(&secp, &key, Params::default().publishing_in_an_output()),
        )
    }

    #[test]
    fn the_annex_graph_is_unchanged_and_the_output_graph_adds_two_per_stage() {
        let (annex, output) = graphs();
        let stages = Params::default().levels as usize + 1;
        assert_eq!(
            output.nodes.len() - annex.nodes.len(),
            2 * stages,
            "a StageData and a MissingData per stage"
        );
        for i in 1..=stages {
            assert!(output
                .nodes
                .iter()
                .any(|n| n.name == format!("StageData{i}")));
            assert!(output
                .nodes
                .iter()
                .any(|n| n.name == format!("MissingData{i}")));
        }
    }

    #[test]
    fn stage_data_has_two_inputs_and_the_op_return_at_the_signed_index() {
        let (_, output) = graphs();
        let sd = output.get("StageData1");
        assert_eq!(sd.spends.len(), 2, "SINGLE on input 0, ALL on input 1");
        assert_eq!(sd.slot_input, Some(0));
        assert_eq!(sd.tx.output.len(), 1);
        assert!(sd.tx.output[0].script_pubkey.is_op_return());
        assert_eq!(sd.tx.output[0].value, Amount::ZERO);
        // output 0 sits at the index of input 0, which is what
        // SIGHASH_SINGLE commits to
        assert_eq!(sd.slot_input.unwrap(), 0);
    }

    #[test]
    fn the_two_inputs_come_from_the_stage_and_only_the_first_is_racing_a_timeout() {
        let (_, output) = graphs();
        let sd = output.get("StageData1");
        let stage = output.get("Claim");
        for (parent, _) in &sd.spends {
            assert_eq!(parent, "Claim");
        }
        let roles: Vec<&Role> = sd
            .spends
            .iter()
            .map(|(_, v)| &stage.outputs[*v].role)
            .collect();
        assert!(matches!(roles[0], Role::DataOut(1)));
        assert!(matches!(roles[1], Role::DataFee(1)));
        // MissingData races only for the first
        let md = output.get("MissingData1");
        assert_eq!(md.spends, vec![("Claim".to_string(), sd.spends[0].1)]);
        assert!(stage.outputs[sd.spends[0].1]
            .leaves
            .iter()
            .any(|l| matches!(l, Leaf::Timeout(_))));
        assert!(!stage.outputs[sd.spends[1].1]
            .leaves
            .iter()
            .any(|l| matches!(l, Leaf::Timeout(_))));
    }

    #[test]
    fn the_graph_is_still_acyclic_and_every_input_points_somewhere() {
        let (_, output) = graphs();
        let mut seen: Vec<&str> = Vec::new();
        for n in &output.nodes {
            for (parent, vout) in &n.spends {
                assert!(
                    seen.contains(&parent.as_str()),
                    "{} before {}",
                    parent,
                    n.name
                );
                assert!(*vout < output.get(parent).outputs.len());
            }
            seen.push(&n.name);
        }
    }

    /// The whole point: a real signature, read by the real M5.
    #[test]
    fn a_real_single_signature_reads_as_a_publication() {
        let (secp, kp) = keys();
        let (key, _) = kp.x_only_public_key();
        let g = Graph::build(&secp, &key, Params::default().publishing_in_an_output());
        let sd = g.get("StageData1");
        let stage = g.get("Claim");
        let prevouts: Vec<TxOut> = sd
            .spends
            .iter()
            .map(|(_, v)| stage.tx.output[*v].clone())
            .collect();

        let msg = signing_message(
            &sd.tx,
            0,
            &Prevouts::All(&prevouts),
            None,
            None,
            TapSighashType::Single,
        )
        .expect("signing message");
        assert_eq!(msg.len(), OUTPUT_PROFILE_LEN, "the 239-byte profile");
        assert_eq!(msg[SPEND_TYPE_OFFSET], 0, "a bare key-path spend");

        let sighash = sha256::Hash::hash(&msg).to_byte_array();
        let tweaked = kp.tap_tweak(&secp, None);
        let sig =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked.to_keypair());
        let w = ProfileWitness::for_message(sig.serialize(), &msg);
        let (xonly, _) = tweaked.to_keypair().x_only_public_key();

        // The window must be sha_single_output, not merely *a* window:
        // checking only the variant would pass with the offsets wrong.
        let mut ser = Vec::new();
        bitcoin::consensus::Encodable::consensus_encode(&sd.tx.output[0], &mut ser).unwrap();
        let sso = sha256::Hash::hash(&ser).to_byte_array();
        match read_output_profile(&secp, &w, &xonly) {
            OutputProfile::Published { window } => {
                assert_eq!(window[..], sso[2..32], "the window is sha_single_output")
            }
            other => panic!("read as {other:?}"),
        }
    }

    #[test]
    fn signing_at_the_wrong_input_index_commits_to_the_wrong_output() {
        let (secp, kp) = keys();
        let (key, _) = kp.x_only_public_key();
        let g = Graph::build(&secp, &key, Params::default().publishing_in_an_output());
        let sd = g.get("StageData1");
        let stage = g.get("Claim");
        let mut tx = sd.tx.clone();
        // a second output for her to commit to instead
        tx.output.push(TxOut {
            value: Amount::from_sat(330),
            script_pubkey: stage.tx.output[0].script_pubkey.clone(),
        });
        let prevouts: Vec<TxOut> = sd
            .spends
            .iter()
            .map(|(_, v)| stage.tx.output[*v].clone())
            .collect();
        let msg = signing_message(
            &tx,
            1,
            &Prevouts::All(&prevouts),
            None,
            None,
            TapSighashType::Single,
        )
        .unwrap();
        let tweaked = kp.tap_tweak(&secp, None);
        let (xonly, _) = tweaked.to_keypair().x_only_public_key();
        let sighash = sha256::Hash::hash(&msg).to_byte_array();
        let sig =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked.to_keypair());
        let w = ProfileWitness::for_message(sig.serialize(), &msg);
        assert_eq!(
            read_output_profile(&secp, &w, &xonly),
            OutputProfile::WrongInputIndex { index: 1 }
        );
    }

    #[test]
    fn what_the_choice_costs() {
        let (annex, output) = graphs();
        let weight = |g: &Graph| -> u64 { g.nodes.iter().map(|n| n.tx.weight().to_wu()).sum() };
        let (wa, wo) = (weight(&annex), weight(&output));
        let stages = Params::default().levels as usize + 1;
        let payload = Params::default().publication_bytes;

        // the publication itself: four units a byte in an output,
        // against one in an annex
        let per_stage = (wo - wa) / stages as u64;
        assert!(
            per_stage > 4 * payload as u64,
            "an output publication costs at least four units a byte: {per_stage}"
        );
        let furniture = per_stage - 4 * payload as u64;
        println!(
            "annex {wa} WU, output {wo} WU, {per_stage} a stage \
             ({} payload + {furniture} furniture)",
            4 * payload
        );

        // where the furniture goes, per stage
        let w = |n: &str| output.get(n).tx.weight().to_wu();
        let stage_delta =
            output.get("Claim").tx.weight().to_wu() - annex.get("Claim").tx.weight().to_wu();
        let sd = w("StageData1") - 4 * payload as u64;
        let md = w("MissingData1");
        println!(
            "  two outputs on the stage {stage_delta}, StageData minus payload {sd}, \
             MissingData {md} (a branch, not the happy path)"
        );
        assert_eq!(stage_delta + sd + md, furniture);
        // What a run that goes well actually pays: the two outputs and
        // StageData's own bytes.  MissingData is only ever broadcast
        // when the publisher fails to publish.
        assert_eq!(stage_delta + sd, 968, "the happy path's furniture");
        assert_eq!(md, 376, "the penalization branch");
        assert_eq!(stage_delta, 344, "two P2TR outputs on the stage");
        // 49 of StageData's bytes are the frame: the OP_0 fillers and
        // OP_PUSHDATA4 that put the file on a block boundary, so that
        // its digest is sha_single_output.  The output's analogue of
        // the annex frame, and the same 4-WU-a-byte lesson.
        assert_eq!(
            crate::compact::output::publication_wu(64) - 4 * payload,
            256,
            "the framed output's own bytes: amount, compact_size and a \
             53-byte script header, all at four units a byte"
        );
    }

    #[test]
    fn signing_all_instead_is_caught_by_the_five_bytes() {
        let (secp, kp) = keys();
        let (key, _) = kp.x_only_public_key();
        let g = Graph::build(&secp, &key, Params::default().publishing_in_an_output());
        let sd = g.get("StageData1");
        let stage = g.get("Claim");
        let prevouts: Vec<TxOut> = sd
            .spends
            .iter()
            .map(|(_, v)| stage.tx.output[*v].clone())
            .collect();
        let tweaked = kp.tap_tweak(&secp, None);
        let (xonly, _) = tweaked.to_keypair().x_only_public_key();

        for (ty, want) in [
            (TapSighashType::All, "every output"),
            (TapSighashType::Default, "every output"),
            (TapSighashType::None, "length"),
            (TapSighashType::SinglePlusAnyoneCanPay, "length"),
            (TapSighashType::AllPlusAnyoneCanPay, "length"),
        ] {
            let msg =
                signing_message(&sd.tx, 0, &Prevouts::All(&prevouts), None, None, ty).unwrap();
            let sighash = sha256::Hash::hash(&msg).to_byte_array();
            let sig = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked.to_keypair());
            let w = ProfileWitness::for_message(sig.serialize(), &msg);
            match read_output_profile(&secp, &w, &xonly) {
                OutputProfile::CommittedToEveryOutput => assert_eq!(want, "every output", "{ty:?}"),
                OutputProfile::WrongLength { bitcount } => {
                    assert_eq!(want, "length", "{ty:?}");
                    assert_ne!(bitcount, 8 * OUTPUT_PROFILE_LEN as u64);
                }
                other => panic!("{ty:?} read as {other:?}"),
            }
        }
    }

    #[test]
    fn a_framed_op_return_carries_what_it_is_given() {
        for n in [1usize, 40, 80, 1_000, 8_064] {
            let spk = spk_for(&vec![0u8; n]);
            assert!(spk.is_op_return());
            assert!(spk.len() > n, "{n}");
        }
    }
}
