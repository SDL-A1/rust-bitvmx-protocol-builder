//! The transaction graph: the claims that make the chain pre-signable.

#[cfg(test)]
mod tests {
    use crate::compact::annex::annex_bytes;
    use crate::compact::commitment::{serialize_output, signing_message, PROFILE_LEN};
    use crate::compact::graph::{is_pinned, Graph, Leaf, Params, Role, TxNode};
    use crate::compact::tracetree::{publication, Node, NODE_BYTES};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::sighash::Prevouts;
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
            let kids: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
            let sf = publication(&kids);
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
        let kids: Vec<Node> = (0..12u8).map(|i| [i; NODE_BYTES]).collect();
        let a = annex_bytes(&publication(&kids));

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
}
