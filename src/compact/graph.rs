//! The dispute transaction graph: a chained spine of stages, with the
//! timeouts and disputes hanging off it.
//!
//! The property the whole arrangement rests on is that a stage's input
//! set and output set are fixed at setup, so its txid is known before
//! anyone knows what it will publish.  A segwit txid does not cover the
//! witness, and the publication lives in the annex, so the chain can be
//! pre-signed even though its contents are decided at dispute time.  That
//! is also why the deduplication reference cannot ride on the stage: a
//! transaction that spends a per-party output has a per-party txid, and
//! the shapes would multiply down the chain.

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_PUSHNUM_1, OP_SHA256,
};
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

/// Dust for the small protocol outputs.
pub const DUST: u64 = 330;
/// Every lock in the graph is one challenge period.  In a chain each
/// clock starts when the transaction that created the output it guards
/// confirmed, so there is no schedule to stagger.
pub const DELTA: u16 = 6 * 24; // blocks, say

/// What an output is for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The prover's stake.
    Stake,
    /// The challenger's bond.
    Bond,
    /// A publication slot: key path only, the 222-byte profile.
    Slot(usize),
    /// A selection output, carrying the digit, the dispute and the timeout.
    Selection(usize),
    /// The declaration output a deduplicating party spends.
    SOut(usize),
    /// One per other party, created by every stage.
    Dedup { level: usize, to: usize },
    /// The output a dispute creates for its answer.
    AnswerSlot,
    /// Output publication only: what `StageData(i)` input 0 spends, and
    /// what `MissingData(i)` takes if that transaction never confirms.
    DataOut(usize),
    /// Output publication only: what `StageData(i)` input 1 spends, so
    /// that a `SIGHASH_ALL` signature can pin the transaction.
    DataFee(usize),
    /// The `OP_RETURN` carrying the dissection, at the index of the
    /// input `SIGHASH_SINGLE` signs.
    Publication { bytes: usize },
}

/// Where a stage's dissection goes.
///
/// Settled at setup, because it changes the transaction graph: an annex
/// rides in the witness of the stage transaction itself, an output needs
/// a transaction of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PublicationMode {
    /// In the stage's own annex. One unit a byte, and Bitcoin Core will
    /// not relay it.
    #[default]
    Annex,
    /// In an `OP_RETURN` of a second transaction. Four units a byte, and
    /// relayed today.
    Output,
}

/// How an output may be spent.  One leaf per variant, plus the key path
/// where the role has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// Key path only: the publisher signs, and the annex rides along.
    KeyPathPublication,
    /// The pre-signed covenant and a one-time signature on the digit.
    Selection,
    /// The pre-signed covenant and a one-time signature on a challenge.
    Dispute,
    /// The pre-signed covenant after a relative timelock.
    Timeout(u16),
    /// A one-time signature naming the party referenced.
    Reference,
    /// Cooperative: both parties sign.
    Cooperative,
    /// The preimage the circuit releases when the claim is wrong.
    ///
    /// Carries `h_b = SHA256(P_b)`, fixed at setup, so the leaf is a
    /// real script rather than a placeholder: a challenger spends it by
    /// putting `P_b` on the stack, which it holds exactly when the
    /// garbled evaluation released it.  See `compact::release`.
    PreimageRelease { h_b: [u8; 32] },
    /// The payout under the signature gadget: a bare `CHECKSIG` against a
    /// key used for nothing else.
    ///
    /// The evaluator does not learn `key`'s secret; it obtains a Schnorr
    /// signature under it, on the one sighash the circuit computes, which
    /// is this transaction's.  See `compact::gsig`.
    ///
    /// That the garbler could sign this leaf itself is not a weakness.
    /// The only thing the signature does is pay the evaluator, so a
    /// garbler that forges it has paid out voluntarily.  What the garbler
    /// must *not* be able to do is move the stake unilaterally, and that
    /// is the business of the other leaves, not this one.
    GadgetRelease { key: XOnlyPublicKey },
}

/// A protocol output, with the leaves it carries.
#[derive(Clone, Debug)]
pub struct Output {
    pub role: Role,
    pub leaves: Vec<Leaf>,
    pub value: u64,
}

impl Output {
    /// The script of one leaf.  Public for the release leaf, which is
    /// the one a party actually has to build a witness for.
    pub fn release_script(leaf: &Leaf, key: &XOnlyPublicKey) -> ScriptBuf {
        Output::script_for(leaf, key)
    }

    fn script_for(leaf: &Leaf, key: &XOnlyPublicKey) -> ScriptBuf {
        // Stand-ins with the right *shape*: what matters structurally is
        // how many leaves an output carries and which of them is timelocked,
        // not the exact opcodes of the one-time-signature check.
        let b = bitcoin::script::Builder::new();
        match leaf {
            Leaf::Timeout(d) => b
                .push_int(*d as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP)
                .push_x_only_key(key)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            Leaf::KeyPathPublication => b.push_opcode(OP_PUSHNUM_1).into_script(),
            // The one leaf whose opcodes matter: it is what the endgame
            // spends, and what it checks is the released secret.
            Leaf::PreimageRelease { h_b } => b
                .push_opcode(OP_SHA256)
                .push_slice(h_b)
                .push_opcode(OP_EQUALVERIFY)
                .push_x_only_key(key)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            // Deliberately not `key`: the gadget's key is its own, and
            // reusing the protocol key here would let one signature serve
            // two purposes.
            Leaf::GadgetRelease { key: g } => b
                .push_x_only_key(g)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
            _ => b
                .push_x_only_key(key)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    /// The Taproot output this becomes.
    pub fn spend_info<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
    ) -> Option<TaprootSpendInfo> {
        let scripts: Vec<ScriptBuf> = self
            .leaves
            .iter()
            .filter(|l| **l != Leaf::KeyPathPublication)
            .map(|l| Output::script_for(l, key))
            .collect();
        if scripts.is_empty() {
            return None; // key path only
        }
        let mut b = TaprootBuilder::new();
        let depth = (scripts.len() as f64).log2().ceil() as u8;
        for (i, s) in scripts.iter().enumerate() {
            // a balanced-enough tree; exact depths only move the control block
            let d = if scripts.len() == 1 { 0 } else { depth.max(1) };
            let d = if i + 1 == scripts.len() && scripts.len() & 1 == 1 && d > 0 {
                d - 1
            } else {
                d
            };
            b = b.add_leaf(d, s.clone()).expect("leaf");
        }
        Some(b.finalize(secp, *key).expect("taptree"))
    }

    pub fn script_pubkey<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
    ) -> ScriptBuf {
        match self.spend_info(secp, key) {
            Some(info) => ScriptBuf::new_p2tr_tweaked(info.output_key()),
            None => ScriptBuf::new_p2tr(secp, *key, None),
        }
    }
}

/// A transaction in the graph, named, with what it spends.
///
/// Called `TxNode` rather than `Node` because `checkpoints::Node` is a
/// state hash, a twenty-byte value, not a transaction.  The two live side
/// by side in the dispute and confusing them is easy.
#[derive(Clone, Debug)]
pub struct TxNode {
    pub name: String,
    pub spends: Vec<(String, usize)>,
    pub outputs: Vec<Output>,
    /// Which of this transaction's inputs carries the publication annex.
    pub slot_input: Option<usize>,
    pub tx: Transaction,
}

impl TxNode {
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }
}

/// Parameters of one dispute instance.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Narrowing levels of the interval search, so `levels + 1` stages.
    pub levels: u32,
    /// How many parties can reference each other's publications.
    pub parties: usize,
    pub delta: u16,
    /// `SHA256(P_b)` for the endgame's release, fixed before any
    /// transaction is signed because it sits in the stake's script.
    pub h_b: [u8; 32],
    /// Where the dissection goes.
    pub mode: PublicationMode,
    /// How big one is, in bytes. At `b = 192` a publication is 8,064.
    pub publication_bytes: usize,
    /// The gadget's key, when the endgame pays by signature rather than
    /// by preimage.  `None` keeps the equality-gated release.
    pub gadget_key: Option<XOnlyPublicKey>,
}

impl Params {
    /// The parameters of a dispute whose endgame releases `P_b`.
    pub fn with_release(self, h_b: [u8; 32]) -> Self {
        Params { h_b, ..self }
    }

    /// Pay the endgame by the signature gadget instead of a preimage.
    ///
    /// This is the shape change C04's resolution makes on chain: the
    /// stake's release leaf stops being `SHA256 <h_b> EQUALVERIFY <P>
    /// CHECKSIG` spent with a 32-byte preimage, and becomes `<P_g>
    /// CHECKSIG` spent with the signature the circuit produced.
    pub fn with_gadget(self, key: XOnlyPublicKey) -> Self {
        Params {
            gadget_key: Some(key),
            ..self
        }
    }

    /// Publish in an `OP_RETURN` rather than in the annex.
    pub fn publishing_in_an_output(self) -> Self {
        Params {
            mode: PublicationMode::Output,
            ..self
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Params {
            levels: 4,
            parties: 2,
            delta: DELTA,
            // A stand-in until a dispute instance seals its own secret;
            // `Params::with_release` is what a real setup calls.
            h_b: [0u8; 32],
            mode: PublicationMode::Annex,
            publication_bytes: 8_064,
            gadget_key: None,
        }
    }
}

/// The whole graph, in topological order.
#[derive(Clone, Debug)]
pub struct Graph {
    pub params: Params,
    pub nodes: Vec<TxNode>,
}

fn p2tr_out<C: Verification>(secp: &Secp256k1<C>, key: &XOnlyPublicKey, o: &Output) -> TxOut {
    TxOut {
        value: Amount::from_sat(o.value),
        script_pubkey: o.script_pubkey(secp, key),
    }
}

/// A bare `OP_RETURN` of value zero, pinned at the slot input's index so
/// that `sha_single_output` is a constant known at setup.
pub fn pinned_output() -> Output {
    Output {
        role: Role::Dedup { level: 0, to: 0 }, // not a protocol output; see `is_pinned`
        leaves: vec![],
        value: 0,
    }
}

impl Graph {
    fn find(&self, name: &str) -> Option<&TxNode> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn get(&self, name: &str) -> &TxNode {
        self.find(name).unwrap_or_else(|| panic!("no node {name}"))
    }

    /// Build the chained spine and everything hanging off it.
    pub fn build<C: Verification>(
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
        params: Params,
    ) -> Self {
        let h_b = params.h_b;
        let mut g = Graph {
            params,
            nodes: Vec::new(),
        };
        let stages = params.levels as usize + 1;
        let others = params.parties - 1;

        // Setup: the stake and the first publication slot.
        g.push(
            secp,
            key,
            "Setup",
            vec![],
            vec![
                Output {
                    role: Role::Stake,
                    leaves: vec![Leaf::Cooperative, release_leaf(&params)],
                    value: 100_000,
                },
                Output {
                    role: Role::Slot(1),
                    leaves: vec![Leaf::KeyPathPublication],
                    value: DUST,
                },
            ],
            None,
        );

        for i in 1..=stages {
            let name = stage_name(i, stages);
            // inputs: the slot, and from stage 2 on the selection output
            let mut spends = vec![(prev_owner(i), slot_vout(i))];
            if i > 1 {
                spends.push((prev_owner(i), sel_vout(i)));
            }

            // outputs, in a fixed order; index 0 is the pinned OP_RETURN
            // so that it sits at the slot input's index
            let mut outs = vec![pinned_output()];
            if i < stages {
                outs.push(Output {
                    role: Role::Slot(i + 1),
                    leaves: vec![Leaf::KeyPathPublication],
                    value: DUST,
                });
            }
            outs.push(Output {
                role: Role::Selection(i + 1),
                leaves: if i + 1 > stages {
                    // the last link: no stage left to select
                    vec![Leaf::Dispute, Leaf::Timeout(params.delta)]
                } else {
                    vec![Leaf::Selection, Leaf::Dispute, Leaf::Timeout(params.delta)]
                },
                value: DUST,
            });
            outs.push(Output {
                role: Role::SOut(i),
                leaves: vec![Leaf::Reference, Leaf::Timeout(params.delta)],
                value: DUST,
            });
            for j in 0..others {
                outs.push(Output {
                    role: Role::Dedup { level: i, to: j },
                    leaves: vec![Leaf::Reference],
                    value: DUST,
                });
            }
            if i == 2 {
                outs.push(Output {
                    role: Role::Bond,
                    leaves: vec![Leaf::Cooperative, Leaf::PreimageRelease { h_b }],
                    value: 50_000,
                });
            }
            // Publishing in an output: the stage carries the two outputs
            // StageData(i) spends -- one for the SIGHASH_SINGLE input
            // that makes the commitment, one for the SIGHASH_ALL input
            // that pins the transaction.
            if params.mode == PublicationMode::Output {
                outs.push(Output {
                    role: Role::DataOut(i),
                    // key path for StageData, a timelocked leaf for
                    // MissingData
                    leaves: vec![Leaf::KeyPathPublication, Leaf::Timeout(params.delta)],
                    value: DUST,
                });
                outs.push(Output {
                    role: Role::DataFee(i),
                    leaves: vec![Leaf::KeyPathPublication],
                    value: DUST,
                });
            }
            g.push(secp, key, &name, spends, outs, Some(0));

            if params.mode == PublicationMode::Output {
                let dv = vout_of(&g, &name, |o| matches!(o.role, Role::DataOut(_)));
                let fv = vout_of(&g, &name, |o| matches!(o.role, Role::DataFee(_)));
                // The publication.  Output 0 sits at the index of input
                // 0, which is what SIGHASH_SINGLE commits to.
                g.push(
                    secp,
                    key,
                    &format!("StageData{i}"),
                    vec![(name.clone(), dv), (name.clone(), fv)],
                    vec![Output {
                        role: Role::Publication {
                            bytes: params.publication_bytes,
                        },
                        leaves: vec![],
                        value: 0,
                    }],
                    Some(0),
                );
                // and the penalization if it never confirms
                g.push(
                    secp,
                    key,
                    &format!("MissingData{i}"),
                    vec![(name.clone(), dv)],
                    vec![Output {
                        role: Role::Stake,
                        leaves: vec![Leaf::Cooperative],
                        value: DUST,
                    }],
                    None,
                );
            }

            // the timeout that takes the stake if this stage is not answered
            let t = format!("Missing{}", i + 1);
            g.push(
                secp,
                key,
                &t,
                vec![(name.clone(), sel_vout_of(&g, &name))],
                vec![Output {
                    role: Role::Stake,
                    leaves: vec![Leaf::Cooperative],
                    value: DUST,
                }],
                None,
            );

            // the publication dispute, terminal, consuming s_out as well
            let d = format!("StageDispute{i}");
            g.push(
                secp,
                key,
                &d,
                vec![
                    (name.clone(), sel_vout_of(&g, &name)),
                    (name.clone(), sout_vout_of(&g, &name)),
                ],
                vec![Output {
                    role: Role::Stake,
                    leaves: vec![Leaf::Cooperative],
                    value: DUST,
                }],
                None,
            );

            // and the reference, when this party deduplicates
            let sd = format!("StageDup{i}");
            g.push(
                secp,
                key,
                &sd,
                vec![(name.clone(), sout_vout_of(&g, &name))],
                vec![],
                None,
            );
        }

        // the endgame's dispute, which is the only one that needs a
        // second message
        let last = stage_name(stages, stages);
        let kw = sel_vout_of(&g, &last);
        g.push(
            secp,
            key,
            "ProverWins",
            vec![(last.clone(), kw)],
            vec![Output {
                role: Role::Stake,
                leaves: vec![Leaf::Cooperative],
                value: DUST,
            }],
            None,
        );
        g.push(
            secp,
            key,
            "Dispute",
            vec![(last.clone(), kw)],
            vec![Output {
                role: Role::AnswerSlot,
                leaves: vec![Leaf::Selection, Leaf::Timeout(params.delta)],
                value: DUST,
            }],
            None,
        );
        g.push(
            secp,
            key,
            "Answer",
            vec![("Dispute".into(), 0)],
            vec![Output {
                role: Role::Stake,
                leaves: vec![Leaf::Cooperative],
                value: DUST,
            }],
            None,
        );
        g.push(
            secp,
            key,
            "MissingAnswer",
            vec![("Dispute".into(), 0)],
            vec![Output {
                role: Role::Stake,
                leaves: vec![Leaf::Cooperative],
                value: DUST,
            }],
            None,
        );
        g
    }

    fn push<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        key: &XOnlyPublicKey,
        name: &str,
        spends: Vec<(String, usize)>,
        outputs: Vec<Output>,
        slot_input: Option<usize>,
    ) {
        let input: Vec<TxIn> = spends
            .iter()
            .map(|(parent, vout)| {
                let txid = if parent.is_empty() {
                    Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros())
                } else {
                    self.get(parent).txid()
                };
                TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout: *vout as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }
            })
            .collect();
        let output: Vec<TxOut> = outputs
            .iter()
            .map(|o| match o.role {
                // The framed scriptPubKey, so that the file starts at
                // byte 64 of the serialized output and its digest is
                // sha_single_output.
                Role::Publication { bytes } => TxOut {
                    value: Amount::ZERO,
                    script_pubkey: super::output::spk_for(&vec![0u8; bytes]),
                },
                _ if is_pinned(o) => TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
                },
                _ => p2tr_out(secp, key, o),
            })
            .collect();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        };
        self.nodes.push(TxNode {
            name: name.to_string(),
            spends,
            outputs,
            slot_input,
            tx,
        });
    }
}

/// Which release leaf the stake carries.
///
/// One leaf either way, so the graph's shape -- and every test that is
/// about its shape -- is unchanged by the choice.  What changes is the
/// witness, which `what_the_gadget_release_saves` measures.
pub fn release_leaf(p: &Params) -> Leaf {
    match p.gadget_key {
        Some(key) => Leaf::GadgetRelease { key },
        None => Leaf::PreimageRelease { h_b: p.h_b },
    }
}

/// Is this output the pinned `OP_RETURN` rather than a protocol output?
pub fn is_pinned(o: &Output) -> bool {
    !matches!(o.role, Role::Publication { .. }) && o.leaves.is_empty() && o.value == 0
}

fn stage_name(i: usize, stages: usize) -> String {
    match i {
        1 => "Claim".into(),
        2 => "Challenge".into(),
        n if n == stages => "Endgame".into(),
        n => format!("Stage{n}"),
    }
}

fn prev_owner(i: usize) -> String {
    if i == 1 {
        "Setup".into()
    } else {
        stage_name(i - 1, usize::MAX)
    }
}

fn slot_vout(i: usize) -> usize {
    if i == 1 {
        1 // Setup's second output
    } else {
        1 // every stage puts the next slot at index 1, after the pinned output
    }
}

fn sel_vout(_i: usize) -> usize {
    2
}

fn vout_of(g: &Graph, name: &str, pred: impl Fn(&Output) -> bool) -> usize {
    g.get(name)
        .outputs
        .iter()
        .position(pred)
        .unwrap_or_else(|| panic!("no such output on {name}"))
}

fn sel_vout_of(g: &Graph, name: &str) -> usize {
    g.get(name)
        .outputs
        .iter()
        .position(|o| matches!(o.role, Role::Selection(_)))
        .expect("a selection output")
}

fn sout_vout_of(g: &Graph, name: &str) -> usize {
    g.get(name)
        .outputs
        .iter()
        .position(|o| matches!(o.role, Role::SOut(_)))
        .expect("an s_out")
}
