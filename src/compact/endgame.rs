//! The endgame, wired: a circuit, a commitment, and a spend.
//!
//! The pieces exist separately -- [`super::bristol`] loads the circuit,
//! [`super::garble`] garbles it, [`super::release`] gates the secret --
//! and this is what joins them into the exchange the dispute graph
//! actually runs:
//!
//! 1. **Setup.**  The prover garbles the option's circuit, commits to
//!    every input wire (two hashes a bit), seals `P_b` under the verdict
//!    wire's one-label, and publishes the tables, the commitments and
//!    `ct`.  `h_b` goes into the stake's script.
//! 2. **The claim.**  The prover opens the input bits of the step she
//!    claims: one preimage a bit, and that preimage is the label.
//! 3. **Adjudication.**  The challenger checks every opening against the
//!    commitments, evaluates, and tries the release.  If the claim was a
//!    lie it now holds `P_b` and spends the stake.
//!
//! What is deliberately absent is in `docs/compact-deferred.md`: the
//! garbling is accepted as given rather than proved, and `ct` is
//! therefore outside a proof it needs to be inside.

use super::bristol::Circuit;
use super::garble::{evaluate, Garbled, Label, Tables};
use super::release::{commit_inputs, open_inputs, BitCommitment, Release, Secret};

/// What the prover publishes at setup.  Everything here is public.
#[derive(Clone, Debug)]
pub struct Published {
    pub tables: Tables,
    pub commitments: Vec<BitCommitment>,
    pub release: Release,
}

impl Published {
    /// Bytes the prover has to put somewhere off chain.  Only `h_b`
    /// reaches the chain, in the stake's script.
    pub fn size(&self) -> usize {
        self.tables.size() + self.commitments.len() * 64 + 32
    }
}

/// The prover's side, with the garbling secrets.
#[derive(Clone, Debug)]
pub struct Endgame {
    pub circuit: Circuit,
    pub tweak: Vec<u8>,
    garbled: Garbled,
    published: Published,
}

/// What adjudication concludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The claim was a lie, and here is the secret that says so.
    Refuted(Secret),
    /// The claim is what the circuit computes.  Nothing is released.
    Stands,
    /// The opening is not the prover's, or is the wrong width.  The
    /// challenger has not refuted anything and nothing is released.
    NotAnOpening,
}

impl Endgame {
    pub fn setup<R: FnMut() -> Label>(
        circuit: Circuit,
        tweak: &[u8],
        secret: &Secret,
        rand: R,
    ) -> Self {
        assert_eq!(circuit.n_outputs, 1, "a gated circuit emits one bit");
        let garbled = Garbled::new(&circuit, rand);
        let commitments = commit_inputs(&garbled.input_labels(&circuit));
        let release = Release::seal(tweak, &garbled.label(circuit.output_wire(0), true), secret);
        let published = Published {
            tables: garbled.tables().clone(),
            commitments,
            release,
        };
        Endgame {
            circuit,
            tweak: tweak.to_vec(),
            garbled,
            published,
        }
    }

    pub fn published(&self) -> &Published {
        &self.published
    }

    /// The prover's opening of a claim: one label per input bit.
    pub fn open(&self, claim: &[bool]) -> Vec<Label> {
        assert_eq!(claim.len(), self.circuit.n_inputs, "claim width");
        claim
            .iter()
            .enumerate()
            .map(|(w, b)| self.garbled.label(w, *b))
            .collect()
    }

    /// What the verdict wire would say, in the clear.  The prover can
    /// compute this; the challenger cannot, which is the point.
    pub fn verdict(&self, claim: &[bool]) -> bool {
        self.circuit.outputs(&self.circuit.eval(claim))[0]
    }
}

/// The challenger's side.  It holds no garbling secret: the circuit, the
/// published material, and the labels the prover opened.
pub fn adjudicate(circuit: &Circuit, p: &Published, tweak: &[u8], opened: &[Label]) -> Outcome {
    if opened.len() != circuit.n_inputs || open_inputs(&p.commitments, opened).is_none() {
        return Outcome::NotAnOpening;
    }
    let wires = evaluate(circuit, &p.tables, opened);
    match p.release.open(tweak, &wires[circuit.output_wire(0)]) {
        Some(secret) => Outcome::Refuted(secret),
        None => Outcome::Stands,
    }
}
