//! The verdict wire, gating a secret.
//!
//! Section 8 of the paper does not want a bit printed on a screen.  It
//! wants: if the claim is wrong, the challenger ends up holding `P_b`
//! and spends the penalization branch; and if the claim is right, the
//! challenger ends up holding nothing.
//!
//! So there is no output decoding table.  With `h_b = SHA256(P_b)` fixed
//! at setup and in the stake's script, the prover publishes
//!
//! ```text
//! ct = SHA256(tweak || W_v^p) xor P_b
//! ```
//!
//! where `W_v^p` is the verdict wire's label for whichever bit `p` is
//! supposed to pay.  A challenger holding that label recovers `P_b`, and
//! knows it did because the hash matches; a challenger holding the other
//! label computes an unrelated pad.
//!
//! # On polarity, and what C04 actually objects to
//!
//! `p` is a free parameter of [`Release::seal`], not a property of this
//! construction: sealing against the zero-label pays on a false verdict
//! just as cheaply as sealing against the one-label pays on a true one.
//! Audit finding C04 is therefore *not* about this primitive.  It is about
//! the case where the thing the circuit must check is a signature, which
//! is too expensive to verify in-circuit and so gets checked by an
//! equality-gated release instead -- and an equality-gated release emits
//! no verdict wire whose label one could choose.  There is nothing to flip.
//!
//! That case is now handled by [`super::gsig`], which does not gate
//! anything: the evaluation *is* the signature, and the predicate that
//! chooses what gets signed negates for the price of one free gate.
//!
//! Two consequences of this module remain, both recorded in
//! `docs/compact-deferred.md`.  The garbler is the prover, so the garbling
//! has to be proved correct.  And `ct` has to be inside that proof,
//! because the challenger cannot check `ct` before it evaluates --
//! publishing `h_b` at setup is what makes the statement expressible.

use bitcoin::hashes::{sha256, Hash};

use super::garble::Label;

/// One tweak per dispute option, so that material from one cannot be
/// replayed against another.
pub const A3_TWEAK: &[u8] = b"compact-bitvmx/A3/release";
pub const COMPRESSION_TWEAK: &[u8] = b"compact-bitvmx/compression/release";
pub const M5_TWEAK: &[u8] = b"compact-bitvmx/M5/release";

pub type Secret = [u8; 32];

/// A full-width pad.  The label is sixteen bytes, so hashing *it* is
/// sixteen bytes; masking a thirty-two byte secret with that would leave
/// half the secret in the clear.
pub fn pad(tweak: &[u8], l: &Label) -> Secret {
    let mut m = Vec::with_capacity(tweak.len() + l.len());
    m.extend_from_slice(tweak);
    m.extend_from_slice(l);
    sha256::Hash::hash(&m).to_byte_array()
}

pub fn commit_secret(p: &Secret) -> [u8; 32] {
    sha256::Hash::hash(p).to_byte_array()
}

/// What the prover publishes for one dispute option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub ct: Secret,
    /// `SHA256(P_b)`, fixed at setup and checked by the stake's script.
    pub h_b: [u8; 32],
}

impl Release {
    /// `paying` is the verdict wire's label for the bit that should
    /// release the secret.  Either label is equally good; see the
    /// module note on C04.
    pub fn seal(tweak: &[u8], paying: &Label, secret: &Secret) -> Self {
        let p = pad(tweak, paying);
        let mut ct = [0u8; 32];
        for i in 0..32 {
            ct[i] = p[i] ^ secret[i];
        }
        Release {
            ct,
            h_b: commit_secret(secret),
        }
    }

    /// What the evaluator can do: decrypt under the label it holds and
    /// see whether the hash matches.  It needs no decoding table and
    /// learns the verdict only through this.
    pub fn open(&self, tweak: &[u8], held: &Label) -> Option<Secret> {
        let p = pad(tweak, held);
        let mut g = [0u8; 32];
        for i in 0..32 {
            g[i] = p[i] ^ self.ct[i];
        }
        (commit_secret(&g) == self.h_b).then_some(g)
    }
}

/// The input commitment: the revealed preimage *is* the circuit's input
/// label.
///
/// The paper commits these under ACW, whose contribution is guaranteed
/// permissionless extraction and a smaller table, not a different
/// binding.  What the protocol needs of the scheme is only this: the
/// prover publishes two hashes per bit at setup, and opening a bit
/// reveals exactly one preimage, which is the label the evaluator then
/// feeds the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitCommitment {
    pub h: [[u8; 32]; 2],
}

impl BitCommitment {
    pub fn of(labels: &[Label; 2]) -> Self {
        BitCommitment {
            h: [
                sha256::Hash::hash(&labels[0]).to_byte_array(),
                sha256::Hash::hash(&labels[1]).to_byte_array(),
            ],
        }
    }

    /// Which bit this label opens, if either.  A label that opens both
    /// would be an equivocation, and the commitment is one-time.
    pub fn opens(&self, l: &Label) -> Option<bool> {
        let d = sha256::Hash::hash(l).to_byte_array();
        if d == self.h[0] {
            Some(false)
        } else if d == self.h[1] {
            Some(true)
        } else {
            None
        }
    }
}

/// Commit to every input wire of a garbling.
pub fn commit_inputs(labels: &[[Label; 2]]) -> Vec<BitCommitment> {
    labels.iter().map(BitCommitment::of).collect()
}

/// The challenger's check before it evaluates: every opened label is one
/// the prover committed to, and the bits it reads off are the claim.
pub fn open_inputs(c: &[BitCommitment], opened: &[Label]) -> Option<Vec<bool>> {
    if c.len() != opened.len() {
        return None;
    }
    c.iter().zip(opened).map(|(b, l)| b.opens(l)).collect()
}
