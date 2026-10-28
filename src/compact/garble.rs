//! A half-gates garbler over the Bristol circuits of [`super::bristol`].
//!
//! Free-XOR \[Kolesnikov--Schneider\]: one global offset `delta` with its
//! low bit set, wire labels `W^0` and `W^0 ^ delta`, so XOR and INV cost
//! nothing.  Half-gates \[Zahur--Rosulek--Evans\]: two ciphertexts per
//! AND, the evaluator's half selected by the colour bit.
//!
//! This is a garbling, not a protocol.  There is no oblivious transfer
//! here -- the evaluator gets its input labels from the prover's own
//! commitment, which is the point of [`super::release`] -- and the
//! garbling is accepted as given rather than proved.  Proving it is the
//! deferred item in `docs/compact-deferred.md`, and
//! Remark 8.5 of the paper is why that item is load-bearing: the
//! verdict is not decoded and read, it gates a secret, so the garbler is
//! the prover and a prover who garbles a circuit that always answers
//! "fine" wins.

use bitcoin::hashes::{sha256, Hash};

use super::bristol::{Circuit, Gate};

pub const LABEL_LEN: usize = 16;
pub type Label = [u8; LABEL_LEN];

pub fn xor(a: &Label, b: &Label) -> Label {
    let mut o = [0u8; LABEL_LEN];
    for i in 0..LABEL_LEN {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// The colour bit, for point-and-permute.
pub fn colour(l: &Label) -> bool {
    l[0] & 1 == 1
}

fn h(l: &Label, tweak: u64) -> Label {
    let mut m = Vec::with_capacity(LABEL_LEN + 8);
    m.extend_from_slice(l);
    m.extend_from_slice(&tweak.to_le_bytes());
    let d = sha256::Hash::hash(&m).to_byte_array();
    let mut o = [0u8; LABEL_LEN];
    o.copy_from_slice(&d[..LABEL_LEN]);
    o
}

/// Labels the evaluator may see: the tables, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tables(Vec<(Label, Label)>);

impl Tables {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// What the garbler publishes, in bytes.
    pub fn size(&self) -> usize {
        self.0.len() * 2 * LABEL_LEN
    }
}

/// The garbler's view: every wire's zero-label, and the offset.
#[derive(Clone, Debug)]
pub struct Garbled {
    delta: Label,
    zero: Vec<Label>,
    tables: Tables,
}

impl Garbled {
    pub fn new<R: FnMut() -> Label>(c: &Circuit, mut rand: R) -> Self {
        let mut delta = rand();
        delta[0] |= 1;
        let mut zero = vec![[0u8; LABEL_LEN]; c.n_wires];
        for z in zero.iter_mut().take(c.n_inputs) {
            *z = rand();
        }
        let mut tables = Vec::with_capacity(c.and_count());
        for (g, gate) in c.gates.iter().enumerate() {
            match *gate {
                Gate::Xor { a, b, out } => zero[out] = xor(&zero[a], &zero[b]),
                Gate::Inv { a, out } => zero[out] = xor(&zero[a], &delta),
                Gate::And { a, b, out } => {
                    let (a0, b0) = (zero[a], zero[b]);
                    let (a1, b1) = (xor(&a0, &delta), xor(&b0, &delta));
                    let (pa, pb) = (colour(&a0), colour(&b0));
                    let tg0 = xor(&h(&a0, 2 * g as u64), &h(&a1, 2 * g as u64));
                    let tg = if pb { xor(&tg0, &delta) } else { tg0 };
                    let wg = if pa {
                        xor(&h(&a0, 2 * g as u64), &tg)
                    } else {
                        h(&a0, 2 * g as u64)
                    };
                    let te = xor(
                        &xor(&h(&b0, 2 * g as u64 + 1), &h(&b1, 2 * g as u64 + 1)),
                        &a0,
                    );
                    let we = if pb {
                        xor(&h(&b0, 2 * g as u64 + 1), &xor(&te, &a0))
                    } else {
                        h(&b0, 2 * g as u64 + 1)
                    };
                    tables.push((tg, te));
                    zero[out] = xor(&wg, &we);
                }
            }
        }
        Garbled {
            delta,
            zero,
            tables: Tables(tables),
        }
    }

    pub fn tables(&self) -> &Tables {
        &self.tables
    }

    pub fn label(&self, wire: usize, bit: bool) -> Label {
        if bit {
            xor(&self.zero[wire], &self.delta)
        } else {
            self.zero[wire]
        }
    }

    /// Both labels of every input wire.  These are what the prover's
    /// one-time commitment is over: revealing a bit reveals its label.
    pub fn input_labels(&self, c: &Circuit) -> Vec<[Label; 2]> {
        (0..c.n_inputs)
            .map(|w| [self.label(w, false), self.label(w, true)])
            .collect()
    }

    /// Input labels for a bit vector: what the prover reveals when she
    /// opens her claim.
    pub fn encode(&self, c: &Circuit, bits: &[bool]) -> Vec<Label> {
        assert_eq!(bits.len(), c.n_inputs, "input width");
        bits.iter()
            .enumerate()
            .map(|(w, b)| self.label(w, *b))
            .collect()
    }

    /// Which bit a label on a wire carries.  Garbler-side knowledge.
    pub fn decode(&self, wire: usize, l: &Label) -> Option<bool> {
        if *l == self.zero[wire] {
            Some(false)
        } else if *l == xor(&self.zero[wire], &self.delta) {
            Some(true)
        } else {
            None
        }
    }
}

/// The evaluator's work: tables and input labels, no garbler secrets.
pub fn evaluate(c: &Circuit, t: &Tables, inputs: &[Label]) -> Vec<Label> {
    assert_eq!(inputs.len(), c.n_inputs, "input width");
    let mut w = vec![[0u8; LABEL_LEN]; c.n_wires];
    w[..inputs.len()].copy_from_slice(inputs);
    let mut next = 0usize;
    for (g, gate) in c.gates.iter().enumerate() {
        match *gate {
            Gate::Xor { a, b, out } => w[out] = xor(&w[a], &w[b]),
            // INV is free: the same label, with its meaning flipped.
            Gate::Inv { a, out } => w[out] = w[a],
            Gate::And { a, b, out } => {
                let (tg, te) = t.0[next];
                next += 1;
                let (wa, wb) = (w[a], w[b]);
                let wg = if colour(&wa) {
                    xor(&h(&wa, 2 * g as u64), &tg)
                } else {
                    h(&wa, 2 * g as u64)
                };
                let we = if colour(&wb) {
                    xor(&h(&wb, 2 * g as u64 + 1), &xor(&te, &wa))
                } else {
                    h(&wb, 2 * g as u64 + 1)
                };
                w[out] = xor(&wg, &we);
            }
        }
    }
    w
}
