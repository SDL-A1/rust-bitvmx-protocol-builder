//! The garbled signature gadget: a circuit whose evaluator produces a
//! signature under the *garbler's* key.
//!
//! This is Futoransky's construction (draft v0.1), and it is what finally
//! answers audit finding C04.
//!
//! # Why the protocol wants it
//!
//! A dispute wants an outcome, not a bit: the party that wins must end up
//! able to *spend*.  The obvious way to get there -- verify a signature
//! inside the circuit and release a secret when it checks -- has the
//! polarity backwards for a mirrored exchange, which is C04: an
//! equality-gated primitive releases on "the signature was correct", and a
//! publication dispute needs to pay on "the signature was *not* correct",
//! which such a primitive does not offer.
//!
//! The gadget removes the question rather than answering it.  Nothing is
//! gated.  The circuit computes a 256-bit scalar `M` and the evaluation
//! *is* a signature on it.  Negating the predicate that chooses which `M`
//! is computed costs one `Gate::Inv`, which under free-XOR is free: no
//! table entry, no ciphertext, no round.
//!
//! # The construction
//!
//! Both Schnorr and ECDSA are affine in one scalar:
//!
//! ```text
//! s = A + B * M
//! ```
//!
//! For BIP340, `A = k` and `B = sk` (both normalised to even-`y`) and `M`
//! is the challenge `e`.  For ECDSA, `A = k^-1 * r * sk` and `B = k^-1`
//! and `M` is the message hash `z`.  Either way `A` and `B` are fixed at
//! garble time and `M` is what the circuit computes.
//!
//! Let wire `i` of the message carry the bit of weight `2^i`, with
//! zero-label `R_i` and one-label `R_i + D` (free-XOR's global offset).
//! Garbling publishes, for each `i`,
//!
//! ```text
//! h_i^0 = H_i(R_i)          h_i^1 = H_i(R_i + D)
//! C_i   = h_i^0 - h_i^1 + B * 2^i
//! ```
//!
//! together with `D_sum = A - sum_i h_i^0`.  An evaluator holding one
//! label `W_i` per wire computes `S_i = H_i(W_i) + m_i * C_i` and
//!
//! ```text
//! s = D_sum + sum_i S_i
//! ```
//!
//! which telescopes: when `m_i = 0` the term is `h_i^0`; when `m_i = 1` it
//! is `h_i^1 + C_i = h_i^0 + B * 2^i`.  So the sum is
//! `sum_i h_i^0 + B * M`, and `s = A + B * M`.
//!
//! All arithmetic is modulo the group order `n`.
//!
//! # Single evaluation is load-bearing
//!
//! An evaluator that ever holds *both* labels of a single message wire
//! learns `h_i^0` and `h_i^1`, and therefore
//!
//! ```text
//! B = (C_i - h_i^0 + h_i^1) * (2^i)^-1
//! ```
//!
//! which for Schnorr is the secret key itself.  [`recover_key`] below
//! performs exactly that extraction, so the invariant is executable rather
//! than a comment: one garbling, one evaluation, one `A`.  The dispute
//! graph has to enforce it, and [`SINGLE_EVALUATION`] names the obligation
//! so the graph's tests can cite it.
//!
//! The same requirement rules out reusing a nonce across disputes, for the
//! ordinary reason: two evaluations with different `M` under one `A` give
//! two equations in two unknowns.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use musig2::secp::{MaybeScalar, Scalar};

use super::garble::{colour, Garbled, Label};

/// The width of the signed scalar: 256 bits, one wire each.
pub const MSG_BITS: usize = 256;

/// The obligation the dispute graph owes this module.
///
/// Kept as a constant so that a graph test can `assert` against something
/// named rather than against a sentence in a doc comment.
///
/// Note what it does *not* say.  "Once, by one party" are sufficient
/// conditions and were how this was first phrased; the necessary one is
/// about the assignment, because the attack needs both labels of a wire
/// and two evaluations on the same inputs hand out the same label on
/// every one of them.  `two_evaluations_on_one_assignment_leak_nothing`
/// checks that.
///
/// The distinction decides whether concurrent challengers could share a
/// garbling, and the answer is no -- but for a reason about the protocol
/// rather than about garbling.  Each challenger must be paid by its own
/// transaction, so the circuit must compute a different message for each,
/// so the message wires take different values however identical the
/// inputs are.
pub const SINGLE_EVALUATION: &str =
    "each garbling of a signature gadget is evaluated on at most one input \
     assignment; evaluating it twice on the same one is harmless";

/// One tweak per dispute option, so material from one gadget cannot be
/// replayed against another.  These mirror `release::*_TWEAK`.
pub const M4_SIG_TWEAK: &[u8] = b"compact-bitvmx/M4/gsig";
pub const M1_SIG_TWEAK: &[u8] = b"compact-bitvmx/M1/gsig";

/// `H_i`: a message wire's label, hashed to a scalar.
///
/// Domain-separated by the gadget's tweak and by the wire index, so the
/// same label on two wires, or in two gadgets, gives unrelated scalars.
fn h_i(tweak: &[u8], i: usize, l: &Label) -> MaybeScalar {
    let mut e = sha256::Hash::engine();
    e.input(tweak);
    e.input(&(i as u32).to_be_bytes());
    e.input(l);
    MaybeScalar::reduce_from(&sha256::Hash::from_engine(e).to_byte_array())
}

/// `2^i mod n` for `i` in `0..MSG_BITS`.
fn two_pow() -> Vec<MaybeScalar> {
    let mut v = Vec::with_capacity(MSG_BITS);
    let mut x = MaybeScalar::one();
    for _ in 0..MSG_BITS {
        v.push(x);
        x = x + x;
    }
    v
}

/// `2^-1 mod n`, which is `(n + 1) / 2`.
///
/// `secp` only exposes a general inverse behind a feature this crate does
/// not enable, and the gadget needs exactly one inverse -- of a power of
/// two.  `two_pow_inv` builds it by repeated multiplication instead, and
/// [`super::super::tests::compact_gsig_test`] checks `2 * HALF == 1`.
const HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA1,
];

/// `(2^i)^-1 mod n`.
pub(crate) fn two_pow_inv(i: usize) -> MaybeScalar {
    let half = MaybeScalar::from(Scalar::from_slice(&HALF).expect("in range"));
    let mut acc = MaybeScalar::one();
    for _ in 0..i {
        acc = acc * half;
    }
    acc
}

/// What the garbler publishes alongside the tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbledSignature {
    /// `C_0 .. C_255`, serialised big-endian.
    pub c: Vec<[u8; 32]>,
    /// `A - sum_i h_i^0`.
    pub d: [u8; 32],
    /// The nonce point's x-only serialisation; the signature's first half.
    pub r_x: [u8; 32],
    /// Output decoding for the message wires: `selectors[i]` is the colour
    /// of `R_i`, so the evaluator reads `m_i = colour(W_i) ^ selectors[i]`.
    ///
    /// Without these the evaluator holds `W_i` but cannot tell which of
    /// `C_i`'s two cases applies.  They are the only part of the gadget
    /// that is per-bit *and* not a scalar, and they are why the material
    /// is 8,288 bytes rather than 8,256.
    pub selectors: Vec<bool>,
}

impl GarbledSignature {
    /// Serialised size, in bytes: `256 * 32 + 32 + 32 + 32 = 8,288`.
    pub fn size(&self) -> usize {
        self.c.len() * 32 + 32 + 32 + self.selectors.len().div_ceil(8)
    }
}

/// The garbler's signing material: `A`, `B`, and the nonce point.
#[derive(Clone, Copy, Debug)]
pub struct Affine {
    pub a: MaybeScalar,
    pub b: MaybeScalar,
    pub r_x: [u8; 32],
}

/// Garble the gadget over `wires`, which must be the circuit's message
/// wires in increasing bit weight: `wires[i]` carries the bit of `2^i`.
///
/// `g` is the garbling those wires belong to; only `label()` is used, so
/// the gadget never touches the offset directly.
pub fn garble(tweak: &[u8], g: &Garbled, wires: &[usize], key: &Affine) -> GarbledSignature {
    assert_eq!(wires.len(), MSG_BITS, "the gadget signs a 256-bit scalar");
    let p2 = two_pow();
    let mut c = Vec::with_capacity(MSG_BITS);
    let mut selectors = Vec::with_capacity(MSG_BITS);
    let mut sum_h0 = MaybeScalar::Zero;

    for (i, &w) in wires.iter().enumerate() {
        let zero = g.label(w, false);
        let one = g.label(w, true);
        let h0 = h_i(tweak, i, &zero);
        let h1 = h_i(tweak, i, &one);
        c.push((h0 - h1 + key.b * p2[i]).serialize());
        selectors.push(colour(&zero));
        sum_h0 = sum_h0 + h0;
    }

    GarbledSignature {
        c,
        d: (key.a - sum_h0).serialize(),
        r_x: key.r_x,
        selectors,
    }
}

/// What the evaluator computes: the message it signed, and `s`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The bits read off the held labels, `m[i]` of weight `2^i`.
    pub m: Vec<bool>,
    /// The 64-byte BIP340 signature, `r_x || s`.
    pub sig: [u8; 64],
}

/// Evaluate the gadget against one label per message wire.
///
/// There is no check here, and there cannot be: the evaluator has no way
/// to tell a correct garbling from an incorrect one before it spends.  A
/// wrong garbling yields a scalar that simply fails verification, which is
/// the same outcome as not evaluating at all -- so the gadget costs the
/// evaluator nothing it was not already risking.
pub fn evaluate(tweak: &[u8], sig: &GarbledSignature, held: &[Label]) -> Evaluation {
    assert_eq!(held.len(), MSG_BITS);
    assert_eq!(sig.c.len(), MSG_BITS);

    let mut s = MaybeScalar::reduce_from(&sig.d);
    let mut m = Vec::with_capacity(MSG_BITS);
    for (i, w) in held.iter().enumerate() {
        let bit = colour(w) ^ sig.selectors[i];
        let mut term = h_i(tweak, i, w);
        if bit {
            term = term + MaybeScalar::reduce_from(&sig.c[i]);
        }
        s = s + term;
        m.push(bit);
    }

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.r_x);
    out[32..].copy_from_slice(&s.serialize());
    Evaluation { m, sig: out }
}

// ---------------------------------------------------------------------------
// BIP340
// ---------------------------------------------------------------------------

/// The BIP340 tagged hash `H_tag(data)`.
fn tagged(tag: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag).to_byte_array();
    let mut e = sha256::Hash::engine();
    e.input(&t);
    e.input(&t);
    for d in data {
        e.input(d);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

/// The garbler, holding a BIP340 key.
#[derive(Clone, Copy, Debug)]
pub struct Signer {
    /// Normalised to the even-`y` representative, as BIP340 requires.
    sk: Scalar,
    /// The x-only public key.
    pub p_x: [u8; 32],
}

impl Signer {
    pub fn new(sk_bytes: &[u8; 32]) -> Self {
        let sk = Scalar::from_slice(sk_bytes).expect("secret key in range");
        let p = sk.base_point_mul();
        let sk = if p.has_odd_y() { -sk } else { sk };
        Signer {
            sk,
            p_x: p.to_even_y().serialize_xonly(),
        }
    }

    /// Fix a nonce and derive `(A, B, R.x)`.
    ///
    /// `A = k` and `B = sk`, both with the even-`y` normalisation applied.
    /// A nonce is good for exactly one garbling; see [`SINGLE_EVALUATION`].
    pub fn affine(&self, nonce: &[u8; 32]) -> Affine {
        let k = Scalar::from_slice(nonce).expect("nonce in range");
        let r = k.base_point_mul();
        let k = if r.has_odd_y() { -k } else { k };
        Affine {
            a: k.into(),
            b: self.sk.into(),
            r_x: r.to_even_y().serialize_xonly(),
        }
    }

    /// The challenge scalar the circuit has to compute:
    /// `e = H_BIP0340/challenge(R.x || P.x || msg) mod n`.
    ///
    /// Note what the circuit's real work is.  `R.x` and `P.x` are known at
    /// garble time, so the tag block and those 64 bytes are a constant
    /// 128-byte prefix whose midstate is absorbed for free; only the
    /// 32-byte `msg` and its padding remain, which is *one* in-circuit
    /// SHA-256 compression.
    pub fn challenge(&self, r_x: &[u8; 32], msg: &[u8; 32]) -> [u8; 32] {
        let e = tagged(b"BIP0340/challenge", &[r_x, &self.p_x, msg]);
        MaybeScalar::reduce_from(&e).serialize()
    }
}

/// `e` as the gadget's wire bits: `bits[i]` has weight `2^i`.
///
/// The scalar is serialised big-endian, so bit `i` lives in byte
/// `31 - i / 8` at position `i % 8`.
pub fn scalar_bits(s: &[u8; 32]) -> Vec<bool> {
    (0..MSG_BITS)
        .map(|i| s[31 - i / 8] >> (i % 8) & 1 == 1)
        .collect()
}

/// The inverse of [`scalar_bits`].
pub fn bits_scalar(bits: &[bool]) -> [u8; 32] {
    assert_eq!(bits.len(), MSG_BITS);
    let mut out = [0u8; 32];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[31 - i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Verify a gadget evaluation as an ordinary BIP340 signature.
pub fn verify(p_x: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    let secp = Secp256k1::verification_only();
    let (Ok(pk), Ok(s)) = (
        XOnlyPublicKey::from_slice(p_x),
        schnorr::Signature::from_slice(sig),
    ) else {
        return false;
    };
    secp.verify_schnorr(&s, &Message::from_digest(*msg), &pk)
        .is_ok()
}

// ---------------------------------------------------------------------------
// The attack the invariant forbids
// ---------------------------------------------------------------------------

/// Recover `B` -- for Schnorr, the signing key -- from both labels of a
/// single message wire.
///
/// This is not a utility.  It exists so that [`SINGLE_EVALUATION`] is
/// tested rather than asserted: if the dispute graph ever lets one party
/// hold both labels of one message wire of one garbling, this function is
/// what that party runs.
pub fn recover_key(
    tweak: &[u8],
    sig: &GarbledSignature,
    i: usize,
    zero: &Label,
    one: &Label,
) -> Option<[u8; 32]> {
    let h0 = h_i(tweak, i, zero);
    let h1 = h_i(tweak, i, one);
    if i >= sig.c.len() {
        return None;
    }
    let num = MaybeScalar::reduce_from(&sig.c[i]) - h0 + h1;
    Some((num * two_pow_inv(i)).serialize())
}
