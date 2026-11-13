//! SHA-256's compression function as a boolean circuit, built rather than
//! loaded.
//!
//! The garbled endgame adjudicates by evaluating a circuit, and nearly
//! every option reduces to one gated compression: M1 reads a length out of
//! a final block, M4 reads a profile out of one, M5 reads another party's,
//! and Section 9.4's memory check asks whether a published node really is
//! the hash of its two children.  That circuit was the one fixture the
//! module did not have --- it is about 3.7 MB in Bristol fashion, which is
//! a poor thing to check in when it is entirely determined by the
//! standard.
//!
//! So it is constructed here, and checked against
//! [`super::sha256_core::compress`], which is `bitcoin_hashes` and
//! therefore the compression Bitcoin itself computes.
//!
//! # What costs gates
//!
//! Under free-XOR only AND gates are paid for, and SHA-256 has three
//! sources of them:
//!
//! | source | ANDs |
//! |---|---:|
//! | message schedule, `48 x 3` additions | `4,464` |
//! | rounds, `64 x 7` additions | `13,888` |
//! | rounds, `Ch` and `Maj` | `4,096` |
//! | the final feed-forward, `8` additions | `248` |
//! | **total** | **`22,696`** |
//!
//! which is the figure the paper measures for one compression.  The
//! rotations and shifts of `Sigma` and `sigma` are free: they are wire
//! relabelling, not gates.
//!
//! An addition costs `31` rather than `32` because the carry out of the
//! top bit is discarded, and the carry itself is one AND a bit rather than
//! two-and-an-OR because under free-XOR
//! `carry' = a ^ ((a ^ b) & (a ^ carry))`.

use super::bristol::{Circuit, Gate};

/// A 32-bit word as wire indices, **index 0 is the most significant bit**,
/// matching the big-endian order SHA-256 is defined in.
pub type Word = [usize; 32];

/// SHA-256's round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Accumulates gates and hands out wire indices.
pub struct Builder {
    gates: Vec<Gate>,
    n_wires: usize,
    zero: usize,
    one: usize,
}

impl Builder {
    /// Start a circuit with `n_inputs` input wires, which are `0..n_inputs`.
    ///
    /// Bristol circuits carry no constants, so a zero is derived as
    /// `x ^ x` from the first input and a one by inverting it.
    pub fn new(n_inputs: usize) -> Self {
        assert!(n_inputs > 0, "need an input to derive a constant from");
        let mut b = Builder {
            gates: Vec::new(),
            n_wires: n_inputs,
            zero: 0,
            one: 0,
        };
        b.zero = b.xor(0, 0);
        b.one = b.inv(b.zero);
        b
    }

    fn alloc(&mut self) -> usize {
        let w = self.n_wires;
        self.n_wires += 1;
        w
    }

    pub fn xor(&mut self, a: usize, b: usize) -> usize {
        let out = self.alloc();
        self.gates.push(Gate::Xor { a, b, out });
        out
    }

    pub fn and(&mut self, a: usize, b: usize) -> usize {
        let out = self.alloc();
        self.gates.push(Gate::And { a, b, out });
        out
    }

    pub fn inv(&mut self, a: usize) -> usize {
        let out = self.alloc();
        self.gates.push(Gate::Inv { a, out });
        out
    }

    pub fn zero(&self) -> usize {
        self.zero
    }

    pub fn one(&self) -> usize {
        self.one
    }

    /// A word of constant bits.
    pub fn constant(&mut self, v: u32) -> Word {
        let mut w = [0usize; 32];
        for (i, slot) in w.iter_mut().enumerate() {
            // index 0 is the most significant bit
            *slot = if (v >> (31 - i)) & 1 == 1 {
                self.one
            } else {
                self.zero
            };
        }
        w
    }

    /// Bitwise XOR, free under free-XOR.
    pub fn xor_word(&mut self, a: &Word, b: &Word) -> Word {
        let mut o = [0usize; 32];
        for i in 0..32 {
            o[i] = self.xor(a[i], b[i]);
        }
        o
    }

    /// `a + b mod 2^32`, a ripple carry costing one AND a bit.
    ///
    /// The carry out of the most significant bit is never computed, which
    /// is why an addition is `31` ANDs and not `32`.
    pub fn add_word(&mut self, a: &Word, b: &Word) -> Word {
        let mut o = [0usize; 32];
        let mut carry = self.zero;
        // index 31 is the least significant bit
        for i in (0..32).rev() {
            let axb = self.xor(a[i], b[i]);
            o[i] = self.xor(axb, carry);
            if i > 0 {
                let axc = self.xor(a[i], carry);
                let t = self.and(axb, axc);
                carry = self.xor(a[i], t);
            }
        }
        o
    }

    /// `Ch(e, f, g) = g ^ (e & (f ^ g))`, one AND a bit.
    pub fn ch(&mut self, e: &Word, f: &Word, g: &Word) -> Word {
        let mut o = [0usize; 32];
        for i in 0..32 {
            let fxg = self.xor(f[i], g[i]);
            let t = self.and(e[i], fxg);
            o[i] = self.xor(g[i], t);
        }
        o
    }

    /// `Maj(a, b, c) = a ^ ((a ^ b) & (a ^ c))`, one AND a bit.
    pub fn maj(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        let mut o = [0usize; 32];
        for i in 0..32 {
            let axb = self.xor(a[i], b[i]);
            let axc = self.xor(a[i], c[i]);
            let t = self.and(axb, axc);
            o[i] = self.xor(a[i], t);
        }
        o
    }

    /// Finish, making `outputs` the top wires: output `k` is wire
    /// `n_wires - 1 - k`, which is what [`Circuit`] requires.
    pub fn finish(mut self, n_inputs: usize, outputs: &[usize]) -> Circuit {
        let zero = self.zero;
        // Emit a copy of each output, last one first, so that the final
        // gate produces output 0 and it lands on the highest wire.
        for &w in outputs.iter().rev() {
            let out = self.alloc();
            self.gates.push(Gate::Xor { a: w, b: zero, out });
        }
        Circuit {
            gates: self.gates,
            n_wires: self.n_wires,
            n_inputs,
            n_outputs: outputs.len(),
        }
    }
}

/// Right rotation, free: it renames wires.
pub fn rotr(w: &Word, n: usize) -> Word {
    let mut o = [0usize; 32];
    for i in 0..32 {
        o[i] = w[(i + 32 - n) % 32];
    }
    o
}

/// Right shift, free except that the vacated bits are the zero wire.
pub fn shr(w: &Word, n: usize, zero: usize) -> Word {
    let mut o = [zero; 32];
    o[n..32].copy_from_slice(&w[..(32 - n)]);
    o
}

/// One application of SHA-256's compression function, as gates.
///
/// `state` is the eight chaining words and `block` the sixteen message
/// words; the result is the eight words of the next chaining state.
pub fn compress(b: &mut Builder, state: &[Word; 8], block: &[Word; 16]) -> [Word; 8] {
    // Message schedule.
    let mut w: Vec<Word> = block.to_vec();
    for t in 16..64 {
        let s0 = {
            let r7 = rotr(&w[t - 15], 7);
            let r18 = rotr(&w[t - 15], 18);
            let s3 = shr(&w[t - 15], 3, b.zero());
            let x = b.xor_word(&r7, &r18);
            b.xor_word(&x, &s3)
        };
        let s1 = {
            let r17 = rotr(&w[t - 2], 17);
            let r19 = rotr(&w[t - 2], 19);
            let s10 = shr(&w[t - 2], 10, b.zero());
            let x = b.xor_word(&r17, &r19);
            b.xor_word(&x, &s10)
        };
        let a1 = b.add_word(&s1, &w[t - 7]);
        let a2 = b.add_word(&a1, &s0);
        let a3 = b.add_word(&a2, &w[t - 16]);
        w.push(a3);
    }

    // Rounds.
    let mut v = *state;
    for (t, wt) in w.iter().enumerate().take(64) {
        let big_s1 = {
            let x = b.xor_word(&rotr(&v[4], 6), &rotr(&v[4], 11));
            b.xor_word(&x, &rotr(&v[4], 25))
        };
        let chv = b.ch(&v[4], &v[5], &v[6]);
        let kt = b.constant(K[t]);

        let t1 = b.add_word(&v[7], &big_s1);
        let t1 = b.add_word(&t1, &chv);
        let t1 = b.add_word(&t1, &kt);
        let t1 = b.add_word(&t1, wt);

        let big_s0 = {
            let x = b.xor_word(&rotr(&v[0], 2), &rotr(&v[0], 13));
            b.xor_word(&x, &rotr(&v[0], 22))
        };
        let majv = b.maj(&v[0], &v[1], &v[2]);
        let t2 = b.add_word(&big_s0, &majv);

        let new_e = b.add_word(&v[3], &t1);
        let new_a = b.add_word(&t1, &t2);

        v = [new_a, v[0], v[1], v[2], new_e, v[4], v[5], v[6]];
    }

    // Feed-forward.
    let mut out = [[0usize; 32]; 8];
    for i in 0..8 {
        out[i] = b.add_word(&state[i], &v[i]);
    }
    out
}

/// Read `n` consecutive words off the input wires, starting at `base`.
fn words_from_inputs<const N: usize>(base: usize) -> [Word; N] {
    let mut out = [[0usize; 32]; N];
    for (i, w) in out.iter_mut().enumerate() {
        for (j, slot) in w.iter_mut().enumerate() {
            *slot = base + i * 32 + j;
        }
    }
    out
}

/// The bare compression: `256` bits of chaining state then `512` bits of
/// block in, `256` bits of next state out.
///
/// Both are big-endian, the order `bitcoin_hashes` uses, so this is
/// directly comparable with [`super::sha256_core::compress`].
pub fn compression_circuit() -> Circuit {
    const N_IN: usize = 256 + 512;
    let mut b = Builder::new(N_IN);
    let state: [Word; 8] = words_from_inputs(0);
    let block: [Word; 16] = words_from_inputs(256);
    let out = compress(&mut b, &state, &block);
    let flat: Vec<usize> = out.iter().flat_map(|w| w.iter().copied()).collect();
    b.finish(N_IN, &flat)
}

/// Bits in a memory tree node: twenty bytes.
pub const NODE_BITS: usize = 160;

/// Section 9.4's memory check, as the verdict circuit the endgame gates a
/// secret with.
///
/// Inputs, in order: the left child, the right child, and the node claimed
/// for their parent --- `480` bits. One output bit, which is `1` when the
/// claim is **wrong**:
///
/// ```text
///     SHA256(left || right)[0..20] != claimed
/// ```
///
/// That polarity is the naysayer's. The prover claims a working; the
/// circuit answers "this node of it is a lie", and the secret is released
/// on that answer.
///
/// The hash is one compression because `left || right` is forty bytes and
/// SHA-256 pads it into a single block: `0x80`, fifteen zero bytes, and
/// the bit length `320`. Those are constants, so they cost nothing to
/// supply and the circuit's whole cost is the compression plus the
/// comparison.
pub fn memory_node_circuit() -> Circuit {
    const N_IN: usize = 3 * NODE_BITS;
    let mut b = Builder::new(N_IN);

    let left: [Word; 5] = words_from_inputs(0);
    let right: [Word; 5] = words_from_inputs(NODE_BITS);
    let claimed: [Word; 5] = words_from_inputs(2 * NODE_BITS);

    // The standard initial value, as constants.
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut state = [[0usize; 32]; 8];
    for (i, w) in state.iter_mut().enumerate() {
        *w = b.constant(IV[i]);
    }

    // The single padded block: left (5 words), right (5 words), then
    // 0x80 and zeros, then the length 320 bits in the last two words.
    let mut block = [[0usize; 32]; 16];
    block[..5].copy_from_slice(&left);
    block[5..10].copy_from_slice(&right);
    block[10] = b.constant(0x8000_0000);
    for w in block.iter_mut().take(14).skip(11) {
        *w = b.constant(0);
    }
    block[14] = b.constant(0);
    block[15] = b.constant(320);

    let digest = compress(&mut b, &state, &block);

    // Is the first twenty bytes of the digest the claimed node? Fold the
    // differences together: any difference makes the claim wrong.
    let mut any_diff = b.zero();
    for i in 0..5 {
        for j in 0..32 {
            let d = b.xor(digest[i][j], claimed[i][j]);
            // any_diff || d, as `a ^ b ^ (a & b)`
            let ab = b.and(any_diff, d);
            let x = b.xor(any_diff, d);
            any_diff = b.xor(x, ab);
        }
    }

    b.finish(N_IN, &[any_diff])
}
