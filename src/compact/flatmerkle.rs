//! FlatMerkle over SHA-256's real 64-byte blocks.
//!
//! A FlatMerkle file is a byte string whose *ordinary* SHA-256 admits
//! logarithmic inclusion proofs, achieved by re-injecting the chaining
//! state of the Merkle-Damgard computation back into the message as MID
//! blocks.  Every item -- data element or MID -- is exactly one block, and
//! a file of `N` elements has `2N - 2` items.
//!
//! The part that matters for publishing in a transaction is the [`Frame`].
//! Bitcoin never hashes the file alone: BIP341's `sha_annex` is
//! `SHA256(compact_size(len) || annex)`, so the file is always preceded by
//! a few bytes that shift every block boundary.  A frame absorbs those
//! bytes into one fixed 64-byte prefix block, which is a public function of
//! `N`, and the file then starts at byte 64 with a derived initial state.

use super::sha256_core::{compress, iv_std, length_padding_blocks, BLOCK_SIZE, STATE_SIZE};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A 32-byte checkpoint padded into a full block, mirroring SHA-256's own
/// bit-padding convention.
fn mid_block(checkpoint: &[u8; STATE_SIZE]) -> Vec<u8> {
    let mut b = checkpoint.to_vec();
    b.push(0x80);
    b.resize(BLOCK_SIZE, 0);
    b
}

/// Pad a data element out to one block.
pub fn pad_element(x: &[u8]) -> Vec<u8> {
    assert!(x.len() <= BLOCK_SIZE, "an element is at most one block");
    let mut b = x.to_vec();
    b.resize(BLOCK_SIZE, 0);
    b
}

/// How a file is embedded in the string Bitcoin actually hashes.
///
/// The prefix must be a *public* function of `N` and of the publication
/// profile, never publisher-supplied: the chain then starts at the derived
/// constant `C(IV, prefix)`, which plays exactly the role the standard IV
/// plays for a standalone file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub prefix: Vec<u8>,
}

impl Frame {
    /// A file hashed on its own, with no prefix.
    pub fn standalone() -> Self {
        Frame { prefix: Vec::new() }
    }

    pub fn new(prefix: Vec<u8>) -> Self {
        assert_eq!(
            prefix.len(),
            BLOCK_SIZE,
            "a frame prefix is exactly one block"
        );
        Frame { prefix }
    }

    pub fn iv(&self) -> [u8; STATE_SIZE] {
        if self.prefix.is_empty() {
            iv_std()
        } else {
            compress(&iv_std(), &self.prefix)
        }
    }

    pub fn hashed_len(&self, n: usize) -> usize {
        self.prefix.len() + total_raw_len(n)
    }
}

/// The smallest file the construction admits.  `build` recurses to
/// `block(a, 1)`, so the top call needs `L - 1 >= 1`.
pub const MIN_ELEMENTS: usize = 4;

/// The file's length in bytes: a pure function of `N`, which the verifier
/// needs in order to reconstruct the finalization padding without seeing
/// the file.
pub fn total_raw_len(n: usize) -> usize {
    assert!(
        n.is_power_of_two() && n >= MIN_ELEMENTS,
        "N must be a power of two, at least {MIN_ELEMENTS}"
    );
    (2 * n - 2) * BLOCK_SIZE
}

/// A built file: its bytes, its digest, and the checkpoints a proof needs.
#[derive(Clone, Debug)]
pub struct StructuredFile {
    pub n: usize,
    pub levels: u32,
    pub elements: Vec<Vec<u8>>,
    pub raw_bytes: Vec<u8>,
    pub checkpoint: HashMap<usize, [u8; STATE_SIZE]>,
    pub ending: HashMap<(usize, u32), [u8; STATE_SIZE]>,
    pub prewrap: HashMap<(usize, u32), [u8; STATE_SIZE]>,
    pub raw_state: [u8; STATE_SIZE],
    pub digest: [u8; STATE_SIZE],
    pub frame: Frame,
}

struct Builder<'a> {
    sf: &'a mut StructuredFile,
    state: [u8; STATE_SIZE],
}

impl<'a> Builder<'a> {
    fn emit_data(&mut self, i: usize) {
        let blk = self.sf.elements[i].clone();
        self.sf.raw_bytes.extend_from_slice(&blk);
        self.state = compress(&self.state, &blk);
    }

    fn emit_mid(&mut self, a: usize) {
        let blk = mid_block(&self.sf.checkpoint[&a]);
        self.sf.raw_bytes.extend_from_slice(&blk);
        self.state = compress(&self.state, &blk);
    }

    fn block(&mut self, a: usize, k: u32) {
        self.sf.checkpoint.entry(a).or_insert(self.state);
        if k == 1 {
            self.emit_data(a);
            self.emit_data(a + 1);
            self.sf.prewrap.insert((a, k), self.state);
            self.emit_mid(a);
        } else {
            let half = 1usize << (k - 1);
            self.block(a, k - 1);
            self.block(a + half, k - 1);
            self.sf.prewrap.insert((a, k), self.state);
            self.emit_mid(a);
        }
        self.sf.ending.insert((a, k), self.state);
    }
}

/// Build the file for `elements`, embedded in `frame`.
///
/// The invariant the whole construction rests on:
/// `digest == SHA256(frame.prefix || raw_bytes)`.
pub fn build(elements: &[Vec<u8>], frame: Frame) -> StructuredFile {
    let n = elements.len();
    assert!(
        n.is_power_of_two() && n >= MIN_ELEMENTS,
        "N must be a power of two and at least {MIN_ELEMENTS}: the recursion \
         bottoms out at a pair of pairs, so N = 2 has no MID block to hang a \
         proof from.  With three node values to an element that is b >= 12, \
         which is the smallest branching factor the paper considers anyway."
    );
    let levels = n.trailing_zeros();
    let iv = frame.iv();
    let mut sf = StructuredFile {
        n,
        levels,
        elements: elements.iter().map(|e| pad_element(e)).collect(),
        raw_bytes: Vec::with_capacity(total_raw_len(n)),
        checkpoint: HashMap::new(),
        ending: HashMap::new(),
        prewrap: HashMap::new(),
        raw_state: [0; STATE_SIZE],
        digest: [0; STATE_SIZE],
        frame: frame.clone(),
    };

    {
        let mut b = Builder {
            sf: &mut sf,
            state: iv,
        };
        b.block(0, levels - 1);
        b.block(1usize << (levels - 1), levels - 1);
        let end = b.state;
        b.sf.raw_state = end;
    }

    let total = frame.prefix.len() + sf.raw_bytes.len();
    let pad = length_padding_blocks(total);
    let mut fstate = sf.raw_state;
    for blk in pad.chunks(BLOCK_SIZE) {
        fstate = compress(&fstate, blk);
    }
    sf.digest = fstate;
    sf
}

// ---------------------------------------------------------------------------
// Inclusion proofs
// ---------------------------------------------------------------------------

/// An opening of one element: the pair of data blocks it sits in, and one
/// reveal per level above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub index: usize,
    pub d0: Vec<u8>,
    pub d1: Vec<u8>,
    pub reveals: Vec<[u8; STATE_SIZE]>,
}

impl Proof {
    /// Bytes on the wire: two blocks and a state per level.
    pub fn nbytes(&self) -> usize {
        2 * BLOCK_SIZE + self.reveals.len() * STATE_SIZE
    }
}

pub fn build_proof(sf: &StructuredFile, index: usize) -> Proof {
    let l = sf.levels;
    let a0 = index - (index % 2);
    let mut pf = Proof {
        index,
        d0: sf.elements[a0].clone(),
        d1: sf.elements[a0 + 1].clone(),
        reveals: Vec::new(),
    };
    let half_top = 1usize << (l - 1);

    fn recurse(sf: &StructuredFile, pf: &mut Proof, a: usize, k: u32, target: usize) {
        if k == 1 {
            return;
        }
        let half = 1usize << (k - 1);
        if target < a + half {
            recurse(sf, pf, a, k - 1, target);
            pf.reveals.push(sf.prewrap[&(a + half, k - 1)]);
        } else {
            pf.reveals.push(sf.ending[&(a, k - 1)]);
            recurse(sf, pf, a + half, k - 1, target);
        }
    }

    if a0 < half_top {
        recurse(sf, &mut pf, 0, l - 1, a0);
        pf.reveals.push(sf.prewrap[&(half_top, l - 1)]);
    } else {
        pf.reveals.push(sf.ending[&(0, l - 1)]);
        recurse(sf, &mut pf, half_top, l - 1, a0);
    }
    pf
}

/// The verifier's domain and well-formedness checks, made before any
/// recursion so that a malformed proof is rejected rather than acted on.
pub fn proof_shape_ok(n: usize, index: usize, data: &[u8], pf: &Proof) -> bool {
    if n < MIN_ELEMENTS || !n.is_power_of_two() || index >= n {
        return false;
    }
    let l = n.trailing_zeros() as usize;
    pf.index == index
        && data.len() <= BLOCK_SIZE
        && pf.d0.len() == BLOCK_SIZE
        && pf.d1.len() == BLOCK_SIZE
        && pf.reveals.len() == l - 1
}

/// Verify an opening in `O(log N)` compressions, finishing with the same
/// standard finalization the file itself used.
///
/// The frame has to be threaded all the way through: it supplies the
/// starting state *and* the total length the finalization padding counts.
/// Verifying against the wrong frame fails, which is the point -- the
/// frame is what ties the file to the transaction that published it.
pub fn verify_proof(
    n: usize,
    digest: &[u8; STATE_SIZE],
    index: usize,
    data: &[u8],
    pf: &Proof,
    frame: &Frame,
) -> bool {
    if !proof_shape_ok(n, index, data, pf) {
        return false;
    }
    let l = n.trailing_zeros();
    let a0 = index - (index % 2);
    let padded = pad_element(data);
    if index == a0 && padded != pf.d0 {
        return false;
    }
    if index == a0 + 1 && padded != pf.d1 {
        return false;
    }

    let half_top = 1usize << (l - 1);
    let mut it = pf.reveals.iter();

    fn eval_block(
        pf: &Proof,
        it: &mut std::slice::Iter<'_, [u8; STATE_SIZE]>,
        a: usize,
        k: u32,
        target: usize,
        ckpt: &[u8; STATE_SIZE],
    ) -> Option<[u8; STATE_SIZE]> {
        if k == 1 {
            let s = compress(&compress(ckpt, &pf.d0), &pf.d1);
            return Some(compress(&s, &mid_block(ckpt)));
        }
        let half = 1usize << (k - 1);
        if target < a + half {
            let left_end = eval_block(pf, it, a, k - 1, target, ckpt)?;
            let sib_prewrap = it.next()?;
            let right_end = compress(sib_prewrap, &mid_block(&left_end));
            Some(compress(&right_end, &mid_block(ckpt)))
        } else {
            let left_end = *it.next()?;
            let right_end = eval_block(pf, it, a + half, k - 1, target, &left_end)?;
            Some(compress(&right_end, &mid_block(ckpt)))
        }
    }

    let raw_state = if a0 < half_top {
        let y = match eval_block(pf, &mut it, 0, l - 1, a0, &frame.iv()) {
            Some(y) => y,
            None => return false,
        };
        let r2 = match it.next() {
            Some(r) => r,
            None => return false,
        };
        compress(r2, &mid_block(&y))
    } else {
        let y_reveal = match it.next() {
            Some(r) => *r,
            None => return false,
        };
        match eval_block(pf, &mut it, half_top, l - 1, a0, &y_reveal) {
            Some(s) => s,
            None => return false,
        }
    };

    if it.next().is_some() {
        return false;
    }

    let pad = length_padding_blocks(frame.hashed_len(n));
    let mut fstate = raw_state;
    for blk in pad.chunks(BLOCK_SIZE) {
        fstate = compress(&fstate, blk);
    }
    &fstate == digest
}

// ---------------------------------------------------------------------------
// Batched openings
// ---------------------------------------------------------------------------

/// Several elements opened at once, carrying each shared reveal only
/// where the recursion actually needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProof {
    /// Pair start -> the two data blocks of that pair.
    pub pairs: BTreeMap<usize, (Vec<u8>, Vec<u8>)>,
    pub reveals: Vec<[u8; STATE_SIZE]>,
}

impl MultiProof {
    pub fn nbytes(&self) -> usize {
        2 * BLOCK_SIZE * self.pairs.len() + STATE_SIZE * self.reveals.len()
    }
}

fn split(a: usize, k: u32, s: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let h = 1usize << (k - 1);
    (
        s.iter().copied().filter(|x| *x < a + h).collect(),
        s.iter().copied().filter(|x| *x >= a + h).collect(),
    )
}

pub fn build_multiproof(sf: &StructuredFile, indices: &[usize]) -> MultiProof {
    let l = sf.levels;
    let starts: BTreeSet<usize> = indices.iter().map(|i| i - (i % 2)).collect();
    let mut mp = MultiProof {
        pairs: starts
            .iter()
            .map(|s| (*s, (sf.elements[*s].clone(), sf.elements[s + 1].clone())))
            .collect(),
        reveals: Vec::new(),
    };

    fn rec(sf: &StructuredFile, mp: &mut MultiProof, a: usize, k: u32, s: &[usize]) {
        if k == 1 {
            return;
        }
        let h = 1usize << (k - 1);
        let (sl, sr) = split(a, k, s);
        if !sl.is_empty() && !sr.is_empty() {
            rec(sf, mp, a, k - 1, &sl);
            rec(sf, mp, a + h, k - 1, &sr);
        } else if !sl.is_empty() {
            rec(sf, mp, a, k - 1, &sl);
            mp.reveals.push(sf.prewrap[&(a + h, k - 1)]);
        } else {
            mp.reveals.push(sf.ending[&(a, k - 1)]);
            rec(sf, mp, a + h, k - 1, &sr);
        }
    }

    let h_top = 1usize << (l - 1);
    let p: Vec<usize> = starts.iter().copied().collect();
    let (pl, pr): (Vec<usize>, Vec<usize>) = p.iter().partition(|s| **s < h_top);
    if !pl.is_empty() && !pr.is_empty() {
        rec(sf, &mut mp, 0, l - 1, &pl);
        rec(sf, &mut mp, h_top, l - 1, &pr);
    } else if !pl.is_empty() {
        rec(sf, &mut mp, 0, l - 1, &pl);
        mp.reveals.push(sf.prewrap[&(h_top, l - 1)]);
    } else {
        mp.reveals.push(sf.ending[&(0, l - 1)]);
        rec(sf, &mut mp, h_top, l - 1, &pr);
    }
    mp
}

/// Verify a batched opening.
///
/// The pair starts are derived from the verifier's own claims, never
/// from the proof: a proof that opens pairs the verifier did not ask
/// about is rejected rather than evaluated.
pub fn verify_multiproof(
    n: usize,
    digest: &[u8; STATE_SIZE],
    claims: &BTreeMap<usize, Vec<u8>>,
    mp: &MultiProof,
    frame: &Frame,
) -> bool {
    if n < MIN_ELEMENTS || !n.is_power_of_two() || claims.is_empty() {
        return false;
    }
    let l = n.trailing_zeros();
    if claims.keys().any(|t| *t >= n) {
        return false;
    }
    let starts: BTreeSet<usize> = claims.keys().map(|t| t - (t % 2)).collect();
    if mp.pairs.keys().copied().collect::<BTreeSet<_>>() != starts {
        return false;
    }
    for (t, data) in claims {
        let (d0, d1) = &mp.pairs[&(t - (t % 2))];
        if d0.len() != BLOCK_SIZE || d1.len() != BLOCK_SIZE {
            return false;
        }
        let want = if t % 2 == 0 { d0 } else { d1 };
        if &pad_element(data) != want {
            return false;
        }
    }

    let mut it = mp.reveals.iter();

    fn ev(
        mp: &MultiProof,
        it: &mut std::slice::Iter<'_, [u8; STATE_SIZE]>,
        a: usize,
        k: u32,
        s: &[usize],
        ckpt: &[u8; STATE_SIZE],
    ) -> Option<[u8; STATE_SIZE]> {
        if k == 1 {
            let (d0, d1) = mp.pairs.get(&a)?;
            let x = compress(&compress(&compress(ckpt, d0), d1), &mid_block(ckpt));
            return Some(x);
        }
        let h = 1usize << (k - 1);
        let (sl, sr) = split(a, k, s);
        let right_end = if !sl.is_empty() && !sr.is_empty() {
            let left_end = ev(mp, it, a, k - 1, &sl, ckpt)?;
            ev(mp, it, a + h, k - 1, &sr, &left_end)?
        } else if !sl.is_empty() {
            let left_end = ev(mp, it, a, k - 1, &sl, ckpt)?;
            compress(it.next()?, &mid_block(&left_end))
        } else {
            let left_end = *it.next()?;
            ev(mp, it, a + h, k - 1, &sr, &left_end)?
        };
        Some(compress(&right_end, &mid_block(ckpt)))
    }

    let h_top = 1usize << (l - 1);
    let p: Vec<usize> = starts.iter().copied().collect();
    let (pl, pr): (Vec<usize>, Vec<usize>) = p.iter().partition(|s| **s < h_top);
    let raw = if !pl.is_empty() && !pr.is_empty() {
        match ev(mp, &mut it, 0, l - 1, &pl, &frame.iv())
            .and_then(|left| ev(mp, &mut it, h_top, l - 1, &pr, &left))
        {
            Some(r) => r,
            None => return false,
        }
    } else if !pl.is_empty() {
        let y = match ev(mp, &mut it, 0, l - 1, &pl, &frame.iv()) {
            Some(y) => y,
            None => return false,
        };
        match it.next() {
            Some(r) => compress(r, &mid_block(&y)),
            None => return false,
        }
    } else {
        let seed = match it.next() {
            Some(r) => *r,
            None => return false,
        };
        match ev(mp, &mut it, h_top, l - 1, &pr, &seed) {
            Some(r) => r,
            None => return false,
        }
    };

    if it.next().is_some() {
        return false;
    }

    let pad = length_padding_blocks(frame.hashed_len(n));
    let mut fstate = raw;
    for blk in pad.chunks(BLOCK_SIZE) {
        fstate = compress(&fstate, blk);
    }
    &fstate == digest
}
