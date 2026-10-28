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
use std::collections::HashMap;

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
