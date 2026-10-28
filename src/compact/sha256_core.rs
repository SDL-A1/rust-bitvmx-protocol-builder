//! SHA-256's compression function and length padding, exposed.
//!
//! FlatMerkle is defined over the *real* compression function, not over an
//! abstraction of it: a publication's digest has to equal the SHA-256 that
//! Bitcoin itself computes over the annex, or the commitment is not a
//! commitment to anything consensus can see.  `bitcoin_hashes` does not
//! offer `compress` directly, but it does offer midstates, and one
//! compression is what a midstate advances by.

use bitcoin::hashes::{sha256, HashEngine};

pub const BLOCK_SIZE: usize = 64;
pub const STATE_SIZE: usize = 32;

/// SHA-256's standard initial chaining value.
pub fn iv_std() -> [u8; STATE_SIZE] {
    sha256::HashEngine::default().midstate().to_byte_array()
}

/// One application of SHA-256's compression function.
///
/// `from_midstate` takes a byte count only so that the engine can finalize
/// correctly later; here we never finalize, we read the midstate back out,
/// so any multiple of the block size does.
pub fn compress(state: &[u8; STATE_SIZE], block: &[u8]) -> [u8; STATE_SIZE] {
    assert_eq!(block.len(), BLOCK_SIZE, "compress takes one block");
    let mut e = sha256::HashEngine::from_midstate(sha256::Midstate(*state), BLOCK_SIZE);
    e.input(block);
    e.midstate().to_byte_array()
}

/// The blocks SHA-256 appends to a message of `total_len` bytes: the 0x80
/// terminator, zero fill, and the 64-bit big-endian bit count.
pub fn length_padding_blocks(total_len: usize) -> Vec<u8> {
    let mut pad = vec![0x80u8];
    while (total_len + pad.len() + 8) % BLOCK_SIZE != 0 {
        pad.push(0);
    }
    pad.extend_from_slice(&((total_len as u64) * 8).to_be_bytes());
    debug_assert_eq!((total_len + pad.len()) % BLOCK_SIZE, 0);
    pad
}

/// The chaining state after the first `n` bytes of `msg`, `n` a multiple of
/// the block size.  This is the `H192` of the publication commitment.
pub fn midstate_at(msg: &[u8], n: usize) -> [u8; STATE_SIZE] {
    assert_eq!(n % BLOCK_SIZE, 0, "midstates land on block boundaries");
    let mut state = iv_std();
    for blk in msg[..n].chunks(BLOCK_SIZE) {
        state = compress(&state, blk);
    }
    state
}

/// Finish a hash from a chaining state and the bytes still to absorb.
pub fn finalize(state: &[u8; STATE_SIZE], tail: &[u8], total_len: usize) -> [u8; STATE_SIZE] {
    let mut buf = tail.to_vec();
    buf.extend_from_slice(&length_padding_blocks(total_len));
    let mut s = *state;
    for blk in buf.chunks(BLOCK_SIZE) {
        s = compress(&s, blk);
    }
    s
}
