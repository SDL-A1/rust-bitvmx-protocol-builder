//! Laying a FlatMerkle file into a Taproot annex.
//!
//! BIP341 commits to `sha_annex = SHA256(compact_size(size of annex) ||
//! annex)`, and the annex itself begins with the mandatory `0x50` prefix
//! byte.  Those bytes are not part of the file, but they are part of what
//! is hashed, so a file laid down naively starts at byte 4 or 6 and every
//! block boundary inside it is wrong.
//!
//! The fix is to pad the front so that `compact_size(len) || 0x50 ||
//! header` fills exactly one 64-byte block.  The header is zeros and its
//! length is a public function of `N`, so the prefix block is a constant
//! both parties can compute, and the file proper starts at byte 64.

use super::flatmerkle::{total_raw_len, StructuredFile};
use super::sha256_core::BLOCK_SIZE;
use bitcoin::hashes::{sha256, Hash};

/// BIP341's annex prefix byte.
pub const ANNEX_PREFIX_BYTE: u8 = 0x50;

/// Bitcoin's variable-length integer encoding.
pub fn compact_size(n: usize) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&(n as u64).to_le_bytes());
        v
    }
}

/// How many zero bytes of header a file of `N` elements needs, and the
/// width of the compact size that precedes it.
///
/// The width depends on the annex length, which depends on the header
/// length, which depends on the width: we try the four legal widths in
/// order and keep the first self-consistent one.
pub fn header_len(n: usize) -> (usize, usize) {
    let flen = total_raw_len(n);
    for p in [1usize, 3, 5, 9] {
        let annex_len = (BLOCK_SIZE - p) + flen;
        if compact_size(annex_len).len() == p {
            return (p, BLOCK_SIZE - p - 1);
        }
    }
    panic!("no self-consistent compact-size width for N = {n}");
}

/// The 64-byte block that precedes the file in what Bitcoin hashes.  A
/// public function of `N`: no part of it is publisher-supplied.
pub fn annex_prefix(n: usize) -> Vec<u8> {
    let (p, hdr) = header_len(n);
    let annex_len = (BLOCK_SIZE - p) + total_raw_len(n);
    let mut pre = compact_size(annex_len);
    pre.push(ANNEX_PREFIX_BYTE);
    pre.resize(BLOCK_SIZE, 0);
    debug_assert_eq!(pre.len(), BLOCK_SIZE);
    debug_assert_eq!(p + 1 + hdr, BLOCK_SIZE);
    pre
}

/// The frame a publication of `N` elements is built in.
pub fn annex_frame(n: usize) -> super::flatmerkle::Frame {
    super::flatmerkle::Frame::new(annex_prefix(n))
}

/// The annex itself: the prefix byte, the zero header, and the file.
pub fn annex_bytes(sf: &StructuredFile) -> Vec<u8> {
    let (_, hdr) = header_len(sf.n);
    let mut a = Vec::with_capacity(1 + hdr + sf.raw_bytes.len());
    a.push(ANNEX_PREFIX_BYTE);
    a.resize(1 + hdr, 0);
    a.extend_from_slice(&sf.raw_bytes);
    a
}

/// What an annex of `N` elements costs on chain, in bytes of witness.
pub fn annex_len(n: usize) -> usize {
    let (_, hdr) = header_len(n);
    1 + hdr + total_raw_len(n)
}

/// BIP341's `sha_annex`.
pub fn sha_annex(annex: &[u8]) -> [u8; 32] {
    let mut buf = compact_size(annex.len());
    buf.extend_from_slice(annex);
    sha256::Hash::hash(&buf).to_byte_array()
}
