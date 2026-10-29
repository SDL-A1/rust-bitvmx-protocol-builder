//! Publishing in an `OP_RETURN` output, and the frame that makes its
//! digest the commitment.
//!
//! The annex module has the same job for the annex, and the reason both
//! exist is the same.  BIP341 does not hash the raw file: it hashes
//! `SHA256(serialize(txout))` for an output, as it hashes
//! `SHA256(compact_size(len) || annex)` for an annex.  So the file has
//! to be preceded by exactly one 64-byte block of serialization header,
//! a public function of `N`, for its FlatMerkle digest to be
//! `sha_single_output` at all.
//!
//! The header is
//!
//! ```text
//! amount (8, zero) || compact_size(script length) || scriptPubKey header
//! ```
//!
//! and the script header is `OP_RETURN`, a run of `OP_0` fillers, and
//! `OP_PUSHDATA4 <length>` --- a single push after `OP_RETURN`, so the
//! script is push-only and provably unspendable, with the file starting
//! exactly at byte 64 of the serialized output.  The fillers are what
//! buy the alignment, and they are the output's analogue of the annex
//! frame's zero header.

use super::annex::compact_size;
use super::flatmerkle::{total_raw_len, Frame, StructuredFile};
use bitcoin::{Amount, ScriptBuf, TxOut};

const BLOCK_SIZE: usize = 64;
/// One `OP_PUSHDATA4` bounds the body, so this layout covers `N` up to
/// `2^25`.  The annex layout, with a nine-byte `compact_size`, reaches
/// further than anything else here needs.
pub const MAX_OUTPUT_BODY: usize = u32::MAX as usize;

/// `(width of the compact_size, length of the script header)`, chosen so
/// that the two together with the eight-byte amount fill one block.
///
/// The width depends on the script length, which depends on the width,
/// so the smallest self-consistent choice is taken.
pub fn header_len(body: usize) -> (usize, usize) {
    for p in [1usize, 3, 5, 9] {
        let h = BLOCK_SIZE - 8 - p;
        if compact_size(h + body).len() == p {
            return (p, h);
        }
    }
    panic!("no consistent compact_size width for a body of {body}")
}

/// `OP_RETURN`, the fillers, and `OP_PUSHDATA4 <length>`.
pub fn script_header(body: usize) -> Vec<u8> {
    assert!(
        body <= MAX_OUTPUT_BODY,
        "a single push bounds the body at 2^32 - 1 bytes"
    );
    let (_, h) = header_len(body);
    let fill = h - 1 - 5; // OP_RETURN, then OP_PUSHDATA4 and four length bytes
    let mut s = vec![0x6a];
    s.resize(1 + fill, 0x00);
    s.push(0x4e);
    s.extend_from_slice(&(body as u32).to_le_bytes());
    debug_assert_eq!(s.len(), h);
    s
}

/// The scriptPubKey carrying a file.
pub fn spk_for(body: &[u8]) -> ScriptBuf {
    let mut s = script_header(body.len());
    s.extend_from_slice(body);
    ScriptBuf::from_bytes(s)
}

/// The zero-value output carrying it.
pub fn txout_for(sf: &StructuredFile) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: spk_for(&sf.raw_bytes),
    }
}

/// The 64-byte prefix block a publication of `N` elements is framed in:
/// a public function of `N`, exactly as the annex prefix is.
pub fn output_prefix(n: usize) -> Vec<u8> {
    let body = total_raw_len(n);
    let head = script_header(body);
    let mut pre = 0i64.to_le_bytes().to_vec();
    pre.extend_from_slice(&compact_size(head.len() + body));
    pre.extend_from_slice(&head);
    assert_eq!(pre.len(), BLOCK_SIZE, "the prefix is exactly one block");
    pre
}

/// The frame a publication of `N` elements is built in.
pub fn output_frame(n: usize) -> Frame {
    Frame::new(output_prefix(n))
}

/// What publishing `N` elements in an output costs, in weight units.
/// Output bytes are not witness bytes, so each costs four.
pub fn publication_wu(n: usize) -> usize {
    let body = total_raw_len(n);
    let (p, h) = header_len(body);
    4 * (8 + p + h + body)
}
