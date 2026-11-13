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
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

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

/// The transaction that carries a stage's dissection.
///
/// Two inputs and one output, and the shape is forced rather than chosen.
///
/// The publication is committed by a `SIGHASH_SINGLE` signature on input
/// `0`, because that hash type signs the output at the signing input's
/// own index -- so the dissection has to be output `0`, and the
/// commitment is then `sha_single_output` over exactly the bytes
/// [`txout_for`] lays down.
///
/// `SIGHASH_SINGLE` leaves the rest of the transaction open, so input
/// `1` carries an ordinary `SIGHASH_ALL` signature and fixes the whole of
/// it. One input with two `CHECKSIG`s in a leaf would be cheaper on chain
/// and is deliberately not done: it puts both signatures in one witness,
/// and the profile witness a dispute reads is then over a message whose
/// length no longer identifies the spend.
///
/// Nothing is pre-signed against this transaction. Its `OP_RETURN` holds
/// bytes decided at dispute time, so its txid is not known at setup --
/// which is why the publication slot it spends carries the timeout rather
/// than this transaction carrying anything downstream.
pub fn data_transaction(slot: OutPoint, fee: OutPoint, sf: &StructuredFile) -> Transaction {
    let input = |previous_output| TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        // Input 0 signs SIGHASH_SINGLE over output 0; input 1 pins the rest.
        input: vec![input(slot), input(fee)],
        output: vec![txout_for(sf)],
    }
}

/// The index whose output a `SIGHASH_SINGLE` signature on this
/// transaction commits to, and so where the publication must sit.
pub const PUBLICATION_VOUT: usize = 0;

/// The input that makes the commitment.
pub const COMMITTING_INPUT: usize = 0;

/// The input that pins the transaction.
pub const PINNING_INPUT: usize = 1;

/// Recover the published file from the scriptPubKey carrying it.
///
/// The inverse of [`spk_for`], and deliberately strict: it accepts only
/// the layout this protocol lays down, so a counterparty reading a
/// dissection off the chain either gets the bytes the publisher framed
/// or gets nothing. Anything else is a publication that did not happen,
/// which is a matter for the profile dispute rather than for a lenient
/// parser.
pub fn body_from_spk(spk: &ScriptBuf) -> Option<Vec<u8>> {
    let s = spk.as_bytes();
    // OP_RETURN, fillers, OP_PUSHDATA4, a four-byte length, the body.
    if s.first() != Some(&0x6a) {
        return None;
    }
    let push = s.iter().position(|b| *b == 0x4e)?;
    // Everything between OP_RETURN and the push must be filler.
    if s[1..push].iter().any(|b| *b != 0x00) {
        return None;
    }
    let len_at = push + 1;
    let body_at = len_at + 4;
    if s.len() < body_at {
        return None;
    }
    let declared = u32::from_le_bytes(s[len_at..body_at].try_into().ok()?) as usize;
    if s.len() != body_at + declared {
        return None;
    }
    // And the header must be the one this body would have been given,
    // which is what makes the file start exactly at byte 64 of the
    // serialized output.
    if s[..body_at] != script_header(declared)[..] {
        return None;
    }
    Some(s[body_at..].to_vec())
}

/// Recover the published file from the transaction carrying it.
///
/// Reads the output a `SIGHASH_SINGLE` signature on the committing input
/// would have signed, and no other: a publication is the output at that
/// index or it is not a publication.
pub fn body_from_transaction(tx: &Transaction) -> Option<Vec<u8>> {
    let txout = tx.output.get(PUBLICATION_VOUT)?;
    if txout.value != Amount::ZERO {
        return None;
    }
    body_from_spk(&txout.script_pubkey)
}
