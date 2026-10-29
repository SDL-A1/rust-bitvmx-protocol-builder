//! The one-compression publication commitment.
//!
//! For a Taproot key-path signature whose BIP341 signing message is
//! exactly 222 bytes, the last 30 bytes of the committed hash begin on the
//! block boundary at 192.  The signature hash is then one compression away
//! from that 30-byte window:
//!
//! ```text
//! sighash = C(H192, window || 0x80 || 0x00^25 || 0x6f0)
//! ```
//!
//! with `0x6f0 = 1776 = 8 * 222` the length field SHA-256 writes into its
//! final block.  Exactly two hash types reach 222 bytes, and both carry an
//! annex -- which is why the length field alone proves an annex is there.

use super::sha256_core::{finalize, midstate_at, STATE_SIZE};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::sighash::{Annex, Prevouts, SighashCache};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{TapSighashType, Transaction, TxOut};

/// The signing-message length that the commitment needs.
pub const PROFILE_LEN: usize = 222;
/// Its length field, in bits.
pub const PROFILE_BITCOUNT: u64 = 8 * PROFILE_LEN as u64;
/// Where the window starts.
pub const WINDOW_START: usize = 192;
/// How long it is.
pub const WINDOW_LEN: usize = 30;

/// The 64 bytes a BIP340 tagged hash puts in front of its message.
pub fn tap_sighash_tag() -> Vec<u8> {
    let t = sha256::Hash::hash(b"TapSighash").to_byte_array();
    let mut v = t.to_vec();
    v.extend_from_slice(&t);
    v
}

/// The complete byte string SHA-256 is applied to in order to obtain a
/// BIP341 signature hash: the tagged-hash prefix, then the epoch byte and
/// `SigMsg` that `rust-bitcoin` writes.
///
/// We capture this rather than trusting a formula, because the whole
/// construction turns on its length.
pub fn signing_message<T: std::borrow::Borrow<TxOut>>(
    tx: &Transaction,
    input_index: usize,
    prevouts: &Prevouts<T>,
    annex: Option<&[u8]>,
    leaf: Option<(TapLeafHash, u32)>,
    ty: TapSighashType,
) -> anyhow::Result<Vec<u8>> {
    let mut cache = SighashCache::new(tx);
    let mut body: Vec<u8> = Vec::new();
    let ann = annex.map(|a| Annex::new(a).expect("annex must start with 0x50"));
    cache
        .taproot_encode_signing_data_to(&mut body, input_index, prevouts, ann, leaf, ty)
        .map_err(|e| anyhow::anyhow!("taproot signing data: {e}"))?;
    let mut msg = tap_sighash_tag();
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Does this message have the profile the commitment needs?
pub fn is_commitment_profile(msg: &[u8]) -> bool {
    msg.len() == PROFILE_LEN
}

/// The 30 bytes the signature commits to, read straight out of the message.
pub fn commitment_window(msg: &[u8]) -> [u8; WINDOW_LEN] {
    assert!(is_commitment_profile(msg), "not the 222-byte profile");
    msg[WINDOW_START..PROFILE_LEN].try_into().expect("30 bytes")
}

/// `H192`: the chaining state before the final block.
pub fn h192(msg: &[u8]) -> [u8; STATE_SIZE] {
    assert!(is_commitment_profile(msg), "not the 222-byte profile");
    midstate_at(msg, WINDOW_START)
}

/// Recompute the signature hash from the commitment alone -- one
/// compression, no knowledge of the transaction.
pub fn sighash_from_commitment(
    h192: &[u8; STATE_SIZE],
    window: &[u8; WINDOW_LEN],
) -> [u8; STATE_SIZE] {
    finalize(h192, window, PROFILE_LEN)
}

/// The final block as it is actually laid out, for inspection: the window,
/// the terminator, the zero fill, and the length field.
/// The final block of a message of the protocol's own profile: the
/// window, the padding byte, zeros, and the 1776-bit length field.
///
/// Only for that profile.  M5 reads messages of every profile, and
/// eleven of the fourteen have a final block this cannot produce, so
/// `dispute::ProfileWitness` carries the block rather than rebuilding
/// it here.
pub fn final_block(window: &[u8; WINDOW_LEN]) -> Vec<u8> {
    let mut b = window.to_vec();
    b.push(0x80);
    b.resize(56, 0);
    b.extend_from_slice(&PROFILE_BITCOUNT.to_be_bytes());
    debug_assert_eq!(b.len(), 64);
    b
}

/// The serialized output a `SIGHASH_SINGLE` spend would commit to, so that
/// a pinned output's hash can be computed as a constant.
pub fn serialize_output(out: &TxOut) -> Vec<u8> {
    let mut v = Vec::new();
    out.consensus_encode(&mut v).expect("vec write");
    v
}
