//! The publication disputes, M1 to M6.
//!
//! None of them demands an answer: in every case the party that alleges
//! the fault is the party that holds the evidence, so a publication
//! dispute is one transaction carrying its own refutation and it decides
//! when it confirms.  Nothing here is settled by a timeout, which matters
//! because a timeout decides against whoever is slow rather than against
//! whoever is wrong.
//!
//! M1 is not re-derived here: refuting a file that is not a canonical
//! FlatMerkle file is paper 1's malformation proof, and the guarantee it
//! rests on -- that for *every* byte string an honest opponent can prove
//! either an inclusion or a malformation -- is inherited, not rebuilt.

use super::commitment::{
    CONSTANT_TAIL, CONSTANT_TAIL_OFFSET, INPUT_INDEX_OFFSET, OUTPUT_DIGEST_OFFSET,
    OUTPUT_FINAL_BLOCK_START, OUTPUT_PROFILE_BITCOUNT, PROFILE_BITCOUNT, SPEND_TYPE_OFFSET,
    WINDOW_LEN,
};
use super::flatmerkle::{verify_proof, Frame, Proof};
use super::sha256_core::{compress, midstate_at, BLOCK_SIZE, STATE_SIZE};
use super::checkpoints::{packed_position, NODE_BYTES, NODE_OFFSET};
use super::search::State as Node;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1, Verification, XOnlyPublicKey};

// ---------------------------------------------------------------------
// M5 and M6: what profile did the publisher actually sign?
// ---------------------------------------------------------------------

/// The profile witness: the publisher's own signature, the chaining
/// state before SHA-256's final block of the message it signed, and that
/// block.
///
/// The disputer cannot have invented this -- it cannot forge under the
/// publisher's key -- so if the signature verifies, the length field and
/// the window are the real ones.
///
/// The final block is carried **whole**, not rebuilt from a thirty-byte
/// head.  `commitment::final_block` rebuilds it as
/// `window || 80 || 00^25 || 1776`, which is right for the protocol's own
/// 222-byte profile and wrong for everything else -- and everything else
/// is exactly what M5 convicts.  Of the fourteen profiles, three have a
/// final block of that shape, and `ALL|ANYONECANPAY` with no annex, the
/// spend M5 exists to catch, is not among them.
///
/// Nothing here checks that the block is correctly shaped padding, and
/// nothing needs to: a disputer who invents one must steer
/// `compress(h192, block)` to a digest the publisher actually signed,
/// which is a free-start preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileWitness {
    pub signature: [u8; 64],
    /// The chaining state before the final block.
    pub h192: [u8; STATE_SIZE],
    /// That block, all sixty-four bytes of it.
    pub final_block: [u8; BLOCK_SIZE],
}

/// What a disputer commits as circuit input: signature, state, block.
pub const PROFILE_WITNESS_LEN: usize = 64 + STATE_SIZE + BLOCK_SIZE;

/// What a profile witness says.  These three cases are exhaustive, which
/// is the whole of the M5 argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Profile {
    /// `8B = 1776` and the window is not the pinned output's: an annex is
    /// present and this is a genuine publication.
    Published { window: [u8; WINDOW_LEN] },
    /// `8B = 1776` but the window is the pinned output's hash: the
    /// publisher signed `SINGLE|ANYONECANPAY` and committed to a constant
    /// everyone could have written down in advance.
    CommittedToPinnedOutput,
    /// `8B = 1776` but the window is the *empty annex's* hash: she carried
    /// the bare 0x50 opt-in tag and published no file.
    ///
    /// This case was missing until the November 2026 audit (C09) found
    /// it.  BIP341 appends `sha_annex`, which is thirty-two bytes whatever
    /// the annex weighs, so an empty annex reaches 1776 bits exactly as a
    /// real publication does and the length field cannot separate them.
    /// Its window is a constant anyone can write down:
    /// `SHA256(0x01 || 0x50)[2..32]`.
    CarriedEmptyAnnex,
    /// Not the protocol's profile at all.
    WrongLength { bitcount: u64 },
    /// The witness is not the publisher's.
    NotHers,
}

impl ProfileWitness {
    /// Build the witness for a message the publisher signed.
    ///
    /// Any message, of any profile: the block is taken as it is rather
    /// than reconstructed, so this works for the ones M5 convicts as
    /// well as for the one it does not.
    pub fn for_message(signature: [u8; 64], msg: &[u8]) -> Self {
        let n_blocks = (msg.len() + 9).div_ceil(BLOCK_SIZE);
        let mut padded = msg.to_vec();
        padded.push(0x80);
        padded.resize(BLOCK_SIZE * n_blocks - 8, 0);
        padded.extend_from_slice(&(8 * msg.len() as u64).to_be_bytes());
        let start = BLOCK_SIZE * (n_blocks - 1);
        ProfileWitness {
            signature,
            h192: midstate_at(&padded, start),
            final_block: padded[start..].try_into().expect("64 bytes"),
        }
    }

    /// The signature hash the witness implies, in one compression.
    pub fn sighash(&self) -> [u8; STATE_SIZE] {
        compress(&self.h192, &self.final_block)
    }

    /// The length field, read out of the final block.
    pub fn bitcount(&self) -> u64 {
        u64::from_be_bytes(self.final_block[56..64].try_into().expect("8 bytes"))
    }

    /// The thirty bytes the one-compression check recovers.  Meaningful
    /// only when the bitcount is the protocol's: it is what tells the
    /// two 222-byte profiles apart.
    pub fn window(&self) -> [u8; WINDOW_LEN] {
        self.final_block[..WINDOW_LEN].try_into().expect("30 bytes")
    }
}

/// What a profile witness says about an *output* publication.
///
/// The annex reading of `read_profile` turns on the length field: of the
/// fourteen combinations exactly two reach 1776 bits and both carry an
/// annex.  That does not transplant.  `SIGHASH_SINGLE`, `SIGHASH_ALL`
/// and `SIGHASH_DEFAULT` all give 239-byte messages, because
/// `sha_outputs` and `sha_single_output` are both 32 bytes.
///
/// What separates them is where the constants sit.  Both layouts agree
/// to byte 202; after that `SINGLE` writes `spend_type`, `input_index`
/// and then the digest, while `ALL` writes the digest and then
/// `spend_type` and `input_index`.  The same five bytes, slid 32 along.
/// They are the only part of either layout the publisher does not
/// choose, so the test is where they are, not what they are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputProfile {
    /// A `SIGHASH_SINGLE` key-path spend at the pinned input index: the
    /// window is `sha_single_output`, and this is a genuine publication.
    Published { window: [u8; WINDOW_LEN] },
    /// Not 239 bytes: `NONE`, or any `ANYONECANPAY` variant, or an annex.
    WrongLength { bitcount: u64 },
    /// The constants are at the *end* of the block, so she committed to
    /// every output rather than to the one carrying the file.
    CommittedToEveryOutput,
    /// `spend_type` is not zero: an annex, or a script-path spend.
    NotABareKeyPath { spend_type: u8 },
    /// Signed at an input whose index is not the pinned one, so
    /// `SIGHASH_SINGLE` commits to some other output.
    WrongInputIndex { index: u32 },
    /// The witness is not the publisher's.
    NotHers,
}

/// Read the profile of an output publication.
///
/// Every clause reads the final block, which the witness carries anyway,
/// so this is one compression and four comparisons.
pub fn read_output_profile<C: Verification>(
    secp: &Secp256k1<C>,
    w: &ProfileWitness,
    slot_key: &XOnlyPublicKey,
) -> OutputProfile {
    let sig = match schnorr::Signature::from_slice(&w.signature) {
        Ok(s) => s,
        Err(_) => return OutputProfile::NotHers,
    };
    if secp
        .verify_schnorr(&sig, &Message::from_digest(w.sighash()), slot_key)
        .is_err()
    {
        return OutputProfile::NotHers;
    }
    // From here the block is the true final block of the true message.
    let n = w.bitcount();
    if n != OUTPUT_PROFILE_BITCOUNT {
        return OutputProfile::WrongLength { bitcount: n };
    }
    // The message's last five bytes, not the block's -- the block ends
    // in SHA-256's length field.
    if w.final_block[CONSTANT_TAIL_OFFSET..CONSTANT_TAIL_OFFSET + CONSTANT_TAIL.len()]
        == CONSTANT_TAIL
    {
        return OutputProfile::CommittedToEveryOutput;
    }
    let st = w.final_block[SPEND_TYPE_OFFSET - OUTPUT_FINAL_BLOCK_START];
    if st != 0 {
        return OutputProfile::NotABareKeyPath { spend_type: st };
    }
    let lo = INPUT_INDEX_OFFSET - OUTPUT_FINAL_BLOCK_START;
    let idx = u32::from_le_bytes(w.final_block[lo..lo + 4].try_into().expect("4 bytes"));
    if idx != 0 {
        return OutputProfile::WrongInputIndex { index: idx };
    }
    OutputProfile::Published {
        window: w.final_block[OUTPUT_DIGEST_OFFSET + 2..OUTPUT_DIGEST_OFFSET + 2 + WINDOW_LEN]
            .try_into()
            .expect("30 bytes"),
    }
}

/// M5, for a publication in an output: the disputer wins unless the
/// witness reads as a publication.
pub fn m5_output_stands<C: Verification>(
    secp: &Secp256k1<C>,
    w: &ProfileWitness,
    slot_key: &XOnlyPublicKey,
) -> bool {
    !matches!(
        read_output_profile(secp, w, slot_key),
        OutputProfile::Published { .. }
    )
}

/// Read the profile a publisher used.
///
/// `pinned_window` is the thirty-byte window of the hash of the output
/// the covenant fixes at the slot input's index -- a constant known at
/// setup.
pub fn read_profile<C: Verification>(
    secp: &Secp256k1<C>,
    w: &ProfileWitness,
    slot_key: &XOnlyPublicKey,
    pinned_window: &[u8; WINDOW_LEN],
) -> Profile {
    let sig = match schnorr::Signature::from_slice(&w.signature) {
        Ok(s) => s,
        Err(_) => return Profile::NotHers,
    };
    if secp
        .verify_schnorr(&sig, &Message::from_digest(w.sighash()), slot_key)
        .is_err()
    {
        return Profile::NotHers;
    }
    // From here the tail is the true tail of the true message.
    let n = w.bitcount();
    if n != PROFILE_BITCOUNT {
        return Profile::WrongLength { bitcount: n };
    }
    if &w.window() == pinned_window {
        return Profile::CommittedToPinnedOutput;
    }
    if w.window() == empty_annex_window() {
        return Profile::CarriedEmptyAnnex;
    }
    Profile::Published { window: w.window() }
}

/// Does M5 stand against this publisher?
pub fn m5_stands<C: Verification>(
    secp: &Secp256k1<C>,
    w: &ProfileWitness,
    slot_key: &XOnlyPublicKey,
    pinned_window: &[u8; WINDOW_LEN],
) -> bool {
    !matches!(
        read_profile(secp, w, slot_key, pinned_window),
        Profile::Published { .. }
    )
}

/// M6 is M5, read one hop over: the disputer exhibits *`z`'s* signature
/// on *`z`'s* slot, and if `z` published nothing then the reference to it
/// answers nothing.
pub fn m6_stands<C: Verification>(
    secp: &Secp256k1<C>,
    referenced: &ProfileWitness,
    referenced_slot_key: &XOnlyPublicKey,
    pinned_window: &[u8; WINDOW_LEN],
) -> bool {
    m5_stands(secp, referenced, referenced_slot_key, pinned_window)
}

/// The node value a published window carries.
/// The window a publisher lands on if she carries the bare 0x50 annex and
/// no file.  `sha_annex` of an empty annex is a constant, so this is one.
pub fn empty_annex_window() -> [u8; WINDOW_LEN] {
    use bitcoin::hashes::{sha256, Hash};
    let d = sha256::Hash::hash(&[0x01u8, 0x50]).to_byte_array();
    let mut w = [0u8; WINDOW_LEN];
    w.copy_from_slice(&d[2..2 + WINDOW_LEN]);
    w
}

pub fn node_value_of(window: &[u8; WINDOW_LEN]) -> Node {
    window[..NODE_BYTES].try_into().expect("20 bytes")
}

// ---------------------------------------------------------------------
// M2: the opening is false
// ---------------------------------------------------------------------

/// A claim about one entry of a publication, and the opening that settles
/// it.
#[derive(Clone, Debug)]
pub struct EntryClaim {
    pub index: usize,
    pub claimed: Node,
    pub element: Vec<u8>,
    pub proof: Proof,
}

/// Is the claim true?  The opening is checked against the digest, and the
/// digest is what the publisher's signature committed to -- so a false
/// opening is not refutable, it is impossible.
pub fn entry_holds(
    n_elements: usize,
    digest: &[u8; STATE_SIZE],
    frame: &Frame,
    c: &EntryClaim,
) -> bool {
    let (elem, off) = packed_position(c.index);
    if c.element.len() < off + NODE_BYTES {
        return false;
    }
    if c.element[off..off + NODE_BYTES] != c.claimed[..] {
        return false;
    }
    verify_proof(n_elements, digest, elem, &c.element, &c.proof, frame)
}

// ---------------------------------------------------------------------
// M4: the publication contradicts the sender's own selection
// ---------------------------------------------------------------------

/// By selecting index `k` at stage `i`, the sender asserts it disagrees
/// with the value the stage-`(i-1)` publication lists there.  Its own
/// publication at stage `i` must therefore *not* hash to that value.
///
/// A sender that republishes the counterparty's vector verbatim would
/// leave the counterparty with two identical vectors and no index to
/// select, and could then run out the clock.  This is the refutation that
/// makes the selection rule total in practice as well as in principle.
#[derive(Clone, Debug)]
pub struct SelfContradiction {
    /// The index the sender signed at this stage.
    pub selected: usize,
    /// The counterparty's previous publication, opened at that index.
    pub previous: EntryClaim,
    /// The node value of the sender's own publication at this stage.
    pub own_value: Node,
}

/// Does M4 stand?  Open the previous publication at the selected index,
/// authenticate this publication's digest, and compare the two 20-byte
/// values: if they are equal the sender has contradicted its own signed
/// selection.
pub fn m4_stands(
    prev_elements: usize,
    prev_digest: &[u8; STATE_SIZE],
    prev_frame: &Frame,
    s: &SelfContradiction,
) -> bool {
    if s.previous.index != s.selected {
        return false;
    }
    if !entry_holds(prev_elements, prev_digest, prev_frame, &s.previous) {
        return false;
    }
    s.previous.claimed == s.own_value
}

/// The node value a publication's digest carries, for comparison.
pub fn value_of_digest(digest: &[u8; STATE_SIZE]) -> Node {
    digest[NODE_OFFSET..NODE_OFFSET + NODE_BYTES]
        .try_into()
        .expect("20 bytes")
}

// ---------------------------------------------------------------------
// Which refutations ride in the dispute, and which are inherited
// ---------------------------------------------------------------------

/// The publication disputes of the interval construction.
///
/// Two of the trace-tree set are gone, and neither is a cheaper version of
/// itself -- they are obligations an interval search does not incur.
///
///   * `WrongNode` refuted a publication that was not the opening of a
///     node its predecessor listed.  An interval has no parent node.
///   * The equal-vector half of `SelfContradiction` rescued a protocol
///     that had stalled because the two vectors matched.  `search::select`
///     is total, so there is no stall to rescue.
///
/// What remains of `SelfContradiction` is its honest half: a sender whose
/// publication hashes to the very value it selected as disagreed has
/// contradicted its own signed selection, and that is still refutable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MCode {
    /// Not a canonical FlatMerkle file.
    Malformed = 0,
    /// The claimed interior state is not the one the file holds.
    FalseOpening = 1,
    /// The publication contradicts the sender's own selection.
    SelfContradiction = 2,
    /// The slot was not spent with the protocol's signature-hash profile.
    BadProfile = 3,
    /// The reference points at a stage that published nothing.
    DanglingReference = 4,
}

/// Where each option's evidence comes from.  Every one of them is the
/// disputer's: none demands an answer.
pub fn evidence_for(code: MCode) -> &'static str {
    match code {
        MCode::Malformed => "a FlatMerkle malformation proof, O(log N)",
        MCode::FalseOpening => "an opening of the published file at that index",
        MCode::SelfContradiction => "an opening, and a comparison of two 20-byte values",
        MCode::BadProfile => "the publisher's own signature",
        MCode::DanglingReference => "the referenced publisher's signature",
    }
}

/// Five codes fit the three-bit option field the challenge message carries,
/// as the trace tree's six did.
pub const MCODE_BITS: u32 = 3;
