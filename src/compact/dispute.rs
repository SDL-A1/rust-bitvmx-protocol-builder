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
    DIGEST_WINDOW_OFFSET, WINDOW_LEN,
};
use super::flatmerkle::{verify_proof, Frame, Proof};
use super::sha256_core::{compress, midstate_at, BLOCK_SIZE, STATE_SIZE};
use super::checkpoints::{packed_position, NODE_BYTES};
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
        window: w.final_block[OUTPUT_DIGEST_OFFSET + DIGEST_WINDOW_OFFSET
            ..OUTPUT_DIGEST_OFFSET + DIGEST_WINDOW_OFFSET + WINDOW_LEN]
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
// The tree's M3, and why it cannot be restated here
// ---------------------------------------------------------------------
//
// The trace tree had an option for a sender whose publication hashed to
// the very value it had selected as disagreed.  It was a real
// contradiction *there* because the tree identified the two objects: a
// child's value WAS the twenty-byte window of the digest of the child's
// own publication, so "my publication hashes to the value I said I
// disagree with" compares a thing to itself.
//
// An interval has no such identity, and the check does not survive the
// change of design.  What the previous publication lists at index `k` is
// a machine-state hash.  What the sender publishes at this stage is a
// dissection of the subinterval `k` names, and its digest is the hash of
// a FlatMerkle file of interior states -- not a state hash at all.  The
// two are different kinds of twenty-byte value.  Comparing them type
// checks and means nothing: it can fire only on a 160-bit collision, and
// an honest sender is as likely to trip it as a dishonest one.
//
// Nor is there a weaker version to keep.  The sender's own value at the
// disagreed point is the *upper endpoint* of its new interval, and
// endpoints are inherited rather than published (`search::Interval`), so
// the chain never sees it at this stage.  It surfaces in the endgame's
// step message, where the lie is adjudicated on its merits.  Which is the
// argument the search already makes: by the full-duplex soundness
// theorem a party that selects inconsistently with its own trace has
// conceded, not attacked, so no option is owed.
//
// This replaces `SelfContradiction`, `m4_stands` and `value_of_digest`,
// all three of which were carried across from the tree unexamined.

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
    /// The slot was not spent with the protocol's signature-hash profile.
    BadProfile = 1,
    /// The reference points at a stage that published nothing.
    DanglingReference = 2,
    /// The reference points at an instance that had already diverged, so
    /// the publication it names dissects a different interval.
    ///
    /// This is what the tree got free from M2 and an interval does not.
    /// See [`divergent_reference`].
    DivergentReference = 3,
}

/// Where each option's evidence comes from.  Every one of them is the
/// disputer's: none demands an answer.
pub fn evidence_for(code: MCode) -> &'static str {
    match code {
        MCode::Malformed => "a FlatMerkle malformation proof, O(log N)",
        MCode::BadProfile => "the publisher's own signature",
        MCode::DanglingReference => "the referenced publisher's signature",
        MCode::DivergentReference => "two selection digits, already on chain",
    }
}

/// Four codes fit a two-bit option field, exactly.
///
/// The tree had five and spent three bits.  Two of those five do not
/// survive the interval: `WrongNode`, which policed a parent-child
/// relation an interval does not have, and `SelfContradiction`, for the
/// reason given above.  A third, `FalseOpening`, was never an option at
/// all -- an opening is checked against a digest the publisher's own
/// signature committed to, so a false one is impossible rather than
/// refutable, and `entry_holds` says so. It was introduced here to keep
/// the count at five when `WrongNode` went, which is backwards: the count
/// is a consequence, not a target.
///
/// `DivergentReference` is the one addition, and it is what lets
/// deduplication run at all here -- see [`divergent_reference`].  It fits
/// the field the other three already needed.
pub const MCODE_BITS: u32 = 2;

// ---------------------------------------------------------------------
// M6: the reference points at an instance that had diverged
// ---------------------------------------------------------------------

/// Is this reference refuted?
///
/// A deduplicating party asserts that the bytes it owes in *this* instance
/// are bytes it already published in *that* one.  The spend of the
/// `Dedup` output proves the other stage confirmed and `BadProfile`
/// proves it was not empty; neither proves it dissects this instance's
/// live interval.  The tree got that from M2, whose opening check a
/// misdirected reference failed; an interval has no parent node and so no
/// M2, which is why deduplication did not transfer.
///
/// It transfers after all, and more cheaply than the option it replaces.
/// The live interval at stage `s` is a function of the selection digits
/// at stages `1..s` and of nothing else -- `search::Interval::subinterval`
/// applied in turn -- and that function is injective, so two instances
/// hold the same interval exactly when their digit prefixes agree.  Each
/// digit is already on chain in the clear, under a one-time key belonging
/// to one instance and one stage, so the predicate's negation is
/// witnessed by a single pair of differing digits.
///
/// There is no circuit here and no binding.  Script verifies the two
/// one-time signatures under keys fixed at setup and compares eight-bit
/// values, which is the same `verify_digits` the selections already use.
/// Re-revealing a digit is not equivocation: a one-time key is punishable
/// on a second *different* message, and this is the same one.
///
/// `here` and `there` are the two instances' digits for stages `1..s`.
/// Returns the first stage at which they differ, which is the witness.
pub fn divergent_reference(here: &[usize], there: &[usize]) -> Option<usize> {
    here.iter()
        .zip(there)
        .position(|(a, b)| a != b)
        .map(|i| i + 1)
}

/// What the refutation puts in the witness: one stage, two digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DivergenceWitness {
    pub stage: usize,
    pub here: usize,
    pub there: usize,
}
