//! The protocol's messages, with their widths.
//!
//! A one-time signature's message width is fixed when its key is
//! generated, long before anyone knows which branch will be taken, so
//! every message here is a fixed-width object padded to its worst case
//! rather than fitted to the case at hand.  Getting a width wrong is not
//! a space bug, it is a protocol bug: the key cannot sign a message it
//! was not sized for.

use super::tracetree::{Node, NODE_BYTES};

/// Winternitz at `NBITS = 4` signs one nibble at a time.
pub const WINTERNITZ_NIBBLE_BITS: usize = 4;

fn nibbles(bits: usize) -> usize {
    bits.div_ceil(WINTERNITZ_NIBBLE_BITS)
}

// ---------------------------------------------------------------- chi'

/// What can be wrong with a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MCode {
    /// Not a canonical FlatMerkle file.
    Malformed = 0,
    /// Anchored only: the publication is of the wrong node.
    WrongNode = 1,
    /// The publication contradicts the sender's own selection.
    SelfContradiction = 2,
    /// The slot was not spent with the protocol's signature-hash profile.
    BadProfile = 3,
    /// The reference points at a stage that published nothing.
    DanglingReference = 4,
}

impl MCode {
    pub fn from_code(c: u8) -> Option<MCode> {
        Some(match c {
            0 => MCode::Malformed,
            1 => MCode::WrongNode,
            2 => MCode::SelfContradiction,
            3 => MCode::BadProfile,
            4 => MCode::DanglingReference,
            _ => return None,
        })
    }

    /// Is the index parameter read at all?  M1, M5 and M6 are about the
    /// publication as a whole; M4's index is the sender's own signed
    /// selection, already on chain.
    pub fn reads_index(self) -> bool {
        matches!(self, MCode::WrongNode)
    }
}

/// The publication challenge: a three-bit option code and an eight-bit
/// index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationChallenge {
    pub option: MCode,
    pub index: u8,
}

/// Three bits of option code.
pub const OPTION_BITS: usize = 3;
/// Eight bits of parameter: one base-`b` digit, for any `b <= 256`.
pub const PARAMETER_BITS: usize = 8;
/// Eleven bits, three Winternitz nibbles, in every branch.
pub const CHALLENGE_BITS: usize = OPTION_BITS + PARAMETER_BITS;

impl PublicationChallenge {
    pub fn bits() -> usize {
        CHALLENGE_BITS
    }

    pub fn nibbles() -> usize {
        nibbles(CHALLENGE_BITS)
    }

    pub fn encode(&self) -> u16 {
        ((self.option as u16) << PARAMETER_BITS) | self.index as u16
    }

    pub fn decode(v: u16) -> Option<Self> {
        if v >> CHALLENGE_BITS != 0 {
            return None;
        }
        Some(PublicationChallenge {
            option: MCode::from_code((v >> PARAMETER_BITS) as u8)?,
            index: (v & 0xFF) as u8,
        })
    }
}

// ----------------------------------------------------------------- chi

/// What can be wrong with the disputed step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ACode {
    /// A read memory access.
    Read = 0,
    /// A write memory access.
    Write = 1,
    /// The instruction's semantics.
    Instruction = 2,
    /// An inclusion claim about the level-L publication.
    Inclusion = 3,
    /// A malformation of it.
    Malformation = 4,
}

/// The endgame challenge: the same shape as `chi'`, and the same width,
/// for the same reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeMessage {
    pub option: ACode,
    pub parameter: u8,
}

impl ChallengeMessage {
    pub fn bits() -> usize {
        CHALLENGE_BITS
    }

    /// Under A1 or A2 the parameter splits: which access is disputed, and
    /// at which level of its path the authentication fails.
    pub fn access_and_level(&self) -> (u8, u8) {
        (self.parameter >> 4, self.parameter & 0x0F)
    }
}

// ----------------------------------------------------------------- tau

/// How many memory slots one RISC-V instruction can touch: two for a
/// fetch that straddles a slot boundary, two more for a load or store
/// that straddles another, and one for the destination register.
pub const MAX_SLOTS: usize = 5;
/// A memory slot.
pub const SLOT_BYTES: usize = 32;
/// An address.
pub const ADDR_BYTES: usize = 4;

/// One slot the step touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub address: u32,
    pub contents: [u8; SLOT_BYTES],
}

/// The step message: everything the circuit reads.
///
/// Padded with zero slots when fewer than `MAX_SLOTS` are touched,
/// because the width is fixed when the key is generated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepMessage {
    pub pre_root: Node,
    pub post_root: Node,
    pub pc: u32,
    pub instruction: u32,
    pub accesses: Vec<Access>,
}

/// `2(20) + 4 + 4 + 5(4 + 32)`.
pub const STEP_MESSAGE_BYTES: usize =
    2 * NODE_BYTES + 4 + 4 + MAX_SLOTS * (ADDR_BYTES + SLOT_BYTES);

impl StepMessage {
    pub fn width() -> usize {
        STEP_MESSAGE_BYTES
    }

    /// Serialize at the fixed width, zero-padding the unused slots.
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.accesses.len() <= MAX_SLOTS);
        let mut v = Vec::with_capacity(STEP_MESSAGE_BYTES);
        v.extend_from_slice(&self.pre_root);
        v.extend_from_slice(&self.post_root);
        v.extend_from_slice(&self.pc.to_be_bytes());
        v.extend_from_slice(&self.instruction.to_be_bytes());
        for i in 0..MAX_SLOTS {
            match self.accesses.get(i) {
                Some(a) => {
                    v.extend_from_slice(&a.address.to_be_bytes());
                    v.extend_from_slice(&a.contents);
                }
                None => v.resize(v.len() + ADDR_BYTES + SLOT_BYTES, 0),
            }
        }
        debug_assert_eq!(v.len(), STEP_MESSAGE_BYTES);
        v
    }
}

// --------------------------------------------------------------- omega

/// A path opening: the two nodes a Merkle path combines at the disputed
/// level, and the FlatMerkle proof binding them to the published
/// multiproof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathOpening {
    pub node: Node,
    pub sibling: Node,
    pub proof: super::flatmerkle::Proof,
}
