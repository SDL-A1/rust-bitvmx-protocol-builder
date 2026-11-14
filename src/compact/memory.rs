//! Merkelized memory, and what authenticating one instruction costs.
//!
//! The machine state is `(pc, root)`, with `root` the Merkle root of
//! memory laid out as `2^levels` slots of 32 bytes.  Registers are
//! memory-mapped, so a register access is an ordinary memory access.
//!
//! The reason to Merkelize rather than search again for a memory fault is
//! the thesis of the paper: a second search reintroduces the asymmetric
//! round trips, and reintroduces them *per memory access*.  Merkelizing
//! makes the round count independent of memory, and the price is the
//! paths -- which is a question about publication, not about search, and
//! is why they are published rather than committed.

use bitcoin::hashes::{sha256, Hash};
use std::collections::{BTreeSet, HashMap};

/// The first paper's leaf: a thirty-two-byte memory slot.
pub const SLOT: usize = 32;

/// This paper's leaf: one four-byte machine word.
///
/// The machine operates on words.  Authenticating slots and then carrying
/// whole slots into the circuit is twenty-eight bytes of context per
/// access that the instruction's semantics never read.  Narrowing the
/// *tree* keeps the pre- and post-state roots and the authenticated
/// contents and only shrinks their width.
pub const WORD: usize = 4;

/// Depth over 2^20 bytes of memory, by leaf width: 2^15 slots, 2^18 words.
pub const SLOT_LEVELS: u32 = 15;
pub const WORD_LEVELS: u32 = 18;

/// Depth of the tree a deployment actually builds: one leaf per word of
/// the 32-bit address space.
///
/// `WORD_LEVELS` is the paper's figure, over a megabyte. BitVMX puts its
/// register file at `0xF000_0000` and its stack at `0xE000_0000`, so a
/// tree over a contiguous megabyte cannot address either; see
/// `bitvmx_cpu_definitions::memory_tree`, which is the tree that runs.
pub const DEPLOYED_WORD_LEVELS: u32 = 30;

/// The leaf width a tree of this depth is over.
///
/// The empty leaf is the hash of a leaf's worth of zeros, so it depends
/// on the width: hashing a 32-byte zero slot in a word-granular tree
/// builds a different tree from the one Definition 8.1 states. It changes
/// no count below -- the empty value never affects how many siblings a
/// proof carries -- but the roots would not be the protocol's roots.
pub fn leaf_bytes(levels: u32) -> usize {
    if levels == SLOT_LEVELS {
        SLOT
    } else {
        WORD
    }
}

/// A tree node, truncated like every other digest in the protocol.
pub const NODE: usize = 20;

/// 32 registers of four bytes are 128 bytes, which is four slots or
/// thirty-two words.  rs1, rs2 and rd are three distinct words either
/// way; at slot granularity they may share a leaf and at word granularity
/// they cannot, which makes the word multiproof slightly larger.
pub const REG_WORDS: usize = 32;

pub type MemNode = [u8; NODE];

fn trunc(d: [u8; 32]) -> MemNode {
    d[..NODE].try_into().expect("20 bytes")
}

fn h(a: &MemNode, b: &MemNode) -> MemNode {
    let mut buf = Vec::with_capacity(2 * NODE);
    buf.extend_from_slice(a);
    buf.extend_from_slice(b);
    trunc(sha256::Hash::hash(&buf).to_byte_array())
}

fn leaf_hash(v: &[u8]) -> MemNode {
    trunc(sha256::Hash::hash(v).to_byte_array())
}

/// A sparse Merkle tree over `2^levels` slots, with a default empty slot.
#[derive(Clone, Debug)]
pub struct MerkleMemory {
    pub levels: u32,
    /// `empty[k]` is the root of an all-empty subtree of height `k`.
    empty: Vec<MemNode>,
    nodes: HashMap<(u32, usize), MemNode>,
}

impl MerkleMemory {
    pub fn new(levels: u32, contents: &HashMap<usize, Vec<u8>>) -> Self {
        Self::with_leaf_bytes(levels, leaf_bytes(levels), contents)
    }

    /// A tree whose empty leaf is `width` zero bytes.
    pub fn with_leaf_bytes(levels: u32, width: usize, contents: &HashMap<usize, Vec<u8>>) -> Self {
        let mut empty = vec![leaf_hash(&vec![0u8; width])];
        for _ in 0..levels {
            let last = *empty.last().expect("seeded");
            empty.push(h(&last, &last));
        }
        let mut m = MerkleMemory {
            levels,
            empty,
            nodes: HashMap::new(),
        };
        for (i, v) in contents {
            m.nodes.insert((levels, *i), leaf_hash(v));
        }
        for d in (0..levels).rev() {
            let touched: BTreeSet<usize> = m
                .nodes
                .keys()
                .filter(|(dd, _)| *dd == d + 1)
                .map(|(_, j)| j / 2)
                .collect();
            for j in touched {
                let v = h(&m.get(d + 1, 2 * j), &m.get(d + 1, 2 * j + 1));
                m.nodes.insert((d, j), v);
            }
        }
        m
    }

    pub fn get(&self, d: u32, j: usize) -> MemNode {
        *self
            .nodes
            .get(&(d, j))
            .unwrap_or(&self.empty[(self.levels - d) as usize])
    }

    pub fn root(&self) -> MemNode {
        self.get(0, 0)
    }

    /// The sibling path of one leaf, bottom up.
    pub fn path(&self, leaf: usize) -> Vec<MemNode> {
        let mut out = Vec::with_capacity(self.levels as usize);
        let mut j = leaf;
        for d in (1..=self.levels).rev() {
            out.push(self.get(d, j ^ 1));
            j /= 2;
        }
        out
    }

    pub fn verify(&self, leaf: usize, value: &[u8], path: &[MemNode]) -> bool {
        let mut cur = leaf_hash(value);
        let mut j = leaf;
        for sib in path {
            cur = if j & 1 == 1 {
                h(sib, &cur)
            } else {
                h(&cur, sib)
            };
            j /= 2;
        }
        cur == self.root()
    }

    /// The distinct sibling nodes a multiproof over `leaves` must carry:
    /// every sibling on a path that is not itself derivable from the
    /// revealed leaves.
    ///
    /// This is the whole economy of §8.2: a straddling pair is two
    /// *adjacent* leaves sharing all but one level, and the register
    /// slots are adjacent too, so independent paths pay for the same
    /// nodes several times over.
    pub fn authenticated_set(&self, leaves: &[usize]) -> BTreeSet<(u32, usize)> {
        let mut known: BTreeSet<(u32, usize)> = leaves.iter().map(|i| (self.levels, *i)).collect();
        let mut need: BTreeSet<(u32, usize)> = BTreeSet::new();
        let mut frontier = known.clone();
        for d in (1..=self.levels).rev() {
            let mut next = BTreeSet::new();
            for (_, j) in frontier.iter().filter(|(dd, _)| *dd == d) {
                if !known.contains(&(d, j ^ 1)) {
                    need.insert((d, j ^ 1));
                }
                next.insert((d - 1, j / 2));
            }
            known.extend(next.iter().copied());
            frontier = next;
        }
        need
    }

    pub fn multiproof_bytes(&self, leaves: &[usize]) -> usize {
        self.authenticated_set(leaves).len() * NODE
    }

    /// The nodes a verifier *computes* while checking the multiproof:
    /// every strict ancestor of a revealed leaf, the root included.
    ///
    /// `authenticated_set` is the verifier's input and this is its
    /// working, and the distinction is the whole of audit finding C05.
    /// Publishing the input makes the result publicly computable; it does
    /// not make one step of the working refutable, because when a
    /// challenger names level `l` the step is `n_{l+1} = C(n_l, s_l)` and
    /// only `s_l` is bound to anything.  A circuit asked to check that
    /// compression can be handed whatever `n_l` the prover likes.
    ///
    /// So both are published.  Then every step relates three bound
    /// values: two children in the file and their parent in the file or,
    /// at the top, in the step message.
    pub fn derived_set(&self, leaves: &[usize]) -> BTreeSet<(u32, usize)> {
        let mut known: BTreeSet<(u32, usize)> = leaves.iter().map(|i| (self.levels, *i)).collect();
        let mut derived: BTreeSet<(u32, usize)> = BTreeSet::new();
        let mut frontier = known.clone();
        for d in (1..=self.levels).rev() {
            let mut next = BTreeSet::new();
            for (_, j) in frontier.iter().filter(|(dd, _)| *dd == d) {
                next.insert((d - 1, j / 2));
            }
            known.extend(next.iter().copied());
            derived.extend(next.iter().copied());
            frontier = next;
        }
        derived
    }

    /// What §9.4 publishes: the multiproof and the working it drives.
    pub fn trace_bytes(&self, leaves: &[usize]) -> usize {
        (self.authenticated_set(leaves).len() + self.derived_set(leaves).len()) * NODE
    }

    /// What independent paths would cost: one full path per touched slot.
    pub fn independent_path_bytes(&self, leaves: &[usize]) -> usize {
        leaves.len() * self.levels as usize * NODE
    }
}

/// Which slots one instruction touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// The reachable pattern that maximises the multiproof.
    Worst,
    /// A register-only instruction: fetch plus rs1, rs2, rd.
    Alu,
    /// Fetch, an aligned data read, and rs1, rd.
    Load,
    /// Fetch, an aligned data write, and rs1, rs2.
    Store,
}

/// 32 registers of four bytes are 128 bytes: four slots at the bottom.
pub const REG_SLOTS: usize = 4;

/// The slots an instruction of this shape touches, given a program
/// counter slot and a data slot.
///
/// Nothing straddles.  BitVMX-CPU rejects unaligned reads, writes and jumps
/// outright, so every fetch and every load or store is a four-byte aligned
/// word lying wholly inside one slot.  An earlier version of this function
/// built `data, data + 1` pairs and a `Worst` of two straddling pairs, and
/// measured a bound the machine cannot reach.
///
/// RISC-V is load/store, so no instruction both touches memory and names
/// three registers: four touched slots is the maximum, not five.
pub fn touched(p: Pattern, pc: usize, data: usize, regs: [usize; 3]) -> Vec<usize> {
    let mut v: Vec<usize> = match p {
        Pattern::Worst => vec![regs[0], regs[2], pc, data],
        Pattern::Alu => vec![pc, regs[0], regs[1], regs[2]],
        Pattern::Load => vec![pc, data, regs[0], regs[2]],
        Pattern::Store => vec![pc, regs[0], regs[1], data],
    };
    v.sort_unstable();
    v.dedup();
    v
}

// ---------------------------------------------------------------------
// The word-granular tree of Compact BitVMX II.
// ---------------------------------------------------------------------

/// The words an instruction of this shape touches.
///
/// Same access model as the slot tree, for the same two reasons.
/// BitVMX-CPU rejects unaligned reads, writes and jumps, so every fetch
/// and every load or store is a four-byte aligned word -- nothing
/// straddles, and at this granularity a word *is* a leaf, so the question
/// does not even arise.  RISC-V is load/store, so no instruction both
/// touches memory and names three registers.
///
/// Four touched leaves is the maximum, exactly as at slot granularity.
/// What differs is that the three registers are now always three distinct
/// leaves, where at slot granularity they could share one.
pub fn touched_words(p: Pattern, pc: usize, data: usize, regs: [usize; 3]) -> Vec<usize> {
    let mut v: Vec<usize> = match p {
        Pattern::Worst => vec![regs[0], regs[2], pc, data],
        Pattern::Alu => vec![pc, regs[0], regs[1], regs[2]],
        Pattern::Load => vec![pc, data, regs[0], regs[2]],
        Pattern::Store => vec![pc, regs[0], regs[1], data],
    };
    v.sort_unstable();
    v.dedup();
    v
}

/// The step message of Definition 8.2: two roots, a program counter, an
/// instruction word, and one address-and-contents pair per touched leaf.
///
/// At word granularity a pair is four plus four bytes, where at slot
/// granularity it was four plus thirty-two.
pub fn step_message_bytes(leaf: usize, leaves: usize) -> usize {
    2 * NODE + 4 + 4 + leaves * (4 + leaf)
}

/// The same vectors `bitvmx_cpu_definitions::memory_tree` pins, and that
/// `compact2/python/memory.py` produces.
///
/// There are three implementations of this tree: the one the emulator
/// runs, the model in the paper repository, and this one. Agreeing on
/// node *counts* is not enough -- the empty leaf's width does not change
/// a count but does change every root -- so they are pinned to concrete
/// bytes here. A disagreement is a disagreement about the protocol, not
/// about an opinion.
#[cfg(test)]
mod cross_check {
    use super::*;

    fn hex(n: &MemNode) -> String {
        n.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn word_tree(contents: &[(usize, u32)]) -> MerkleMemory {
        let map: HashMap<usize, Vec<u8>> = contents
            .iter()
            .map(|(i, w)| (*i, w.to_be_bytes().to_vec()))
            .collect();
        MerkleMemory::new(WORD_LEVELS, &map)
    }

    #[test]
    fn the_zero_word_leaf() {
        assert_eq!(
            hex(&leaf_hash(&[0u8; WORD])),
            "df3f619804a92fdb4057192dc43dd748ea778adc"
        );
        assert_ne!(
            hex(&leaf_hash(&[0u8; SLOT])),
            "df3f619804a92fdb4057192dc43dd748ea778adc",
            "a zero slot is not a zero word, which is the whole point"
        );
    }

    #[test]
    fn the_empty_root_of_the_word_tree() {
        assert_eq!(
            hex(&word_tree(&[]).root()),
            "bac77725f5cfaa5386da6723865ec4b4f0be00b5"
        );
    }

    #[test]
    fn a_populated_root() {
        let t = word_tree(&[(0, 11), (31, 22), (65_536, 33), (196_607, 44)]);
        assert_eq!(hex(&t.root()), "6f3f7354099b983e93c611cbc5dcd9a594e2609d");
    }

    #[test]
    fn a_root_after_one_word_changes() {
        let t = word_tree(&[(0, 11), (31, 0xcafe_babe), (65_536, 33), (196_607, 44)]);
        assert_eq!(hex(&t.root()), "4a8bd32caa72513360aaeae9994e4a540358a327");
    }

    #[test]
    fn the_leaf_width_follows_the_depth() {
        assert_eq!(leaf_bytes(SLOT_LEVELS), SLOT);
        assert_eq!(leaf_bytes(WORD_LEVELS), WORD);
        assert_eq!(leaf_bytes(DEPLOYED_WORD_LEVELS), WORD);
        // And the slot tree is unchanged: it really is over 32-byte slots.
        let slot = MerkleMemory::new(SLOT_LEVELS, &HashMap::new());
        let word = MerkleMemory::new(WORD_LEVELS, &HashMap::new());
        assert_ne!(hex(&slot.root()), hex(&word.root()));
    }

    #[test]
    fn a_path_still_verifies_after_the_change() {
        let t = word_tree(&[(0, 11), (31, 22), (65_536, 33)]);
        for (i, w) in [(0usize, 11u32), (31, 22), (65_536, 33)] {
            let p = t.path(i);
            assert!(t.verify(i, &w.to_be_bytes(), &p), "leaf {i}");
            assert!(
                !t.verify(i, &(w + 1).to_be_bytes(), &p),
                "leaf {i} tampered"
            );
        }
        // And an untouched leaf opens as the empty word.
        let p = t.path(12_345);
        assert!(t.verify(12_345, &0u32.to_be_bytes(), &p));
    }
}
