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

/// A memory slot.
pub const SLOT: usize = 32;
/// A tree node, truncated like every other digest in the protocol.
pub const NODE: usize = 20;

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
        let mut empty = vec![leaf_hash(&[0u8; SLOT])];
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

    /// What independent paths would cost: one full path per touched slot.
    pub fn independent_path_bytes(&self, leaves: &[usize]) -> usize {
        leaves.len() * self.levels as usize * NODE
    }
}

/// Which slots one instruction touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// Four scattered slots: a straddling fetch and a straddling access.
    /// The bound the protocol must budget for.
    Worst,
    /// A register-only instruction: fetch plus the register block.
    Alu,
    /// Fetch, a straddling data read, and the destination register.
    Load,
    /// Fetch, the source registers, and a straddling data write.
    Store,
}

/// 32 registers of four bytes are 128 bytes: four slots at the bottom.
pub const REG_SLOTS: usize = 4;

/// The slots an instruction of this shape touches, given a program
/// counter slot and a data slot.
pub fn touched(p: Pattern, pc: usize, data: usize, regs: [usize; 3]) -> Vec<usize> {
    let mut v: Vec<usize> = match p {
        Pattern::Worst => vec![pc, pc + 1, data, data + 1],
        Pattern::Alu => vec![pc, regs[0], regs[1], regs[2]],
        Pattern::Load => vec![pc, data, data + 1, regs[0], regs[2]],
        Pattern::Store => vec![pc, regs[0], regs[1], data, data + 1],
    };
    v.sort_unstable();
    v.dedup();
    v
}
