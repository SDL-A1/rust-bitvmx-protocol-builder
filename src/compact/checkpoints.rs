//! The checkpoint publication.
//!
//! Mirrors `compact2/python/checkpoints.py`, which is the specification
//! every figure in Compact BitVMX II is produced by.  Replaces the
//! trace-tree module: a stage publishes the `b - 1` interior states of a
//! dissection of the live interval, not the `b` children of a node.
//!
//! The packing is the tree's and is kept: twenty-byte states go three to a
//! sixty-four-byte FlatMerkle element, which is why `b = 192` fills 64
//! elements exactly -- and why `b - 1 = 191` fills the same 64, so the
//! change costs nothing.

use super::annex::annex_frame;
use super::flatmerkle::{build, total_raw_len, StructuredFile};
use super::sha256_core::BLOCK_SIZE;

/// A state hash is twenty bytes.
pub const NODE_BYTES: usize = 20;

/// Three of them to a sixty-four-byte element, leaving four spare.
pub const PER_ELEMENT: usize = 3;

/// Where a state value begins inside a publication's *digest*.
///
/// This is about the digest, not about an element.  A `222`-byte
/// signature commits to thirty bytes of the message, starting at offset
/// two, so the twenty bytes a stage is bound to are taken from there.
/// Packing inside an element is a separate question and the answer is
/// zero -- see [`packed_position`], which must agree with [`pack`].
pub const NODE_OFFSET: usize = 2;

/// A `b`-way dissection is fixed by its `b - 1` interior states.
pub fn interior_states(b: usize) -> usize {
    b - 1
}

/// Which element holds the `t`-th packed state, and at what offset.
///
/// This is the tree's `child_position` unchanged.  What it indexes is now
/// an interior dissection point rather than a child of a node, but states
/// are packed into elements the same way: three flush at `0`, `20`, `40`,
/// with four bytes of zero padding after them.
///
/// It must agree with [`pack`], and `pack_round_trips` checks that it
/// does.  It briefly did not: an earlier rewrite added `NODE_OFFSET`
/// here, confusing the digest window with the element layout, which
/// nothing caught because no packing function existed to disagree with.
pub fn packed_position(t: usize) -> (usize, usize) {
    (t / PER_ELEMENT, (t % PER_ELEMENT) * NODE_BYTES)
}

/// Elements a `b`-way dissection's publication needs.
pub fn elements_for(b: usize) -> usize {
    interior_states(b).div_ceil(PER_ELEMENT)
}

/// FlatMerkle takes a power of two elements, at least four.
pub fn feasible(b: usize) -> bool {
    let n = elements_for(b);
    n >= 4 && n.is_power_of_two()
}

/// The published file, in bytes.
pub fn publication_bytes(b: usize) -> usize {
    total_raw_len(elements_for(b))
}

/// Narrowing levels to isolate one step of a `steps`-step trace.
pub fn levels(steps: usize, b: usize) -> u32 {
    let mut l = 0u32;
    let mut n = 1usize;
    while n < steps {
        n *= b;
        l += 1;
    }
    l
}

/// Width of a selection digit, in bits.
pub fn selection_bits(b: usize) -> u32 {
    usize::BITS - (b - 1).leading_zeros()
}

/// A state hash, as a publication carries it.
pub type Node = [u8; NODE_BYTES];

/// Pack interior states three to a sixty-four-byte element.
///
/// The last element is short unless `PER_ELEMENT` divides the count, and
/// `b - 1` states is exactly the case where it usually does not: the
/// remainder is zero-padded like the four spare bytes of a full element.
pub fn pack(states: &[Node]) -> Vec<Vec<u8>> {
    states
        .chunks(PER_ELEMENT)
        .map(|c| {
            let mut e = Vec::with_capacity(BLOCK_SIZE);
            for v in c {
                e.extend_from_slice(v);
            }
            e.resize(BLOCK_SIZE, 0);
            e
        })
        .collect()
}

/// Read packed states back out, `n` of them.
pub fn unpack(elements: &[Vec<u8>], n: usize) -> Vec<Node> {
    let mut out = Vec::with_capacity(n);
    for e in elements {
        for t in 0..PER_ELEMENT {
            let s = t * NODE_BYTES;
            if s + NODE_BYTES <= e.len() {
                out.push(e[s..s + NODE_BYTES].try_into().expect("20 bytes"));
            }
        }
    }
    out.truncate(n);
    out
}

/// A stage's publication: the FlatMerkle file of the interior states of
/// its dissection, framed as it will ride in the annex.
///
/// Note what is *not* here, and it is the point of the interval search.
/// The tree had `node_value`, which read a parent's child value out of a
/// publication's digest, because a publication's digest had to be a value
/// some other publication listed.  Nothing lists this one.  The digest is
/// what the stage's own signature commits to and that is the end of it.
pub fn publication(states: &[Node]) -> StructuredFile {
    let elements = pack(states);
    build(&elements, annex_frame(elements.len()))
}
