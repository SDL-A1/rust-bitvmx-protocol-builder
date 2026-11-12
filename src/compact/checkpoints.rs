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

use super::flatmerkle::total_raw_len;

/// A state hash is twenty bytes.
pub const NODE_BYTES: usize = 20;

/// Three of them to a sixty-four-byte element, leaving four spare.
pub const PER_ELEMENT: usize = 3;

/// Where a packed state begins inside its element.
pub const NODE_OFFSET: usize = 2;

/// A `b`-way dissection is fixed by its `b - 1` interior states.
pub fn interior_states(b: usize) -> usize {
    b - 1
}

/// Which element holds the `t`-th packed state, and at what offset.
///
/// This is the tree's `child_position` unchanged.  What it indexes is now
/// an interior dissection point rather than a child of a node, but states
/// are packed into elements the same way.
pub fn packed_position(t: usize) -> (usize, usize) {
    (t / PER_ELEMENT, (t % PER_ELEMENT) * NODE_BYTES + NODE_OFFSET)
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
