//! The trace tree: a complete `b`-ary tree whose every internal node is a
//! publication.
//!
//! A node's value is twenty bytes of the SHA-256 of the publication that
//! lists its children, taken from offset two so that the whole of it lies
//! inside the thirty bytes a `222`-byte signature commits to.  That is
//! what makes a node authenticable in one compression rather than a
//! Merkle path.

use super::annex::annex_frame;
use super::flatmerkle::{build, StructuredFile, MIN_ELEMENTS};
use super::sha256_core::BLOCK_SIZE;

/// A node value is a 20-byte truncation of SHA-256.
pub const NODE_BYTES: usize = 20;
/// Three to a 64-byte element: 60 bytes of payload, four of zero padding,
/// which is the best a 20-byte digest can do in a 64-byte block.
pub const PER_ELEMENT: usize = 3;
/// The window a `222`-byte signature commits to starts at offset two, so
/// the node value does too.
pub const NODE_OFFSET: usize = 2;

pub type Node = [u8; NODE_BYTES];

/// Is this a branching factor the construction admits?
///
/// Three node values to an element and FlatMerkle's power-of-two
/// restriction between them force `b = 3 * 2^k`, and the recursion needs
/// at least four elements, so `b >= 12`.
pub fn feasible(b: usize) -> bool {
    b % PER_ELEMENT == 0 && {
        let n = b / PER_ELEMENT;
        n >= MIN_ELEMENTS && n.is_power_of_two()
    }
}

pub fn elements_for(b: usize) -> usize {
    b / PER_ELEMENT
}

/// Pack `b` node values three to a block.
pub fn pack(children: &[Node]) -> Vec<Vec<u8>> {
    assert_eq!(children.len() % PER_ELEMENT, 0);
    children
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

/// Unpack a publication's elements back into node values.
pub fn unpack(elements: &[Vec<u8>], b: usize) -> Vec<Node> {
    let mut out = Vec::with_capacity(b);
    for e in elements {
        for t in 0..PER_ELEMENT {
            let s = t * NODE_BYTES;
            out.push(e[s..s + NODE_BYTES].try_into().expect("20 bytes"));
        }
    }
    out.truncate(b);
    out
}

/// The publication of a node: the FlatMerkle file of its children, framed
/// as it will be published.
pub fn publication(children: &[Node]) -> StructuredFile {
    let elements = pack(children);
    build(&elements, annex_frame(elements.len()))
}

/// The value of the node that publication belongs to.
pub fn node_value(sf: &StructuredFile) -> Node {
    sf.digest[NODE_OFFSET..NODE_OFFSET + NODE_BYTES]
        .try_into()
        .expect("20 bytes")
}

/// Where a child sits inside a publication: which element, and at what
/// offset in it.
pub fn child_position(t: usize) -> (usize, usize) {
    (t / PER_ELEMENT, (t % PER_ELEMENT) * NODE_BYTES)
}

/// A party's trace tree, materialised.
///
/// Held level by level rather than as a recursion, because the search
/// needs every node of every level it touches and nothing above it.
#[derive(Clone, Debug)]
pub struct TraceTree {
    pub b: usize,
    pub levels: u32,
    /// `values[d]` holds level `d`, so `values[0]` is the root alone and
    /// `values[levels]` the leaves.
    values: Vec<Vec<Node>>,
}

impl TraceTree {
    /// Build from the leaves.  Steps beyond the end of the execution
    /// repeat the halting state, so the tree is complete and the padding
    /// is self-evident.
    pub fn from_leaves(b: usize, levels: u32, leaves: Vec<Node>) -> Self {
        assert!(feasible(b), "b = {b} is not a usable branching factor");
        let expect = (b as u128).pow(levels) as usize;
        assert_eq!(leaves.len(), expect, "a complete tree has b^L leaves");

        let mut values: Vec<Vec<Node>> = vec![Vec::new(); levels as usize + 1];
        values[levels as usize] = leaves;
        for d in (0..levels as usize).rev() {
            let below = &values[d + 1];
            values[d] = below
                .chunks(b)
                .map(|c| node_value(&publication(c)))
                .collect();
        }
        TraceTree { b, levels, values }
    }

    pub fn root(&self) -> Node {
        self.values[0][0]
    }

    pub fn level(&self, d: u32) -> &[Node] {
        &self.values[d as usize]
    }

    /// The value of node `(d, j)`.
    pub fn value(&self, d: u32, j: usize) -> Node {
        self.values[d as usize][j]
    }

    /// The children of node `(d, j)`, which is what a stage publishes.
    pub fn children(&self, d: u32, j: usize) -> Vec<Node> {
        assert!(d < self.levels, "leaves have no children");
        let below = &self.values[d as usize + 1];
        below[j * self.b..(j + 1) * self.b].to_vec()
    }

    pub fn publication_of(&self, d: u32, j: usize) -> StructuredFile {
        publication(&self.children(d, j))
    }

    pub fn leaves(&self) -> &[Node] {
        &self.values[self.levels as usize]
    }
}

/// How many levels a trace of `steps` needs at branching factor `b`.
pub fn levels_for(steps: u128, b: usize) -> u32 {
    let mut l = 0u32;
    let mut cap = 1u128;
    while cap < steps {
        cap *= b as u128;
        l += 1;
    }
    l.max(1)
}
