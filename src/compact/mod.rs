//! Compact BitVMX: publishing a dissection in a Taproot annex.
//!
//! A port of the reference implementation behind the FlatMerkle series,
//! against `rust-bitcoin`'s own transaction and sighash code, so that the
//! construction is checked where it actually has to hold.
//!
//! This branch targets the *interval* search of Compact BitVMX II.  The
//! trace-tree design layer -- `tracetree`, `graph` and `messages` -- has
//! been removed rather than ported: a stage now publishes the b-1 interior
//! states of a dissection of the live interval, so there is no parent node
//! for a publication to open from and no tree to walk.  What remains below
//! is either design-independent or is being rewritten against the interval.

pub mod annex;
pub mod bristol;
pub mod commitment;
pub mod endgame;
pub mod flatmerkle;
pub mod fraud;
pub mod garble;
pub mod memory;
pub mod output;
pub mod release;
pub mod search;
pub mod sha256_core;

// Out of the build, not deleted.  `search.rs` walks a TraceTree and
// `dispute.rs` carries the M-codes and the child-position arithmetic that
// only a tree needs, so neither compiles once the tree is gone.  They are
// kept as the reference for the interval rewrite -- the sighash profiles,
// the witness shapes and the M4 predicate in dispute.rs are all still
// wanted, and retyping them from memory is how detail gets lost.
//
//   pub mod dispute;
