//! Compact BitVMX: publishing a dissection in a Taproot annex.
//!
//! A port of the reference implementation behind the FlatMerkle series,
//! against `rust-bitcoin`'s own transaction and sighash code, so that the
//! construction is checked where it actually has to hold.
//!
//! This branch targets the *interval* search of Compact BitVMX II.  A
//! stage now publishes the b-1 interior states of a dissection of the live
//! interval, so there is no parent node for a publication to open from and
//! no tree to walk; `tracetree` and `messages` are gone with it.
//!
//! `graph` came back.  Dropping it with the rest was over-broad: the
//! transaction graph is indexed by *stage*, not by tree node, and the only
//! thing the tree contributed to it was the justification in its header.
//! It was restored unchanged and its 23 tests passed as written.  What the
//! interval search actually changes there is one leaf -- the endgame's
//! release, which under `gsig` pays by signature rather than by preimage.

pub mod annex;
pub mod bristol;
pub mod checkpoints;
pub mod commitment;
pub mod dispute;
pub mod endgame;
pub mod flatmerkle;
pub mod fraud;
pub mod garble;
pub mod graph;
pub mod gsig;
pub mod memory;
pub mod output;
pub mod release;
pub mod search;
pub mod sha256_circuit;
pub mod sha256_core;

// Still out of the build: `compact_circuit_test` (18 tests), which needs
// the endgame circuit rebuilt around the signature gadget rather than the
// equality-gated release.
