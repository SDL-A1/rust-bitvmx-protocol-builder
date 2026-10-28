//! Compact BitVMX: publishing a dissection in a Taproot annex.
//!
//! A port of the reference implementation behind the FlatMerkle series,
//! against `rust-bitcoin`'s own transaction and sighash code, so that the
//! construction is checked where it actually has to hold.

pub mod annex;
pub mod commitment;
pub mod dispute;
pub mod flatmerkle;
pub mod fraud;
pub mod graph;
pub mod memory;
pub mod messages;
pub mod search;
pub mod sha256_core;
pub mod tracetree;
