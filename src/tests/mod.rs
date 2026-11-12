pub mod autovalues_fees_test;
pub mod builder_connection_test;
pub mod builder_outputs_test;
pub mod builder_persistance_test;
pub mod compact_fraud_test;
pub mod compact_graph_test;
pub mod compact_gsig_test;
pub mod compact_dispute_test;
pub mod compact_endgame_test;
pub mod compact_search_test;
pub mod compact_test;

// Still out of the build.  Not dead weight: it is the specification the
// endgame circuit has to satisfy, and it comes back when that circuit is
// rebuilt around the signature gadget.
//
//   pub mod compact_circuit_test;    // 18 tests



pub mod graph_test;
pub mod input_test;
pub mod ots_checksig;
pub mod output_test;
pub mod single_scripts_test;
pub mod utils;
pub mod weight_computing_test;
