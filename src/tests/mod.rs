pub mod autovalues_fees_test;
pub mod builder_connection_test;
pub mod builder_outputs_test;
pub mod builder_persistance_test;
pub mod compact_fraud_test;
pub mod compact_search_test;
pub mod compact_test;

// Out of the build with the trace-tree layer they exercise.  These are not
// dead weight: compact_graph_test alone is 23 tests over the stage graph,
// and the dispute and endgame suites carry the witness shapes and the
// sighash profiles.  They are the specification the interval rewrite has
// to satisfy, restated for a graph that no longer exists, and each comes
// back as its module does.
//
//   pub mod compact_circuit_test;    // 18 tests, uses compact::graph
//   pub mod compact_dispute_test;    // 20 tests, M-codes and tracetree
//   pub mod compact_endgame_test;    // 16 tests, uses compact::messages
//   pub mod compact_graph_test;      // 23 tests, the stage graph itself

pub mod graph_test;
pub mod input_test;
pub mod ots_checksig;
pub mod output_test;
pub mod single_scripts_test;
pub mod utils;
pub mod weight_computing_test;
