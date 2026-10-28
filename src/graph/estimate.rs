use std::cmp;

use bitcoin::consensus::Encodable;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Transaction, Witness};

use crate::errors::GraphError;
use crate::scripts::ProtocolScript;
use crate::types::input::{InputType, SpendMode};
use crate::types::OutputType;

pub fn script_num_size(n: u32) -> usize {
    if n == 0 {
        return 0;
    }

    // Minimal number of bytes needed to hold n
    let bits = 32 - n.leading_zeros();
    let len = bits.div_ceil(8) as usize; // ceil(bits/8)

    // Extra byte needed if the top bit of the most significant byte
    // is set, since CScriptNum encodes sign in that bit.
    let msb = ((n >> (8 * (len - 1))) & 0x80) as u8;
    if msb != 0 {
        len + 1
    } else {
        len
    }
}

/// Variable-length integer (CompactSize) encoded length for n.
pub fn compact_size_len(n: usize) -> usize {
    match n {
        0..=252 => 1,
        253..=0xFFFF => 3,
        0x10000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Serialize-length contribution of one witness item = compact(len) + len.
fn witness_item_overhead(len: usize) -> usize {
    compact_size_len(len) + len
}

/// Size of tx serialized with empty witnesses (aka "stripped" size).
fn stripped_size_bytes(tx: &Transaction) -> usize {
    let mut t = tx.clone();
    for inp in &mut t.input {
        inp.witness = Witness::default();
    }
    let mut buf = Vec::new();
    t.consensus_encode(&mut buf).expect("encode");
    buf.len()
}

/// Estimate witness bytes for a single input, according to its kind.
/// NOTE: This returns only the per-input witness bytes; the caller should add marker+flag (2 bytes) once per tx if any witness exists.
fn estimate_input_witness_bytes(
    transaction_name: &str,
    input: &InputType,
    index: usize,
) -> Result<usize, GraphError> {
    let output = input.output_type()?;
    let annex_len = input.annex_len();

    let size = match output {
        OutputType::SegwitPublicKey { .. } => {
            // 2 items: sig (~73), pubkey (33)
            let count = 2usize;
            compact_size_len(count) + witness_item_overhead(73) + witness_item_overhead(33)
        }

        OutputType::SegwitScript { script, .. } => {
            // Items: [stack...] + witness_script
            let count = script.stack_items().len() + 1;
            let mut size = compact_size_len(count);
            for it in script.stack_items() {
                let len = it.size();
                size += witness_item_overhead(len);
            }
            size += witness_item_overhead(script.get_script().len());
            size
        }

        OutputType::Taproot { leaves, .. } => {
            let leaves = match input.spend_mode() {
                SpendMode::Script { leaf } => &vec![leaves[*leaf].clone()],
                SpendMode::Scripts {
                    leaves: leaf_indices,
                } => &leaf_indices.iter().map(|&i| leaves[i].clone()).collect(),
                SpendMode::KeyOnly { .. } => &Vec::<ProtocolScript>::new(),
                _ => leaves,
            };

            // Items: [optional annex], signature
            let sig_len = 64 + 1; // 64 bytes for schnorr sig + 1 byte for sighash type
            let count = 1;
            let mut max_size = compact_size_len(count);

            max_size += witness_item_overhead(sig_len);

            for leaf in leaves {
                // Items: [optional annex] + [stack...] + tapscript + control block
                let ctrl_len = output
                    .get_taproot_spend_info()
                    .map_err(|_| {
                        GraphError::InvalidTaprootInfo(transaction_name.to_string(), index)
                    })?
                    .unwrap()
                    .control_block(&(leaf.get_script().clone(), LeafVersion::TapScript))
                    .unwrap()
                    .size();

                let count = leaf.stack_items().len() + 2; // +tapscript +control
                let mut size_script_path = compact_size_len(count);
                for it in leaf.stack_items() {
                    let len = it.size();
                    size_script_path += witness_item_overhead(len);
                }
                size_script_path += witness_item_overhead(leaf.get_script().len());
                size_script_path += witness_item_overhead(ctrl_len);

                max_size = cmp::max(max_size, size_script_path);
            }

            if annex_len > 0 {
                // One more witness item.  The item count's own compact size
                // does not grow with it below 253 items, so the annex costs
                // its length plus its own length prefix, and nothing else.
                max_size += witness_item_overhead(annex_len);
            }

            max_size
        }
        OutputType::SegwitUnspendable { .. } | OutputType::ExternalUnknown { .. } => 0,
    };

    Ok(size)
}

/// Compute estimated vbytes from stripped size and total witness bytes (including marker+flag if present).
fn vbytes_from_parts(
    stripped_size: usize,
    total_witness_bytes_including_marker_flag: usize,
) -> u64 {
    let s = stripped_size as u64;
    let w = total_witness_bytes_including_marker_flag as u64;
    s + w.div_ceil(4) // ceil(w/4)
}

/// Estimate the minimum relay fee (in sats) for `tx` at `feerate_sat_per_vb`,
/// using per-input spend descriptions.
/// This is suitable for setting the parent (Ptx) output so the child (Ctx) pays at least this fee.
pub fn estimate_min_relay_fee(
    tx: &Transaction,
    transaction_name: &str,
    inputs: &[InputType],
    feerate_sat_per_vb: u64, // e.g., 1 for floor; consider a buffer in practice
    safety_margin_percent: u64, // Optional safety margin in satoshis
) -> Result<u64, GraphError> {
    let stripped = stripped_size_bytes(tx);

    // Sum per-input witness bytes.
    let mut witness_sum = 0usize;
    for (index, input) in inputs.iter().enumerate() {
        witness_sum += estimate_input_witness_bytes(transaction_name, input, index)?;
    }

    // If there is at least one witness-bearing input, add marker+flag (2 bytes) once.
    let total_witness = witness_sum + if witness_sum > 0 { 2 } else { 0 };

    let vbytes = vbytes_from_parts(stripped, total_witness);
    let estimation = feerate_sat_per_vb * vbytes * (100 + safety_margin_percent) / 100;

    Ok(estimation)
}
