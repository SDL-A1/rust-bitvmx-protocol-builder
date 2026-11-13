//! Worst-case weight of a dispute, measured rather than modelled.
//!
//! Three settings are compared, all over a `2^30`-step trace:
//!
//! 1. **BitVMX as it stands.** Dissections are Winternitz commitments that
//!    Script reads, `nary = 8`, ten rounds.
//! 2. **Compact, Script endgame.** Dissections are published in a Taproot
//!    annex, `b = 192`, four stages; the endgame's memory check is a
//!    blake3 node challenge in Script.
//! 3. **Compact, garbled-circuit endgame.** The same search; the memory
//!    check is a garbled circuit and only its challenge message and the
//!    published file reach the chain.
//!
//! What is measured here is the Winternitz cost per committed byte, which
//! is what setting 1 is made of and what settings 2 and 3 avoid for the
//! dissections.  Script sizes for the endgame come from
//! `bitcoin-script-riscv`'s `script_sizes` report; publication and
//! garbled-circuit figures from `compact2/python`.
#[cfg(test)]
mod tests {
    use key_manager::winternitz::{
        checksum_length, message_digits_length, to_checksummed_message, Winternitz, WinternitzType,
    };

    use bitcoin_script_stack::stack::StackTracker;

    use crate::scripts::ots_checksig_internal;

    /// What one Winternitz-committed message costs on chain.
    struct Ots {
        digits: usize,
        script_bytes: usize,
        witness_bytes: usize,
    }

    impl Ots {
        /// Witness bytes ride at one weight unit each; the script does too,
        /// since a tapscript leaf is revealed in the witness.
        fn weight(&self) -> usize {
            self.script_bytes + self.witness_bytes
        }
    }

    fn measure_ots(message_bytes: usize) -> Ots {
        let message = vec![0xabu8; message_bytes];
        let digits_len = message_digits_length(message.len());
        let checksummed = to_checksummed_message(&message);
        let checksum_size = checksum_length(digits_len);
        let message_size = checksummed.len() - checksum_size;

        let master = vec![0u8; 16];
        let w = Winternitz::new();
        let sk = w
            .generate_private_key(
                &master,
                WinternitzType::HASH160,
                message_size,
                checksum_size,
                1,
            )
            .unwrap();
        let pk = w
            .generate_public_key(
                &master,
                WinternitzType::HASH160,
                message_size,
                checksum_size,
                1,
            )
            .unwrap();
        let sig = w.sign_message(message_size, &checksummed, &sk);

        // The witness: per digit, a 20-byte hash with its length prefix and
        // the digit itself as a minimal push.
        let digits = sig.len();
        let witness_bytes = digits * (1 + 20 + 1);

        // The script: the hash chains unrolled, which is what Script has to
        // execute to read the committed value.
        let mut stack = StackTracker::new();
        for i in 0..digits {
            stack.hexstr(&hex::encode(sig.to_hashes()[i].clone()));
            stack.number(sig.checksummed_message_digits()[i] as u32);
        }
        let before = stack.get_script().len();
        let _ = ots_checksig_internal(&mut stack, &pk, false).unwrap();
        let script_bytes = stack.get_script().len() - before;

        Ots {
            digits,
            script_bytes,
            witness_bytes,
        }
    }

    #[test]
    fn what_a_winternitz_commitment_costs_per_byte() {
        println!(
            "\n{:>8} {:>8} {:>12} {:>12} {:>10} {:>12}",
            "bytes", "digits", "script", "witness", "total WU", "WU/byte"
        );
        println!("{}", "-".repeat(68));
        let mut per_byte_20 = 0.0;
        for bytes in [1usize, 4, 8, 20, 32] {
            let m = measure_ots(bytes);
            let per_byte = m.weight() as f64 / bytes as f64;
            if bytes == 20 {
                per_byte_20 = per_byte;
            }
            println!(
                "{:>8} {:>8} {:>12} {:>12} {:>10} {:>12.1}",
                bytes,
                m.digits,
                m.script_bytes,
                m.witness_bytes,
                m.weight(),
                per_byte
            );
        }
        println!(
            "\na 20-byte midstate costs {:.0} WU to make Script-readable",
            20.0 * per_byte_20
        );
        assert!(per_byte_20 > 0.0);
    }

    /// Script sizes measured by `bitcoin-script-riscv`'s `script_sizes`
    /// report, which builds each with the code the protocol builds it with.
    mod measured_scripts {
        /// Largest challenge BitVMX can put on chain today.
        pub const BITVMX_WORST_CHALLENGE: usize = 72_203; // read_value
        /// The compact endgame's memory check, in Script.
        pub const MEMORY_NODE: usize = 71_040;
        /// The state-hash check, which both settings need.
        pub const TRACE_HASH_MERKLE: usize = 70_256;
        pub const TRACE_HASH_LAST_STEP: usize = 70_196;
    }

    /// Figures from `compact2/python`, which models what never touches
    /// this repo: annex publication and garbled-circuit refutation.
    /// Figures from `compact2/python`, which models what never touches
    /// this repo: annex publication and garbled-circuit refutation.
    mod from_the_paper {
        /// One stage's dissection, framed, in a Taproot annex. Witness, so
        /// one weight unit a byte.
        pub const PUBLICATION_ANNEX: usize = 8_128;
        /// The same dissection in an `OP_RETURN` output. Non-witness, so
        /// four weight units a byte.
        pub const PUBLICATION_OPRETURN: usize = 32_512;
        /// What an `OP_RETURN` stage costs beyond its payload: two outputs
        /// on the stage, the data transaction's own inputs and overhead,
        /// and the frame. An annex needs none of this -- it rides in the
        /// stage transaction's own witness, which is the whole reason a
        /// stage's txid stays fixed at setup.
        pub const OPRETURN_FURNITURE: usize = 968;
        /// tau committed under ACW (4,16).
        pub const ACW_TAU: usize = 21_402;
        /// Refuting one node of the multiproof, in a circuit.
        pub const GARBLED_NODE_REFUTATION: usize = 11_357;
    }

    /// How a dissection reaches the chain.
    #[derive(Clone, Copy, PartialEq)]
    enum Medium {
        Annex,
        OpReturn,
    }

    impl Medium {
        fn name(&self) -> &'static str {
            match self {
                Medium::Annex => "annex",
                Medium::OpReturn => "OP_RETURN",
            }
        }

        /// What one stage's dissection costs, payload and furniture.
        fn stage_publication(&self) -> usize {
            match self {
                Medium::Annex => from_the_paper::PUBLICATION_ANNEX,
                Medium::OpReturn => {
                    from_the_paper::PUBLICATION_OPRETURN + from_the_paper::OPRETURN_FURNITURE
                }
            }
        }
    }

    /// One row of the comparison.
    struct Setting {
        name: String,
        prover: usize,
        verifier: usize,
        transactions: u32,
    }

    impl Setting {
        fn total(&self) -> usize {
            self.prover + self.verifier
        }
    }

    /// On-chain messages the search consumes, mirroring
    /// `SearchMode::messages` in the emulator: a selection and a dissection
    /// are separate messages in the asymmetric search and one message in
    /// the full-duplex one, and both end with an adjudication message that
    /// carries the trailing selection.
    fn search_messages(rounds: u32, full_duplex: bool) -> u32 {
        if full_duplex {
            rounds + 1
        } else {
            2 * rounds + 1
        }
    }

    /// How many of `rounds` stages each party dissects.  The full-duplex
    /// search alternates; the asymmetric one gives every dissection to the
    /// prover.
    fn dissection_split(rounds: usize, full_duplex: bool) -> (usize, usize) {
        if full_duplex {
            (rounds.div_ceil(2), rounds / 2)
        } else {
            (rounds, 0)
        }
    }

    #[test]
    fn worst_case_weight_of_a_dispute_in_three_settings() {
        let midstate = measure_ots(20).weight();
        let digit = measure_ots(1).weight();
        let final_trace_last_step = measure_ots(60).weight();
        let tau_winternitz = measure_ots(80).weight();

        let mut rows: Vec<Setting> = Vec::new();

        // ---- BitVMX, dissections committed, nary = 8, ten rounds -------
        for full_duplex in [false, true] {
            let rounds = 10usize;
            let per_round_hashes = 7usize; // nary - 1
            let (p_stages, v_stages) = dissection_split(rounds, full_duplex);
            // Whoever dissects at a stage also pays that stage's digit in
            // the full-duplex search; in the asymmetric one the verifier
            // pays every digit.
            let (p_digits, v_digits) = if full_duplex {
                (p_stages, v_stages)
            } else {
                (0, rounds)
            };
            let prover =
                p_stages * per_round_hashes * midstate + p_digits * digit + final_trace_last_step;
            let verifier = v_stages * per_round_hashes * midstate
                + v_digits * digit
                + measured_scripts::BITVMX_WORST_CHALLENGE;
            rows.push(Setting {
                name: format!(
                    "BitVMX, {} (committed, nary=8)",
                    if full_duplex { "full-duplex" } else { "today" }
                ),
                prover,
                verifier,
                // the search, plus the challenge transaction
                transactions: search_messages(rounds as u32, full_duplex) + 1,
            });
        }

        // ---- compact: b = 192, four stages, always full-duplex ---------
        for medium in [Medium::Annex, Medium::OpReturn] {
            let rounds = 4usize;
            let (p_stages, v_stages) = dissection_split(rounds, true);
            let stage = medium.stage_publication() + digit;
            // Publications, and each needs a transaction of its own under
            // OP_RETURN: the four stage dissections, and the endgame's proof
            // and working. An output is part of the txid, so it cannot ride
            // on a transaction that was pre-signed before its contents were
            // known.
            let publications = rounds as u32 + 1;
            let extra_tx = match medium {
                Medium::Annex => 0,
                Medium::OpReturn => publications,
            };
            let search_tx = search_messages(rounds as u32, true) + extra_tx;

            for garbled in [false, true] {
                // Both endgames publish the multiproof *and the working it
                // drives*. Neither can skip it: the three nodes a node check
                // consumes have to be bound to something, and a multiproof
                // alone binds only its own siblings -- finding C05. So the
                // published file is common to the two, and only how the
                // compression is checked differs.
                let published = medium.stage_publication();
                let (endgame_prover, endgame_verifier) = if garbled {
                    (
                        from_the_paper::ACW_TAU + published,
                        from_the_paper::GARBLED_NODE_REFUTATION,
                    )
                } else {
                    (
                        tau_winternitz + published,
                        // NOTE: a floor, not a total. This is the blake3
                        // compression alone. Binding the three nodes to the
                        // published file needs a FlatMerkle opening checked
                        // in Script as well, which is not built and so not
                        // costed here. The garbled endgame does that opening
                        // inside the circuit, where it is already paid for.
                        measured_scripts::MEMORY_NODE.max(measured_scripts::TRACE_HASH_MERKLE),
                    )
                };
                rows.push(Setting {
                    name: format!(
                        "compact, {} endgame [{}]",
                        if garbled { "garbled" } else { "Script " },
                        medium.name()
                    ),
                    prover: p_stages * stage + endgame_prover,
                    verifier: v_stages * stage + endgame_verifier,
                    // the search, plus the refutation transaction
                    transactions: search_tx + 1,
                });
            }
        }

        println!("\n| setting | prover WU | verifier WU | total WU | txs | % block |");
        println!("|---|---:|---:|---:|---:|---:|");
        for r in &rows {
            println!(
                "| {} | {} | {} | **{}** | {} | {:.2}% |",
                r.name,
                r.prover,
                r.verifier,
                r.total(),
                r.transactions,
                r.total() as f64 / 4_000_000.0 * 100.0
            );
        }

        println!("\nmeasured inputs:");
        println!("  20-byte midstate, Winternitz HASH160 : {midstate} WU");
        println!("  the same in an annex                 : 20 WU");
        println!("  the same in an OP_RETURN             : 80 WU");
        println!("  one selection digit                  : {digit} WU");
        println!("  final trace under last_step (60 B)   : {final_trace_last_step} WU");
        println!("  tau under Merkle memory (80 B), WOTS : {tau_winternitz} WU");

        // The full-duplex search moves cost rather than removing it.
        assert_eq!(
            rows[0].prover + rows[0].verifier,
            rows[1].prover + rows[1].verifier,
            "full-duplex halves the transactions and leaves the weight alone"
        );
        assert!(rows[1].transactions < rows[0].transactions);
        assert!(rows[2].total() < rows[1].total());
        // Under OP_RETURN every publication costs a transaction of its own.
        assert_eq!(rows[4].transactions, rows[2].transactions + 5);
    }
}
