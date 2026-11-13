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

    #[test]
    fn worst_case_weight_of_a_dispute_in_three_settings() {
        let midstate = measure_ots(20).weight();
        let digit = measure_ots(1).weight();
        // The final trace a step adjudication commits: two reads with their
        // last_step pointers, the pc read, the write, witness and memory
        // witness.
        let final_trace_last_step = measure_ots(60).weight();
        // Under Merkle memory the pointers go and two roots arrive: tau is
        // 80 bytes (Definition 8.2).
        let tau_winternitz = measure_ots(80).weight();

        // Setting 1 commits its dissections rather than publishing them, so
        // the medium does not reach it.
        let s1_prover = 70 * midstate + final_trace_last_step;
        let s1_verifier = 10 * digit + measured_scripts::BITVMX_WORST_CHALLENGE;

        println!("\n=== worst-case weight of one dispute, 2^30-step trace ===");
        println!(
            "{:<40} {:>11} {:>11} {:>11} {:>9}",
            "setting", "prover WU", "verifier WU", "total WU", "% block"
        );

        let row = |name: &str, p: usize, v: usize| {
            println!(
                "{:<40} {:>11} {:>11} {:>11} {:>8.2}%",
                name,
                p,
                v,
                p + v,
                (p + v) as f64 / 4_000_000.0 * 100.0
            );
        };

        println!("{}", "-".repeat(86));
        row(
            "1. BitVMX today (commits, no medium)",
            s1_prover,
            s1_verifier,
        );

        let mut totals = Vec::new();
        for medium in [Medium::Annex, Medium::OpReturn] {
            // Settings 2 and 3 share a search: b = 192, four stages,
            // full-duplex so each message carries both a selection and the
            // next dissection, and the parties alternate.
            let stage = medium.stage_publication() + digit;
            let (prover_stages, verifier_stages) = (2usize, 2usize);

            // Setting 2: the endgame is Script. tau is Winternitz-committed
            // like everything else BitVMX commits.
            let s2_prover = prover_stages * stage + tau_winternitz;
            // A dispute ends in one challenge, so the worst case is the
            // largest single script the verifier can be made to run.
            let s2_verifier = verifier_stages * stage
                + measured_scripts::MEMORY_NODE.max(measured_scripts::TRACE_HASH_MERKLE);

            // Setting 3: the endgame is a garbled circuit. tau is committed
            // under ACW, and the proof and its working are published in the
            // same medium as the dissections.
            let endgame_published = medium.stage_publication();
            let s3_prover = prover_stages * stage + from_the_paper::ACW_TAU + endgame_published;
            let s3_verifier = verifier_stages * stage + from_the_paper::GARBLED_NODE_REFUTATION;

            println!("{}", "-".repeat(86));
            row(
                &format!("2. compact, Script endgame [{}]", medium.name()),
                s2_prover,
                s2_verifier,
            );
            row(
                &format!("3. compact, garbled endgame [{}]", medium.name()),
                s3_prover,
                s3_verifier,
            );
            totals.push((medium, s2_prover + s2_verifier, s3_prover + s3_verifier));
        }

        println!("\nmeasured inputs:");
        println!("  a 20-byte midstate, Winternitz HASH160 : {midstate} WU");
        println!("  the same midstate in an annex           : 20 WU");
        println!("  the same midstate in an OP_RETURN       : 80 WU");
        println!("  one selection digit                     : {digit} WU");
        println!("  the final trace under last_step (60 B)  : {final_trace_last_step} WU");
        println!("  tau under Merkle memory (80 B), WOTS    : {tau_winternitz} WU");

        let (_, annex2, annex3) = totals[0];
        let (_, opret2, opret3) = totals[1];
        println!(
            "\nOP_RETURN over annex: setting 2 {:.2}x, setting 3 {:.2}x",
            opret2 as f64 / annex2 as f64,
            opret3 as f64 / annex3 as f64
        );
        assert!(s1_prover > annex2, "compact must beat what is deployed");
        assert!(opret2 > annex2 && opret3 > annex3, "an output is dearer");
    }
}
