//! The RV32IM step as a garbled circuit.
//!
//! The emulator executes RV32I **and M** -- `Mul`, `Mulh`, `Mulhsu`,
//! `Mulhu`, `Div`, `Divu`, `Rem`, `Remu` are all in
//! `fetcher.rs`'s `op_arithmetic` arm -- and `bitcoin-script-riscv` has a
//! verification script for every one of them. The garbled endgame had only
//! `rv32i_verdict`, so a dispute over a `mul` had no circuit to adjudicate
//! it: the Script endgame covered more of the instruction set than the
//! garbled one did.
//!
//! `rv32im_verdict` closes that. It is the same verdict shape -- the
//! prover's claimed post-state in, one bit out -- over the CPU with
//! `rv32m=True`.
#[cfg(test)]
mod tests {
    use crate::compact::bristol::Circuit;
    use crate::compact::endgame::{adjudicate, Endgame, Outcome};
    use crate::compact::garble::{Label, LABEL_LEN};
    use crate::compact::release::A3_TWEAK;
    use bitcoin::hashes::{sha256, Hash};

    const RV32IM: &str = include_str!("fixtures/rv32im_verdict.bristol");
    const RV32IM_VECTORS: &str = include_str!("fixtures/rv32im_verdict.vectors");
    const RV32I_VECTORS: &str = include_str!("fixtures/rv32i_verdict.vectors");

    fn labels_from(seed: u8) -> impl FnMut() -> Label {
        let mut n: u64 = 0;
        move || {
            n += 1;
            let mut m = [0u8; 9];
            m[0] = seed;
            m[1..].copy_from_slice(&n.to_le_bytes());
            let d = sha256::Hash::hash(&m).to_byte_array();
            let mut l = [0u8; LABEL_LEN];
            l.copy_from_slice(&d[..LABEL_LEN]);
            l
        }
    }

    fn circuit() -> Circuit {
        Circuit::parse(RV32IM).expect("the rv32im fixture parses")
    }

    fn vectors(src: &str) -> Vec<(String, Vec<bool>, bool)> {
        src.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let name = it.next().unwrap().to_string();
                let ins = it.next().unwrap().bytes().map(|b| b == b'1').collect();
                let out = it.next().unwrap() == "1";
                (name, ins, out)
            })
            .collect()
    }

    /// `add3lie` -> `add`.
    fn opcode(name: &str) -> String {
        name.trim_end_matches("ok")
            .trim_end_matches("lie")
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .to_string()
    }

    #[test]
    fn the_circuit_is_the_verdict_shape_over_rv32im() {
        let c = circuit();
        assert_eq!(c.n_inputs, 450, "the same interface as rv32i_verdict");
        assert_eq!(c.n_outputs, 1, "one bit, which gates the secret");
        assert_eq!(c.and_count(), 7_304);
        // The M extension roughly doubles the step: rv32i_verdict is 3,453.
        assert!(c.and_count() > 2 * 3_453 - 500);
    }

    #[test]
    fn every_vector_evaluates_to_its_recorded_verdict() {
        // The truth in these vectors comes from the model's own evaluator,
        // so a disagreement here is a disagreement with the reference.
        let c = circuit();
        let vs = vectors(RV32IM_VECTORS);
        assert_eq!(vs.len(), 320, "320 cases");
        assert_eq!(
            vs.iter().filter(|(_, _, out)| *out).count(),
            160,
            "half of them lies"
        );
        for (name, ins, want) in &vs {
            assert_eq!(ins.len(), c.n_inputs, "{name}: input width");
            assert_eq!(c.outputs(&c.eval(ins))[0], *want, "{name}");
        }
    }

    #[test]
    fn the_m_extension_is_covered() {
        // The gap this circuit exists to close, asserted rather than
        // assumed: every multiply and divide the emulator can execute has
        // vectors here, and none of them has vectors against rv32i.
        let m_ops = [
            "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
        ];
        let covered: std::collections::BTreeSet<String> = vectors(RV32IM_VECTORS)
            .iter()
            .map(|(n, _, _)| opcode(n))
            .collect();
        for op in m_ops {
            assert!(covered.contains(op), "rv32im must cover {op}");
        }

        let rv32i: std::collections::BTreeSet<String> = vectors(RV32I_VECTORS)
            .iter()
            .map(|(n, _, _)| opcode(n))
            .collect();
        for op in m_ops {
            assert!(
                !rv32i.contains(op),
                "{op} is exactly what rv32i cannot adjudicate"
            );
        }
        assert!(covered.len() >= 20, "twenty opcodes: {covered:?}");
    }

    #[test]
    fn a_lie_about_a_multiply_releases_the_secret() {
        let secret = [0x5cu8; 32];
        let c = circuit();
        let e = Endgame::setup(circuit(), A3_TWEAK, &secret, labels_from(77));

        let mut tried = 0;
        for (name, ins, want) in vectors(RV32IM_VECTORS) {
            let op = opcode(&name);
            if !matches!(op.as_str(), "mul" | "div" | "rem" | "mulh") {
                continue;
            }
            tried += 1;
            let outcome = adjudicate(&c, e.published(), A3_TWEAK, &e.open(&ins));
            if want {
                assert_eq!(
                    outcome,
                    Outcome::Refuted(secret),
                    "{name} is a lie and must release the secret"
                );
            } else {
                assert_eq!(outcome, Outcome::Stands, "{name} is honest");
            }
        }
        assert!(tried >= 32, "exercised {tried} multiply/divide cases");
    }

    #[test]
    fn rv32im_adjudicates_everything_rv32i_does() {
        // Stronger than expected, and worth pinning: the two circuits share
        // an interface -- 450 bits in, one out -- and rv32im agrees with
        // rv32i on *every* rv32i vector. It is a strict superset, not an
        // alternative, so a deployment that cannot predict whether its
        // program uses M can garble rv32im and be right either way.
        //
        // The reason to keep rv32i at all is price: 3,437 AND gates against
        // 7,288, which at two ciphertexts a gate is about 123 kB of garbled
        // table saved per endgame.
        let c = circuit();
        let rv32i = vectors(RV32I_VECTORS);
        assert!(!rv32i.is_empty());
        for (name, ins, want) in &rv32i {
            assert_eq!(
                c.outputs(&c.eval(ins))[0],
                *want,
                "{name}: rv32im must agree with rv32i on an rv32i step"
            );
        }
        println!(
            "rv32im agrees on all {} rv32i vectors; it costs {} AND gates \
             against 3,437",
            rv32i.len(),
            c.and_count()
        );
    }
}

#[cfg(test)]
mod tests_support {
    use crate::compact::bristol::Circuit;

    const RV32IM: &str = include_str!("fixtures/rv32im_verdict.bristol");
    const HONEST_DIV: &str = include_str!("fixtures/rv32im_honest_div.vectors");
    const BAD_WITNESS: &str = include_str!("fixtures/rv32im_bad_witness.vectors");

    pub fn circuit_for_support() -> Circuit {
        Circuit::parse(RV32IM).expect("the rv32im fixture parses")
    }

    /// `(name, inputs, verdict)` for a prover who corrupts the quotient
    /// and claims the corrupted result.
    pub fn bad_witness_vectors() -> Vec<(String, Vec<bool>, bool)> {
        parse(BAD_WITNESS)
    }

    /// `(name, inputs, verdict)` for honest divisions claimed honestly.
    pub fn honest_div_vectors() -> Vec<(String, Vec<bool>, bool)> {
        parse(HONEST_DIV)
    }

    fn parse(src: &str) -> Vec<(String, Vec<bool>, bool)> {
        src.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let name = it.next().unwrap().to_string();
                let ins = it.next().unwrap().bytes().map(|b| b == b'1').collect();
                let out = it.next().unwrap() == "1";
                (name, ins, out)
            })
            .collect()
    }
}

/// Division is witnessed, and the witness is checked.
///
/// `div` and `rem` are not built as dividers. The prover witnesses the
/// quotient and remainder as non-deterministic inputs and the circuit
/// checks `q*d + r == n` with the multiplier it already has — which is
/// why the whole M extension costs 3,851 AND gates rather than a
/// divider's worth more, and why 64 bits of witness ride in the input
/// interface and have to be committed on chain.
///
/// Both directions are tested here, and they are different properties:
///
/// - **Honest divisions stand.** An earlier revision added a 32-bit
///   remainder to a 64-bit product, which `add_adder` silently truncated,
///   so the check compared the *product's* sign against the *sum's*.
///   Those differ exactly when `q*d + r` is negative and `q*d` is not — a
///   zero quotient with a negative dividend — and `div(-1, 2)` refuted an
///   honest prover. Sign-extending the remainder fixed it at no cost in
///   AND gates: the extra work is all XOR, which free-XOR makes free.
/// - **Witnessed lies are refuted.** The dangerous prover corrupts the
///   quotient *and* claims the corrupted result, so the result comparison
///   passes and only the status bit catches her.
#[cfg(test)]
mod division_witness {
    use super::tests_support::*;

    #[test]
    fn every_honest_division_stands() {
        let vs = honest_div_vectors();
        assert_eq!(vs.len(), 10, "ten honest divisions");
        let refuted: Vec<String> = vs
            .iter()
            .filter(|(_, _, r)| *r)
            .map(|(n, _, _)| n.clone())
            .collect();
        assert!(
            refuted.is_empty(),
            "an honest division must never be refuted: {refuted:?}"
        );
    }

    #[test]
    fn the_zero_quotient_negative_dividend_cases_are_covered() {
        // The three that used to fail, named so the regression is explicit.
        let names: Vec<String> = honest_div_vectors()
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        for case in ["div_-1_2", "div_-7_-9", "rem_-1_2"] {
            assert!(names.contains(&case.to_string()), "{case} must be tested");
        }
    }

    #[test]
    fn a_witnessed_lie_is_still_refuted() {
        // The soundness direction, which could not be tested while honest
        // divisions were failing: the prover corrupts the quotient and
        // claims what the corrupted witness produces.
        let vs = bad_witness_vectors();
        assert_eq!(vs.len(), 24, "six rounds over four division opcodes");
        for (name, _, refuted) in &vs {
            assert!(refuted, "{name}: a witnessed lie must be refuted");
        }
    }

    #[test]
    fn the_circuit_agrees_with_both_fixtures() {
        // The recorded verdicts are what the circuit answers, so this
        // checks the fixtures are current.
        let c = circuit_for_support();
        for (name, ins, want) in honest_div_vectors() {
            assert_eq!(c.outputs(&c.eval(&ins))[0], want, "honest {name}");
        }
        for (name, ins, want) in bad_witness_vectors() {
            assert_eq!(c.outputs(&c.eval(&ins))[0], want, "bad witness {name}");
        }
    }
}
