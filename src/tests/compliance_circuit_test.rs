//! The step circuit against the RISC-V compliance suite.
//!
//! The emulator and the Bitcoin Script verifier are both validated against
//! these 47 ELFs: `BitVMX-CPU`'s `compliance.rs` runs them with
//! `verify_on_chain`, so every retired instruction's trace goes through
//! `verify_script`. The garbled step circuit was not. It had a few hundred
//! hand-emitted vectors over twenty opcodes, which is how a division
//! defect survived in it -- an honest `div(-1, 2)` was reported as faulted
//! -- while Script was exercising the same case on every run through a
//! fuzz test it was not obvious anybody was relying on.
//!
//! This closes that. `rv32im_verdict` already answers exactly the question
//! that matters: *given the claim, is it a lie?* So for every instruction
//! the suite retires, the claim is built from what the emulator actually
//! did and the circuit must answer **no**.
//!
//! The corpus is regenerated with
//!
//! ```sh
//! cargo test -p emulator --test dump_compliance_traces -- --ignored
//! cp /tmp/compliance-traces.tsv src/tests/fixtures/
//! ```
#[cfg(test)]
mod tests {
    use crate::compact::bristol::Circuit;
    use std::collections::BTreeMap;

    const RV32IM: &str = include_str!("fixtures/rv32im_verdict.bristol");
    const TRACES: &str = include_str!("fixtures/compliance-traces.tsv");

    /// Input bit ranges of `rv32im_verdict`, read off `verdict.input_map`.
    /// Every group is contiguous and bit `k` is the value's bit `k`.
    const PC: usize = 0;
    const STATUS: usize = 32;
    const MEMORY: usize = 33;
    const INSTR: usize = 97;
    const ND_DIV: usize = 129;
    const ND_MOD: usize = 161;
    const VAL_RD: usize = 193;
    const VAL_RS1: usize = 225;
    const VAL_RS2: usize = 257;
    const CLAIM_RESULT: usize = 289;
    const CLAIM_PC: usize = 321;
    const CLAIM_STATUS: usize = 353;
    const CLAIM_MEMORY: usize = 354;
    const CLAIM_ADDRESS: usize = 418;
    const N_INPUTS: usize = 450;

    /// `MemoryWitness` access kinds.
    const REGISTER: u8 = 0;
    const MEM: u8 = 1;

    struct Step {
        elf: String,
        step: u64,
        pc: u32,
        micro: u8,
        opcode: u32,
        rs1: u32,
        r2_addr: u32,
        rs2: u32,
        write_addr: u32,
        write_val: u32,
        write_pc: u32,
        write_micro: u8,
        witness: u32,
        mw: u8,
    }

    impl Step {
        fn reads(&self) -> (u8, u8, u8) {
            ((self.mw >> 4) & 3, (self.mw >> 2) & 3, self.mw & 3)
        }
    }

    fn parse() -> Vec<Step> {
        TRACES
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                let h = |i: usize| u32::from_str_radix(f[i].trim(), 16).unwrap();
                Step {
                    elf: f[0].to_string(),
                    step: f[1].trim().parse().unwrap(),
                    pc: h(2),
                    micro: f[3].trim().parse().unwrap(),
                    opcode: h(4),
                    rs1: h(6),
                    r2_addr: h(7),
                    rs2: h(8),
                    write_addr: h(9),
                    write_val: h(10),
                    write_pc: h(11),
                    write_micro: f[12].trim().parse().unwrap(),
                    witness: h(13),
                    mw: u8::from_str_radix(f[14].trim(), 16).unwrap(),
                }
            })
            .collect()
    }

    /// Sign-extend the low `bits` of `v` to 32.
    fn sign_extend(v: u32, bits: u32) -> u32 {
        let m = 1u32 << (bits - 1);
        ((v & ((1u32 << bits) - 1)) ^ m).wrapping_sub(m)
    }

    fn put(bits: &mut [bool], at: usize, width: usize, v: u64) {
        for k in 0..width {
            bits[at + k] = (v >> k) & 1 == 1;
        }
    }

    /// Build the circuit's 450 input bits for one retired instruction, or
    /// `None` if the trace does not determine them.
    fn inputs(s: &Step) -> Option<(Vec<bool>, &'static str)> {
        let (r1a, r2a, wa) = s.reads();
        if s.micro != 0 || s.write_micro != 0 {
            return None;
        }
        if s.step == 0 {
            return None;
        }
        let is_load = r2a == MEM;
        let is_store = wa == MEM;
        let funct3 = (s.opcode >> 12) & 7;
        // sb and sh splice into the old word, which the trace does not
        // carry; sw overwrites it entirely.
        if is_store && funct3 != 2 {
            return None;
        }
        if r1a == MEM {
            return None;
        }

        // ECALL is a syscall the emulator services; the circuit does not
        // model it, and the trace shows it writing a0 without advancing
        // the pc.
        if s.opcode & 0x7F == 0x73 {
            return None;
        }

        // A write to x0 is discarded, and the emulator elides the whole
        // step: `addi x0, x1, 50` records no reads and no write, so the
        // operands are not in the trace to be reconstructed.
        let rd = (s.opcode >> 7) & 0x1F;
        let writes_rd = matches!(
            s.opcode & 0x7F,
            0x33 | 0x13 | 0x03 | 0x37 | 0x17 | 0x6F | 0x67
        );
        if writes_rd && rd == 0 {
            return None;
        }

        // div and rem witness the half the instruction does not return.
        let (mut nd_div, mut nd_mod) = (0u32, 0u32);
        if s.opcode & 0x7F == 0x33 && (s.opcode >> 25) & 0x7F == 0x01 {
            match funct3 {
                4 | 5 => {
                    nd_div = s.write_val;
                    nd_mod = s.witness;
                }
                6 | 7 => {
                    nd_div = s.witness;
                    nd_mod = s.write_val;
                }
                _ => {}
            }
        }

        // For a load the trace's read_2 is the word, not a register. Only
        // the window's low four bytes are ever read: lw is four-byte
        // aligned, lh two-byte, lb reads one.
        let memory = if is_load { s.rs2 as u64 } else { 0 };
        let val_rs2 = if is_load { 0 } else { s.rs2 };
        // The circuit emits the *effective* address, `rs1 + imm`, which
        // for a sub-word access is not the aligned address the emulator
        // records: `lb a4, 1(sp)` reads the word at `sp` and the circuit
        // says `sp + 1`.
        let address = if is_load {
            s.rs1.wrapping_add(sign_extend(s.opcode >> 20, 12))
        } else if is_store {
            let imm = ((s.opcode >> 25) << 5) | ((s.opcode >> 7) & 0x1F);
            s.rs1.wrapping_add(sign_extend(imm, 12))
        } else {
            0
        };

        let mut b = vec![false; N_INPUTS];
        put(&mut b, PC, 32, s.pc as u64);
        put(&mut b, STATUS, 1, 0);
        put(&mut b, MEMORY, 64, memory);
        put(&mut b, INSTR, 32, s.opcode as u64);
        put(&mut b, ND_DIV, 32, nd_div as u64);
        put(&mut b, ND_MOD, 32, nd_mod as u64);
        put(&mut b, VAL_RD, 32, 0);
        put(&mut b, VAL_RS1, 32, s.rs1 as u64);
        put(&mut b, VAL_RS2, 32, val_rs2 as u64);

        // The claim: what the emulator actually did.
        let claim_result = if wa == REGISTER { s.write_val } else { 0 };
        put(&mut b, CLAIM_RESULT, 32, claim_result as u64);
        put(&mut b, CLAIM_PC, 32, s.write_pc as u64);
        put(&mut b, CLAIM_STATUS, 1, 0);
        let claim_memory = if is_store { s.write_val as u64 } else { memory };
        put(&mut b, CLAIM_MEMORY, 64, claim_memory);
        put(&mut b, CLAIM_ADDRESS, 32, address as u64);

        let kind = if is_load {
            "load"
        } else if is_store {
            "store"
        } else {
            "register"
        };
        Some((b, kind))
    }

    #[test]
    fn the_circuit_agrees_with_the_emulator_across_the_compliance_suite() {
        let c = Circuit::parse(RV32IM).expect("the rv32im fixture parses");
        assert_eq!(c.n_inputs, N_INPUTS);
        let steps = parse();
        assert!(steps.len() > 13_000, "the corpus: {}", steps.len());

        let mut checked: BTreeMap<&str, usize> = BTreeMap::new();
        let mut skipped = 0usize;
        let mut elfs: BTreeMap<String, usize> = BTreeMap::new();
        let mut failures: Vec<String> = Vec::new();
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();

        for s in &steps {
            let Some((bits, kind)) = inputs(s) else {
                skipped += 1;
                continue;
            };
            *checked.entry(kind).or_default() += 1;
            *elfs.entry(s.elf.clone()).or_default() += 1;
            if c.outputs(&c.eval(&bits))[0] {
                let rd = (s.opcode >> 7) & 0x1F;
                let tag = format!(
                    "op={:#04x} funct3={} rd={}{}",
                    s.opcode & 0x7F,
                    (s.opcode >> 12) & 7,
                    rd,
                    if rd == 0 { " (x0)" } else { "" }
                );
                *kinds.entry(tag).or_default() += 1;
                failures.push(format!(
                    "{}:{} pc={:#010x} instr={:#010x} ({kind})",
                    s.elf, s.step, s.pc, s.opcode
                ));
            }
        }

        let total: usize = checked.values().sum();
        println!(
            "checked {total} of {} instructions from {} programs: {:?}",
            steps.len(),
            elfs.len(),
            checked
        );
        println!("skipped {skipped}");

        if !failures.is_empty() {
            println!("\nrefuted, by shape:");
            let mut v: Vec<_> = kinds.iter().collect();
            v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
            for (k, n) in v.iter().take(12) {
                println!("  {n:>5}  {k}");
            }
        }
        assert!(
            failures.is_empty(),
            "the circuit refuted {} instructions the emulator executed; \
             first few: {:?}",
            failures.len(),
            &failures[..failures.len().min(8)]
        );
        assert!(total > 11_000, "expected a real corpus, checked {total}");
        assert!(elfs.len() >= 40, "expected the suite, got {}", elfs.len());
    }
}
