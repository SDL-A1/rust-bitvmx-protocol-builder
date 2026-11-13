# Circuit fixtures

`rv32i_verdict.bristol` is option A3's circuit: one RISC-V step with the
prover's claimed post-state as input and one verdict bit as output.
450 input bits, 11,317 gates, 3,437 of them AND.

`rv32im_verdict.bristol` is the same shape over the CPU with the M
extension: 450 input bits, 27,399 gates, 7,288 of them AND.  The emulator
executes RV32IM and `bitcoin-script-riscv` verifies all of it, so without
this circuit a dispute over a `mul` had nothing to adjudicate it.  It is a
strict superset: it agrees with `rv32i_verdict` on every RV32I vector, so
a deployment that cannot predict whether its program uses M can garble
this one and be right either way, at 7,288 AND gates against 3,437.

`rv32i_verdict.vectors` is 192 cases and `rv32im_verdict.vectors` 320,
half of each lies, one per line as `<name> <input bits> <output bit>`.
The RV32IM set covers twenty opcodes including all eight of M.  Both files are produced by
`compact/circuits/emit.py` in the paper repository, from a model with its
own opcode tests, and the outputs come from that model's evaluator -- so
a disagreement here is a disagreement with the reference, not with an
opinion about RISC-V.

Do not edit them.  Regenerate with

    python3 emit.py <fair-riscv-mpc> <outdir>
