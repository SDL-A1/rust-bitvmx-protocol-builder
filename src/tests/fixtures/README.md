# Circuit fixtures

`rv32i_verdict.bristol` is option A3's circuit: one RISC-V step with the
prover's claimed post-state as input and one verdict bit as output.
450 input bits, 11,317 gates, 3,437 of them AND.

`rv32i_verdict.vectors` is 128 cases, half of them lies, one per line as
`<name> <input bits> <output bit>`.  Both files are produced by
`compact/circuits/emit.py` in the paper repository, from a model with its
own opcode tests, and the outputs come from that model's evaluator -- so
a disagreement here is a disagreement with the reference, not with an
opinion about RISC-V.

Do not edit them.  Regenerate with

    python3 emit.py <fair-riscv-mpc> <outdir>
