# compact: what is deferred, and why

Tracking notes for the `compact` module. Nothing here is a bug; these
are decisions to revisit, recorded so they are not mistaken for
oversights later.

## 1. Garbled circuits are semi-honest for now

The `compact` module implements the dispute protocol end to end *except*
the garbled circuit that decides the disputed RISC-V step. The circuit is
being built **semi-honest** first: both parties accept the garbling as
given.

Malicious security is available and is not blocked -- the garbling engine
proves circuit correctness with a Nova recursive SNARK, and a step
circuit is well inside the sizes it handles. What is deferred is only the
wiring:

- [ ] Carry the correctness proof, and the Lamport proof that accompanies
      it, through the dispute graph
- [ ] A branch by which a party refuses a mis-garbled circuit rather than
      having to trust it
- [ ] Decide whether the proof is checked off chain by the counterparty
      or made a condition of a spend

**Why the order.** Nothing else in the construction depends on it. The
circuit's inputs are committed with one-time signatures whose revealed
preimages double as the input labels, and that commitment -- which is
where the endgame's weight actually goes -- is independent of how the
circuit is garbled or of whether its construction is proved.

## 2. The step circuit is larger than the paper estimated

Section 8 estimates a RISC-V step at "on the order of a thousand gates
... one to two orders below a single SHA-256 compression at 22,573".
Measured in the metric that comparison is made in -- AND gates, XOR free:

| circuit | Bristol gates | AND gates | garbling |
|---|---|---|---|
| RV32I  | 24,033 |  7,702 | 335 ms |
| RV32IM | 43,153 | 14,591 | 635 ms |

A step is about a third of a SHA-256 compression, and two thirds with
`M`. The paper's conclusion survives -- the instruction is still the
cheapest thing in the endgame -- but the number was out by roughly eight
times.

The circuit is translated from `fair-riscv-mpc` rather than rewritten,
and validated against it: 180/180 agreement over 15 opcodes with random
operands, comparing all 1,121 output bits, and 64/64 agreement between
the model and a real garbled evaluation. See `compact/circuits/` in the
paper repository for the translation and the cross-checks.

An earlier revision of this file quoted 10,623 "ciphertexts" for RV32I.
That was the source model's own count, in which a multi-way multiplexer
costs a full table; it is not comparable to an AND-gate figure and should
not have been written down next to one.
