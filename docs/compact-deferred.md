# compact: what is deferred, and why

Tracking notes for the `compact` module. Nothing here is a bug; these
are decisions to revisit, recorded so they are not mistaken for
oversights later.

## 1. Garbled circuits are semi-honest

The `compact` module implements the dispute protocol end to end *except*
the garbled circuit that decides the disputed RISC-V step. The circuit
is being built **semi-honest**: both parties accept the garbling as
given.

That is enough to make the endgame work and to measure it, but it is not
the final security model. Proving the circuit was garbled correctly,
rather than trusting it, comes from the separate garbling engine reached
through `bitvmx-job-dispatcher-types::garbled_messages::GarbledJobType`
(`Prove` / `Verify` / `ImportProof` / `Evaluate`). That engine is not
available here.

Deferred:

- [ ] A correctness proof for the garbling
- [ ] The Lamport proof that accompanies it in the proof blob
- [ ] Wiring either into the dispute graph, so that a party can refuse a
      mis-garbled circuit rather than having to trust it

**Why it can wait.** Nothing else in the construction depends on it. The
circuit's inputs are committed with one-time signatures whose revealed
preimages double as the input labels, and that commitment -- which is
where the endgame's weight actually goes -- is independent of how the
circuit is garbled or of whether its construction is proved.

## 2. The step circuit's gate count is not what the paper estimates

Section 8 of the paper estimates a RISC-V step at "on the order of a
thousand gates ... one to two orders below a single SHA-256 compression
at 22,573". Measured against a real circuit (`fair-riscv-mpc`, free-XOR
with half-gate-style AND/OR):

| circuit | operations | hashes to garble | ciphertexts |
|---|---|---|---|
| RV32I   |  4,520 |  5,046 | 10,623 |
| RV32IM  | 14,706 | 16,943 | 19,359 |

So a step is within one order of a SHA-256 compression, not one to two
orders below it, and with `M` it is about a third of one. The paper's
*conclusion* survives -- the instruction is still the cheapest thing in
the endgame -- but the number does not.

The measured circuit is not optimised: its multiplexers are multi-way
with full tables rather than decomposed into two-way muxes at one AND
each, and the mux ciphertexts dominate (9,730 of 10,623 for RV32I). A
tuned circuit would be smaller. The honest statement is a measured
range, not a single estimate.
