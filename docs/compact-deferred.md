# compact: what is deferred, and why

Tracking notes for the `compact` module. Nothing here is a bug; these
are decisions to revisit, recorded so they are not mistaken for
oversights later.

## 1. The garbled circuits exist, but are not wired in

The `compact` module implements the dispute protocol end to end *except*
the garbled circuits that decide a disputed step or a disputed
compression. Those circuits are now built and measured -- see
`compact/circuits/` in the paper repository -- and emitted as Bristol
files with test vectors. What is deferred is the wiring:

- [ ] Carry the input labels from the one-time-signature commitment into
      the evaluation, so the committed bits and the circuit's inputs are
      the same objects
- [ ] Publish `ct`, and add the branch a challenger spends with the
      released `P_b`
- [ ] Carry the garbling-correctness proof, and the Lamport proof that
      accompanies it, through the dispute graph
- [ ] A branch by which a party refuses a mis-garbled circuit rather than
      having to trust it
- [ ] Decide whether the proof is checked off chain by the counterparty
      or made a condition of a spend

**One thing changed since this file was first written.** The garbling
proof used to look optional -- semi-honest first, malicious later. It is
not optional. The circuit's verdict does not get decoded and read; it
*gates* a secret, which means there is no output decoding table and the
garbler is the prover, the party whose committed bits are the labels. A
prover who garbles a circuit that always answers "the step was fine"
wins. So the Nova correctness proof is load-bearing, and `ct` has to be
inside the proved statement, because the challenger cannot check `ct`
before it evaluates. Publishing `h_b = SHA256(P_b)` at setup is what
makes that statement expressible, at one more compression.

Nothing else in the construction depends on this. The circuit's inputs
are committed with one-time signatures whose revealed preimages double as
the input labels, and that commitment -- which is where the endgame's
weight actually goes -- is independent of how the circuit is garbled.

## 2. The step circuit is larger than the paper estimated

Section 8 of the paper originally estimated a RISC-V step at "on the
order of a thousand gates ... one to two orders below a single SHA-256
compression at 22,573". Measured in the metric that comparison is made
in -- AND gates, XOR free:

| circuit | Bristol gates | AND gates | garbling |
|---|---|---|---|
| RV32I  | 23,604 |  7,304 | 341 ms |
| RV32IM | 39,686 | 11,155 | 487 ms |

A step is about a third of a SHA-256 compression, and half of one with
`M`. The paper's conclusion survives -- the instruction is still the
cheapest thing in the endgame -- but the number was out by roughly eight
times.

Three later measurements matter for anyone reading these figures:

* **The adder is a free variable.** As the source model builds it, a
  ripple carry costs two ANDs and an OR per bit; under free-XOR the carry
  is `a ^ ((a^b) & (a^cin))`, one AND. That substitution alone takes
  RV32I from 7,702 to 7,304 and RV32IM from 14,591 to 11,155, with every
  output bit unchanged. A gate count measures the builder as much as the
  function, so do not compare these against another implementation's
  without checking its adder.
* **Most of the circuit is addressing, not semantics.** 4,441 of RV32I's
  AND gates are register-file multiplexing. Supplying the operands
  instead of selecting them gives 3,277 AND gates on a 289-bit input
  rather than 1,185.
* **The dispute wants a bit, not a state.** The prover has already
  claimed a post-state, so the claim is an input and the only output is
  one verdict bit -- 3,437 AND gates for the step, 22,951 for the
  compression. Emitting the recomputed state would be a soundness bug,
  not merely waste: decoding it hands the evaluator a correct execution
  of the step it is disputing.

An earlier revision of this file quoted 10,623 "ciphertexts" for RV32I.
That was the source model's own count, in which a multi-way multiplexer
costs a full table; it is not comparable to an AND-gate figure and should
not have been written down next to one.

## 3. Deduplication is specified but not built

Several challengers selecting the same node can be answered once. The
graph shape for it is settled -- a single stage transaction with one
`s_out` output that a `StageDup` reference consumes, kept off the spine
so the chain is not broken -- and `compact_graph_test` checks that shape
exists and that `StageDup` and the M5 dispute contend for `s_out` as
intended. What is not built is the path that actually takes it: deciding
when to deduplicate, and the pointer from the duplicate to the original.

It was left out on purpose. The construction's result is a publication
cost, and deduplication is an optimisation on top of a cost that is
already measured.
