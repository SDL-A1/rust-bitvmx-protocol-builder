# compact: what is deferred, and why

Tracking notes for the `compact` module. Nothing here is a bug; these
are decisions to revisit, recorded so they are not mistaken for
oversights later.

## 1. The circuits are wired; the garbling is still trusted

The `compact` module now runs the endgame exchange end to end:
`bristol` loads a circuit, `garble` garbles it with free-XOR and
half-gates, `release` commits to the inputs and seals `P_b` under the
verdict wire's one-label, and `endgame` joins them into setup, claim and
adjudication.  `Leaf::PreimageRelease` carries `h_b` and is a real
script, executed by `bitcoin-scriptexec` with a real BIP341 script-path
signature: the released secret spends the stake, and no other preimage
does.

Over the 128 fixture vectors of A3's circuit, 64 lies release `P_b` byte
for byte and 64 honest claims release nothing.

Two things about that are worth stating plainly.

**The input commitment is not ACW.**  What the protocol needs of the
scheme is only that the prover publish two hashes a bit at setup and
that opening a bit reveal exactly one preimage, which is the label.
`release::BitCommitment` is that, with SHA-256.  ACW's contribution is
guaranteed permissionless extraction and a smaller table, not a
different binding, and the paper's weights (33.44 WU a bit) are ACW's.
Swapping it in changes `BitCommitment` and nothing above it.

**The garbling is accepted as given, and that is now load-bearing.**  It
used to look like an upgrade: semi-honest first, malicious later.  It is
not.  The verdict is never decoded and read -- it gates a secret, so
there is no output decoding table and the garbler is the prover, the
party whose committed bits are the labels.  A prover who garbles a
circuit that always answers "the step was fine" wins.  What is left:

- [ ] Carry the garbling-correctness proof, and the Lamport proof that
      accompanies it, through the dispute graph
- [ ] Put `ct` inside the proved statement.  The challenger cannot check
      `ct` before it evaluates; publishing `h_b` at setup is what makes
      the statement `SHA256(ct xor H(W_v^1)) == h_b` expressible, at one
      more compression
- [ ] A branch by which a party refuses a mis-garbled circuit rather
      than having to trust it
- [ ] Decide whether the proof is checked off chain by the counterparty
      or made a condition of a spend

The engine already proves circuit correctness with a Nova recursive
SNARK, and a step circuit is well inside the sizes it handles, so none
of this is blocked.

**The fixtures --- resolved.**  A3's verdict circuit is checked in
(251 kB).  The gated compression, which A1, A2, A4, B1, B2, M1--M4 and
Section 9.4's memory check all reduce to, is *built* rather than checked
in: `sha256_circuit` constructs it and tests it against
`sha256_core::compress`, which is `bitcoin_hashes` and therefore the
compression Bitcoin computes.  It costs 22,696 AND gates, the paper's
figure, reached the way the paper counts it.  3.7 MB of Bristol text was
a poor thing to carry for a circuit the standard determines entirely;
`Circuit::to_bristol` emits it if a fixture is ever wanted.

`memory_node_circuit` is Section 9.4 on top of it --- left child, right
child, claimed parent in, one verdict bit out, 22,856 AND gates --- and
runs through `Endgame::setup`, `open` and `adjudicate`: a wrong node
releases the secret byte for byte, an honest one releases nothing, and
the published material is 762,144 bytes, which is the 0.73 MB the paper
prices a compression at.

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

## 3. Both publication modes build, and both have been to a node

`Params::publishing_in_an_output()` switches the graph from an annex
publication to an `OP_RETURN` one: every stage gains a `DataOut` and a
`DataFee` output, a `StageData` spends both -- `SIGHASH_SINGLE` on input
0 for the commitment, `SIGHASH_ALL` on input 1 to pin the transaction --
and a `MissingData` races the first.  `dispute::read_output_profile` is
M5 for that profile, four clauses, all inside the one final block the
witness already carries.

`tests/annex_regtest.rs` takes both to a real `bitcoind` on regtest.
The annex is accepted by consensus and rejected by policy
(`bad-witness-nonstandard`); the output publication is accepted by
both, which is the claim the mode exists for and is now asserted
rather than printed.  Run them with `--test-threads=1`: each mines its
own blocks against one chain.

What is still missing there:

- [ ] `MissingData` after the timelock -- a script-path spend of the
      `DataOut` leaf, which nothing yet exercises against a node
- [ ] A `StageData` built by `Graph::build` rather than by the test, so
      that the graph's own outputs are the ones spent

Two figures the implementation corrected.  The furniture went from 401
WU a stage to 968 plus 376 on the penalization branch: the first number
counted one output and one input, where there are two of each, plus
StageData's overhead and a whole MissingData.  And the publication went
from 32,316 WU to 32,512, because the file has to start at byte 64 of
the serialized output for its digest to be `sha_single_output` -- the
output's analogue of the annex frame, bought with 49 bytes of `OP_0`
fillers and an `OP_PUSHDATA4`.

## 4. Deduplication is specified but not built

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

## 5. The division circuit rejects some honest divisions

`div` and `rem` are not built as dividers.  The prover witnesses the
quotient and remainder as non-deterministic inputs (`nd_div`, `nd_mod`)
and the circuit checks `q*d + r == n` with the multiplier it already has.
That is why the whole M extension costs 3,851 AND gates rather than a
divider's worth more, and why 64 bits of witness are in the input
interface of both circuits -- RV32I allocates them too, unused, which is
why both are 450 bits wide.

The check mishandles one case.  When the quotient is **zero** and the
dividend is **negative**, the product is zero and its high word is all
zeros; but `q*d + r` is then negative, and its sixty-four-bit form needs a
high word of all ones.  The remainder is not sign-extended into the
product before the consistency check, so `check_2` compares a zero high
word against a set sign bit and the division is flagged as faulty.

Measured, in `riscv.py`'s `create_multiply_opcodes`:

| case | q | r | verdict on an honest claim |
|---|---:|---:|---|
| `div(-1, 2)`   | 0 | -1 | **wrongly refuted** |
| `div(-7, -9)`  | 0 | -7 | **wrongly refuted** |
| `rem(-1, 2)`   | 0 | -1 | **wrongly refuted** |
| `div(-5, 3)`   | -1 | -2 | stands |
| `div(-10, 3)`  | -3 | -1 | stands |
| `div(7, 9)`    | 0 | 7 | stands |
| `divu(7, 9)`   | 0 | 7 | stands |

This is a liveness failure rather than a soundness one, and it is severe:
an honest prover who executes `div(-1, 2)` claims no fault, the circuit
says there was one, and she is refuted and loses her stake for a correct
instruction.  `|n| < |d|` with `n` negative is an ordinary thing for a
program to do.

`rv32im_honest_div.vectors` is the evidence and
`rv32im_verdict_test::division_defect` pins it, asserting the defect so
that the tests fail when it is fixed.

The emulator is not affected -- it computes with Rust's own `/` and `%` --
and its division tests never reach the case: they cover divide by zero,
overflow, and four non-zero quotients.  Whether
`bitcoin-script-riscv`'s separate `div`/`rem` scripts share the defect is
**untested**, and should be the first thing checked, because if Script is
correct then the two backends disagree about a valid instruction.

What to do:

- [ ] Sign-extend `nd_mod` into the sixty-four-bit product before
      `verify`, in `create_multiply_opcodes`
- [ ] Check `bitcoin-script-riscv`'s `div`/`rem` against the same cases
- [ ] Re-emit the fixtures; the gate count will move
- [ ] Enable `bad_witness_vectors` in `emit.py`, which is written and not
      called: it asserts that a prover who corrupts the quotient *and*
      claims the corrupted result is still refuted, which is the soundness
      direction and could not be tested while honest cases were failing
