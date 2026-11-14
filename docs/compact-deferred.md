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

## 4. Deduplication: the reference is built, the decision is not

Several challengers selecting the same node can be answered once. The
graph shape for it is settled -- a single stage transaction with one
`s_out` output that a `StageDup` reference consumes, kept off the spine
so the chain is not broken -- and `compact_graph_test` checks that shape
exists and that `StageDup` and the M5 dispute contend for `s_out` as
intended. What is not built is the path that actually takes it: deciding
when to deduplicate, and the pointer from the duplicate to the original.

**The reference now exists.** `StageDup` spends two outputs, and the pair
is the whole mechanism: a `Dedup` output of the stage being pointed at,
whose spend is what consensus accepts as proof that the stage confirmed
-- no signature can establish that, since a party can sign a stage and
never broadcast it -- and the stage's own `s_out`, of fixed shape
whatever the stage did, which `StageDispute` also wants. Only one of them
can have it, so "no reference was made" is readable without anybody
asserting it.

Three tests pin it: a reference spends a `Dedup` and an `s_out`; the
`Dedup` outputs are emitted whether or not anyone takes them, which is
the standing charge Table 7.1's "shape" column prices; and a reference is
told apart from a dispute by what it spent rather than by anybody's word.

One graph is one instance, so the `Dedup` a `StageDup` spends here is its
own stage's -- the right shape and a degenerate reference. A deployment
takes it from another instance's stage.

**What is still not built** is the decision: when to deduplicate, and the
pointer that says *which* instance's stage is being referred to. That
wants the multi-instance protocol state, and M6 of Section 7.3 -- the
check that the instance referred to has the same digit prefix, and so the
same interval -- is what makes a wrong pointer refutable. Neither is in
the graph.

It was left out on purpose. The construction's result is a publication
cost, and deduplication is an optimisation on top of a cost that is
already measured.

## 5. The division circuit rejected some honest divisions --- fixed

`div` and `rem` are not built as dividers.  The prover witnesses the
quotient and remainder as non-deterministic inputs (`nd_div`, `nd_mod`)
and the circuit checks `q*d + r == n` with the multiplier it already has.
That is why the M extension costs 3,851 AND gates rather than a divider's
worth more, and why 64 bits of witness sit in the input interface of both
circuits --- RV32I allocates them too, unused, which is why both are 450
bits wide.  The saving is paid for on chain, in 64 more committed bits.

**The defect.** `add_adder` truncates to `min(len(left), len(right))`, so
adding a 32-bit remainder to a 64-bit product dropped the high word
entirely, and the check compared the *product's* sign against the *sum's*.
Those differ exactly when `q*d + r` is negative and `q*d` is not --- a
zero quotient with a negative dividend.  An honest prover executing
`div(-1, 2)` claimed no fault, the circuit said there was one, and she was
refuted and lost her stake for a correct instruction.  `|n| < |d|` with
`n` negative is an ordinary thing for a program to do.

**The fix.** Widen the remainder the way the product was signed ---
sign-extended for `div`/`rem`, zero-extended for `divu`/`remu` --- add at
the full 64 bits, and require the high word to be the dividend's own sign
extension.  That replaces the old `high1`/`high0` pair and the two sign
clauses with one comparison.

**It costs nothing.** 123 more Bristol gates, every one of them XOR, so
under free-XOR the AND counts are unchanged: RV32IM stays at 11,155,
narrow at 7,128, verdict at 7,288, and RV32I is untouched ---
`rv32i_verdict.bristol` regenerates byte-identical.

Both directions are now tested, and they are different properties.
`rv32im_honest_div.vectors` is ten honest divisions including the three
that used to fail; `rv32im_bad_witness.vectors` is twenty-four cases of
the dangerous prover, who corrupts the quotient *and* claims the corrupted
result so that the result comparison passes and only the status bit
catches her.  All twenty-four are refuted.  The soundness direction could
not be tested at all while honest divisions were failing, which is how the
defect was found.

The emulator is unaffected --- it computes with Rust's own `/` and `%` ---
and its division tests never reach the case: they cover divide by zero,
overflow, and four non-zero quotients.  Adding one is worth doing.
