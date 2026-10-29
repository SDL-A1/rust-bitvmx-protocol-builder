# Who supplies the circuit's inputs, and who owns the labels

Status: **open problem**, found 2026-10-29. Nothing here is implemented.
Two candidate mechanisms are written out so they can be compared.

## 1. The problem

A garbled circuit has two parties. The **garbler** chooses, for every
wire, two random labels `L^0` and `L^1`, and knows both. The
**evaluator** holds exactly one label per input wire and learns nothing
else.

The endgame's release (Remark 8.5) fixes who is who. The verdict is not
decoded and read; it *gates* a secret. There is no output decoding
table, so the evaluator learns the verdict only by recovering `P_b` and
seeing its hash match. The party who must end up holding `P_b` is the
**challenger**, because `P_b` spends the prover's stake. So:

> the prover garbles, the challenger evaluates.

That is forced, and it is why the garbling-correctness proof is
load-bearing: a prover who garbles a circuit that always answers "fine"
wins.

Now ask where each circuit's inputs come from.

| option | what the circuit reads | whose data is it? |
|---|---|---|
| A1, A2, A3 | the disputed step: pre-state, instruction, operands, claimed post-state | the **prover's** |
| M1 malformed | a FlatMerkle fraud proof over her publication | the **challenger's** |
| M2 false opening | an opening contradicting her claim | the **challenger's** |
| M3 wrong node | an opening of her previous publication | the **challenger's** |
| M4 self-contradiction | an opening, and two 20-byte values | the **challenger's** |
| M5 bad profile | her signature, and the final block it signed | the **challenger's** |
| M6 dangling reference | the referenced party's signature | the **challenger's** |

Section 6 says this explicitly — *"the party who alleges the fault is
the party who holds the evidence"* — and it is what makes a publication
dispute one transaction with no answer demanded.

**The two facts do not compose.** For A1–A3 the prover both garbles and
supplies the inputs, so she opens her own commitment and the revealed
preimages *are* the labels: this is the BitVM3 arrangement, and
`compact::release::BitCommitment` implements it. For M1–M6 the prover
garbles but the *challenger* supplies the inputs, and the challenger has
no way to obtain a label. He knows the bits he wants to feed in; he does
not know `L^b` for any of them, and he cannot ask the prover for them
without a second message — which is the thing Section 6 is built to
avoid.

Today the protocol has no mechanism here at all. `Endgame::open` takes a
claim and returns labels from the garbler's own table; there is nothing
a challenger could call.

## 2. Why no test caught it

Worth recording, because the gap is structural rather than careless.

* `compact_dispute_test.rs` tests `read_profile`, `entry_holds`,
  `m5_stands` and the rest as **pure predicates over data**. Given a
  witness, do they return the right verdict? They never ask where the
  witness came from or who could have produced it.
* `compact_circuit_test.rs` tests the garbling, the commitment and the
  release — but only through `Endgame`, and only on A3's circuit, which
  is the one case where the prover supplies the inputs.
* `compact_graph_test.rs` tests shape: every input points at an output
  that exists, every lock is one delta, the spine is a chain. Shape says
  nothing about who can produce a witness.

The flaw lives in the seam between two modules that are each correct in
isolation, and no test crosses the seam. The missing test is roughly:

> for each dispute option, the party who raises it can actually
> construct the circuit inputs it needs, using only material that party
> possesses.

That test would have failed on M1 through M6 the day it was written.

## 3. Mechanism A — crossed label commitment ("the encryption idea")

Keep the prover as garbler. Give the challenger a way to turn *his* own
one-time-signature preimages into *her* labels, with no interaction
after setup.

### Setup, once per dispute option

The challenger generates a one-time signature key for the evidence he
might later have to commit. For each input bit `i` of that evidence it
gives him two preimages `x_i^0`, `x_i^1`, and the two public hashes

```
h_i^0 = H(x_i^0)        h_i^1 = H(x_i^1)
```

go on chain in the dispute leaf, exactly as a one-time commitment
normally does.

The prover garbles the option's circuit and obtains `L_i^0`, `L_i^1` for
the same bits. She then publishes, off chain, the **translation table**

```
T_i^0 = L_i^0  XOR  KDF(x_i^0)        T_i^1 = L_i^1  XOR  KDF(x_i^1)
```

— each label masked by a pad derived from the preimage that opens that
bit to that value. She can compute these because `h_i^b` is public and
she is told... no: she cannot, and this is the point to get right.

**She must be given the preimages' pads, not the preimages.** The
challenger therefore publishes, at setup, `KDF(x_i^0)` and `KDF(x_i^1)`
for every bit — or equivalently the prover and challenger run the setup
jointly, with the challenger sending `(KDF(x_i^0), KDF(x_i^1))` and
keeping `x_i^b` secret. Publishing the pads is safe: a pad does not open
the one-time signature, and the on-chain check is on `h_i^b = H(x_i^b)`,
which the pad does not reveal. Use two independent derivations,

```
h_i^b = H("ots"  || x_i^b)          the on-chain commitment
p_i^b = H("pad"  || x_i^b)          the pad, published at setup
```

so that knowing `p_i^b` is no help in forging `x_i^b`.

### The dispute

The challenger's transaction reveals `x_i^{b_i}` for his chosen bits —
this is just the one-time signature on his evidence, which the leaf
already checks. He then computes `p_i^{b_i}` himself, and

```
L_i^{b_i} = T_i^{b_i}  XOR  p_i^{b_i}
```

gives him exactly one label per input wire and nothing about the other.
He evaluates, and if the verdict is one he recovers `P_b` and spends the
stake. **One transaction, no answer demanded, no timeout deciding.**

### What it costs

Two 16-byte ciphertexts per input bit, published once at setup. For the
worst option, M1's 768-byte witness, that is 6,144 bits and about
**197 KB** per challenger per option — small beside the megabyte of M5
translation material already budgeted.

### What it assumes

* The challenger's OTS keys exist before the prover garbles, so setup
  has an ordering: challenger publishes pads, prover publishes tables.
* The prover must not learn which bit the challenger will reveal. She
  does not: she sees both pads and publishes both tables.
* A challenger who reveals *both* preimages for one bit gets both
  labels, and with free-XOR that yields the global offset and breaks the
  garbling. This is the usual one-time-signature discipline — equivocate
  and you forfeit — but here the consequence is worse than usual and
  should be stated as a security requirement, not a convention.

## 4. Mechanism B — co-signature ("the other party signs the publication")

The alternative raised on 2026-10-29. In a full-duplex stage both
parties publish, so make each party's stage transaction carry a
**co-signature on the counterparty's previous publication signature**.

Then the digest the challenger later disputes is one he has already
endorsed on chain, and — as in paper 2.5, where *"the bits of `s` are
inputs from Bob's copy, whose labels Alice's co-signature releases"* —
that co-signature is the vehicle that hands over the labels.

### Why it may cost no round

The obvious objection is that co-signing is a second message, and
Section 6 exists to remove second messages. It need not be: party `C`
is already sending a stage transaction at `i+1`, and the co-signature on
`P`'s stage-`i` publication can ride in it. No extra transaction, no
extra round, no new timeout.

### Why refusing to co-sign is self-defeating

If `C` withholds the co-signature, `C` cannot later dispute stage `i` —
so withholding costs `C` the only thing it buys. No penalty branch is
needed; the incentive is structural. **This needs checking**: it is only
true if every dispute `C` might raise about stage `i` goes through the
co-signed digest, and M5 in particular is about `P` having published
*nothing*, where there may be no digest to co-sign.

### What it would simplify

Table 6.1's *bindings* column disappears. M1 to M4 each carry one or two
160-byte profile witnesses purely to authenticate a digest; if the
digest is already co-signed, that authentication is on chain and the
witness is not needed. The worst dispute drops from 768 bytes to 608,
and M2 and M3 from 448 to 288.

## 5. What to decide

1. Mechanism A or B, or both (A is general; B is cheaper where it
   applies and may not cover M5).
2. Under B, what happens to M5, where the complaint is that there is no
   publication to co-sign.
3. Whether the evidence commitment is one fixed-width key sized for the
   worst option — 768 bytes in every branch, by the same argument that
   makes `chi'` eleven bits in every branch — or six keys, one per
   option, each sized for its own. The paper does not say, and Table 6.1
   quietly assumes the second.
4. Figure 2 should show `rho` on `StageDispute`. It currently shows only
   `OTS_X(chi')`, which is eleven bits, and the note "the refutation
   rides with it" — so the figure makes a stage dispute look two orders
   smaller than it is.
