//! The garbled signature gadget.
//!
//! These pin three things: the gadget telescopes to a real BIP340
//! signature, the published material is the 8,288 bytes the paper claims,
//! and the single-evaluation invariant is not decorative -- two labels on
//! one wire hand over the key.

#[cfg(test)]
mod tests {
    use crate::compact::bristol::{Circuit, Gate};
    use crate::compact::garble::{evaluate as geval, Garbled, Label, LABEL_LEN};
    use crate::compact::gsig::{self, Affine, Signer, M4_SIG_TWEAK, MSG_BITS, SINGLE_EVALUATION};

    /// A deterministic label source, so every test here is reproducible.
    fn labels(seed: u64) -> impl FnMut() -> Label {
        use bitcoin::hashes::{sha256, Hash};
        let mut n = seed;
        move || {
            n = n
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let d = sha256::Hash::hash(&n.to_le_bytes()).to_byte_array();
            let mut l = [0u8; LABEL_LEN];
            l.copy_from_slice(&d[..LABEL_LEN]);
            l
        }
    }

    /// A circuit whose 256 outputs are its 256 inputs, routed through one XOR
    /// with a constant-zero wire so the wires are genuinely garbled ones and
    /// not the input labels themselves.
    ///
    /// The gadget does not care what produced the message wires; what it needs
    /// is a garbling that owns them.  The real M4 circuit computes `e` with a
    /// single SHA-256 compression, which `sha256_core` already models.
    fn identity_256() -> (Circuit, Vec<usize>) {
        let n_inputs = MSG_BITS + 1; // the last input is pinned to zero
        let mut gates = Vec::new();
        let mut wires = Vec::new();
        for i in 0..MSG_BITS {
            let out = n_inputs + i;
            gates.push(Gate::Xor {
                a: i,
                b: MSG_BITS,
                out,
            });
            wires.push(out);
        }
        let c = Circuit {
            n_wires: n_inputs + MSG_BITS,
            n_inputs,
            n_outputs: MSG_BITS,
            gates,
        };
        (c, wires)
    }

    /// Garble, evaluate on `m`, and return what the evaluator got.
    fn run(m_bits: &[bool], key: &Affine) -> (gsig::GarbledSignature, gsig::Evaluation) {
        let (c, wires) = identity_256();
        let g = Garbled::new(&c, labels(7));
        let sig = gsig::garble(M4_SIG_TWEAK, &g, &wires, key);

        let mut inputs: Vec<bool> = m_bits.to_vec();
        inputs.push(false); // the pinned zero
        let in_labels = g.encode(&c, &inputs);
        let out = geval(&c, g.tables(), &in_labels);
        let held: Vec<Label> = wires.iter().map(|&w| out[w]).collect();

        let ev = gsig::evaluate(M4_SIG_TWEAK, &sig, &held);
        (sig, ev)
    }

    #[test]
    fn the_evaluation_is_a_valid_bip340_signature() {
        let signer = Signer::new(&[0x11; 32]);
        let key = signer.affine(&[0x22; 32]);

        let msg = [0xABu8; 32];
        let e = signer.challenge(&key.r_x, &msg);
        let (_, ev) = run(&gsig::scalar_bits(&e), &key);

        // The evaluator read back exactly the challenge the circuit carried.
        assert_eq!(gsig::bits_scalar(&ev.m), e);
        assert!(
            gsig::verify(&signer.p_x, &msg, &ev.sig),
            "the gadget's output must verify as an ordinary Schnorr signature"
        );
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let signer = Signer::new(&[0x11; 32]);
        let key = signer.affine(&[0x22; 32]);

        let msg = [0xABu8; 32];
        let e = signer.challenge(&key.r_x, &msg);
        let (_, ev) = run(&gsig::scalar_bits(&e), &key);

        let other = [0xACu8; 32];
        assert!(!gsig::verify(&signer.p_x, &other, &ev.sig));
    }

    /// The point of the gadget for C04: the circuit chooses *which* message is
    /// signed, and the choice is free.  Here the same garbling, evaluated on
    /// the challenge of a different transaction, signs that one instead -- no
    /// gate, table or round distinguishes the two cases.
    #[test]
    fn the_circuit_chooses_what_gets_signed() {
        let signer = Signer::new(&[0x33; 32]);

        for msg in [[0x01u8; 32], [0xFEu8; 32]] {
            // A fresh nonce per garbling; see SINGLE_EVALUATION.
            let mut nonce = [0x44u8; 32];
            nonce[0] = msg[0];
            let key = signer.affine(&nonce);
            let e = signer.challenge(&key.r_x, &msg);
            let (_, ev) = run(&gsig::scalar_bits(&e), &key);
            assert!(gsig::verify(&signer.p_x, &msg, &ev.sig), "msg {:?}", msg[0]);
        }
    }

    #[test]
    fn the_material_is_8288_bytes() {
        let signer = Signer::new(&[0x11; 32]);
        let key = signer.affine(&[0x22; 32]);
        let (sig, _) = run(&vec![false; MSG_BITS], &key);

        assert_eq!(sig.c.len(), MSG_BITS);
        assert_eq!(sig.selectors.len(), MSG_BITS);
        assert_eq!(sig.size(), MSG_BITS * 32 + 32 + 32 + 32);
        assert_eq!(sig.size(), 8_288);
    }

    /// The invariant, executable.  Both labels of one message wire reveal `B`,
    /// which for Schnorr is the signing key.
    #[test]
    fn both_labels_of_one_wire_recover_the_key() {
        assert!(SINGLE_EVALUATION.contains("at most one input assignment"));

        let signer = Signer::new(&[0x55; 32]);
        let key = signer.affine(&[0x66; 32]);

        let (c, wires) = identity_256();
        let g = Garbled::new(&c, labels(7));
        let sig = gsig::garble(M4_SIG_TWEAK, &g, &wires, &key);

        // An adversary that saw the gadget evaluated twice holds both labels
        // of some wire.  Any wire will do; take a middle one.
        let i = 137;
        let zero = g.label(wires[i], false);
        let one = g.label(wires[i], true);
        let recovered =
            gsig::recover_key(M4_SIG_TWEAK, &sig, i, &zero, &one).expect("2^i is invertible");

        assert_eq!(
            recovered,
            key.b.serialize(),
            "two labels on one message wire hand over B"
        );

        // And B really is the signing key: it signs anything.
        let msg = [0x77u8; 32];
        let e = signer.challenge(&key.r_x, &msg);
        let forged = key.a + key.b * musig2::secp::MaybeScalar::reduce_from(&e);
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&key.r_x);
        raw[32..].copy_from_slice(&forged.serialize());
        assert!(gsig::verify(&signer.p_x, &msg, &raw));
    }

    #[test]
    fn bit_order_round_trips() {
        let s = [
            0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x0F, 0x1E, 0x2D, 0x3C,
            0x4B, 0x5A, 0x69, 0x78,
        ];
        let b = gsig::scalar_bits(&s);
        assert_eq!(b.len(), MSG_BITS);
        // Bit 0 is the least significant bit of the big-endian serialisation.
        assert_eq!(b[0], s[31] & 1 == 1);
        assert_eq!(b[255], s[0] >> 7 & 1 == 1);
        assert_eq!(gsig::bits_scalar(&b), s);
    }

    /// The hard-coded `2^-1 mod n` really is one, and the powers of it really
    /// invert the powers of two the gadget weights its wires by.
    #[test]
    fn the_half_constant_inverts_two() {
        use crate::compact::gsig::two_pow_inv;
        use musig2::secp::MaybeScalar;

        let two = MaybeScalar::one() + MaybeScalar::one();
        assert_eq!(two * two_pow_inv(1), MaybeScalar::one());

        let mut p = MaybeScalar::one();
        for i in 0..MSG_BITS {
            assert_eq!(p * two_pow_inv(i), MaybeScalar::one(), "2^{}", i);
            p = p + p;
        }
    }
    /// What the invariant actually forbids, which is narrower than how
    /// `SINGLE_EVALUATION` phrases it.
    ///
    /// The attack needs both labels of one message wire.  Two evaluations
    /// of the same garbling on the *same* assignment hand out the same
    /// label on every wire, so they leak nothing -- "evaluated once, by
    /// one party" are sufficient conditions, and the necessary one is
    /// "on one input assignment".
    ///
    /// This matters for concurrent challengers: it says exactly when a
    /// garbling could be shared, and the answer turns out to be never,
    /// because each challenger must be paid by a different transaction
    /// and so the circuit must compute a different message for each.
    #[test]
    fn two_evaluations_on_one_assignment_leak_nothing() {
        let signer = Signer::new(&[0x11; 32]);
        let key = signer.affine(&[0x22; 32]);
        let msg = [0xABu8; 32];
        let e = signer.challenge(&key.r_x, &msg);
        let bits = gsig::scalar_bits(&e);

        let (c, wires) = identity_256();
        let g = Garbled::new(&c, labels(7));
        let sig = gsig::garble(M4_SIG_TWEAK, &g, &wires, &key);

        // Two evaluators, same assignment.
        let held = |b: &[bool]| -> Vec<Label> {
            let mut inputs = b.to_vec();
            inputs.push(false);
            let out = geval(&c, g.tables(), &g.encode(&c, &inputs));
            wires.iter().map(|&w| out[w]).collect()
        };
        let a = held(&bits);
        let b = held(&bits);
        assert_eq!(a, b, "the same assignment gives the same labels");

        // So no wire has both of its labels, and the extraction has
        // nothing to work with.
        for i in 0..MSG_BITS {
            assert_eq!(a[i], b[i]);
        }
        assert_eq!(
            gsig::evaluate(M4_SIG_TWEAK, &sig, &a).sig,
            gsig::evaluate(M4_SIG_TWEAK, &sig, &b).sig,
            "and both produce the same signature, which is the point"
        );

        // One differing bit is all it takes, though.
        let mut other = bits.clone();
        other[137] = !other[137];
        let c2 = held(&other);
        assert_ne!(a[137], c2[137], "now both labels of wire 137 are out");
        let (zero, one) = if gsig::scalar_bits(&e)[137] {
            (c2[137], a[137])
        } else {
            (a[137], c2[137])
        };
        assert_eq!(
            gsig::recover_key(M4_SIG_TWEAK, &sig, 137, &zero, &one).unwrap(),
            key.b.serialize(),
            "two assignments differing in one bit hand over the key"
        );
    }
}
