//! The SHA-256 compression circuit, against the compression Bitcoin uses.
#[cfg(test)]
mod tests {
    use crate::compact::sha256_circuit::compression_circuit;
    use crate::compact::sha256_core::{compress, iv_std, BLOCK_SIZE, STATE_SIZE};

    /// Bytes to bits, most significant first, which is the order the
    /// circuit's words are laid out in.
    fn bits(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1 == 1))
            .collect()
    }

    fn unbits(bits: &[bool]) -> Vec<u8> {
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
            .collect()
    }

    fn run(state: &[u8; STATE_SIZE], block: &[u8]) -> Vec<u8> {
        let c = compression_circuit();
        let mut input = bits(state);
        input.extend(bits(block));
        assert_eq!(input.len(), c.n_inputs);
        // `eval` returns every wire; `outputs` picks the top ones out.
        unbits(&c.outputs(&c.eval(&input)))
    }

    #[test]
    fn it_computes_the_compression_bitcoin_computes() {
        let c = compression_circuit();
        assert_eq!(c.n_inputs, 768, "256 bits of state, 512 of block");
        assert_eq!(c.n_outputs, 256, "and 256 of next state");

        // The empty-message padding block from the standard initial value:
        // this is SHA-256 of the empty string.
        let mut block = [0u8; BLOCK_SIZE];
        block[0] = 0x80;
        let want = compress(&iv_std(), &block);
        assert_eq!(run(&iv_std(), &block), want.to_vec());
        assert_eq!(
            hex::encode(want),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "which is SHA-256 of the empty string"
        );
    }

    #[test]
    fn it_agrees_on_arbitrary_states_and_blocks() {
        // A deterministic sweep rather than one vector: every bit of both
        // inputs reaches the output through a different path.
        let mut state = iv_std();
        for round in 0..8u32 {
            let mut block = [0u8; BLOCK_SIZE];
            for (i, b) in block.iter_mut().enumerate() {
                *b = ((i as u32).wrapping_mul(2_654_435_761).wrapping_add(round) >> 3) as u8;
            }
            let want = compress(&state, &block);
            assert_eq!(run(&state, &block), want.to_vec(), "round {round}");
            state = want;
        }
    }

    #[test]
    fn one_flipped_input_bit_changes_the_output() {
        let mut block = [0u8; BLOCK_SIZE];
        block[0] = 0x80;
        let base = run(&iv_std(), &block);
        for bit in [0usize, 7, 255, 256, 400, 767] {
            let c = compression_circuit();
            let mut input = bits(&iv_std());
            input.extend(bits(&block));
            input[bit] = !input[bit];
            let got = unbits(&c.outputs(&c.eval(&input)));
            assert_ne!(got, base, "flipping input bit {bit} must change it");
        }
    }

    #[test]
    fn the_and_count_is_the_paper_s_figure() {
        // Remark 8.4 of compact2 measures one SHA-256 compression at
        // 22,696 AND gates under free-XOR. The breakdown:
        //   message schedule  48 x 3 additions x 31 =  4,464
        //   rounds            64 x 7 additions x 31 = 13,888
        //   rounds            64 x (Ch 32 + Maj 32) =  4,096
        //   feed-forward           8 additions x 31 =    248
        let c = compression_circuit();
        assert_eq!(48 * 3 * 31 + 64 * 7 * 31 + 64 * 64 + 8 * 31, 22_696);
        assert_eq!(
            c.and_count(),
            22_696,
            "the built circuit must cost what the paper measured"
        );
    }

    #[test]
    fn it_round_trips_through_bristol_text() {
        // The circuit is built rather than checked in, so the serialized
        // form has to agree with the built one -- otherwise a fixture
        // emitted from it would not be the circuit that was tested.
        let c = compression_circuit();
        let text = c.to_bristol();
        let parsed = crate::compact::bristol::Circuit::parse(&text)
            .expect("a circuit we emitted must parse");
        assert_eq!(parsed.n_wires, c.n_wires);
        assert_eq!(parsed.n_inputs, c.n_inputs);
        assert_eq!(parsed.n_outputs, c.n_outputs);
        assert_eq!(parsed.and_count(), c.and_count());

        let mut block = [0u8; BLOCK_SIZE];
        block[0] = 0x80;
        let mut input = bits(&iv_std());
        input.extend(bits(&block));
        assert_eq!(
            parsed.outputs(&parsed.eval(&input)),
            c.outputs(&c.eval(&input))
        );
    }
}

#[cfg(test)]
mod memory_node {
    use crate::compact::sha256_circuit::{memory_node_circuit, NODE_BITS};
    use bitcoin::hashes::{sha256, Hash};

    fn bits(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1 == 1))
            .collect()
    }

    /// What `memory_tree::parent` computes: SHA256(l || r) truncated.
    fn parent(l: &[u8; 20], r: &[u8; 20]) -> [u8; 20] {
        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(l);
        buf[20..].copy_from_slice(r);
        let d = sha256::Hash::hash(&buf);
        let mut o = [0u8; 20];
        o.copy_from_slice(&d.to_byte_array()[..20]);
        o
    }

    fn refuted(l: &[u8; 20], r: &[u8; 20], claimed: &[u8; 20]) -> bool {
        let c = memory_node_circuit();
        let mut input = bits(l);
        input.extend(bits(r));
        input.extend(bits(claimed));
        assert_eq!(input.len(), 3 * NODE_BITS);
        c.outputs(&c.eval(&input))[0]
    }

    fn node(seed: u8) -> [u8; 20] {
        let mut o = [0u8; 20];
        for (i, b) in o.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        o
    }

    #[test]
    fn an_honest_node_is_not_refuted() {
        for s in 0..6u8 {
            let (l, r) = (node(s), node(s + 100));
            assert!(
                !refuted(&l, &r, &parent(&l, &r)),
                "honest node for seed {s}"
            );
        }
    }

    #[test]
    fn a_wrong_node_is_refuted() {
        let (l, r) = (node(1), node(2));
        let good = parent(&l, &r);
        for bit in [0usize, 7, 80, 159] {
            let mut bad = good;
            bad[bit / 8] ^= 1 << (7 - bit % 8);
            assert!(refuted(&l, &r, &bad), "one flipped bit at {bit}");
        }
        assert!(
            refuted(&r, &l, &good),
            "left and right are not interchangeable"
        );
    }

    #[test]
    fn what_the_check_costs_in_gates() {
        let c = memory_node_circuit();
        assert_eq!(c.n_inputs, 480, "left, right and the claimed parent");
        assert_eq!(c.n_outputs, 1, "one verdict bit, which gates the secret");
        // The compression, plus one AND a bit to fold 160 differences.
        assert_eq!(c.and_count(), 22_696 + 160);
        println!(
            "memory_node_circuit: {} AND gates, {} wires",
            c.and_count(),
            c.n_wires
        );
    }
}

/// The memory check through the real garbled endgame.
///
/// The circuit above is only a component until it is garbled, opened and
/// adjudicated the way the dispute graph does it. This drives
/// `Endgame::setup`, `open` and `adjudicate` over it: a prover who
/// publishes a wrong node hands the challenger the secret, and an honest
/// one hands over nothing.
#[cfg(test)]
mod garbled_memory_endgame {
    use crate::compact::endgame::{adjudicate, Endgame, Outcome};
    use crate::compact::garble::Label;
    use crate::compact::sha256_circuit::{memory_node_circuit, NODE_BITS};
    use bitcoin::hashes::{sha256, Hash};

    fn bits(bytes: &[u8]) -> Vec<bool> {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1 == 1))
            .collect()
    }

    fn parent(l: &[u8; 20], r: &[u8; 20]) -> [u8; 20] {
        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(l);
        buf[20..].copy_from_slice(r);
        let d = sha256::Hash::hash(&buf);
        let mut o = [0u8; 20];
        o.copy_from_slice(&d.to_byte_array()[..20]);
        o
    }

    fn node(seed: u8) -> [u8; 20] {
        let mut o = [0u8; 20];
        for (i, b) in o.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        o
    }

    /// Deterministic label source, so a failure is reproducible.
    fn labels(seed: u64) -> impl FnMut() -> Label {
        let mut s = seed;
        move || {
            let mut l = [0u8; 16];
            for chunk in l.chunks_mut(8) {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                chunk.copy_from_slice(&s.to_le_bytes());
            }
            l[0] |= 1; // the colour bit the garbler needs
            l
        }
    }

    fn claim_bits(l: &[u8; 20], r: &[u8; 20], claimed: &[u8; 20]) -> Vec<bool> {
        let mut v = bits(l);
        v.extend(bits(r));
        v.extend(bits(claimed));
        assert_eq!(v.len(), 3 * NODE_BITS);
        v
    }

    #[test]
    fn a_lie_about_a_memory_node_releases_the_secret() {
        let secret = [7u8; 32];
        let tweak = b"memory-node";
        let e = Endgame::setup(memory_node_circuit(), tweak, &secret, labels(1));

        let (l, r) = (node(3), node(9));
        let mut wrong = parent(&l, &r);
        wrong[0] ^= 0x80;

        let claim = claim_bits(&l, &r, &wrong);
        assert!(e.verdict(&claim), "the circuit says the claim is a lie");

        let opened = e.open(&claim);
        match adjudicate(&e.circuit, e.published(), tweak, &opened) {
            Outcome::Refuted(got) => assert_eq!(got, secret, "and the secret is released"),
            other => panic!("expected the secret, got {other:?}"),
        }
    }

    #[test]
    fn an_honest_memory_node_releases_nothing() {
        let secret = [7u8; 32];
        let tweak = b"memory-node";
        let e = Endgame::setup(memory_node_circuit(), tweak, &secret, labels(2));

        let (l, r) = (node(3), node(9));
        let claim = claim_bits(&l, &r, &parent(&l, &r));
        assert!(!e.verdict(&claim), "the circuit says the claim stands");

        let opened = e.open(&claim);
        assert_eq!(
            adjudicate(&e.circuit, e.published(), tweak, &opened),
            Outcome::Stands,
            "an honest publisher keeps the secret"
        );
    }

    #[test]
    fn a_forged_opening_refutes_nothing() {
        let secret = [7u8; 32];
        let tweak = b"memory-node";
        let e = Endgame::setup(memory_node_circuit(), tweak, &secret, labels(3));

        let (l, r) = (node(3), node(9));
        let mut wrong = parent(&l, &r);
        wrong[0] ^= 0x80;
        let mut opened = e.open(&claim_bits(&l, &r, &wrong));
        opened[0] = [0xAA; 16];

        assert_eq!(
            adjudicate(&e.circuit, e.published(), tweak, &opened),
            Outcome::NotAnOpening,
            "a label the prover never committed is not an opening"
        );
    }

    #[test]
    fn what_the_prover_publishes_for_one_memory_check() {
        let secret = [7u8; 32];
        let e = Endgame::setup(memory_node_circuit(), b"t", &secret, labels(4));
        let bytes = e.published().size();
        println!(
            "memory node endgame: {} AND gates, {} bytes off chain ({:.2} MB)",
            e.circuit.and_count(),
            bytes,
            bytes as f64 / 1_048_576.0
        );
        // Two 128-bit ciphertexts an AND gate, plus the input commitments
        // and the sealed secret. The paper prices one compression at
        // 0.73 MB and this is a compression plus a 160-bit comparison.
        assert!(
            (0.70..0.80).contains(&(bytes as f64 / 1_048_576.0)),
            "about three quarters of a megabyte, as the paper says: {bytes}"
        );
    }
}
