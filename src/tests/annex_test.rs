//! A BIP341 annex on a Taproot input: storing it, and paying for it.

#[cfg(test)]
mod tests {
    use crate::errors::GraphError;
    use crate::scripts::SignMode;
    use crate::types::input::{InputType, SighashType, SpendMode};
    use bitcoin::Witness;

    fn input() -> InputType {
        InputType::new(
            &SpendMode::KeyOnly {
                key_path_sign: SignMode::Single,
            },
            &SighashType::taproot_all(),
        )
    }

    #[test]
    fn an_input_has_no_annex_until_one_is_set() {
        let i = input();
        assert_eq!(i.annex(), None);
        assert_eq!(i.annex_len(), 0);
    }

    #[test]
    fn an_annex_must_carry_the_0x50_prefix() {
        let mut i = input();
        // BIP341 identifies the annex by its first byte; without it the
        // witness element is just a stack item.
        assert!(matches!(
            i.set_annex(vec![0x51, 1, 2, 3]),
            Err(GraphError::InvalidAnnex)
        ));
        assert!(matches!(i.set_annex(vec![]), Err(GraphError::InvalidAnnex)));
        assert_eq!(i.annex_len(), 0, "a rejected annex is not stored");

        let good = vec![0x50, 0xAA, 0xBB];
        assert!(i.set_annex(good.clone()).is_ok());
        assert_eq!(i.annex(), Some(&good[..]));
        assert_eq!(i.annex_len(), good.len());
    }

    #[test]
    fn annex_len_is_the_whole_annex_including_the_prefix() {
        let mut i = input();
        let payload = vec![0u8; 1000];
        let mut annex = vec![0x50];
        annex.extend_from_slice(&payload);
        i.set_annex(annex).unwrap();
        assert_eq!(i.annex_len(), 1001);
    }

    /// What an annex really adds to a serialized witness, measured rather
    /// than derived: one more item, so its own length plus the compact
    /// size that prefixes it. The item *count*'s compact size does not
    /// grow with it below 253 items, which is what the estimator used to
    /// charge for.
    #[test]
    fn an_annex_costs_its_length_plus_its_own_length_prefix() {
        for len in [1usize, 10, 252, 253, 1000, 65535, 65536] {
            let annex = {
                let mut a = vec![0x50];
                a.resize(len, 0);
                a
            };
            let sig = vec![0u8; 64];

            let mut without = Witness::new();
            without.push(&sig);
            let mut with = Witness::new();
            with.push(&sig);
            with.push(&annex);

            let compact = match len {
                0..=252 => 1,
                253..=65535 => 3,
                _ => 5,
            };
            assert_eq!(
                with.size() - without.size(),
                len + compact,
                "annex of {len} bytes"
            );
        }
    }

    #[test]
    fn a_witness_with_an_annex_round_trips() {
        use bitcoin::consensus::{deserialize, serialize};
        let mut annex = vec![0x50];
        annex.extend_from_slice(&[0xCD; 500]);
        let mut w = Witness::new();
        w.push(vec![0u8; 64]);
        w.push(&annex);

        let back: Witness = deserialize(&serialize(&w)).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back.taproot_annex(), Some(&annex[..]));
    }
}
