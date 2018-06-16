#[cfg(test)]
mod tests {
    use pairing::bls12_381::*;
    use pairing::{PrimeField, PrimeFieldRepr};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn roundtrip_fr_bytes() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            // create a random element
            let fr: Fr = rng.gen();

            // get the representation
            let fr_repr = fr.into_repr();

            // turn the represenation into bytes
            let mut bytes = Vec::new();
            fr_repr.write_le(&mut bytes).unwrap();

            // check the byte length
            assert_eq!(bytes.len(), (64 * 4) / 8);

            // lets go back into FrRepr

            // empty
            let mut fr_repr_back = FrRepr::default();
            // read bytes
            fr_repr_back.read_le(bytes.as_slice()).unwrap();

            // check its the same
            assert_eq!(fr_repr, fr_repr_back);

            // got Fr
            let fr_back = Fr::from_repr(fr_repr_back).unwrap();

            // it's the same
            assert_eq!(fr, fr_back);
        }
    }
}
