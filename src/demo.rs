#[cfg(test)]
mod tests {
    use pairing::bls12_381::*;
    use pairing::{PrimeField, PrimeFieldRepr};
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::multipack;

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

    #[test]
    fn roundtrip_bytes() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            // lets say we have some random bytes
            let input: Vec<u8> = (0..128).map(|_| rng.gen()).collect();

            // lets convert them to bits
            let input_bits: Vec<bool> = multipack::bytes_to_bits(&input);

            // make sure we have the right amount of bits
            assert_eq!(input_bits.len(), 128 * 8);

            // which we want to store in Fr elements
            let frs = multipack::compute_multipacking::<Bls12>(&input_bits);

            // lets convert these into bytes that we could store somewhere
            let bytes = frs.iter().fold(Vec::new(), |mut acc, fr| {
                fr.into_repr().write_le(&mut acc).unwrap();
                acc
            });

            assert_eq!(bytes.len(), frs.len() * 32);

            // lets pull them back into frs
            let frs_back: Vec<Fr> = bytes
                .chunks(8 * 4)
                .map(|chunk| {
                    let mut fr_repr_back = FrRepr::default();
                    fr_repr_back.read_le(chunk).unwrap();
                    Fr::from_repr(fr_repr_back).unwrap()
                })
                .collect();

            assert_eq!(frs.len(), frs_back.len());
            assert_eq!(frs, frs_back);

            // get our bytes back
            let bytes_back: Vec<u8> = frs_back.iter().fold(Vec::new(), |mut acc, fr| {
                fr.into_repr().write_le(&mut acc).unwrap();
                acc
            });

            assert_eq!(bytes, bytes_back);
        }
    }
}
