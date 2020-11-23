use bellperson::gadgets::boolean::Boolean;
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};

pub fn xor<E, CS>(
    cs: &mut CS,
    key: &[Boolean],
    input: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let key_len = key.len();
    assert_eq!(key_len, 32 * 8);

    input
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            Boolean::xor(
                cs.namespace(|| format!("xor bit: {}", i)),
                byte,
                &key[i % key_len],
            )
        })
        .collect::<Result<Vec<_>, SynthesisError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto;
    use crate::util::{bits_to_bytes, bytes_into_boolean_vec};
    use bellperson::gadgets::boolean::Boolean;
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use bellperson::{bls::Bls12, ConstraintSystem};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_xor_input_circut() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        for i in 0..10 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let data: Vec<u8> = (0..(i + 1) * 32).map(|_| rng.gen()).collect();

            let key_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "key");
                bytes_into_boolean_vec(&mut cs, Some(key.as_slice()), key.len()).unwrap()
            };

            let data_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "data bits");
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
            };

            let out_bits =
                xor(&mut cs, key_bits.as_slice(), data_bits.as_slice()).expect("xor failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(out_bits.len(), data_bits.len(), "invalid output length");

            // convert Vec<Boolean> to Vec<u8>
            let actual = bits_to_bytes(
                out_bits
                    .iter()
                    .map(|v| v.get_value().unwrap())
                    .collect::<Vec<bool>>()
                    .as_slice(),
            );

            let expected = crypto::xor::encode(key.as_slice(), data.as_slice()).unwrap();

            assert_eq!(expected, actual, "circuit and non circuit do not match");

            // -- roundtrip
            let roundtrip_bits = {
                let mut cs = cs.namespace(|| "roundtrip");
                xor(&mut cs, key_bits.as_slice(), out_bits.as_slice()).expect("xor faield")
            };

            let roundtrip = bits_to_bytes(
                roundtrip_bits
                    .iter()
                    .map(|v| v.get_value().unwrap())
                    .collect::<Vec<bool>>()
                    .as_slice(),
            );

            assert_eq!(data, roundtrip, "failed to roundtrip");
        }
    }
}
