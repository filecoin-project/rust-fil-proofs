use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::blake2s::blake2s;
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::jubjub::JubjubEngine;

const EMPTY_PERSONA: [u8; 8] = [0u8; 8];

pub fn kdf<E, CS>(
    cs: &mut CS,
    id: Vec<Boolean>,
    parents: Vec<Vec<Boolean>>,
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...
    let ciphertexts = parents.into_iter().fold(id, |mut acc, parent| {
        acc.extend(parent);
        acc
    });

    {
        let cs = cs.namespace(|| "blake2s");
        blake2s(cs, ciphertexts.as_slice(), &EMPTY_PERSONA)
    }
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use bellman::ConstraintSystem;
    use blake2_rfc::blake2s::Blake2s;
    use circuit::test::TestConstraintSystem;
    use crypto;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::blake2s;
    use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
    use util::{bits_into_bytes, bytes_into_boolean_vec};

    #[test]
    fn test_kdf_input_circut() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let id: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let parents: Vec<Vec<u8>> = (0..20)
            .map(|_| (0..32).map(|_| rng.gen()).collect())
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                bytes_into_boolean_vec(&mut cs, Some(p.as_slice()), p.len()).unwrap()
            })
            .collect();
        let out = kdf(&mut cs, id_bits.clone(), parents_bits.clone()).unwrap();

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(out.len(), 32 * 8, "invalid output length");

        let input_bytes = parents.iter().fold(id, |mut acc, parent| {
            acc.extend(parent);
            acc
        });
        let input_len = input_bytes.len();

        // convert Vec<Boolean> to Vec<u8>
        let actual = bits_into_bytes(
            out.iter()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>()
                .as_slice(),
        );

        let expected = crypto::kdf::kdf(input_bytes.as_slice());

        let mut h = Blake2s::with_params(32, &[], &[], &[0u8; 8]);
        h.update(input_bytes.as_slice());
        let h_result = h.finalize();

        assert_eq!(
            h_result.as_bytes().to_vec(),
            expected,
            "non circuit and Blake2s do not match"
        );
        assert_eq!(expected, actual, "circuit and non circuit do not match");
    }
}
