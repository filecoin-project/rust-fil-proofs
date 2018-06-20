use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::jubjub::JubjubEngine;

use circuit::pedersen::pedersen_md_no_padding;

/// Key derivation function, using pedersen hashes as the underlying primitive.
pub fn kdf<E, CS>(
    mut cs: CS,
    params: &E::Params,
    id: Vec<Boolean>,
    parents: Vec<Vec<Boolean>>,
    m: usize,
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

    assert_eq!(ciphertexts.len(), 8 * 32 * (1 + m), "invalid input length");

    pedersen_md_no_padding(cs.namespace(|| "pedersen"), params, ciphertexts.as_slice())
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use bellman::ConstraintSystem;
    use circuit::test::TestConstraintSystem;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::boolean::Boolean;
    use sapling_crypto::jubjub::JubjubBls12;

    use crypto;
    use util::{bits_to_bytes, bytes_into_boolean_vec};

    #[test]
    fn kdf_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubBls12::new();

        let m = 20;
        let id: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let parents: Vec<Vec<u8>> = (0..m)
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
        let out = kdf(
            cs.namespace(|| "kdf"),
            &params,
            id_bits.clone(),
            parents_bits.clone(),
            m,
        ).unwrap();

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 27917);
        assert_eq!(out.len(), 32 * 8, "invalid output length");

        let input_bytes = parents.iter().fold(id, |mut acc, parent| {
            acc.extend(parent);
            acc
        });

        // convert Vec<Boolean> to Vec<u8>
        let actual = bits_to_bytes(
            out.iter()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>()
                .as_slice(),
        );

        let expected = crypto::kdf::kdf(input_bytes.as_slice(), m);
        assert_eq!(expected, actual, "circuit and non circuit do not match");
    }
}
