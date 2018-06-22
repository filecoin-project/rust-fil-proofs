use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::circuit::num;
use sapling_crypto::jubjub::JubjubEngine;

use circuit::pedersen::pedersen_md_no_padding;

/// Key derivation function, using pedersen hashes as the underlying primitive.
pub fn kdf<E, CS>(
    mut cs: CS,
    params: &E::Params,
    id: Vec<Boolean>,
    parents: Vec<Vec<Boolean>>,
    m: usize,
) -> Result<num::AllocatedNum<E>, SynthesisError>
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
    use crypto;
    use fr32::fr_into_bytes;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::boolean::Boolean;
    use sapling_crypto::jubjub::JubjubBls12;
    use util::bytes_into_boolean_vec;

    #[test]
    fn kdf_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = &JubjubBls12::new();

        let m = 20;

        let id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let parents: Vec<Vec<u8>> = (0..m).map(|_| fr_into_bytes::<Bls12>(&rng.gen())).collect();

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
        assert_eq!(cs.num_constraints(), 27661);

        let input_bytes = parents.iter().fold(id, |mut acc, parent| {
            acc.extend(parent);
            acc
        });

        let expected = crypto::kdf::kdf::<Bls12>(input_bytes.as_slice(), m);

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
