use bellperson::{ConstraintSystem, SynthesisError};
use ff::PrimeField;
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::circuit::sha256::sha256 as sha256_circuit;
use fil_sapling_crypto::circuit::{multipack, num};
use fil_sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::uint64;

/// Key derivation function.
pub fn kdf<E, CS>(
    mut cs: CS,
    id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    node: Option<uint64::UInt64>,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // ciphertexts will become a buffer of the layout
    // id | node | encodedParentNode1 | encodedParentNode1 | ...

    let mut ciphertexts = id.to_vec();

    if let Some(node) = node {
        ciphertexts.extend_from_slice(&node.to_bits_le());
    }

    for parent in parents.into_iter() {
        ciphertexts.extend_from_slice(&parent);
    }

    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;
    let be_bits = alloc_bits
        .iter()
        .map(|v| v.get_value())
        .map(|v| v.ok_or_else(|| SynthesisError::AssignmentMissing))
        .collect::<Result<Vec<bool>, _>>()?;

    let le_bits = be_bits
        .chunks(8)
        .flat_map(|chunk| chunk.into_iter().rev())
        .copied()
        .take(E::Fr::CAPACITY as usize)
        .collect::<Vec<bool>>();

    let fr = multipack::compute_multipacking::<E>(&le_bits)[0];

    num::AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || Ok(fr))
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec_be;
    use bellperson::ConstraintSystem;
    use fil_sapling_crypto::circuit::boolean::Boolean;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn kdf_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let m = 20;

        let id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let parents: Vec<Vec<u8>> = (0..m).map(|_| fr_into_bytes::<Bls12>(&rng.gen())).collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec_be(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                bytes_into_boolean_vec_be(&mut cs, Some(p.as_slice()), p.len()).unwrap()
            })
            .collect();
        let out = kdf(cs.namespace(|| "kdf"), &id_bits, parents_bits.clone(), None)
            .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 292540);

        let input_bytes = parents.iter().fold(id, |mut acc, parent| {
            acc.extend(parent);
            acc
        });

        let expected = crypto::kdf::kdf(input_bytes.as_slice(), m);

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
