use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::blake2s::blake2s as blake2s_circuit;
use fil_sapling_crypto::circuit::boolean::Boolean;
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
        ciphertexts.extend(node.to_bits_le());
    }

    for parent in parents.into_iter() {
        ciphertexts.extend(parent);
    }

    let personalization = vec![0u8; 8];
    let alloc_bits = blake2s_circuit(cs.namespace(|| "hash"), &ciphertexts[..], &personalization)?;
    let fr = match alloc_bits[0].get_value() {
        Some(_) => {
            let bits = alloc_bits
                .iter()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>();
            // TODO: figure out if we can avoid this
            let frs = multipack::compute_multipacking::<E>(&bits);
            Ok(frs[0])
        }
        None => Err(SynthesisError::AssignmentMissing),
    };

    num::AllocatedNum::<E>::alloc(cs.namespace(|| "num"), || fr)
}

#[cfg(test)]
mod tests {
    use super::kdf;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec;
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
        let out = kdf(cs.namespace(|| "kdf"), &id_bits, parents_bits.clone(), None)
            .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 240282);

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
