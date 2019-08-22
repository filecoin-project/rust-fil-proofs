use algebra::curves::bls12_377::Bls12_377 as Bls12;
use dpc::gadgets::prf::blake2s::blake2s_gadget;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::bits::uint32::UInt32;
use snark_gadgets::boolean::Boolean;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::utils::AllocGadget;

use crate::circuit::multipack;

/// Key derivation function, using pedersen hashes as the underlying primitive.
pub fn kdf<CS>(
    mut cs: CS,
    id: Vec<Boolean>,
    parents: Vec<Vec<Boolean>>,
    m: usize,
) -> Result<FpGadget<Bls12>, SynthesisError>
where
    CS: ConstraintSystem<Bls12>,
{
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...
    let ciphertexts = parents.into_iter().fold(id, |mut acc, parent| {
        acc.extend(parent);
        acc
    });

    assert_eq!(ciphertexts.len(), 8 * 32 * (1 + m), "invalid input length");

    let alloc_uint32 = blake2s_gadget(cs.ns(|| "hash"), &ciphertexts[..])?;

    let fr = match alloc_uint32[0].get_value() {
        Some(_) => {
            let bits = alloc_uint32
                .iter()
                .map(UInt32::to_bits_le)
                .flatten()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>();
            // TODO: figure out if we can avoid this
            let frs = multipack::compute_multipacking::<Bls12>(&bits);
            Ok(frs[0])
        }
        None => Err(SynthesisError::AssignmentMissing),
    };

    FpGadget::alloc(cs.ns(|| "num"), || fr)
}

#[cfg(test)]
mod tests {
    use super::kdf;

    use algebra::curves::bls12_377::Bls12_377 as Bls12;
    use snark::ConstraintSystem;
    use snark_gadgets::boolean::Boolean;
    use snark_gadgets::fields::FieldGadget;

    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn kdf_circuit() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let m = 20;

        let id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let parents: Vec<Vec<u8>> = (0..m).map(|_| fr_into_bytes::<Bls12>(&rng.gen())).collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.ns(|| "id");
            bytes_into_boolean_vec(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.ns(|| format!("parents {}", i));
                bytes_into_boolean_vec(&mut cs, Some(p.as_slice()), p.len()).unwrap()
            })
            .collect();
        let out = kdf(cs.ns(|| "kdf"), id_bits.clone(), parents_bits.clone(), m)
            .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 243296);

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
