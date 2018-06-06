use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::blake2s::blake2s;
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::jubjub::JubjubEngine;

pub fn kdf<E, CS>(
    cs: &mut CS,
    id: Vec<Boolean>,
    parents: Vec<Vec<Boolean>>,
    persona: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...
    let mut list = vec![id];
    list.extend(parents);

    // TODO: can we avoid cloning?
    let ciphertexts: Vec<Boolean> = list.iter().flat_map(|l| (*l).clone()).collect();

    {
        let cs = cs.namespace(|| "blake2s");
        blake2s(cs, ciphertexts.as_slice(), persona)
    }
}

#[cfg(test)]
mod test {
    use super::kdf;
    use bellman::ConstraintSystem;
    use blake2_rfc::blake2s::Blake2s;
    use circuit::test::TestConstraintSystem;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
    use sapling_crypto::jubjub::JubjubEngine;

    #[test]
    fn test_kdf() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let persona = b"12345678";
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let id: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let parents: Vec<Vec<u8>> = (0..20)
            .map(|_| (0..32).map(|_| rng.gen()).collect())
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            alloc_bits(&mut cs, id.clone())
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                alloc_bits(&mut cs, (*p).clone())
            })
            .collect();
        let out = kdf(&mut cs, id_bits.clone(), parents_bits.clone(), persona).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(out.len(), 32 * 8);

        let mut input_bytes: Vec<u8> = Vec::new();
        input_bytes.extend(id);
        for p in parents.iter() {
            input_bytes.extend(p.clone())
        }

        let mut h = Blake2s::with_params(32, &[], &[], persona);
        h.update(input_bytes.as_slice());
        let h_result = h.finalize();

        // convert hash to bits
        let expected = h_result
            .as_ref()
            .iter()
            .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
            .collect::<Vec<bool>>();

        // pull bits from returned result
        let actual = out.iter()
            .map(|v| v.get_value().unwrap())
            .collect::<Vec<bool>>();

        assert_eq!(expected, actual);
    }

    fn alloc_bits<E, CS>(cs: &mut CS, data: Vec<u8>) -> Vec<Boolean>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let mut input_bits = vec![];

        for (byte_i, input_byte) in data.into_iter().enumerate() {
            for bit_i in 0..8 {
                let cs = cs.namespace(|| format!("input bit {} {}", byte_i, bit_i));

                input_bits.push(
                    AllocatedBit::alloc(cs, Some((input_byte >> bit_i) & 1u8 == 1u8))
                        .unwrap()
                        .into(),
                );
            }
        }

        input_bits
    }
}
