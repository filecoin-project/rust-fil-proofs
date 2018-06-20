use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::circuit::pedersen_hash;
use sapling_crypto::jubjub::JubjubEngine;

use crypto::pedersen::PEDERSEN_BLOCK_SIZE;

/// Pedersen hashing for inputs with lenght multiple of the block size. Based on a Merkle-Damgarad construction.
pub fn pedersen_md_no_padding<E, CS>(
    mut cs: CS,
    params: &E::Params,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    assert!(
        data.len() >= 2 * PEDERSEN_BLOCK_SIZE,
        "must be at least 2 block sizes long"
    );

    assert_eq!(
        data.len() % PEDERSEN_BLOCK_SIZE,
        0,
        "data must be a multiple of the block size"
    );

    let mut chunks = data.chunks(PEDERSEN_BLOCK_SIZE);
    let mut cur: Vec<Boolean> = chunks.nth(0).unwrap().to_vec();

    for (i, block) in chunks.enumerate() {
        let mut cs = cs.namespace(|| format!("block {}", i));
        for b in block {
            // TODO: no cloning
            cur.push(b.clone());
        }
        cur = pedersen_compression(cs.namespace(|| "initial hash"), params, &cur)?;
    }

    Ok(cur)
}

pub fn pedersen_compression<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    params: &E::Params,
    bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let h = pedersen_hash::pedersen_hash(
        cs.namespace(|| "inner hash"),
        pedersen_hash::Personalization::NoteCommitment,
        &bits,
        params,
    )?.get_x()
        .clone();
    let mut out = h.into_bits_le(cs.namespace(|| "h into bits"))?;

    // needs padding, because x does not always translate to exactly 256 bits
    while out.len() < PEDERSEN_BLOCK_SIZE {
        out.push(Boolean::Constant(false));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::pedersen_md_no_padding;
    use bellman::ConstraintSystem;
    use circuit::test::TestConstraintSystem;
    use crypto;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::boolean::Boolean;
    use sapling_crypto::jubjub::JubjubBls12;
    use util::{bits_to_bytes, bytes_into_boolean_vec};

    #[test]
    fn test_pedersen_input_circut() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..6 {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let params = &JubjubBls12::new();

            let data_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "data");
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
            };
            let out =
                pedersen_md_no_padding(cs.namespace(|| "pedersen"), params, &data_bits).unwrap();

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(out.len(), 32 * 8, "invalid output length");

            let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());
            let actual = bits_to_bytes(
                &out.iter()
                    .map(|b| b.get_value().unwrap())
                    .collect::<Vec<_>>(),
            );

            assert_eq!(expected, actual, "circuit and non circuit do not match");
        }
    }
}
