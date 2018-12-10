use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::boolean::Boolean;
use sapling_crypto::circuit::{num, pedersen_hash};
use sapling_crypto::jubjub::JubjubEngine;

use crate::crypto::pedersen::PEDERSEN_BLOCK_SIZE;

/// Pedersen hashing for inputs with length multiple of the block size. Based on a Merkle-Damgard construction.
pub fn pedersen_md_no_padding<E, CS>(
    mut cs: CS,
    params: &E::Params,
    data: &[Boolean],
) -> Result<num::AllocatedNum<E>, SynthesisError>
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
    let chunks_len = chunks.len();

    for (i, block) in chunks.enumerate() {
        let mut cs = cs.namespace(|| format!("block {}", i));
        for b in block {
            // TODO: no cloning
            cur.push(b.clone());
        }
        if i == chunks_len - 1 {
            // last round, skip
        } else {
            cur = pedersen_compression(cs.namespace(|| "hash"), params, &cur)?;
        }
    }

    // hash and return a num at the end
    pedersen_compression_num(cs.namespace(|| "last hash"), params, &cur)
}

pub fn pedersen_compression_num<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    params: &E::Params,
    bits: &[Boolean],
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    Ok(pedersen_hash::pedersen_hash(
        cs.namespace(|| "inner hash"),
        pedersen_hash::Personalization::NoteCommitment,
        &bits,
        params,
    )?
    .get_x()
    .clone())
}

pub fn pedersen_compression<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    params: &E::Params,
    bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let h = pedersen_compression_num(cs.namespace(|| "compression"), params, bits)?;
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
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::util::bytes_into_boolean_vec;
    use bellman::ConstraintSystem;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::boolean::Boolean;
    use sapling_crypto::jubjub::JubjubBls12;

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

            let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }
}
