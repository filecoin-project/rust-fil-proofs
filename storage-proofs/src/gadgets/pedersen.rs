use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::{circuit::pedersen_hash, jubjub::JubjubEngine};

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
        "must be at least 2 block sizes long ({})",
        data.len()
    );

    assert_eq!(
        data.len() % PEDERSEN_BLOCK_SIZE,
        0,
        "data must be a multiple of the block size ({})",
        data.len()
    );

    let mut chunks = data.chunks(PEDERSEN_BLOCK_SIZE);
    let mut cur: Vec<Boolean> = chunks.next().unwrap().to_vec();
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
        pedersen_hash::Personalization::None,
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
    let mut out = h.to_bits_le(cs.namespace(|| "h into bits"))?;

    // needs padding, because x does not always translate to exactly 256 bits
    while out.len() < PEDERSEN_BLOCK_SIZE {
        out.push(Boolean::Constant(false));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::gadgets::TestConstraintSystem;
    use crate::util::bytes_into_boolean_vec;
    use bellperson::gadgets::boolean::Boolean;
    use bellperson::ConstraintSystem;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_pedersen_single_input_circut() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        let cases = [(32, 689), (64, 1376)];

        for (bytes, constraints) in &cases {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

            let data_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "data");
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
            };
            let out = pedersen_compression_num(&mut cs, &JJ_PARAMS, &data_bits)
                .expect("pedersen hashing failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(
                cs.num_constraints(),
                *constraints,
                "constraint size changed for {} bytes",
                *bytes
            );

            let expected = crypto::pedersen::pedersen(data.as_slice());

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }

    #[test]
    fn test_pedersen_md_input_circut() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        let cases = [
            (64, 1376),   // 64 bytes
            (96, 2751),   // 96 bytes
            (128, 4126),  // 128 bytes
            (160, 5501),  // 160 bytes
            (256, 9626),  // 160 bytes
            (512, 20626), // 512 bytes
        ];

        for (bytes, constraints) in &cases {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

            let data_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "data");
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
            };
            let out = pedersen_md_no_padding(cs.namespace(|| "pedersen"), &JJ_PARAMS, &data_bits)
                .expect("pedersen hashing failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(
                cs.num_constraints(),
                *constraints,
                "constraint size changed {}",
                bytes
            );

            let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match {} bytes",
                bytes
            );
        }
    }
}
