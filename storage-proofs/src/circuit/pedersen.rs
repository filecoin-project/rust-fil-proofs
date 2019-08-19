use algebra::curves::bls12_381::Bls12_381 as Bls12;
use algebra::curves::jubjub::JubJubProjective as JubJub;
use algebra::curves::ProjectiveCurve;
use algebra::fields::PrimeField;

use dpc::{
    crypto_primitives::crh::{pedersen::PedersenCRH, pedersen::PedersenParameters},
    gadgets::crh::{pedersen::PedersenCRHGadget, FixedLengthCRHGadget},
};
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::groups::curves::twisted_edwards::jubjub::JubJubGadget;
use snark_gadgets::utils::{AllocGadget, ToBytesGadget};

use crate::crypto::pedersen::{BigWindow, PEDERSEN_BLOCK_SIZE};

type CRHGadget = PedersenCRHGadget<JubJub, Bls12, JubJubGadget>;
type CRH = PedersenCRH<JubJub, BigWindow>;

/// Pedersen hashing for inputs with length multiple of the block size. Based on a Merkle-Damgard construction.
pub fn pedersen_md_no_padding<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bytes: &[UInt8],
    params: &PedersenParameters<JubJub>,
) -> Result<FpGadget<Bls12>, SynthesisError> {
    assert!(
        (bytes.len() * 8) >= 2 * PEDERSEN_BLOCK_SIZE,
        "must be at least 2 block sizes long"
    );

    assert_eq!(
        (bytes.len() * 8) % PEDERSEN_BLOCK_SIZE,
        0,
        "must be a multiple of the block size"
    );

    let mut chunks = bytes.chunks(PEDERSEN_BLOCK_SIZE / 8);
    let mut cur: Vec<UInt8> = chunks.nth(0).unwrap().to_vec();
    let chunks_len = chunks.len();

    for (i, block) in chunks.enumerate() {
        let mut cs = cs.ns(|| format!("block {}", i));
        for b in block {
            // TODO: no cloning
            cur.push(b.clone());
        }
        if i == chunks_len - 1 {
            // last round, skip
        } else {
            cur = pedersen_compression(cs.ns(|| "hash"), &cur, params)?;
        }
    }

    // hash and return a num at the end
    pedersen_compression_num(cs.ns(|| "last hash"), &cur, params)
}

pub fn pedersen_compression_num<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bytes: &[UInt8],
    params: &PedersenParameters<JubJub>,
) -> Result<FpGadget<Bls12>, SynthesisError> {
    let gadget_parameters =
        <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::ParametersGadget::alloc(
            &mut cs.ns(|| "gadget_parameters"),
            || Ok(params),
        )
        .unwrap();

    let gadget_result = <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::check_evaluation_gadget(
        &mut cs.ns(|| "gadget_evaluation"),
        &gadget_parameters,
        &bytes,
    )
    .unwrap();

    Ok(gadget_result.x)
}

pub fn pedersen_compression<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bytes: &[UInt8],
    params: &PedersenParameters<JubJub>,
) -> Result<Vec<UInt8>, SynthesisError> {
    let h = pedersen_compression_num(cs.ns(|| "compression"), bytes, params)?;
    let mut out = h.to_bytes(cs.ns(|| "h into bits"))?;

    // to_bits convert the value to a big-endian number, we need it to be little-endian
    out.reverse();

    Ok(out)
}

#[cfg(test)]
mod tests {

    use super::*;

    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::singletons::PEDERSEN_PARAMS;

    #[test]
    fn test_pedersen_input_circuit() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..6 {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();

            let data_bytes: Vec<UInt8> = {
                let mut cs = cs.ns(|| "data");
                data.iter()
                    .enumerate()
                    .map(|(byte_i, input_byte)| {
                        let cs = cs.ns(|| format!("input_byte_{}", byte_i));
                        UInt8::alloc(cs, || Ok(*input_byte)).unwrap()
                    })
                    .collect()
            };
            let out =
                pedersen_md_no_padding(cs.ns(|| "pedersen"), &data_bytes[..], &PEDERSEN_PARAMS)
                    .expect("pedersen hashing failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");

            let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());
            assert_eq!(
                expected,
                out.value.unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }

    #[test]
    fn test_pedersen_md_input_circuit() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let cases = [
            (64, 8576),  // 64 bytes
            (128, 9088), // 128 bytes
        ];

        for (bytes, constraints) in &cases {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

            let data_bytes: Vec<UInt8> = {
                let mut cs = cs.ns(|| "data");
                data.iter()
                    .enumerate()
                    .map(|(byte_i, input_byte)| {
                        let cs = cs.ns(|| format!("input_byte_{}", byte_i));
                        UInt8::alloc(cs, || Ok(*input_byte)).unwrap()
                    })
                    .collect()
            };
            let out = pedersen_compression_num(
                cs.ns(|| "pedersen"),
                data_bytes.as_slice(),
                &PEDERSEN_PARAMS,
            )
            .expect("pedersen hashing failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(
                cs.num_constraints(),
                *constraints,
                "constraint size changed {}",
                bytes
            );

            let expected = crypto::pedersen::pedersen(data.as_slice()).into_affine().x;
            assert_eq!(
                expected,
                out.value.unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }
}
