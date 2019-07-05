use rand::thread_rng;

use algebra::curves::bls12_381::Bls12_381;
use algebra::curves::{jubjub::JubJubProjective as JubJub, ProjectiveCurve};
use dpc::{
    crypto_primitives::crh::{
        pedersen::PedersenCRH,
        FixedLengthCRH,
    },
    gadgets::crh::{pedersen::PedersenCRHGadget, pedersen::PedersenCRHGadgetParameters, FixedLengthCRHGadget},
};
use algebra::PairingEngine as Engine;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::bits::boolean::Boolean;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::groups::curves::twisted_edwards::jubjub::JubJubGadget;
use snark_gadgets::utils::ToBitsGadget;

use crate::crypto::pedersen::PEDERSEN_BLOCK_SIZE;
use crate::util::bits_to_bytes;
use crate::hasher::Window;

/// Pedersen hashing for inputs with length multiple of the block size. Based on a Merkle-Damgard construction.
pub fn pedersen_md_no_padding<E, CS>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<FpGadget<E>, SynthesisError>
where
    E: Engine,
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
        let mut cs = cs.ns(|| format!("block {}", i));
        for b in block {
            // TODO: no cloning
            cur.push(b.clone());
        }
        if i == chunks_len - 1 {
            // last round, skip
        } else {
            cur = pedersen_compression(cs.ns(|| "hash"), &cur)?;
        }
    }

    // hash and return a num at the end
    pedersen_compression_num(cs.ns(|| "last hash"), &cur)
}

pub fn pedersen_compression_num<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<FpGadget<E>, SynthesisError> {
    // TODO: Add personalization
    // TODO: Used fixed seed for RNG

    let rng = &mut thread_rng();
    type CRHGadget = PedersenCRHGadget<JubJub, Bls12_381, JubJubGadget>;
    type CRH = PedersenCRH<JubJub, Window>;

    let parameters = CRH::setup(rng).unwrap();


    let gadget_parameters =
        <CRHGadget as FixedLengthCRHGadget<CRH, Bls12_381>>::ParametersGadget::alloc(
            &mut cs.ns(|| "gadget_parameters"),
            || Ok(&parameters),
        )
            .unwrap();

    let input_bytes =
        UInt8::alloc_input_vec(&mut cs, UInt8::from_bits_le(bits).unwrap()).unwrap();

    let gadget_result =
        <CRHGadget as FixedLengthCRHGadget<CRH, Bls12_381>>::check_evaluation_gadget(
            &mut cs.ns(|| "gadget_evaluation"),
            &gadget_parameters,
            &input_bytes,
        )
            .unwrap();

    Ok(gadget_result.x)
}

pub fn pedersen_compression<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    let h = pedersen_compression_num(cs.ns(|| "compression"), bits)?;
//    let mut out = h.into_bits_le(cs.ns(|| "h into bits"))?;
    let mut out = h.to_bits(cs.ns(|| "h into bits"))?;

    // needs padding, because x does not always translate to exactly 256 bits
    while out.len() < PEDERSEN_BLOCK_SIZE {
        out.push(Boolean::Constant(false));
    }

    Ok(out)
}

//#[cfg(test)]
//mod tests {
//    use super::pedersen_md_no_padding;
//    use crate::circuit::test::TestConstraintSystem;
//    use crate::crypto;
//    use crate::util::bytes_into_boolean_vec;
//    use bellperson::ConstraintSystem;
//    use fil_sapling_crypto::circuit::boolean::Boolean;
//    use fil_sapling_crypto::jubjub::JubjubBls12;
//    use paired::bls12_381::Bls12;
//    use rand::{Rng, SeedableRng, XorShiftRng};
//
//    #[test]
//    fn test_pedersen_input_circut() {
//        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
//
//        for i in 2..6 {
//            let mut cs = TestConstraintSystem::<Bls12>::new();
//            let data: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
//            let params = &JubjubBls12::new();
//
//            let data_bits: Vec<Boolean> = {
//                let mut cs = cs.ns(|| "data");
//                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
//            };
//            let out = pedersen_md_no_padding(cs.ns(|| "pedersen"), data_bits.as_slice())
//                .expect("pedersen hashing failed");
//
//            assert!(cs.is_satisfied(), "constraints not satisfied");
//
//            let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());
//
//            assert_eq!(
//                expected,
//                out.get_value().unwrap(),
//                "circuit and non circuit do not match"
//            );
//        }
//    }
//}
