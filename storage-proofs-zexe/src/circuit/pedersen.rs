use snark_gadgets::fields::FieldGadget;

use bitvec::prelude::*;
use algebra::curves::bls12_381::Bls12_381 as Bls12;
use algebra::curves::jubjub::JubJubProjective as JubJub;

use dpc::{
    crypto_primitives::crh::{pedersen::PedersenCRH, pedersen::PedersenParameters, FixedLengthCRH},
    gadgets::crh::{
        pedersen::PedersenCRHGadget, pedersen::PedersenCRHGadgetParameters, FixedLengthCRHGadget,
    },
};
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::bits::boolean::Boolean;
use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::groups::curves::twisted_edwards::jubjub::JubJubGadget;
use snark_gadgets::utils::{AllocGadget, ToBitsGadget};

use crate::crypto::pedersen::{BigWindow, PEDERSEN_BLOCK_SIZE};
use crate::crypto::pedersen::Personalization;
use crate::util::bits_to_bytes;


type CRHGadget = PedersenCRHGadget<JubJub, Bls12, JubJubGadget>;
type CRH = PedersenCRH<JubJub, BigWindow>;

/// Pedersen hashing for inputs with length multiple of the block size. Based on a Merkle-Damgard construction.
pub fn pedersen_md_no_padding<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bits: &[Boolean],
    params: &PedersenParameters<JubJub>,
) -> Result<FpGadget<Bls12>, SynthesisError> {
    assert!(
        bits.len() >= 2 * PEDERSEN_BLOCK_SIZE,
        "must be at least 2 block sizes long"
    );

    assert_eq!(
        bits.len() % PEDERSEN_BLOCK_SIZE,
        0,
        "must be a multiple of the block size"
    );

    let mut chunks = bits.chunks(PEDERSEN_BLOCK_SIZE);
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
            cur = pedersen_compression(cs.ns(|| "hash"), &cur, params)?;
        }
    }

    // hash and return a num at the end
    pedersen_compression_num(cs.ns(|| "last hash"), &cur, params)
}

pub fn pedersen_compression_num<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bits: &[Boolean],
    params: &PedersenParameters<JubJub>,
) -> Result<FpGadget<Bls12>, SynthesisError> {

    let gadget_parameters =
        <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::ParametersGadget::alloc(
            &mut cs.ns(|| "gadget_parameters"),
            || Ok(params),
        )
        .unwrap();

    let mut personalization = Personalization::NoteCommitment
        .get_bits()
        .into_iter()
        .map(|v| Boolean::Constant(v))
        .collect::<Vec<Boolean>>();

    let mut bits_with_personalization = personalization
        .into_iter()
        .chain(bits.to_vec().into_iter())
        .collect::<Vec<_>>();

    while bits_with_personalization.len() % 8 != 0 {
        bits_with_personalization.push(Boolean::Constant(false));
    }

    let input_bytes = bits_with_personalization
        .chunks(8)
        .into_iter()
        .map(|v| UInt8::from_bits_le(v))
        .collect::<Vec<UInt8>>();

    let gadget_result = <CRHGadget as FixedLengthCRHGadget<CRH, Bls12>>::check_evaluation_gadget(
        &mut cs.ns(|| "gadget_evaluation"),
        &gadget_parameters,
        &input_bytes,
    )
    .unwrap();

    Ok(gadget_result.x)
}

pub fn pedersen_compression<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    bits: &[Boolean],
    params: &PedersenParameters<JubJub>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let h = pedersen_compression_num(cs.ns(|| "compression"), bits, params)?;
    let mut out = h.to_bits(cs.ns(|| "h into bits"))?;

    // to_bits convert the value to a big-endian number, we need it to be little-endian
    out.reverse();

    // Needs padding, because x does not always translate to exactly 256 bits
    while out.len() < PEDERSEN_BLOCK_SIZE {
        out.push(Boolean::Constant(false));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {

    use super::*;

    use algebra::curves::ProjectiveCurve;
    use bitvec::prelude::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::util::bytes_into_boolean_vec;
    use crate::singletons::PEDERSEN_PARAMS;

    #[test]
    fn test_pedersen_input_circuit() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..6 {
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let data: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();

            let data_bits: Vec<Boolean> = {
                let mut cs = cs.ns(|| "data");
                bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
            };

            let out =
                pedersen_md_no_padding(cs.ns(|| "pedersen"),
                                         data_bits.as_slice(),
                                         &PEDERSEN_PARAMS)
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
}
