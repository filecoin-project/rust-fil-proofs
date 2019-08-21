use algebra::curves::bls12_381::Bls12_381 as Bls12;
use algebra::curves::ProjectiveCurve;
use dpc::gadgets::prf::blake2s::blake2s_gadget;
use fil_proofs_tooling::metadata::Metadata;
use rand::{Rng, SeedableRng, XorShiftRng};
use snark::ConstraintSystem;
use snark_gadgets::bits::boolean::Boolean;
use snark_gadgets::bits::uint32::UInt32;
use snark_gadgets::fields::FieldGadget;
use snark_gadgets::uint8::UInt8;
use snark_gadgets::utils::AllocGadget;
use storage_proofs::circuit::pedersen::{pedersen_compression_num, pedersen_md_no_padding};
use storage_proofs::circuit::test::TestConstraintSystem;
use storage_proofs::crypto;
use storage_proofs::singletons::PEDERSEN_PARAMS;
use storage_proofs::util::{bits_to_bytes, bytes_into_boolean_vec};

fn blake2s_count(bytes: usize) -> Result<Report, failure::Error> {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.ns(|| "data");
        bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
    };

    let out = blake2s_gadget(&mut cs, &data_bits)?;
    let bits = out
        .iter()
        .map(UInt32::to_bits_le)
        .flatten()
        .map(|v| v.get_value().unwrap())
        .collect::<Vec<bool>>();

    assert!(cs.is_satisfied(), "constraints not satisfied");

    let expected = blake2s_simd::blake2s(&data);
    assert_eq!(
        expected.as_ref(),
        &bits_to_bytes(&bits[..])[..],
        "circuit and non circuit do not match"
    );

    Ok(Report {
        hash_fn: "blake2s".into(),
        bytes,
        constraints: cs.num_constraints(),
    })
}

fn pedersen_count(bytes: usize) -> Result<Report, failure::Error> {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

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
    if bytes < 128 {
        let out = pedersen_compression_num(&mut cs, &data_bytes, &PEDERSEN_PARAMS)?;
        assert!(cs.is_satisfied(), "constraints not satisfied");

        let point = crypto::pedersen::pedersen(data.as_slice());
        let expected = point.into_affine().x;

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    } else {
        let out = pedersen_md_no_padding(cs.ns(|| "pedersen"), &data_bytes, &PEDERSEN_PARAMS)
            .expect("pedersen hashing failed");
        assert!(cs.is_satisfied(), "constraints not satisfied");
        let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());
        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }

    Ok(Report {
        hash_fn: "pedersen".into(),
        bytes,
        constraints: cs.num_constraints(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Report {
    hash_fn: String,
    constraints: usize,
    bytes: usize,
}

pub fn run() -> Result<(), failure::Error> {
    let reports = vec![
        blake2s_count(32)?,
        blake2s_count(64)?,
        blake2s_count(128)?,
        blake2s_count(256)?,
        pedersen_count(32)?,
        pedersen_count(64)?,
        pedersen_count(128)?,
        pedersen_count(256)?,
    ];

    // print reports
    let wrapped = Metadata::wrap(reports)?;
    serde_json::to_writer(std::io::stdout(), &wrapped)?;

    Ok(())
}
