use bellperson::ConstraintSystem;
use fil_proofs_tooling::metadata::Metadata;
use fil_sapling_crypto::circuit as scircuit;
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::jubjub::JubjubBls12;
use paired::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use storage_proofs::circuit::pedersen::{pedersen_compression_num, pedersen_md_no_padding};
use storage_proofs::circuit::test::TestConstraintSystem;
use storage_proofs::crypto;
use storage_proofs::util::{bits_to_bytes, bytes_into_boolean_vec};

fn blake2s_count(bytes: usize) -> Result<Report, failure::Error> {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.namespace(|| "data");
        bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
    };

    let personalization = vec![0u8; 8];
    let out: Vec<bool> = scircuit::blake2s::blake2s(&mut cs, &data_bits, &personalization)?
        .into_iter()
        .map(|b| b.get_value().unwrap())
        .collect();

    assert!(cs.is_satisfied(), "constraints not satisfied");

    let expected = blake2s_simd::blake2s(&data);
    assert_eq!(
        expected.as_ref(),
        &bits_to_bytes(&out[..])[..],
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

    let params = &JubjubBls12::new();

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.namespace(|| "data");
        bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len()).unwrap()
    };

    if bytes < 128 {
        let out = pedersen_compression_num(&mut cs, params, &data_bits)?;
        assert!(cs.is_satisfied(), "constraints not satisfied");

        let expected = crypto::pedersen::pedersen(data.as_slice());
        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    } else {
        let out = pedersen_md_no_padding(cs.namespace(|| "pedersen"), params, &data_bits)
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
