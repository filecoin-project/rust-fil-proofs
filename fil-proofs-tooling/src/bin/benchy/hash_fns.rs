use bellperson::gadgets::boolean::Boolean;
use bellperson::util_cs::test_cs::TestConstraintSystem;
use bellperson::ConstraintSystem;
use fil_proofs_tooling::metadata::Metadata;
use paired::bls12_381::Bls12;
use rand::RngCore;
use serde::Serialize;
use storage_proofs::crypto;
use storage_proofs::gadgets::pedersen::{pedersen_compression_num, pedersen_md_no_padding};
use storage_proofs::util::{bits_to_bytes, bytes_into_boolean_vec, bytes_into_boolean_vec_be};

fn blake2s_count(bytes: usize) -> anyhow::Result<Report> {
    let rng = &mut rand::thread_rng();

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.namespace(|| "data");
        bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len())
            .expect("failed to convert to boolean vector")
    };

    let personalization = vec![0u8; 8];
    let out: Vec<bool> =
        bellperson::gadgets::blake2s::blake2s(&mut cs, &data_bits, &personalization)?
            .into_iter()
            .map(|b| b.get_value().expect("failed to get bool value"))
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

fn sha256_count(bytes: usize) -> anyhow::Result<Report> {
    let mut rng = rand::thread_rng();

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.namespace(|| "data");
        bytes_into_boolean_vec_be(&mut cs, Some(data.as_slice()), data.len())
            .expect("failed to convert bytes into boolean vector big endian")
    };

    let _out: Vec<bool> = bellperson::gadgets::sha256::sha256(&mut cs, &data_bits)?
        .into_iter()
        .map(|b| b.get_value().expect("failed to get bool value"))
        .collect();

    assert!(cs.is_satisfied(), "constraints not satisfied");

    Ok(Report {
        hash_fn: "sha256".into(),
        bytes,
        constraints: cs.num_constraints(),
    })
}

fn pedersen_count(bytes: usize) -> anyhow::Result<Report> {
    let mut rng = rand::thread_rng();

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(&mut data);

    let data_bits: Vec<Boolean> = {
        let mut cs = cs.namespace(|| "data");
        bytes_into_boolean_vec(&mut cs, Some(data.as_slice()), data.len())
            .expect("failed to convert bytes into boolean vector")
    };

    if bytes < 128 {
        let out = pedersen_compression_num(&mut cs, &data_bits)?;
        assert!(cs.is_satisfied(), "constraints not satisfied");

        let expected = crypto::pedersen::pedersen(data.as_slice());
        assert_eq!(
            expected,
            out.get_value()
                .expect("failed to get value from pedersen num"),
            "circuit and non circuit do not match"
        );
    } else {
        let out = pedersen_md_no_padding(cs.namespace(|| "pedersen"), &data_bits)
            .expect("pedersen hashing failed");
        assert!(cs.is_satisfied(), "constraints not satisfied");
        let expected = crypto::pedersen::pedersen_md_no_padding(data.as_slice());
        assert_eq!(
            expected,
            out.get_value()
                .expect("failed to get value from pedersen md"),
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

pub fn run() -> anyhow::Result<()> {
    let reports = vec![
        blake2s_count(32)?,
        blake2s_count(64)?,
        blake2s_count(128)?,
        blake2s_count(256)?,
        pedersen_count(32)?,
        pedersen_count(64)?,
        pedersen_count(128)?,
        pedersen_count(256)?,
        sha256_count(32)?,
        sha256_count(64)?,
        sha256_count(128)?,
        sha256_count(256)?,
    ];

    // print reports
    let wrapped = Metadata::wrap(reports)?;
    serde_json::to_writer(std::io::stdout(), &wrapped)?;

    Ok(())
}
