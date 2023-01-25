#![cfg(feature = "test-aggregate")]

use anyhow::Result;
use bellperson::groth16;
use bincode::serialize;
use blstrs::{Bls12, Scalar as Fr};
use ff::Field;
use filecoin_hashers::R1CSHasher;
use filecoin_proofs::{
    aggregate_seal_commit_proofs, seal_pre_commit_phase2, validate_cache_for_commit,
    verify_aggregate_seal_commit_proofs, DefaultTreeDomain, MerkleTreeTrait,
    PoseidonArityAllFields, ProverId, SealCommitOutput, SectorShape2KiB, SectorShape32KiB,
    SectorShape4KiB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB,
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{api_version::ApiVersion, is_legacy_porep_id};
use tempfile::NamedTempFile;

mod api_shared;

use api_shared::{
    generate_piece_file, generate_proof, porep_config, run_seal_pre_commit_phase1,
    ARBITRARY_POREP_ID_V1_1_0, TEST_SEED,
};

#[test]
#[ignore]
fn test_seal_proof_aggregation_1_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 1; // Requires auto-padding

    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_3_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 3; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_5_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 5; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_257_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 257; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_2_4kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 2;

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape4KiB<Fr>>(SECTOR_SIZE_4_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_1_32kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 1; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, &porep_id, proofs_to_aggregate)
}

#[test]
#[ignore]
fn test_seal_proof_aggregation_818_32kib_porep_id_v1_1_base_8() -> Result<()> {
    let proofs_to_aggregate = 818; // Requires auto-padding

    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
    assert!(!is_legacy_porep_id(porep_id));
    aggregate_proofs::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, &porep_id, proofs_to_aggregate)
}

//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_818_32gib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 818; // Requires auto-padding
//
//    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
//    assert!(!is_legacy_porep_id(porep_id));
//    let verified = aggregate_proofs::<SectorShape32GiB>(
//        SECTOR_SIZE_32_GIB,
//        &porep_id,
//        ApiVersion::V1_1_0,
//        proofs_to_aggregate,
//    )?;
//    assert!(verified);
//
//    Ok(())
//}

//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_818_64gib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 818; // Requires auto-padding
//
//    let porep_id = ARBITRARY_POREP_ID_V1_1_0;
//    assert!(!is_legacy_porep_id(porep_id));
//    let verified = aggregate_proofs::<SectorShape64GiB>(
//        SECTOR_SIZE_64_GIB,
//        &porep_id,
//        ApiVersion::V1_1_0,
//        proofs_to_aggregate,
//    )?;
//    assert!(verified);
//
//    Ok(())
//}

//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_1024_2kib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 1024;
//    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
//}
//
//#[test]
//#[ignore]
//fn test_seal_proof_aggregation_65536_2kib_porep_id_v1_1_base_8() -> Result<()> {
//    let proofs_to_aggregate = 65536;
//    inner_test_seal_proof_aggregation_2kib_porep_id_v1_1_base_8(proofs_to_aggregate)
//}

fn aggregate_proofs<Tree>(
    sector_size: u64,
    porep_id: &[u8; 32],
    num_proofs_to_aggregate: usize,
) -> Result<()>
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Hasher: R1CSHasher,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain<Fr> = Fr::random(&mut rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let api_version = ApiVersion::V1_1_0;
    let aggregate_versions = vec![
        groth16::aggregate::AggregateVersion::V1,
        groth16::aggregate::AggregateVersion::V2,
    ];
    for aggregate_version in aggregate_versions {
        let mut commit_outputs = Vec::with_capacity(num_proofs_to_aggregate);
        let mut commit_inputs = Vec::with_capacity(num_proofs_to_aggregate);
        let mut seeds = Vec::with_capacity(num_proofs_to_aggregate);
        let mut comm_rs = Vec::with_capacity(num_proofs_to_aggregate);

        let (commit_output, commit_input, seed, comm_r) = create_seal_for_aggregation::<_, Tree>(
            &mut rng,
            sector_size,
            prover_id,
            porep_id,
            api_version,
        )?;

        for _ in 0..num_proofs_to_aggregate {
            commit_outputs.push(commit_output.clone());
            commit_inputs.extend(commit_input.clone());
            seeds.push(seed);
            comm_rs.push(comm_r);
        }

        let config = porep_config(sector_size, *porep_id, api_version);
        let aggregate_proof = aggregate_seal_commit_proofs::<Tree>(
            config,
            &comm_rs,
            &seeds,
            commit_outputs.as_slice(),
            aggregate_version,
        )?;
        assert!(verify_aggregate_seal_commit_proofs::<Tree>(
            config,
            aggregate_proof.clone(),
            &comm_rs,
            &seeds,
            commit_inputs.clone(),
            aggregate_version,
        )?);

        // This ensures that once we generate an snarkpack proof
        // with one version, it cannot verify with another.
        let conflicting_aggregate_version = match aggregate_version {
            groth16::aggregate::AggregateVersion::V1 => groth16::aggregate::AggregateVersion::V2,
            groth16::aggregate::AggregateVersion::V2 => groth16::aggregate::AggregateVersion::V1,
        };
        assert!(!verify_aggregate_seal_commit_proofs::<Tree>(
            config,
            aggregate_proof,
            &comm_rs,
            &seeds,
            commit_inputs,
            conflicting_aggregate_version,
        )?);
    }

    Ok(())
}

fn create_seal_for_aggregation<R, Tree>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<(SealCommitOutput, Vec<Vec<Fr>>, [u8; 32], [u8; 32])>
where
    R: Rng,
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
{
    fil_logger::maybe_init();

    let (mut piece_file, _piece_bytes) = generate_piece_file(sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");

    let config = porep_config(sector_size, *porep_id, api_version);
    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let (piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    generate_proof::<Tree>(
        config,
        cache_dir.path(),
        &sealed_sector_file,
        prover_id,
        sector_id,
        ticket,
        seed,
        &pre_commit_output,
        &piece_infos,
    )
    .map(|(result, inputs, seed, comm_r)| {
        let inputs: Vec<Vec<Fr>> = inputs.into_iter().map(Into::into).collect();
        (result, inputs, seed, comm_r)
    })
}

#[test]
fn test_aggregate_proof_encode_decode() -> Result<()> {
    // This byte vector is a natively serialized aggregate proof generated from the
    // 'test_seal_proof_aggregation_257_2kib_porep_id_v1_1_base_8' test.
    let aggregate_proof_bytes = std::include_bytes!("./aggregate_proof_bytes");
    let expected_aggregate_proof_len = 29_044;

    // Re-construct the aggregate proof from the bytes, using the native deserialization method.
    let aggregate_proof: groth16::aggregate::AggregateProof<Bls12> =
        groth16::aggregate::AggregateProof::read(std::io::Cursor::new(&aggregate_proof_bytes))?;
    let aggregate_proof_count = aggregate_proof.tmipp.gipa.nproofs as usize;
    let expected_aggregate_proof_count = 512;

    assert_eq!(aggregate_proof_count, expected_aggregate_proof_count);

    // Re-serialize the proof to ensure a round-trip match.
    let mut aggregate_proof_bytes2 = Vec::new();
    aggregate_proof.write(&mut aggregate_proof_bytes2)?;

    assert_eq!(aggregate_proof_bytes.len(), expected_aggregate_proof_len);
    assert_eq!(aggregate_proof_bytes.len(), aggregate_proof_bytes2.len());
    assert_eq!(aggregate_proof_bytes, aggregate_proof_bytes2.as_slice());

    // Note: the native serialization format is more compact than bincode serialization, so assert that here.
    let bincode_serialized_proof = serialize(&aggregate_proof)?;
    let expected_bincode_serialized_proof_len = 56_436;

    assert!(aggregate_proof_bytes2.len() < bincode_serialized_proof.len());
    assert_eq!(
        bincode_serialized_proof.len(),
        expected_bincode_serialized_proof_len
    );

    Ok(())
}
