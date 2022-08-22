#![cfg(feature = "test-upgrade")]

use std::fs::{metadata, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use anyhow::{ensure, Context, Error, Result};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use filecoin_hashers::{Domain, Hasher};
use filecoin_proofs::{
    add_piece, clear_cache, decode_from, encode_into, generate_empty_sector_update_proof,
    generate_empty_sector_update_proof_with_vanilla, generate_partition_proofs,
    generate_piece_commitment, generate_single_partition_proof, remove_encoded_data,
    seal_pre_commit_phase2, validate_cache_for_commit, verify_empty_sector_update_proof,
    verify_partition_proofs, verify_single_partition_proof, Commitment, DefaultPieceHasher,
    DefaultTreeDomain, DefaultTreeHasher, MerkleTreeTrait, PaddedBytesAmount,
    PoseidonArityAllFields, ProverId, SectorUpdateConfig, UnpaddedBytesAmount,
};
#[cfg(not(feature = "big-tests"))]
use filecoin_proofs::{
    SectorShape16KiB, SectorShape2KiB, SectorShape32KiB, SectorShape4KiB, SECTOR_SIZE_16_KIB,
    SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB,
};
#[cfg(feature = "big-tests")]
use filecoin_proofs::{
    SectorShape32GiB, SectorShape512MiB, SectorShape64GiB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_64_GIB,
};
use halo2_proofs::pasta::{Fp, Fq};
use log::info;
use memmap::MmapOptions;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
#[cfg(not(feature = "big-tests"))]
use storage_proofs_core::is_legacy_porep_id;
use storage_proofs_core::{api_version::ApiVersion, sector::SectorId};
use storage_proofs_update::constants::{TreeDHasher, TreeRHasher};
use tempfile::{tempdir, NamedTempFile, TempDir};

mod api_shared;

use api_shared::{
    generate_piece_file, porep_config, run_seal_pre_commit_phase1, ARBITRARY_POREP_ID_V1_1_0,
    TEST_SEED,
};

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_seal_lifecycle_upgrade_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle_upgrade::<SectorShape2KiB<Fr>, Fr>(
        SECTOR_SIZE_2_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
    )
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_halo2_seal_lifecycle_upgrade_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle_upgrade::<SectorShape2KiB<Fp>, Fp>(
        SECTOR_SIZE_2_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
    )?;
    seal_lifecycle_upgrade::<SectorShape2KiB<Fq>, Fq>(
        SECTOR_SIZE_2_KIB,
        &porep_id,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_upgrade_4kib_sub_8_2_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape4KiB<Fr>, Fr>(
        SECTOR_SIZE_4_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_seal_lifecycle_upgrade_16kib_sub_8_2_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape16KiB<Fr>, Fr>(
        SECTOR_SIZE_16_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_seal_lifecycle_upgrade_32kib_top_8_8_2_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape32KiB<Fr>, Fr>(
        SECTOR_SIZE_32_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_upgrade_512mib_top_8_0_0_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape512MiB<Fr>, Fr>(
        SECTOR_SIZE_512_MIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_upgrade_32gib_top_8_8_0_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape32GiB<Fr>, Fr>(
        SECTOR_SIZE_32_GIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_upgrade_64gib_top_8_8_2_v1_1() -> Result<()> {
    seal_lifecycle_upgrade::<SectorShape64GiB<Fr>, Fr>(
        SECTOR_SIZE_64_GIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

fn seal_lifecycle_upgrade<Tree, F>(
    sector_size: u64,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<()>
where
    Tree: 'static + MerkleTreeTrait<Field = F, Hasher = TreeRHasher<F>>,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    F: PrimeField,
    DefaultPieceHasher<F>: Hasher<Field = F>,
    DefaultTreeHasher<F>: Hasher<Field = F>,
{
    let mut rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr = DefaultTreeDomain::<Tree::Field>::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let (_, replica, _, _) = create_seal_for_upgrade::<_, Tree, Tree::Field>(
        &mut rng,
        sector_size,
        prover_id,
        porep_id,
        api_version,
    )?;
    replica.close()?;

    Ok(())
}

fn create_seal_for_upgrade<R, Tree, F>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<(SectorId, NamedTempFile, Commitment, TempDir)>
where
    R: Rng,
    Tree: 'static + MerkleTreeTrait<Field = F, Hasher = TreeRHasher<F>>,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    F: PrimeField,
    TreeDHasher<F>: Hasher<Field = F>,
    TreeRHasher<F>: Hasher<Field = F>,
{
    fil_logger::maybe_init();

    let (mut piece_file, _piece_bytes) = generate_piece_file(sector_size)?;
    let sealed_sector_file = NamedTempFile::new()?;
    let cache_dir = tempdir().expect("failed to create temp dir");

    let porep_config = porep_config(sector_size, *porep_id, api_version);
    let config = SectorUpdateConfig::from_porep_config(porep_config);
    let ticket = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let (_piece_infos, phase1_output) = run_seal_pre_commit_phase1::<Tree>(
        porep_config,
        prover_id,
        sector_id,
        ticket,
        &cache_dir,
        &mut piece_file,
        &sealed_sector_file,
    )?;

    let pre_commit_output = seal_pre_commit_phase2(
        porep_config,
        phase1_output,
        cache_dir.path(),
        sealed_sector_file.path(),
    )?;
    let comm_r = pre_commit_output.comm_r;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_sector_file.path())?;

    // Upgrade the cc sector here.
    let new_sealed_sector_file = NamedTempFile::new()?;
    let new_cache_dir = tempdir().expect("failed to create temp dir");

    // create and generate some random data in staged_data_file.
    let (mut new_piece_file, _new_piece_bytes) = generate_piece_file(sector_size)?;
    let number_of_bytes_in_piece =
        UnpaddedBytesAmount::from(PaddedBytesAmount(porep_config.sector_size.into()));

    let new_piece_info =
        generate_piece_commitment(new_piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    new_piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let mut new_staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut new_piece_file,
        &mut new_staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    let new_piece_infos = vec![new_piece_info];

    // New replica (new_sealed_sector_file) is currently 0 bytes --
    // set a length here to ensure proper mmap later.  Lotus will
    // already be passing in a destination path of the proper size in
    // the future, so this is a test specific work-around.
    let new_replica_target_len = metadata(&sealed_sector_file)?.len();
    let f_sealed_sector = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(new_sealed_sector_file.path())
        .with_context(|| format!("could not open path={:?}", new_sealed_sector_file.path()))?;
    f_sealed_sector.set_len(new_replica_target_len)?;

    let encoded = encode_into::<Tree, F>(
        porep_config,
        new_sealed_sector_file.path(),
        new_cache_dir.path(),
        sealed_sector_file.path(),
        cache_dir.path(),
        new_staged_sector_file.path(),
        &new_piece_infos,
    )?;

    // Generate a single partition proof
    let partition_proof = generate_single_partition_proof::<Tree, F>(
        config,
        0, // first partition
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
        sealed_sector_file.path(), /* sector key file */
        cache_dir.path(),          /* sector key path needed for p_aux and t_aux */
        new_sealed_sector_file.path(),
        new_cache_dir.path(),
    )?;

    // Verify the single partition proof
    let proof_is_valid = verify_single_partition_proof::<Tree, F>(
        config,
        0, // first partition
        partition_proof,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
    )?;
    ensure!(proof_is_valid, "Partition proof (single) failed to verify");

    // Generate all partition proofs
    let partition_proofs = generate_partition_proofs::<Tree, F>(
        config,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
        sealed_sector_file.path(), /* sector key file */
        cache_dir.path(),          /* sector key path needed for p_aux and t_aux */
        new_sealed_sector_file.path(),
        new_cache_dir.path(),
    )?;

    // Verify all partition proofs
    let proofs_are_valid = verify_partition_proofs::<Tree, F>(
        config,
        &partition_proofs,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
    )?;
    ensure!(proofs_are_valid, "Partition proofs failed to verify");

    let proof = generate_empty_sector_update_proof_with_vanilla::<Tree, F>(
        porep_config,
        partition_proofs,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
    )?;
    let valid = verify_empty_sector_update_proof::<Tree, F>(
        porep_config,
        &proof.0,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
    )?;
    ensure!(valid, "Compound proof failed to verify");

    let proof = generate_empty_sector_update_proof::<Tree, F>(
        porep_config,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
        sealed_sector_file.path(), /* sector key file */
        cache_dir.path(),          /* sector key path needed for p_aux and t_aux */
        new_sealed_sector_file.path(),
        new_cache_dir.path(),
    )?;
    let valid = verify_empty_sector_update_proof::<Tree, F>(
        porep_config,
        &proof.0,
        comm_r,
        encoded.comm_r_new,
        encoded.comm_d_new,
    )?;
    ensure!(valid, "Compound proof failed to verify");

    let decoded_sector_file = NamedTempFile::new()?;
    // New replica (new_sealed_sector_file) is currently 0 bytes --
    // set a length here to ensure proper mmap later.  Lotus will
    // already be passing in a destination path of the proper size in
    // the future, so this is a test specific work-around.
    let decoded_sector_target_len = metadata(&sealed_sector_file)?.len();
    let f_decoded_sector = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(decoded_sector_file.path())
        .with_context(|| format!("could not open path={:?}", decoded_sector_file.path()))?;
    f_decoded_sector.set_len(decoded_sector_target_len)?;

    decode_from::<Tree, F>(
        config,
        decoded_sector_file.path(),
        new_sealed_sector_file.path(),
        sealed_sector_file.path(),
        cache_dir.path(), /* sector key path needed for p_aux (for comm_c/comm_r_last) */
        encoded.comm_d_new,
    )?;
    // When the data is decoded, it MUST match the original new staged data.
    compare_elements::<F>(decoded_sector_file.path(), new_staged_sector_file.path())?;

    decoded_sector_file.close()?;

    // Remove Data here
    let remove_encoded_file = NamedTempFile::new()?;
    let remove_encoded_cache_dir = tempdir().expect("failed to create temp dir");
    // New replica (new_sealed_sector_file) is currently 0 bytes --
    // set a length here to ensure proper mmap later.  Lotus will
    // already be passing in a destination path of the proper size in
    // the future, so this is a test specific work-around.
    let remove_encoded_target_len = metadata(&sealed_sector_file)?.len();
    let f_remove_encoded = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(remove_encoded_file.path())
        .with_context(|| format!("could not open path={:?}", remove_encoded_file.path()))?;
    f_remove_encoded.set_len(remove_encoded_target_len)?;

    // Note: we pass cache_dir to the remove, which is the original
    // dir where the data was sealed (for p_aux/t_aux).
    remove_encoded_data::<Tree, F>(
        config,
        remove_encoded_file.path(),
        remove_encoded_cache_dir.path(),
        new_sealed_sector_file.path(),
        cache_dir.path(),
        new_staged_sector_file.path(),
        encoded.comm_d_new,
    )?;
    // When the data is removed, it MUST match the original sealed data.
    compare_elements::<F>(remove_encoded_file.path(), sealed_sector_file.path())?;

    remove_encoded_file.close()?;

    clear_cache::<Tree>(cache_dir.path())?;
    clear_cache::<Tree>(new_cache_dir.path())?;

    Ok((sector_id, sealed_sector_file, comm_r, cache_dir))
}

fn compare_elements<F: PrimeField>(path1: &Path, path2: &Path) -> Result<(), Error> {
    info!("Comparing elements between {:?} and {:?}", path1, path2);
    let f_data1 = OpenOptions::new()
        .read(true)
        .open(path1)
        .with_context(|| format!("could not open path={:?}", path1))?;
    let data1 = unsafe {
        MmapOptions::new()
            .map(&f_data1)
            .with_context(|| format!("could not mmap path={:?}", path1))
    }?;
    let f_data2 = OpenOptions::new()
        .read(true)
        .open(path2)
        .with_context(|| format!("could not open path={:?}", path2))?;
    let data2 = unsafe {
        MmapOptions::new()
            .map(&f_data2)
            .with_context(|| format!("could not mmap path={:?}", path2))
    }?;
    let field_size = 32;
    let end = metadata(path1)?.len() as u64;
    ensure!(
        metadata(path2)?.len() as u64 == end,
        "File sizes must match"
    );

    for i in (0..end).step_by(field_size) {
        let index = i as usize;
        let fr1 = bytes_into_field::<F>(&data1[index..index + field_size])?;
        let fr2 = bytes_into_field::<F>(&data2[index..index + field_size])?;
        ensure!(fr1 == fr2, "Data mismatch when comparing elements");
    }
    info!("Match found for {:?} and {:?}", path1, path2);

    Ok(())
}

#[inline]
fn bytes_into_field<F: PrimeField>(le_bytes: &[u8]) -> Result<F> {
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(le_bytes);
    F::from_repr_vartime(repr).ok_or_else(|| fr32::Error::BadFrBytes.into())
}
