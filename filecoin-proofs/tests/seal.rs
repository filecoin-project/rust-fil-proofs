#![cfg(feature = "test-seal")]

use anyhow::Result;
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use filecoin_proofs::{
    DefaultPieceHasher, DefaultTreeDomain, DefaultTreeHasher, MerkleTreeTrait,
    PoseidonArityAllFields, SectorShape16KiB, SectorShape2KiB, SectorShape32KiB, SectorShape4KiB,
    SECTOR_SIZE_16_KIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB,
};
#[cfg(feature = "big-tests")]
use filecoin_proofs::{
    SectorShape32GiB, SectorShape512MiB, SectorShape64GiB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_64_GIB,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{api_version::ApiVersion, is_legacy_porep_id};

mod api_shared;

use api_shared::{create_seal, ARBITRARY_POREP_ID_V1_0_0, ARBITRARY_POREP_ID_V1_1_0, TEST_SEED};

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_porep_id_v1_base_8() -> Result<()> {
    let porep_id_v1: u64 = 0; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, ApiVersion::V1_0_0)
}

#[test]
#[ignore]
fn test_seal_lifecycle_2kib_porep_id_v1_1_base_8() -> Result<()> {
    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, &porep_id, ApiVersion::V1_1_0)
}

#[test]
#[ignore]
fn test_seal_lifecycle_4kib_sub_8_2_v1() -> Result<()> {
    seal_lifecycle::<SectorShape4KiB<Fr>>(
        SECTOR_SIZE_4_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_4kib_sub_8_2_v1_1() -> Result<()> {
    seal_lifecycle::<SectorShape4KiB<Fr>>(
        SECTOR_SIZE_4_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_16kib_sub_8_2_v1() -> Result<()> {
    seal_lifecycle::<SectorShape16KiB<Fr>>(
        SECTOR_SIZE_16_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_16kib_sub_8_2_v1_1() -> Result<()> {
    seal_lifecycle::<SectorShape16KiB<Fr>>(
        SECTOR_SIZE_16_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_32kib_top_8_8_2_v1() -> Result<()> {
    seal_lifecycle::<SectorShape32KiB<Fr>>(
        SECTOR_SIZE_32_KIB,
        &ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_0_0,
    )
}

#[test]
#[ignore]
fn test_seal_lifecycle_32kib_top_8_8_2_v1_1() -> Result<()> {
    seal_lifecycle::<SectorShape32KiB<Fr>>(
        SECTOR_SIZE_32_KIB,
        &ARBITRARY_POREP_ID_V1_1_0,
        ApiVersion::V1_1_0,
    )
}

// These tests are good to run, but take a long time.

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_512mib_porep_id_v1_top_8_0_0_api_v1() -> Result<()> {
    let porep_id_v1: u64 = 2; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape512MiB<Fr>>(SECTOR_SIZE_512_MIB, &porep_id, ApiVersion::V1_0_0)
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_512mib_porep_id_v1_top_8_0_0_api_v1_1() -> Result<()> {
    let porep_id_v1_1: u64 = 7; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape512MiB<Fr>>(SECTOR_SIZE_512_MIB, &porep_id, ApiVersion::V1_1_0)
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_32gib_porep_id_v1_top_8_8_0_api_v1() -> Result<()> {
    let porep_id_v1: u64 = 3; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape32GiB<Fr>>(SECTOR_SIZE_32_GIB, &porep_id, ApiVersion::V1_0_0)
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_32gib_porep_id_v1_1_top_8_8_0_api_v1_1() -> Result<()> {
    let porep_id_v1_1: u64 = 8; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape32GiB<Fr>>(SECTOR_SIZE_32_GIB, &porep_id, ApiVersion::V1_1_0)
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_64gib_porep_id_v1_top_8_8_2_api_v1() -> Result<()> {
    let porep_id_v1: u64 = 4; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1.to_le_bytes());
    assert!(is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape64GiB<Fr>>(SECTOR_SIZE_64_GIB, &porep_id, ApiVersion::V1_0_0)
}

#[cfg(feature = "big-tests")]
#[test]
fn test_seal_lifecycle_64gib_porep_id_v1_1_top_8_8_2_api_v1_1() -> Result<()> {
    let porep_id_v1_1: u64 = 9; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));
    seal_lifecycle::<SectorShape64GiB<Fr>>(SECTOR_SIZE_64_GIB, &porep_id, ApiVersion::V1_1_0)
}

fn seal_lifecycle<Tree>(
    sector_size: u64,
    porep_id: &[u8; 32],
    api_version: ApiVersion,
) -> Result<()>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);
    let prover_fr = DefaultTreeDomain::<Tree::Field>::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let (_, replica, _, _) = create_seal::<_, Tree>(
        &mut rng,
        sector_size,
        prover_id,
        false,
        porep_id,
        api_version,
    )?;
    replica.close()?;

    Ok(())
}
