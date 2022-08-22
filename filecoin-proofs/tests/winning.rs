#![cfg(feature = "test-winning")]
// TODO (jake): remove (import specific sector shapes when `big-tests` is enabled or not).
#![allow(unused_imports)]

use anyhow::Result;
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use filecoin_proofs::{
    generate_fallback_sector_challenges, generate_single_vanilla_proof, generate_winning_post,
    generate_winning_post_sector_challenge, generate_winning_post_with_vanilla,
    verify_winning_post, DefaultPieceHasher, DefaultTreeDomain, DefaultTreeHasher, MerkleTreeTrait,
    PoStConfig, PoStType, PoseidonArityAllFields, PrivateReplicaInfo, PublicReplicaInfo,
    SectorShape16KiB, SectorShape2KiB, SectorShape32KiB, SectorShape4KiB, SECTOR_SIZE_16_KIB,
    SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, WINNING_POST_CHALLENGE_COUNT,
    WINNING_POST_SECTOR_COUNT,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::api_version::ApiVersion;

mod api_shared;

use api_shared::{
    create_fake_seal, create_seal, ARBITRARY_POREP_ID_V1_0_0, ARBITRARY_POREP_ID_V1_1_0, TEST_SEED,
};

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_winning_post_2kib_base_8() -> Result<()> {
    winning_post::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape2KiB<Fr>>(SECTOR_SIZE_2_KIB, true, ApiVersion::V1_1_0)
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_winning_post_4kib_sub_8_2() -> Result<()> {
    winning_post::<SectorShape4KiB<Fr>>(SECTOR_SIZE_4_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape4KiB<Fr>>(SECTOR_SIZE_4_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape4KiB<Fr>>(SECTOR_SIZE_4_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape4KiB<Fr>>(SECTOR_SIZE_4_KIB, true, ApiVersion::V1_1_0)
}

#[cfg(feature = "big-tests")]
#[test]
#[ignore]
fn test_winning_post_16kib_sub_8_8() -> Result<()> {
    winning_post::<SectorShape16KiB<Fr>>(SECTOR_SIZE_16_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape16KiB<Fr>>(SECTOR_SIZE_16_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape16KiB<Fr>>(SECTOR_SIZE_16_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape16KiB<Fr>>(SECTOR_SIZE_16_KIB, true, ApiVersion::V1_1_0)
}

#[cfg(feature = "big-tests")]
#[test]
#[ignore]
fn test_winning_post_32kib_top_8_8_2() -> Result<()> {
    winning_post::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, false, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, true, ApiVersion::V1_0_0)?;
    winning_post::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, false, ApiVersion::V1_1_0)?;
    winning_post::<SectorShape32KiB<Fr>>(SECTOR_SIZE_32_KIB, true, ApiVersion::V1_1_0)
}

fn winning_post<Tree>(sector_size: u64, fake: bool, api_version: ApiVersion) -> Result<()>
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Arity: PoseidonArityAllFields,
    Tree::SubTreeArity: PoseidonArityAllFields,
    Tree::TopTreeArity: PoseidonArityAllFields,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
    DefaultTreeHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let prover_fr = DefaultTreeDomain::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let porep_id = match api_version {
        ApiVersion::V1_0_0 => ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_1_0 => ARBITRARY_POREP_ID_V1_1_0,
    };

    let (sector_id, replica, comm_r, cache_dir) = if fake {
        create_fake_seal::<_, Tree>(&mut rng, sector_size, &porep_id, api_version)?
    } else {
        create_seal::<_, Tree>(
            &mut rng,
            sector_size,
            prover_id,
            true,
            &porep_id,
            api_version,
        )?
    };
    let sector_count = WINNING_POST_SECTOR_COUNT;

    let random_fr = DefaultTreeDomain::random(&mut rng);
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
        api_version,
    };

    let challenged_sectors = generate_winning_post_sector_challenge::<Tree>(
        &config,
        &randomness,
        sector_count as u64,
        prover_id,
    )?;
    assert_eq!(challenged_sectors.len(), sector_count);
    assert_eq!(challenged_sectors[0], 0); // with a sector_count of 1, the only valid index is 0

    let pub_replicas = vec![(sector_id, PublicReplicaInfo::new(comm_r)?)];
    let private_replica_info =
        PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?;

    /////////////////////////////////////////////
    // The following methods of proof generation are functionally equivalent:
    // 1)
    //
    let priv_replicas = vec![(sector_id, private_replica_info.clone())];
    let proof = generate_winning_post::<Tree>(&config, &randomness, &priv_replicas[..], prover_id)?;

    let valid =
        verify_winning_post::<Tree>(&config, &randomness, &pub_replicas[..], prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    //
    // 2)
    let mut vanilla_proofs = Vec::with_capacity(sector_count);
    let challenges =
        generate_fallback_sector_challenges::<Tree>(&config, &randomness, &[sector_id], prover_id)?;

    let single_proof = generate_single_vanilla_proof::<Tree>(
        &config,
        sector_id,
        &private_replica_info,
        &challenges[&sector_id],
    )?;

    vanilla_proofs.push(single_proof);

    let proof = generate_winning_post_with_vanilla::<Tree>(
        &config,
        &randomness,
        prover_id,
        vanilla_proofs,
    )?;
    /////////////////////////////////////////////

    let valid =
        verify_winning_post::<Tree>(&config, &randomness, &pub_replicas[..], prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    replica.close()?;

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
fn test_winning_post_empty_sector_challenge() -> Result<()> {
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let prover_fr = DefaultTreeDomain::<Fr>::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let sector_count = 0;
    let sector_size = SECTOR_SIZE_2_KIB;
    let api_version = ApiVersion::V1_1_0;

    let (_, replica, _, _) = create_seal::<_, SectorShape2KiB<Fr>>(
        &mut rng,
        sector_size,
        prover_id,
        true,
        &ARBITRARY_POREP_ID_V1_1_0,
        api_version,
    )?;

    let random_fr = DefaultTreeDomain::<Fr>::random(&mut rng);
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: false,
        api_version,
    };

    assert!(
        generate_winning_post_sector_challenge::<SectorShape2KiB<Fr>>(
            &config,
            &randomness,
            sector_count as u64,
            prover_id
        )
        .is_err()
    );

    replica.close()?;

    Ok(())
}
