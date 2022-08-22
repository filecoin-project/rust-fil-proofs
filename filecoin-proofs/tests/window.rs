#![cfg(feature = "test-window")]

use std::collections::BTreeMap;

use anyhow::Result;
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use filecoin_proofs::{
    generate_fallback_sector_challenges, generate_single_vanilla_proof,
    generate_single_window_post_with_vanilla, generate_window_post,
    generate_window_post_with_vanilla, get_num_partition_for_fallback_post,
    merge_window_post_partition_proofs, verify_window_post, DefaultPieceHasher, DefaultTreeHasher,
    MerkleTreeTrait, PoStConfig, PoStType, PoseidonArityAllFields, PrivateReplicaInfo,
    PublicReplicaInfo, WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT,
};
#[cfg(not(feature = "big-tests"))]
use filecoin_proofs::{SectorShape2KiB, SectorShape4KiB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_4_KIB};
#[cfg(feature = "big-tests")]
use filecoin_proofs::{SectorShape16KiB, SectorShape32KiB, SECTOR_SIZE_16_KIB, SECTOR_SIZE_32_KIB};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{api_version::ApiVersion, sector::SectorId};

mod api_shared;

use api_shared::{
    create_fake_seal, create_seal, ARBITRARY_POREP_ID_V1_0_0, ARBITRARY_POREP_ID_V1_1_0, TEST_SEED,
};

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_window_post_single_partition_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            sector_count / 2,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            sector_count / 2,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_window_post_two_partitions_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_window_post_two_partitions_matching_4kib_sub_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_4_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape4KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape4KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(feature = "big-tests")]
#[test]
#[ignore]
fn test_window_post_two_partitions_matching_16kib_sub_8_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_16_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape16KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape16KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(feature = "big-tests")]
#[test]
#[ignore]
fn test_window_post_two_partitions_matching_32kib_top_8_8_2() -> Result<()> {
    let sector_size = SECTOR_SIZE_32_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape32KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape32KiB<Fr>>(
            sector_size,
            2 * sector_count,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_window_post_two_partitions_smaller_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            2 * sector_count - 1,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            2 * sector_count - 1,
            sector_count,
            true,
            version,
        )?;
    }

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
#[ignore]
fn test_window_post_single_partition_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            sector_count,
            sector_count,
            false,
            version,
        )?;
        window_post::<SectorShape2KiB<Fr>>(sector_size, sector_count, sector_count, true, version)?;
    }

    Ok(())
}

fn window_post<Tree>(
    sector_size: u64,
    total_sector_count: usize,
    sector_count: usize,
    fake: bool,
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

    let mut sectors = Vec::with_capacity(total_sector_count);
    let mut pub_replicas = BTreeMap::new();
    let mut priv_replicas = BTreeMap::new();

    let prover_fr = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let porep_id = match api_version {
        ApiVersion::V1_0_0 => ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_1_0 => ARBITRARY_POREP_ID_V1_1_0,
    };

    for _ in 0..total_sector_count {
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
        priv_replicas.insert(
            sector_id,
            PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?,
        );
        pub_replicas.insert(sector_id, PublicReplicaInfo::new(comm_r)?);
        sectors.push((sector_id, replica, comm_r, cache_dir, prover_id));
    }
    assert_eq!(priv_replicas.len(), total_sector_count);
    assert_eq!(pub_replicas.len(), total_sector_count);
    assert_eq!(sectors.len(), total_sector_count);

    let random_fr = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        typ: PoStType::Window,
        priority: false,
        api_version,
    };

    /////////////////////////////////////////////
    // The following methods of proof generation are functionally equivalent:
    // 1)
    let proof = generate_window_post::<Tree>(&config, &randomness, &priv_replicas, prover_id)?;

    let valid = verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    // 2)
    let replica_sectors = priv_replicas
        .iter()
        .map(|(sector, _replica)| *sector)
        .collect::<Vec<SectorId>>();

    let challenges = generate_fallback_sector_challenges::<Tree>(
        &config,
        &randomness,
        &replica_sectors,
        prover_id,
    )?;

    let mut vanilla_proofs = Vec::with_capacity(replica_sectors.len());

    for (sector_id, replica) in priv_replicas.iter() {
        let sector_challenges = &challenges[sector_id];
        let single_proof =
            generate_single_vanilla_proof::<Tree>(&config, *sector_id, replica, sector_challenges)?;

        vanilla_proofs.push(single_proof);
    }

    let proof =
        generate_window_post_with_vanilla::<Tree>(&config, &randomness, prover_id, vanilla_proofs)?;
    /////////////////////////////////////////////

    let valid = verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &proof)?;
    assert!(valid, "proof did not verify");

    Ok(())
}

#[cfg(not(feature = "big-tests"))]
#[test]
fn test_window_post_partition_matching_2kib_base_8() -> Result<()> {
    let sector_size = SECTOR_SIZE_2_KIB;
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let versions = vec![ApiVersion::V1_0_0, ApiVersion::V1_1_0];
    for version in versions {
        partition_window_post::<SectorShape2KiB<Fr>>(
            sector_size,
            3, // Validate the scenarios of two partition
            sector_count,
            false,
            version,
        )?;
        partition_window_post::<SectorShape2KiB<Fr>>(sector_size, 3, sector_count, true, version)?;
    }

    Ok(())
}

fn partition_window_post<Tree>(
    sector_size: u64,
    total_sector_count: usize,
    sector_count: usize,
    fake: bool,
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
    use anyhow::anyhow;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let mut sectors = Vec::with_capacity(total_sector_count);
    let mut pub_replicas = BTreeMap::new();
    let mut priv_replicas = BTreeMap::new();

    let prover_fr = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    let porep_id = match api_version {
        ApiVersion::V1_0_0 => ARBITRARY_POREP_ID_V1_0_0,
        ApiVersion::V1_1_0 => ARBITRARY_POREP_ID_V1_1_0,
    };

    for _ in 0..total_sector_count {
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
        priv_replicas.insert(
            sector_id,
            PrivateReplicaInfo::new(replica.path().into(), comm_r, cache_dir.path().into())?,
        );
        pub_replicas.insert(sector_id, PublicReplicaInfo::new(comm_r)?);
        sectors.push((sector_id, replica, comm_r, cache_dir, prover_id));
    }
    assert_eq!(priv_replicas.len(), total_sector_count);
    assert_eq!(pub_replicas.len(), total_sector_count);
    assert_eq!(sectors.len(), total_sector_count);

    let random_fr = <Tree::Hasher as Hasher>::Domain::random(&mut rng);
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(AsRef::<[u8]>::as_ref(&random_fr));

    let config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        typ: PoStType::Window,
        priority: false,
        api_version,
    };

    let replica_sectors = priv_replicas
        .iter()
        .map(|(sector, _replica)| *sector)
        .collect::<Vec<SectorId>>();

    let challenges = generate_fallback_sector_challenges::<Tree>(
        &config,
        &randomness,
        &replica_sectors,
        prover_id,
    )?;

    let num_sectors_per_chunk = config.sector_count;
    let mut proofs = Vec::new();

    let partitions = get_num_partition_for_fallback_post(&config, replica_sectors.len());
    for partition_index in 0..partitions {
        let sector_ids = replica_sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        let mut partition_priv_replicas = BTreeMap::new();
        for id in sector_ids {
            let p_sector = match priv_replicas.get(id) {
                Some(v) => v,
                _ => {
                    continue;
                }
            };

            partition_priv_replicas.insert(*id, p_sector);
        }

        let mut vanilla_proofs = Vec::new();
        for (sector_id, sector) in partition_priv_replicas.iter() {
            let sector_challenges = &challenges[sector_id];
            let single_proof = generate_single_vanilla_proof::<Tree>(
                &config,
                *sector_id,
                sector,
                sector_challenges,
            )?;

            vanilla_proofs.push(single_proof);
        }

        let proof = generate_single_window_post_with_vanilla(
            &config,
            &randomness,
            prover_id,
            vanilla_proofs,
            partition_index,
        )?;

        proofs.push(proof);
    }

    let final_proof = merge_window_post_partition_proofs(proofs)?;
    let valid =
        verify_window_post::<Tree>(&config, &randomness, &pub_replicas, prover_id, &final_proof)?;
    assert!(valid, "proofs did not verify");

    Ok(())
}
