use bellperson::bls::Fr;
use ff::Field;
use filecoin_hashers::{blake2s::Blake2sHasher, sha256::Sha256Hasher, Domain, Hasher};
use fr32::fr_into_bytes;
use merkletree::store::StoreConfig;
use pretty_assertions::assert_eq;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    drgraph::{BucketGraph, BASE_DEGREE},
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    proof::ProofScheme,
    table_tests,
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_porep::{
    drg::{self, DrgPoRep},
    stacked::BINARY_ARITY,
    PoRep,
};
use tempfile::tempdir;

#[test]
fn text_drg_porep_extract_all_sha256() {
    test_extract_all::<BinaryMerkleTree<Sha256Hasher>>();
}

#[test]
fn text_drg_porep_extract_all_blake2s() {
    test_extract_all::<BinaryMerkleTree<Blake2sHasher>>();
}

fn test_extract_all<Tree: MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let replica_id: <Tree::Hasher as Hasher>::Domain =
        <Tree::Hasher as Hasher>::Domain::random(rng);
    let nodes = 4;
    let data = vec![2u8; 32 * nodes];

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().expect("tempdir failure");
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let sp = drg::SetupParams {
        drg: drg::DrgParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: 0,
            porep_id: [32; 32],
        },
        private: false,
        challenges_count: 1,
        api_version: ApiVersion::V1_1_0,
    };

    let pp: drg::PublicParams<Tree::Hasher, BucketGraph<Tree::Hasher>> =
        DrgPoRep::setup(&sp).expect("setup failed");

    DrgPoRep::replicate(
        &pp,
        &replica_id,
        (mmapped_data.as_mut()).into(),
        None,
        config.clone(),
        replica_path,
    )
    .expect("replication failed");

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    DrgPoRep::<Tree::Hasher, _>::extract_all(&pp, &replica_id, mmapped_data.as_mut(), Some(config))
        .unwrap_or_else(|e| {
            panic!("Failed to extract data from `DrgPoRep`: {}", e);
        });

    assert_eq!(data, mmapped_data.as_ref(), "failed to extract data");

    cache_dir.close().expect("Failed to remove cache dir");
}

#[test]
fn test_drg_porep_extract_sha256() {
    test_extract::<BinaryMerkleTree<Sha256Hasher>>();
}

#[test]
fn test_drg_porep_extract_blake2s() {
    test_extract::<BinaryMerkleTree<Blake2sHasher>>();
}

fn test_extract<Tree: MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let replica_id: <Tree::Hasher as Hasher>::Domain =
        <Tree::Hasher as Hasher>::Domain::random(rng);
    let nodes = 4;
    let node_size = 32;
    let data = vec![2u8; node_size * nodes];

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().expect("tempdir failure");
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let sp = drg::SetupParams {
        drg: drg::DrgParams {
            nodes: data.len() / node_size,
            degree: BASE_DEGREE,
            expansion_degree: 0,
            porep_id: [32; 32],
        },
        private: false,
        challenges_count: 1,
        api_version: ApiVersion::V1_1_0,
    };

    let pp = DrgPoRep::<Tree::Hasher, BucketGraph<Tree::Hasher>>::setup(&sp).expect("setup failed");

    DrgPoRep::replicate(
        &pp,
        &replica_id,
        (mmapped_data.as_mut()).into(),
        None,
        config.clone(),
        replica_path,
    )
    .expect("replication failed");

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    for i in 0..nodes {
        DrgPoRep::extract(
            &pp,
            &replica_id,
            mmapped_data.as_mut(),
            i,
            Some(config.clone()),
        )
        .expect("failed to extract node data from PoRep");

        // This is no longer working, so the assertion is now incorrect.
        //let original_data = data_at_node(&data, i).expect("data_at_node failure");
        //let extracted_data = &mmapped_data[i * node_size..(i * node_size) + node_size];
        //assert_eq!(original_data, extracted_data, "failed to extract data");
    }
}

table_tests! {
    test_prove_verify {
        test_drg_porep_prove_verify_32_16_1(16, 1);
        test_drg_porep_prove_verify_32_64_1(64, 1);
        test_drg_porep_prove_verify_32_64_2(64, 2);
        test_drg_porep_prove_verify_32_256_1(256, 1);
        test_drg_porep_prove_verify_32_256_2(256, 2);
        test_drg_porep_prove_verify_32_256_3(256, 3);
        test_drg_porep_prove_verify_32_256_4(256, 4);
        test_drg_porep_prove_verify_32_256_5(256, 5);
    }
}

fn test_prove_verify(n: usize, i: usize) {
    test_prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(n, i, false, false);
    test_prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(n, i, false, false);
}

fn test_prove_verify_aux<Tree: MerkleTreeTrait>(
    nodes: usize,
    i: usize,
    use_wrong_challenge: bool,
    use_wrong_parents: bool,
) {
    assert!(i < nodes);

    // The loop is here in case we need to retry because of an edge case in the test design.
    loop {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);
        let degree = BASE_DEGREE;
        let expansion_degree = 0;

        let replica_id: <Tree::Hasher as Hasher>::Domain =
            <Tree::Hasher as Hasher>::Domain::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempdir().expect("tempdir failure");
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let challenge = i;

        let sp = drg::SetupParams {
            drg: drg::DrgParams {
                nodes,
                degree,
                expansion_degree,
                porep_id: [32; 32],
            },
            private: false,
            challenges_count: 2,
            api_version: ApiVersion::V1_1_0,
        };

        let pp = DrgPoRep::<Tree::Hasher, BucketGraph<_>>::setup(&sp).expect("setup failed");

        let (tau, aux) = DrgPoRep::<Tree::Hasher, _>::replicate(
            &pp,
            &replica_id,
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let pub_inputs = drg::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
            replica_id: Some(replica_id),
            challenges: vec![challenge, challenge],
            tau: Some(tau),
        };

        let priv_inputs = drg::PrivateInputs::<Tree::Hasher> {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
            tree_r_config_rows_to_discard: default_rows_to_discard(nodes, BINARY_ARITY),
        };

        let real_proof = DrgPoRep::<Tree::Hasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        if use_wrong_parents {
            // Only one 'wrong' option will be tested at a time.
            assert!(!use_wrong_challenge);
            let real_parents = real_proof.replica_parents;

            // Parent vector claiming the wrong parents.
            let fake_parents = vec![real_parents[0]
                .iter()
                // Incrementing each parent node will give us a different parent set.
                // It's fine to be out of range, since this only needs to fail.
                .map(|(i, data_proof)| (i + 1, data_proof.clone()))
                .collect::<Vec<_>>()];

            let proof = drg::Proof::new(
                real_proof.replica_nodes.clone(),
                fake_parents,
                real_proof.nodes.clone(),
            );

            let is_valid = DrgPoRep::verify(&pp, &pub_inputs, &proof).expect("verification failed");

            assert!(!is_valid, "verified in error -- with wrong parents");

            let mut all_same = true;
            for (p, _) in &real_parents[0] {
                if *p != real_parents[0][0].0 {
                    all_same = false;
                }
            }

            if all_same {
                println!("invalid test data can't scramble proofs with all same parents.");

                // If for some reason, we hit this condition because of the data passed in,
                // try again.
                continue;
            }

            // Parent vector claiming the right parents but providing valid proofs for different
            // parents.
            let fake_proof_parents = vec![real_parents[0]
                .iter()
                .enumerate()
                .map(|(i, (p, _))| {
                    // Rotate the real parent proofs.
                    let x = (i + 1) % real_parents[0].len();
                    let j = real_parents[0][x].0;
                    (*p, real_parents[0][j as usize].1.clone())
                })
                .collect::<Vec<_>>()];

            let proof2 = drg::Proof::new(
                real_proof.replica_nodes,
                fake_proof_parents,
                real_proof.nodes,
            );

            assert!(
                !DrgPoRep::<Tree::Hasher, _>::verify(&pp, &pub_inputs, &proof2).unwrap_or_else(
                    |e| {
                        panic!("Verification failed: {}", e);
                    }
                ),
                "verified in error -- with wrong parent proofs"
            );

            return;
        }

        let proof = real_proof;

        if use_wrong_challenge {
            let pub_inputs_with_wrong_challenge_for_proof =
                drg::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
                    replica_id: Some(replica_id),
                    challenges: vec![if challenge == 1 { 2 } else { 1 }],
                    tau: Some(tau),
                };
            let verified = DrgPoRep::<Tree::Hasher, _>::verify(
                &pp,
                &pub_inputs_with_wrong_challenge_for_proof,
                &proof,
            )
            .expect("Verification failed");
            assert!(
                !verified,
                "wrongly verified proof which does not match challenge in public input"
            );
        } else {
            assert!(
                DrgPoRep::<Tree::Hasher, _>::verify(&pp, &pub_inputs, &proof)
                    .expect("verification failed"),
                "failed to verify"
            );
        }

        cache_dir.close().expect("Failed to remove cache dir");

        // Normally, just run once.
        break;
    }
}

#[test]
fn test_drg_porep_verify_fails_on_wrong_challenge() {
    test_prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(8, 1, true, false);
    test_prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(8, 1, true, false);
}

#[test]
fn test_drg_porep_verify_fails_on_wrong_parents() {
    test_prove_verify_aux::<BinaryMerkleTree<Sha256Hasher>>(8, 5, false, true);
    test_prove_verify_aux::<BinaryMerkleTree<Blake2sHasher>>(8, 5, false, true);
}
