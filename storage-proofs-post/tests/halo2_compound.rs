use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U8};
use halo2_proofs::pasta::Fp;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    halo2::{CompoundProof, Halo2Field, Halo2Keypair},
    merkle::{generate_tree, DiskTree, MerkleTreeTrait},
    proof::ProofScheme,
    TEST_SEED,
};
use storage_proofs_post::{
    fallback::{self as vanilla, FallbackPoSt, SetupParams},
    halo2::{
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB,
        },
        window, winning, PostCircuit, WindowPostCircuit, WinningPostCircuit,
    },
};
use tempfile::tempdir;

type TreeR<U, V, W> = DiskTree<PoseidonHasher<Fp>, U, V, W>;
type TreeRDomain = <PoseidonHasher<Fp> as Hasher>::Domain;

fn test_winning_post_compound<'a, U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
    FallbackPoSt<'a, TreeR<U, V, W>>: CompoundProof<
        Fp,
        SECTOR_NODES,
        VanillaSetupParams = SetupParams,
        VanillaPublicInputs = vanilla::PublicInputs<TreeRDomain>,
        VanillaPartitionProof = vanilla::Proof<<TreeR<U, V, W> as MerkleTreeTrait>::Proof>,
        Circuit = PostCircuit<Fp, U, V, W, SECTOR_NODES>,
    >,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let vanilla_setup_params = SetupParams {
        sector_size: (SECTOR_NODES << 5) as u64,
        challenge_count: winning::CHALLENGE_COUNT,
        sector_count: 1,
        api_version: ApiVersion::V1_1_0,
    };

    let vanilla_pub_params = FallbackPoSt::<TreeR<U, V, W>>::setup(&vanilla_setup_params).unwrap();

    let randomness = Fp::random(&mut rng);
    let prover_id = Fp::random(&mut rng);

    let sector_id = 55u64;
    let temp_dir = tempdir().expect("tempdir failure");
    let temp_path = temp_dir.path();
    let (_replica, tree_r) =
        generate_tree::<TreeR<U, V, W>, _>(&mut rng, SECTOR_NODES, Some(temp_path.to_path_buf()));
    let comm_c = Fp::random(&mut rng);
    let root_r = tree_r.root();
    let comm_r = <PoseidonHasher<Fp> as Hasher>::Function::hash2(&comm_c.into(), &root_r);

    let vanilla_pub_inputs = vanilla::PublicInputs {
        randomness: randomness.into(),
        prover_id: prover_id.into(),
        sectors: vec![vanilla::PublicSector {
            id: sector_id.into(),
            comm_r,
        }],
        // Use `k = None` because we are using these inputs in a compound proof.
        k: None,
    };

    let priv_sectors = [vanilla::PrivateSector::<TreeR<U, V, W>> {
        tree: &tree_r,
        comm_c: comm_c.into(),
        comm_r_last: root_r,
    }];

    let vanilla_priv_inputs = vanilla::PrivateInputs {
        sectors: &priv_sectors,
    };

    let partition_count = 1;
    let vanilla_partition_proofs = FallbackPoSt::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )
    .expect("failed to generate vanilla_partition proofs");
    assert_eq!(vanilla_partition_proofs.len(), partition_count);
    assert_eq!(vanilla_partition_proofs[0].sectors.len(), 1);

    let keypair = {
        let circ =
            PostCircuit::from(WinningPostCircuit::<Fp, U, V, W, SECTOR_NODES>::blank_circuit());
        Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair")
    };

    let circ_partition_proofs = <
        FallbackPoSt::<TreeR<U, V, W>> as CompoundProof<Fp, SECTOR_NODES>
    >::prove_all_partitions_with_vanilla(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &vanilla_partition_proofs,
        &keypair,
    )
    .expect("failed to generate halo2 circuit proofs from vanilla partition proofs");

    <FallbackPoSt<TreeR<U, V, W>> as CompoundProof<Fp, SECTOR_NODES>>::verify_all_partitions(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &circ_partition_proofs,
        &keypair,
    )
    .expect("failed to verify halo2 circuit partition proofs");
}

#[test]
fn test_winning_post_compound_2kib_halo2() {
    test_winning_post_compound::<U8, U0, U0, SECTOR_NODES_2_KIB>()
}

#[test]
fn test_winning_post_compound_4kib_halo2() {
    test_winning_post_compound::<U8, U2, U0, SECTOR_NODES_4_KIB>()
}

#[test]
fn test_winning_post_compound_16kib_halo2() {
    test_winning_post_compound::<U8, U8, U0, SECTOR_NODES_16_KIB>()
}

#[test]
fn test_winning_post_compound_32kib_halo2() {
    test_winning_post_compound::<U8, U8, U2, SECTOR_NODES_32_KIB>()
}

fn test_window_post_compound<'a, U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
    FallbackPoSt<'a, TreeR<U, V, W>>: CompoundProof<
        Fp,
        SECTOR_NODES,
        VanillaSetupParams = SetupParams,
        VanillaPublicInputs = vanilla::PublicInputs<TreeRDomain>,
        VanillaPartitionProof = vanilla::Proof<<TreeR<U, V, W> as MerkleTreeTrait>::Proof>,
        Circuit = PostCircuit<Fp, U, V, W, SECTOR_NODES>,
    >,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let partition_count = 2;
    let sectors_challenged_per_partition =
        window::sectors_challenged_per_partition::<SECTOR_NODES>();
    // Test when the prover's sector set length is not divisible by the number of sectors challenged
    // per partition.
    let total_prover_sectors = partition_count * sectors_challenged_per_partition - 1;

    let vanilla_setup_params = SetupParams {
        sector_size: (SECTOR_NODES << 5) as u64,
        challenge_count: window::SECTOR_CHALLENGES,
        sector_count: sectors_challenged_per_partition,
        api_version: ApiVersion::V1_1_0,
    };

    let vanilla_pub_params = FallbackPoSt::<TreeR<U, V, W>>::setup(&vanilla_setup_params).unwrap();

    let temp_dir = tempdir().expect("tempdir failure");
    let temp_path = temp_dir.path().to_path_buf();

    let mut trees_r = Vec::with_capacity(sectors_challenged_per_partition);
    let mut comms_c = Vec::with_capacity(sectors_challenged_per_partition);
    let mut roots_r = Vec::with_capacity(sectors_challenged_per_partition);
    let mut pub_sectors = Vec::with_capacity(sectors_challenged_per_partition);

    for sector_index in 0..total_prover_sectors {
        let sector_id = sector_index as u64;

        let (_replica, tree_r) =
            generate_tree::<TreeR<U, V, W>, _>(&mut rng, SECTOR_NODES, Some(temp_path.clone()));

        let comm_c = Fp::random(&mut rng);
        let root_r = tree_r.root();
        let comm_r = <PoseidonHasher<Fp> as Hasher>::Function::hash2(&comm_c.into(), &root_r);

        pub_sectors.push(vanilla::PublicSector {
            id: sector_id.into(),
            comm_r,
        });

        trees_r.push(tree_r);
        comms_c.push(comm_c);
        roots_r.push(root_r);
    }

    let priv_sectors: Vec<vanilla::PrivateSector<TreeR<U, V, W>>> = trees_r
        .iter()
        .zip(comms_c.iter().copied())
        .zip(roots_r.iter().copied())
        .map(|((tree_r, comm_c), root_r)| vanilla::PrivateSector {
            tree: tree_r,
            comm_c: comm_c.into(),
            comm_r_last: root_r,
        })
        .collect();

    let randomness = Fp::random(&mut rng);
    let prover_id = Fp::random(&mut rng);

    let vanilla_pub_inputs = vanilla::PublicInputs {
        randomness: randomness.into(),
        prover_id: prover_id.into(),
        sectors: pub_sectors,
        // Use `k = None` because we are using these inputs in a compound proof.
        k: None,
    };

    let vanilla_priv_inputs = vanilla::PrivateInputs {
        sectors: &priv_sectors,
    };

    let vanilla_partition_proofs = FallbackPoSt::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )
    .expect("failed to generate vanilla_partition proofs");
    assert_eq!(vanilla_partition_proofs.len(), partition_count);
    // The vanilla prover should perform sector padding.
    assert!(vanilla_partition_proofs
        .iter()
        .all(|proof| proof.sectors.len() == sectors_challenged_per_partition));

    let keypair = {
        let circ =
            PostCircuit::from(WindowPostCircuit::<Fp, U, V, W, SECTOR_NODES>::blank_circuit());
        Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair")
    };

    let circ_partition_proofs = <
        FallbackPoSt::<TreeR<U, V, W>> as CompoundProof<Fp, SECTOR_NODES>
    >::prove_all_partitions_with_vanilla(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &vanilla_partition_proofs,
        &keypair,
    )
    .expect("failed to generate halo2 circuit proofs from vanilla partition proofs");

    <FallbackPoSt<TreeR<U, V, W>> as CompoundProof<Fp, SECTOR_NODES>>::verify_all_partitions(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &circ_partition_proofs,
        &keypair,
    )
    .expect("failed to verify halo2 circuit partition proofs");
}

#[test]
fn test_window_post_compound_2kib_halo2() {
    test_window_post_compound::<U8, U0, U0, SECTOR_NODES_2_KIB>()
}

#[test]
fn test_window_post_compound_4kib_halo2() {
    test_window_post_compound::<U8, U2, U0, SECTOR_NODES_4_KIB>()
}

#[test]
fn test_window_post_compound_16kib_halo2() {
    test_window_post_compound::<U8, U8, U0, SECTOR_NODES_16_KIB>()
}

#[test]
fn test_window_post_compound_32kib_halo2() {
    test_window_post_compound::<U8, U8, U2, SECTOR_NODES_32_KIB>()
}
