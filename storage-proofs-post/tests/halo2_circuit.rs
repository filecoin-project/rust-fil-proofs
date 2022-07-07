use std::convert::TryInto;
use std::marker::PhantomData;
use std::sync::Once;

use ff::{Field, PrimeField};
use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U8};
use halo2_proofs::{dev::MockProver, pasta::Fp};
use log::{info, trace};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    halo2::{create_proof, verify_proof, CircuitRows, Halo2Field, Halo2Keypair},
    merkle::{generate_tree, DiskTree, MerkleProofTrait, MerkleTreeTrait},
    TEST_SEED,
};
use storage_proofs_post::halo2::{
    constants::{
        SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB, SECTOR_NODES_32_KIB,
        SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB,
    },
    window, winning, SectorProof, WindowPostCircuit, WinningPostCircuit,
};
use tempfile::tempdir;

pub type TreeR<U, V, W> = DiskTree<PoseidonHasher<Fp>, U, V, W>;

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}
fn test_winning_post_circuit<U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    info!("test_winning_post_circuit [SectorNodes={}]", SECTOR_NODES);
    let sector_id = 0u64;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let randomness = Fp::random(&mut rng);

    let temp_dir = tempdir().expect("tempdir failure");
    let temp_path = temp_dir.path();
    info!("Creating random TreeR");
    let (replica, tree_r) =
        generate_tree::<TreeR<U, V, W>, _>(&mut rng, SECTOR_NODES, Some(temp_path.to_path_buf()));

    let root_r = tree_r.root();
    let comm_c = Fp::random(&mut rng);
    let comm_r = <PoseidonHasher<Fp> as Hasher>::Function::hash2(&comm_c.into(), &root_r);

    info!("Generating challenges");
    let challenges = winning::generate_challenges::<Fp, SECTOR_NODES>(randomness, sector_id);

    info!("Formatting leafs for TreeR");
    let leafs_r = challenges
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let c = *c as usize;
            let start = c << 5;
            let leaf_bytes = &replica[start..start + 32];
            let mut repr = <Fp as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(leaf_bytes);
            let leaf = Fp::from_repr_vartime(repr).unwrap_or_else(|| {
                panic!("leaf bytes are not a valid field element for c_{}={}", i, c)
            });
            Some(leaf)
        })
        .collect::<Vec<Option<Fp>>>()
        .try_into()
        .unwrap();

    info!("Generating Proof paths for R leaves");
    let paths_r = challenges
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let c = *c as usize;
            let merkle_proof = tree_r
                .gen_proof(c)
                .unwrap_or_else(|_| panic!("failed to generate merkle proof for c_{}={}", i, c));
            merkle_proof
                .path()
                .iter()
                .map(|(siblings, _)| siblings.iter().map(|&sib| Some(sib.into())).collect())
                .collect::<Vec<Vec<Option<Fp>>>>()
        })
        .collect::<Vec<Vec<Vec<Option<Fp>>>>>()
        .try_into()
        .unwrap();

    trace!("Forming public inputs");
    let pub_inputs = winning::PublicInputs::<Fp, SECTOR_NODES> {
        comm_r: Some(comm_r.into()),
        challenges: challenges
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<Option<u32>>>()
            .try_into()
            .unwrap(),
    };
    let pub_inputs_vec = pub_inputs.to_vec();

    trace!("Forming private inputs");
    let priv_inputs = winning::PrivateInputs::<Fp, U, V, W, SECTOR_NODES> {
        comm_c: Some(comm_c),
        root_r: Some(root_r.into()),
        leafs_r,
        paths_r,
        _tree_r: PhantomData,
    };

    let circ = WinningPostCircuit {
        pub_inputs,
        priv_inputs,
    };

    info!("WinningPost Prover starting");
    let prover = MockProver::run(circ.k(), &circ, pub_inputs_vec.clone()).unwrap();
    trace!("WinningPost Prover complete");

    info!("WinningPost Verify starting");
    assert!(prover.verify().is_ok());
    trace!("WinningPost Verify complete");

    let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ).unwrap();
    let proof = create_proof(&keypair, circ, &pub_inputs_vec, &mut rng)
        .expect("failed to generate halo2 proof");
    verify_proof(&keypair, &proof, &pub_inputs_vec).expect("failed to verify halo2 proof");
}

#[test]
fn test_winning_post_circuit_2kib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U0, U0, SECTOR_NODES_2_KIB>()
}

#[test]
fn test_winning_post_circuit_4kib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U2, U0, SECTOR_NODES_4_KIB>()
}

#[test]
fn test_winning_post_circuit_16kib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U8, U0, SECTOR_NODES_16_KIB>()
}

#[test]
fn test_winning_post_circuit_32kib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U8, U2, SECTOR_NODES_32_KIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_winning_post_circuit_512mib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U0, U0, SECTOR_NODES_512_MIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_winning_post_circuit_32gib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U8, U0, SECTOR_NODES_32_GIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_winning_post_circuit_64gib_halo2() {
    init_logger();
    test_winning_post_circuit::<U8, U8, U2, SECTOR_NODES_64_GIB>()
}

fn test_window_post_circuit<U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    info!("test_window_post_circuit [SectorNodes={}]", SECTOR_NODES);
    let challenged_sector_count = window::sectors_challenged_per_partition::<SECTOR_NODES>();
    let k = 0;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let randomness = Fp::random(&mut rng);

    let temp_dir = tempdir().expect("tempdir failure");
    let temp_path = temp_dir.path().to_path_buf();

    trace!("Forming public inputs");
    let mut pub_inputs = window::PublicInputs::<Fp, SECTOR_NODES> {
        comms_r: Vec::with_capacity(challenged_sector_count),
        challenges: Vec::with_capacity(challenged_sector_count),
    };

    trace!("Forming private inputs");
    let mut priv_inputs = window::PrivateInputs::<Fp, U, V, W, SECTOR_NODES> {
        sector_proofs: Vec::with_capacity(challenged_sector_count),
    };

    // Note that for this test, this TreeR is re-used instead of
    // re-generated for each sector (in the interest of runtime)
    trace!("Generating Random TreeR");
    let (replica, tree_r) =
        generate_tree::<TreeR<U, V, W>, _>(&mut rng, SECTOR_NODES, Some(temp_path.clone()));

    let root_r = tree_r.root();
    let comm_c = Fp::random(&mut rng);
    let comm_r = <PoseidonHasher<Fp> as Hasher>::Function::hash2(&comm_c.into(), &root_r);

    info!(
        "Gathering requirements for WindowPost over {} sectors",
        challenged_sector_count
    );
    for sector_index in 0..challenged_sector_count {
        trace!(
            "WindowPoSting over sector index {}/{}",
            sector_index,
            challenged_sector_count
        );
        let sector_id = sector_index as u64;

        trace!("Generating challenges for sector index {}", sector_index);
        let challenges =
            window::generate_challenges::<Fp, SECTOR_NODES>(randomness, k, sector_index, sector_id);

        pub_inputs.comms_r.push(Some(comm_r.into()));
        pub_inputs.challenges.push(
            challenges
                .iter()
                .copied()
                .map(Some)
                .collect::<Vec<Option<u32>>>()
                .try_into()
                .unwrap(),
        );

        trace!("Formatting leafs for TreeR [sector index {}]", sector_index);
        let leafs_r = challenges
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = *c as usize;
                let start = c << 5;
                let leaf_bytes = &replica[start..start + 32];
                let mut repr = <Fp as PrimeField>::Repr::default();
                repr.as_mut().copy_from_slice(leaf_bytes);
                let leaf = Fp::from_repr_vartime(repr).unwrap_or_else(|| {
                    panic!(
                        "leaf bytes are not a valid field element for c_{}={} (sector_{})",
                        i, c, sector_index,
                    )
                });
                Some(leaf)
            })
            .collect::<Vec<Option<Fp>>>()
            .try_into()
            .unwrap();

        trace!(
            "Generating Proof paths for TreeR leaves [sector index {}]",
            sector_index
        );
        let paths_r = challenges
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = *c as usize;
                let merkle_proof = tree_r.gen_proof(c).unwrap_or_else(|_| {
                    panic!(
                        "failed to generate merkle proof for c_{}={} (sector_{})",
                        i, c, sector_index,
                    )
                });
                merkle_proof
                    .path()
                    .iter()
                    .map(|(siblings, _)| siblings.iter().map(|&sib| Some(sib.into())).collect())
                    .collect::<Vec<Vec<Option<Fp>>>>()
            })
            .collect::<Vec<Vec<Vec<Option<Fp>>>>>()
            .try_into()
            .unwrap();

        priv_inputs.sector_proofs.push(SectorProof {
            comm_c: Some(comm_c),
            root_r: Some(root_r.into()),
            leafs_r,
            paths_r,
            _tree_r: PhantomData,
        });
    }

    let pub_inputs_vec = pub_inputs.to_vec();

    let circ = WindowPostCircuit {
        pub_inputs,
        priv_inputs,
    };

    info!("WindowPost Prover starting");
    let prover = MockProver::run(circ.k(), &circ, pub_inputs_vec.clone()).unwrap();
    trace!("WindowPost Prover complete");

    info!("WindowPost Verify starting");
    assert!(prover.verify().is_ok());
    trace!("WindowPost Verify complete");

    let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ).unwrap();
    let proof = create_proof(&keypair, circ, &pub_inputs_vec, &mut rng)
        .expect("failed to generate halo2 proof");
    verify_proof(&keypair, &proof, &pub_inputs_vec).expect("failed to verify halo2 proof");
}

#[test]
fn test_window_post_circuit_2kib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U0, U0, SECTOR_NODES_2_KIB>()
}

#[test]
fn test_window_post_circuit_4kib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U2, U0, SECTOR_NODES_4_KIB>()
}

#[test]
fn test_window_post_circuit_16kib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U8, U0, SECTOR_NODES_16_KIB>()
}

#[test]
fn test_window_post_circuit_32kib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U8, U2, SECTOR_NODES_32_KIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_window_post_circuit_512mib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U0, U0, SECTOR_NODES_512_MIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_window_post_circuit_32gib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U8, U0, SECTOR_NODES_32_GIB>()
}

#[cfg(feature = "big-tests")]
#[test]
fn test_window_post_circuit_64gib_halo2() {
    init_logger();
    test_window_post_circuit::<U8, U8, U2, SECTOR_NODES_64_GIB>()
}
