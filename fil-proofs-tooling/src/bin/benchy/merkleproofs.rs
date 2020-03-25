use anyhow::Result;
use log::info;
use merkletree::merkle::{is_merkle_tree_size_valid, FromIndexedParallelIterator, MerkleTree};
use merkletree::store::DiskStore;
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use storage_proofs::hasher::{Domain, Hasher, PoseidonHasher};
use storage_proofs::util::NODE_SIZE;
use typenum::{Unsigned, U0, U1, U2, U8};

#[allow(clippy::type_complexity)]
fn generate_tree<R: Rng, BaseTreeArity: Unsigned>(
    rng: &mut R,
    size: usize,
) -> Result<
    MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        BaseTreeArity,
    >,
> {
    let el = <PoseidonHasher as Hasher>::Domain::random(rng);
    info!("--- create tree {} KiB", (size * NODE_SIZE) / 1024);
    MerkleTree::from_par_iter((0..size).into_par_iter().map(|_| el))
}

#[allow(clippy::type_complexity)]
fn generate_sub_tree<R: Rng, BaseTreeArity: Unsigned, SubTreeArity: Unsigned>(
    rng: &mut R,
    size: usize,
) -> Result<
    MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        BaseTreeArity,
        SubTreeArity,
    >,
> {
    let base_tree_count = BaseTreeArity::to_usize();
    let mut trees = Vec::with_capacity(base_tree_count);
    info!("-- create sub-tree {} KiB", (size * NODE_SIZE) / 1024);
    for _ in 0..base_tree_count {
        trees.push(generate_tree::<R, BaseTreeArity>(
            rng,
            size / base_tree_count,
        )?);
    }

    MerkleTree::from_trees(trees)
}

#[allow(clippy::type_complexity)]
fn generate_proofs<
    R: Rng,
    BaseTreeArity: Unsigned,
    SubTreeArity: Unsigned,
    TopTreeArity: Unsigned,
>(
    rng: &mut R,
    tree: MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        BaseTreeArity,
        SubTreeArity,
        TopTreeArity,
    >,
    nodes: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    info!("creating {} inclusion proofs", proofs_count);

    for _ in 0..proofs_count {
        let challenge = rng.gen_range(0, nodes);
        let proof = tree.gen_proof(challenge).expect("failed to generate proof");
        if validate {
            assert!(proof
                .validate::<<PoseidonHasher as Hasher>::Function>()
                .expect("failed to validate"));
        }
    }

    Ok(())
}

fn run_tree_bench<R: Rng, BaseTreeArity: Unsigned, SubTreeArity: Unsigned>(
    rng: &mut R,
    nodes: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let arity = BaseTreeArity::to_usize();
    let tree_count = SubTreeArity::to_usize();

    info!(
        "is_merkle_tree_size_valid({}, {})? {}",
        nodes,
        arity,
        is_merkle_tree_size_valid(nodes / tree_count, arity)
    );
    assert!(is_merkle_tree_size_valid(nodes / tree_count, arity));

    let mut trees = Vec::with_capacity(tree_count);
    for _ in 0..tree_count {
        trees.push(generate_tree::<R, BaseTreeArity>(rng, nodes / tree_count)?);
    }

    let tree: MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        BaseTreeArity,
        SubTreeArity,
    > = MerkleTree::from_trees(trees)?;

    generate_proofs::<R, BaseTreeArity, SubTreeArity, U0>(rng, tree, nodes, proofs_count, validate)
}

fn run_top_tree_bench<
    R: Rng,
    BaseTreeArity: Unsigned,
    SubTreeArity: Unsigned,
    TopTreeArity: Unsigned,
>(
    rng: &mut R,
    nodes: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let base_tree_count = BaseTreeArity::to_usize();
    let sub_tree_count = SubTreeArity::to_usize();
    let top_tree_count = TopTreeArity::to_usize();

    info!(
        "base layer check: is_merkle_tree_size_valid({}, {})? {}",
        nodes / top_tree_count / sub_tree_count / base_tree_count,
        base_tree_count,
        is_merkle_tree_size_valid(
            nodes / top_tree_count / sub_tree_count / base_tree_count,
            base_tree_count
        )
    );
    assert!(is_merkle_tree_size_valid(
        nodes / top_tree_count / sub_tree_count / base_tree_count,
        base_tree_count
    ));

    info!(
        "sub-tree layer check: is_merkle_tree_size_valid({}, {})? {}",
        nodes / top_tree_count / sub_tree_count,
        sub_tree_count,
        is_merkle_tree_size_valid(nodes / top_tree_count / sub_tree_count, sub_tree_count)
    );
    assert!(is_merkle_tree_size_valid(
        nodes / top_tree_count / sub_tree_count,
        sub_tree_count
    ));

    info!(
        "top-tree layer check: is_merkle_tree_size_valid({}, {})? {}",
        nodes / top_tree_count,
        top_tree_count,
        is_merkle_tree_size_valid(nodes / top_tree_count, top_tree_count)
    );
    assert!(is_merkle_tree_size_valid(
        nodes / top_tree_count,
        sub_tree_count
    ));

    let mut sub_trees = Vec::with_capacity(sub_tree_count);
    for i in 0..top_tree_count {
        info!(
            "- create top-tree layer {}/{} -- {} KiB",
            i + 1,
            top_tree_count,
            (nodes * NODE_SIZE) / top_tree_count / 1024
        );
        sub_trees.push(generate_sub_tree::<R, BaseTreeArity, SubTreeArity>(
            rng,
            nodes / top_tree_count,
        )?);
    }

    let tree = MerkleTree::from_sub_trees(sub_trees)?;

    generate_proofs::<R, BaseTreeArity, SubTreeArity, TopTreeArity>(
        rng,
        tree,
        nodes,
        proofs_count,
        validate,
    )
}

pub fn run(size: usize, proofs_count: usize, validate: bool) -> Result<()> {
    // These sizes are supported without requiring compound merkle trees.
    // Valid --size args are: 2, 8192, 524288, 33554432
    pub const SECTOR_SIZE_2_KIB: u64 = 2_048;
    pub const SECTOR_SIZE_8_MIB: u64 = 1 << 23;
    pub const SECTOR_SIZE_512_MIB: u64 = 1 << 29;
    pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

    // These sizes require compound merkle trees.
    // Valid --size args are: 4, 16384, 1048576, 67108864
    pub const SECTOR_SIZE_4_KIB: u64 = 2 * SECTOR_SIZE_2_KIB;
    pub const SECTOR_SIZE_16_MIB: u64 = 2 * SECTOR_SIZE_8_MIB;
    pub const SECTOR_SIZE_1_GIB: u64 = 2 * SECTOR_SIZE_512_MIB;
    pub const SECTOR_SIZE_64_GIB: u64 = 2 * SECTOR_SIZE_32_GIB;

    let mut rng = thread_rng();

    let nodes = size / NODE_SIZE;
    info!("sector size of {} consists of {} nodes", size, nodes);

    match size as u64 {
        // 2 KIB sectors are composed of a single 2KIB tree of arity 8.
        SECTOR_SIZE_2_KIB => run_tree_bench::<_, U8, U1>(&mut rng, nodes, proofs_count, validate),
        // 4 KIB sectors are composed of 2 2KIB trees each of arity 8.
        SECTOR_SIZE_4_KIB => run_tree_bench::<_, U8, U2>(&mut rng, nodes, proofs_count, validate),
        // 8 MIB sectors are composed of a single 8MIB tree of arity 8.
        SECTOR_SIZE_8_MIB => run_tree_bench::<_, U8, U1>(&mut rng, nodes, proofs_count, validate),
        // 16 MIB sectors are composed of 2 8MIB trees each of arity 8.
        SECTOR_SIZE_16_MIB => run_tree_bench::<_, U8, U2>(&mut rng, nodes, proofs_count, validate),
        // 512 MIB sectors are composed of a single 512MIB tree of arity 8.
        SECTOR_SIZE_512_MIB => run_tree_bench::<_, U8, U1>(&mut rng, nodes, proofs_count, validate),
        // 1 GIB sectors are composed of 2 512MB trees each of arity 8.
        SECTOR_SIZE_1_GIB => run_tree_bench::<_, U8, U2>(&mut rng, nodes, proofs_count, validate),
        // 32 GIB sectors are composed of 8 4GIB trees each of arity 8.
        SECTOR_SIZE_32_GIB => run_tree_bench::<_, U8, U8>(&mut rng, nodes, proofs_count, validate),
        // 64 GIB sectors are composed of 2 32 GIB trees.
        SECTOR_SIZE_64_GIB => run_top_tree_bench::<_, U8, U8, U2>(&mut rng, nodes, proofs_count, validate),
        _ => panic!("Invalid sector size specified (valid values are: 2, 4, 8192, 16384, 524288, 1048576, 33554432, 67108864)")
    }
}
