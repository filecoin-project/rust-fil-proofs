use anyhow::Result;
use log::info;
use merkletree::merkle::{is_merkle_tree_size_valid, FromIndexedParallelIterator, MerkleTree};
use merkletree::store::DiskStore;
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use storage_proofs::hasher::{Domain, Hasher, PoseidonHasher};
use storage_proofs::util::NODE_SIZE;
use typenum::{Unsigned, U16, U2, U4, U8};

#[allow(clippy::type_complexity)]
fn generate_tree<R: Rng, U: Unsigned>(
    rng: &mut R,
    size: usize,
) -> Result<
    MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        U,
    >,
> {
    let el = <PoseidonHasher as Hasher>::Domain::random(rng);
    info!("create tree {} KiB", (size * NODE_SIZE) / 1024);
    MerkleTree::from_par_iter((0..size).into_par_iter().map(|_| el))
}

fn generate_proofs<R: Rng, U: Unsigned>(
    rng: &mut R,
    tree: MerkleTree<
        <PoseidonHasher as Hasher>::Domain,
        <PoseidonHasher as Hasher>::Function,
        DiskStore<<PoseidonHasher as Hasher>::Domain>,
        U,
    >,
    nodes: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    info!("creating {} inclusion proofs", proofs_count);

    let mut proofs = Vec::with_capacity(proofs_count);
    for _ in 0..proofs_count {
        let challenge = rng.gen_range(0, nodes);

        proofs.push(tree.gen_proof(challenge)?);
    }
    assert_eq!(proofs.len(), proofs_count);

    info!("proofs created");

    if validate {
        info!("validating proofs");

        for proof in proofs {
            assert!(proof.validate::<<PoseidonHasher as Hasher>::Function>());
        }

        info!("all proofs validated");
    }

    Ok(())
}

pub fn run(size: usize, proofs_count: usize, arity: usize, validate: bool) -> Result<()> {
    let mut rng = thread_rng();

    let nodes = size / NODE_SIZE;

    info!(
        "is_merkle_tree_size_valid({}, {})? {}",
        nodes,
        arity,
        is_merkle_tree_size_valid(nodes, arity)
    );
    assert!(is_merkle_tree_size_valid(nodes, arity));

    if arity == 2 {
        let tree = generate_tree::<_, U2>(&mut rng, nodes)?;
        return generate_proofs::<_, U2>(&mut rng, tree, nodes, proofs_count, validate);
    } else if arity == 4 {
        let tree = generate_tree::<_, U4>(&mut rng, nodes)?;
        return generate_proofs::<_, U4>(&mut rng, tree, nodes, proofs_count, validate);
    } else if arity == 8 {
        let tree = generate_tree::<_, U8>(&mut rng, nodes)?;
        return generate_proofs::<_, U8>(&mut rng, tree, nodes, proofs_count, validate);
    } else if arity == 16 {
        let tree = generate_tree::<_, U16>(&mut rng, nodes)?;
        return generate_proofs::<_, U16>(&mut rng, tree, nodes, proofs_count, validate);
    }

    panic!("Invalid arity specified")
}
