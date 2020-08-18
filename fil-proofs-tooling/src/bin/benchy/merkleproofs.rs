use std::fs::{create_dir, remove_dir_all};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use filecoin_proofs::with_shape;
use log::{debug, info};
use rand::{thread_rng, Rng};
use storage_proofs::hasher::Hasher;
use storage_proofs::merkle::{
    generate_tree, get_base_tree_count, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper,
};
use storage_proofs::util::default_rows_to_discard;
use typenum::Unsigned;

fn generate_proofs<R: Rng, Tree: MerkleTreeTrait>(
    rng: &mut R,
    tree: &MerkleTreeWrapper<
        <Tree as MerkleTreeTrait>::Hasher,
        <Tree as MerkleTreeTrait>::Store,
        <Tree as MerkleTreeTrait>::Arity,
        <Tree as MerkleTreeTrait>::SubTreeArity,
        <Tree as MerkleTreeTrait>::TopTreeArity,
    >,
    base_tree_nodes: usize,
    nodes: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let proofs_count = if proofs_count >= nodes {
        info!(
            "requested {} proofs, but instead challenging all {} nodes sequentially",
            proofs_count, nodes
        );

        nodes
    } else {
        proofs_count
    };

    info!(
        "creating {} inclusion proofs over {} nodes (validate enabled? {})",
        proofs_count, nodes, validate
    );

    let rows_to_discard = default_rows_to_discard(
        base_tree_nodes,
        <Tree as MerkleTreeTrait>::Arity::to_usize(),
    );
    for i in 0..proofs_count {
        let challenge = if proofs_count == nodes {
            i
        } else {
            rng.gen_range(0, nodes)
        };
        debug!("challenge[{}] = {}", i, challenge);
        let proof = tree
            .gen_cached_proof(challenge, Some(rows_to_discard))
            .expect("failed to generate proof");
        if validate {
            assert!(proof.validate(challenge));
        }
    }

    Ok(())
}

pub fn run_merkleproofs_bench<Tree: 'static + MerkleTreeTrait>(
    size: usize,
    proofs_count: usize,
    validate: bool,
) -> Result<()> {
    let tree_count = get_base_tree_count::<Tree>();
    let base_tree_leaves =
        size / std::mem::size_of::<<Tree::Hasher as Hasher>::Domain>() / tree_count;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let temp_path = std::env::temp_dir().join(format!("merkle-proof-bench-{}", timestamp));
    create_dir(&temp_path)?;

    let mut rng = thread_rng();
    info!(
        "generating merkle tree for sector size {} [base_tree_leaves {}, tree_count {}]",
        size, base_tree_leaves, tree_count
    );
    let (_data, tree) = generate_tree::<Tree, _>(
        &mut rng,
        base_tree_leaves * tree_count,
        Some(temp_path.clone()),
    );
    generate_proofs::<_, Tree>(
        &mut rng,
        &tree,
        base_tree_leaves,
        base_tree_leaves * tree_count,
        proofs_count,
        validate,
    )?;

    remove_dir_all(&temp_path)?;

    Ok(())
}

pub fn run(size: usize, proofs_count: usize, validate: bool) -> Result<()> {
    with_shape!(
        size as u64,
        run_merkleproofs_bench,
        size,
        proofs_count,
        validate
    )
}
