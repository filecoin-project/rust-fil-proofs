// Creates the merkle proofs out of the given challenges. This is the same binary for Interactive
// and Non-interactive PoReps. Synthetic PoReps have a different (two phases) approach.

use std::{fs, marker::PhantomData, path::PathBuf};

use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Hasher;
use filecoin_proofs::{with_shape, DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE};
use generic_array::typenum::Unsigned;
use log::info;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, merkle::MerkleTreeTrait, util::NODE_SIZE,
};
use storage_proofs_porep::stacked::{
    Labels, PublicInputs, StackedBucketGraph, StackedDrg, SynthProofs, Tau, TemporaryAux,
    TemporaryAuxCache, BINARY_ARITY,
};

/// Note that `comm_c` and `comm_d` are not strictly needed as they could be read from the
/// generated trees. Though they are passed in for sanity checking.
#[derive(Debug, Deserialize, Serialize)]
struct MerkleProofsParameters {
    challenges: Vec<usize>,
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_c: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    /// The directory where the trees are stored.
    input_dir: String,
    num_layers: usize,
    num_partitions: usize,
    /// The path to the file the proofs should be stored into.
    output_path: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    porep_id: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    replica_path: String,
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct MerkleProofsOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

// TODO vmx 2023-09-15: This is a copy of `TemporaryAux::new()` which is only available on a branch
// at the moment, hence this code is copied here. Once merged, this can be removed.
fn new_temporary_aux<Tree: MerkleTreeTrait>(
    sector_nodes: usize,
    num_layers: usize,
    cache_path: PathBuf,
) -> TemporaryAux<Tree, Sha256Hasher> {
    use merkletree::merkle::get_merkle_tree_len;
    use storage_proofs_core::{merkle::get_base_tree_count, util};

    let labels = (1..=num_layers)
        .map(|layer| StoreConfig {
            path: cache_path.clone(),
            id: CacheKey::label_layer(layer),
            size: Some(sector_nodes),
            rows_to_discard: 0,
        })
        .collect();

    let tree_d_size = get_merkle_tree_len(sector_nodes, BINARY_ARITY)
        .expect("Tree must have enough leaves and have an arity of power of two");
    let tree_d_config = StoreConfig {
        path: cache_path.clone(),
        id: CacheKey::CommDTree.to_string(),
        size: Some(tree_d_size),
        rows_to_discard: 0,
    };

    let tree_count = get_base_tree_count::<Tree>();
    let tree_nodes = sector_nodes / tree_count;
    let tree_size = get_merkle_tree_len(tree_nodes, Tree::Arity::to_usize())
        .expect("Tree must have enough leaves and have an arity of power of two");

    let tree_r_last_config = StoreConfig {
        path: cache_path.clone(),
        id: CacheKey::CommRLastTree.to_string(),
        size: Some(tree_size),
        rows_to_discard: util::default_rows_to_discard(tree_nodes, Tree::Arity::to_usize()),
    };

    let tree_c_config = StoreConfig {
        path: cache_path,
        id: CacheKey::CommCTree.to_string(),
        size: Some(tree_size),
        rows_to_discard: 0,
    };

    TemporaryAux {
        labels: Labels::new(labels),
        tree_d_config,
        tree_r_last_config,
        tree_c_config,
        _g: PhantomData,
    }
}

#[allow(clippy::too_many_arguments)]
fn merkle_proofs<Tree: 'static + MerkleTreeTrait>(
    challenges: Vec<usize>,
    comm_c: [u8; 32],
    comm_d: [u8; 32],
    input_dir: String,
    num_layers: usize,
    num_partitions: usize,
    porep_id: [u8; 32],
    replica_id: [u8; 32],
    replica_path: String,
    sector_size: u64,
    seed: [u8; 32],
) -> Result<Vec<u8>> {
    let sector_nodes = (sector_size as usize) / NODE_SIZE;
    let graph = StackedBucketGraph::<Tree::Hasher>::new_stacked(
        sector_nodes,
        DRG_DEGREE,
        EXP_DEGREE,
        porep_id,
        ApiVersion::V1_2_0,
    )?;
    let tau = Tau {
        comm_d: comm_d.into(),
        // `comm_r` is not used during merkle proof generation, hence we can set it to an
        // arbitrary value.
        comm_r: [1u8; 32].into(),
    };
    let public_inputs = PublicInputs {
        replica_id: replica_id.into(),
        tau: Some(tau),
        k: None,
        seed: Some(seed),
    };
    let t_aux = new_temporary_aux(
        sector_size as usize / NODE_SIZE,
        num_layers,
        PathBuf::from(&input_dir),
    );
    let t_aux_cache = TemporaryAuxCache::new(&t_aux, replica_path.into(), false)
        .expect("failed to restore contents of t_aux");

    let num_challenges = challenges.len() / num_partitions;
    let all_partition_proofs = challenges
        .chunks_exact(num_challenges)
        .map(|challenge_positions| {
            StackedDrg::<Tree, DefaultPieceHasher>::prove_layers_generate(
                &graph,
                &public_inputs,
                comm_c.into(),
                &t_aux_cache,
                challenge_positions.to_vec(),
                num_layers,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    // For serialization we pretend that all proofs are in a single partition.
    let proofs_single_partition = all_partition_proofs
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut proofs_bytes = Vec::new();
    SynthProofs::write(&mut proofs_bytes, &proofs_single_partition[..])
        .expect("serializtion into vector always succeeds");
    Ok(proofs_bytes)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: MerkleProofsParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let proofs = with_shape!(
        params.sector_size,
        merkle_proofs,
        params.challenges,
        params.comm_c,
        params.comm_d,
        params.input_dir,
        params.num_layers,
        params.num_partitions,
        params.porep_id,
        params.replica_id,
        params.replica_path,
        params.sector_size,
        params.seed,
    )?;

    fs::write(&params.output_path, proofs)?;

    let output = MerkleProofsOutput::default();
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
