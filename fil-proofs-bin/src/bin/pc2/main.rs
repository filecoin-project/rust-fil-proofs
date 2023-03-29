use std::fmt;
use std::fs::{OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use filecoin_proofs::{
    get_base_tree_leafs, get_base_tree_size, parameters::setup_params, DefaultBinaryTree,
    DefaultPieceHasher, PaddedBytesAmount,
};
use log::{info, trace};
use memmap2::MmapOptions;
use merkletree::store::{DiskStore, StoreConfig, Store};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, drgraph::BASE_DEGREE, proof::ProofScheme,
    util::default_rows_to_discard, merkle::BinaryMerkleTree, Data
};
use storage_proofs_porep::stacked::{
    LayerChallenges, SetupParams, StackedDrg, BINARY_ARITY, EXP_DEGREE, Labels,
};

type DefaultStackedDrg<'a> = StackedDrg<'a, DefaultBinaryTree, DefaultPieceHasher>;

#[derive(Deserialize, Serialize)]
struct Pc2Parameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    ///// The path to the Merkle tree that was built on top of the original sector data.
    //data_tree_path: PathBuf,
    // TODO vmx 2023-03-28: Think about if "layers" should be called "labels" to match the rest of
    // the code base. I'm currently unsure which name is better.
    ///// The layers from the SDR operation.
    //layers: Vec<PathBuf>,
    num_layers: usize,
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    partitions: usize,
    #[serde(with = "SerHex::<StrictPfx>")]
    porep_id: [u8; 32],
    /// This is a path to a copy of the original sector data that will be manipulated in-place.
    //replica_path: PathBuf,
    replica_path: String,
    sector_size: u64,
}

// TODO vmx 2023-03-29: update that oen to actually print all members
impl fmt::Debug for Pc2Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdrParameters")
            .field("num_layers", &self.num_layers)
            .field("output_dir", &self.output_dir)
            .field("porep_id", &format!("0x{}", hex::encode(self.porep_id)))
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct SdrOutput {
    layers: Vec<PathBuf>,
}

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<Pc2Parameters, serde_json::Error> {
    let line = input
        .lines()
        .next()
        .expect("Nothing to iterate")
        .expect("Failed to read line");
    serde_json::from_str(&line)
}

/// Outputs an object serialized as JSON.
fn print_line<W: Write, S: Serialize>(output: &mut W, data: S) -> Result<()> {
    let line = serde_json::to_vec(&data)?;
    output.write_all(&line)?;
    output.write_all(&[b'\n'])?;
    Ok(())
}

// TODO vmx 2023-03-19: Think about calling seal_pre_commit_phase2 directly as this function really
// is kind of the same. I'd only need to construct PoRepConfig and SealPreCommitPhase1Output from
// the input parameters.
fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params = parse_line(BufReader::new(io::stdin()))?;
    info!("{:?}", params);

    //DO the steps from seal_pre_commit_phase2 (in /home/vmx/src/pl/filecoin/rust-fil-proofs/filecoin-proofs/src/api/seal.rs).

    let setup_params = DefaultStackedDrg::setup(&setup_params(
        PaddedBytesAmount(params.sector_size),
        params.partitions,
        params.porep_id,
        // TODO vmx 2023-03-29: the api version should be a shared constant across all binaries.
        ApiVersion::V1_2_0,
    )?)?;

    //let config = StoreConfig::new(
    //    PathBuf::from(params.output_dir),
    //    CacheKey::CommDTree.to_string(),
    //    default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
    //);

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&params.replica_path)
        .with_context(|| {
            format!(
                "could not open replica_path={:?}",
                params.replica_path
            )
        })?;
    let data = unsafe {
        MmapOptions::new().map_mut(&f_data).with_context(|| {
            format!(
                "could not mmap replica_path={:?}",
                //params.replica_path.as_ref().display()
                params.replica_path
            )
        })?
    };
    let data: Data<'_> = (data, params.replica_path.clone().into()).into();

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(params.sector_size.into())?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;

    // Load data tree from disk
    let data_tree = {
        trace!(
            "sector_size: {}, base tree size {}, base tree leafs {}",
            params.sector_size,
            base_tree_size,
            base_tree_leafs,
        );
        let config = StoreConfig::new(
            PathBuf::from(params.output_dir.clone()),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        );

        //let store: DiskStore<DefaultPieceDomain> =
        let store  =
            DiskStore::new_from_disk(base_tree_size, BINARY_ARITY, &config)?;
        BinaryMerkleTree::<DefaultPieceHasher>::from_data_store(store, base_tree_leafs)?
    };
    trace!("vmx: data_tree len: {}", data_tree.len());

    let labels = (1..=params.num_layers).map(|layer| {
        StoreConfig {
            path: params.output_dir.clone().into(),
            id: CacheKey::label_layer(layer),
            size: Some(data_tree.len()),
            rows_to_discard: default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        }
    }).collect();

    let (tau, (p_aux, t_aux)) = DefaultStackedDrg::replicate_phase2(
        &setup_params,
        Labels::new(labels),
        data,
        Some(data_tree),
        params.output_dir.into(),
        params.replica_path.into()
    )?;



    //let output = SdrOutput { layers };
    //info!("{:?}", output);
    //print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
