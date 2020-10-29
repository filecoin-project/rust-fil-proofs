use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use anyhow::Result;
use clap::{value_t, App, Arg};
use serde::{Deserialize, Serialize};

use filecoin_proofs::constants::*;
use filecoin_proofs::types::*;
use filecoin_proofs::with_shape;
use storage_proofs::hasher::Sha256Hasher;
use storage_proofs::porep::stacked::{LayerChallenges, SetupParams, StackedDrg};
use storage_proofs::proof::ProofScheme;

const PARENT_CACHE_JSON_OUTPUT: &str = "./parent_cache.json";

pub type ParentCacheSummaryMap = BTreeMap<String, ParentCacheSummary>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParentCacheSummary {
    pub sector_size: usize,
    pub digest: String,
}

fn gen_graph_cache<Tree: 'static + MerkleTreeTrait>(
    sector_size: usize,
    porep_id: [u8; 32],
    parent_cache_summary_map: &mut ParentCacheSummaryMap,
) -> Result<()> {
    let nodes = (sector_size / 32) as usize;
    let drg_degree = filecoin_proofs::constants::DRG_DEGREE;
    let expansion_degree = filecoin_proofs::constants::EXP_DEGREE;

    // Note that layers and challenge_count don't affect the graph, so
    // we just use dummy values of 1 for the setup params.
    let layers = 1;
    let challenge_count = 1;
    let layer_challenges = LayerChallenges::new(layers, challenge_count);

    let sp = SetupParams {
        nodes,
        degree: drg_degree,
        expansion_degree,
        porep_id,
        layer_challenges,
    };

    let pp = StackedDrg::<Tree, Sha256Hasher>::setup(&sp).expect("failed to setup DRG");
    let parent_cache = pp.graph.parent_cache()?;

    let data = ParentCacheSummary {
        digest: parent_cache.digest,
        sector_size: parent_cache.sector_size,
    };
    parent_cache_summary_map.insert(
        parent_cache
            .path
            .file_stem()
            .expect("file_stem failure")
            .to_str()
            .expect("file stem to_str failure")
            .to_string(),
        data,
    );

    Ok(())
}

fn main() -> Result<()> {
    fil_logger::init();

    let matches = App::new("gen_graph_cache")
        .version("0.1")
        .about("Generates and/or verifies parent graph cache files")
        .arg(
            Arg::with_name("json")
                .long("json")
                .help("Creates a new json output file.")
                .default_value("false"),
        )
        .arg(
            Arg::with_name("size")
                .long("size")
                .help("Generate and/or verify the graph cache files for a single sector size")
                .default_value("0"),
        )
        .get_matches();

    // NOTE: The porep_ids below are tied to the versioned values provided in
    // filecoin-proofs-api:src/registry [porep_id()] that matches the specified
    // sector size and must be updated when that value is updated for the proper
    // graph cache generation/validation.
    //
    // If this value changes, previously existing cache files will no longer be
    // used and new cache files will be generated.
    let sector_sizes_and_porep_ids: Vec<(u64, [u8; 32])> = vec![
        (
            SECTOR_SIZE_2_KIB,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_8_MIB,
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_512_MIB,
            [
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_32_GIB,
            [
                3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_64_GIB,
            [
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_2_KIB, // v1.1
            [
                5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_8_MIB, // v1.1
            [
                6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_512_MIB, // v1.1
            [
                7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_32_GIB, // v1.1
            [
                8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
        (
            SECTOR_SIZE_64_GIB, // v1.1
            [
                9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        ),
    ];

    let supported_sector_sizes = sector_sizes_and_porep_ids
        .iter()
        .map(|vals| vals.0)
        .collect::<Vec<u64>>();
    let mut parent_cache_summary_map: ParentCacheSummaryMap = BTreeMap::new();

    let size = value_t!(matches, "size", u64).expect("failed to get size");
    let json = value_t!(matches, "json", bool).expect("failed to get json");

    if size == 0 {
        println!(
            "gen_graph_cache: sizes {:?}, output json {}",
            supported_sector_sizes, json
        );
    } else if supported_sector_sizes.contains(&size) {
        println!("gen_graph_cache: size {}, output json {}", size, json);
    } else {
        println!(
            "Unsupported sector size {} (must be one of {:?})",
            size, supported_sector_sizes
        );
        return Ok(());
    }

    for (sector_size, porep_id) in sector_sizes_and_porep_ids {
        // 'size' 0 indicates no size was specified, so we run all sizes.
        if size != 0 && size != sector_size {
            continue;
        }

        with_shape!(
            sector_size as u64,
            gen_graph_cache,
            sector_size as usize,
            porep_id,
            &mut parent_cache_summary_map,
        )?;
    }

    // Output all json to PARENT_CACHE_JSON_OUTPUT in the current
    // directory.
    if json {
        let json_output_path = Path::new(PARENT_CACHE_JSON_OUTPUT);
        let json_file = File::create(&json_output_path)?;
        let writer = BufWriter::new(json_file);
        serde_json::to_writer_pretty(writer, &parent_cache_summary_map)?;
        println!("Wrote {:?}", json_output_path);
    } else {
        println!("{:?}", parent_cache_summary_map);
    }

    Ok(())
}
