use anyhow::Result;

use filecoin_proofs::constants::*;
use filecoin_proofs::types::*;
use filecoin_proofs::with_shape;
use storage_proofs::hasher::Sha256Hasher;
use storage_proofs::porep::stacked::{LayerChallenges, SetupParams, StackedDrg};
use storage_proofs::proof::ProofScheme;

fn gen_graph_cache<Tree: 'static + MerkleTreeTrait>(
    sector_size: usize,
    challenge_count: usize,
    layers: usize,
) -> Result<()> {
    let nodes = (sector_size / 32) as usize;
    let drg_degree = filecoin_proofs::constants::DRG_DEGREE;
    let expansion_degree = filecoin_proofs::constants::EXP_DEGREE;
    let layer_challenges = LayerChallenges::new(layers, challenge_count);

    // NOTE: This porep_id is tied to the versioned value provided in
    // filecoin-proofs-api:src/registry [porep_id()] and must be
    // updated when that value is updated for the proper graph cache.
    let arbitrary_porep_id = [0; 32];
    let sp = SetupParams {
        nodes,
        degree: drg_degree,
        expansion_degree,
        porep_id: arbitrary_porep_id,
        layer_challenges,
    };

    let pp = StackedDrg::<Tree, Sha256Hasher>::setup(&sp).expect("failed to setup DRG");

    pp.graph.parent_cache()?;

    Ok(())
}

fn main() -> Result<()> {
    fil_logger::init();

    let supported_sector_sizes = vec![
        SECTOR_SIZE_2_KIB,
        SECTOR_SIZE_4_KIB,
        SECTOR_SIZE_16_KIB,
        SECTOR_SIZE_32_KIB,
        SECTOR_SIZE_8_MIB,
        SECTOR_SIZE_16_MIB,
        SECTOR_SIZE_512_MIB,
        SECTOR_SIZE_1_GIB,
        SECTOR_SIZE_32_GIB,
        SECTOR_SIZE_64_GIB,
    ];

    for sector_size in supported_sector_sizes {
        let challenge_count = *filecoin_proofs::constants::POREP_MINIMUM_CHALLENGES
            .read()
            .expect("POREP_MINIMUM_CHALLENGES read failure")
            .get(&sector_size)
            .expect("unknown sector size") as usize;

        let layers = *filecoin_proofs::constants::LAYERS
            .read()
            .expect("LAYERS read failure")
            .get(&sector_size)
            .expect("unknown sector size") as usize;

        with_shape!(
            sector_size as u64,
            gen_graph_cache,
            sector_size as usize,
            challenge_count,
            layers
        )?;
    }

    Ok(())
}
