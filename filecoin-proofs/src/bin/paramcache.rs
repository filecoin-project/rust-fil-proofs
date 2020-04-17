use log::{info, warn};
use rand::rngs::OsRng;
use structopt::StructOpt;

use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{
    public_params, window_post_public_params, winning_post_public_params,
};
use filecoin_proofs::types::*;
use filecoin_proofs::with_shape;
use filecoin_proofs::PoStType;
use std::collections::HashSet;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::porep::stacked::{StackedCompound, StackedDrg};
use storage_proofs::post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};

const PUBLISHED_SECTOR_SIZES: [u64; 11] = [
    SECTOR_SIZE_2_KIB,
    SECTOR_SIZE_4_KIB,
    SECTOR_SIZE_16_KIB,
    SECTOR_SIZE_32_KIB,
    SECTOR_SIZE_8_MIB,
    SECTOR_SIZE_16_MIB,
    SECTOR_SIZE_512_MIB,
    SECTOR_SIZE_1_GIB,
    SECTOR_SIZE_4_GIB,
    SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_64_GIB,
];

fn cache_porep_params<Tree: 'static + MerkleTreeTrait>(porep_config: PoRepConfig) {
    info!("PoRep params");

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    )
    .unwrap();

    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<Tree, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        let _ = StackedCompound::<Tree, DefaultPieceHasher>::get_param_metadata(
            circuit,
            &public_params,
        );
    }
    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<Tree, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        StackedCompound::<Tree, DefaultPieceHasher>::get_groth_params(
            Some(&mut OsRng),
            circuit,
            &public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let circuit = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
            StackedDrg<Tree, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);

        StackedCompound::<Tree, DefaultPieceHasher>::get_verifying_key(
            Some(&mut OsRng),
            circuit,
            &public_params,
        )
        .expect("failed to get verifying key");
    }
}

fn cache_winning_post_params<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) {
    info!("Winning PoSt params");

    let post_public_params = winning_post_public_params::<Tree>(post_config).unwrap();

    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);
        let _ = <FallbackPoStCompound<Tree>>::get_param_metadata(post_circuit, &post_public_params)
            .expect("failed to get metadata");
    }
    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);
        <FallbackPoStCompound<Tree>>::get_groth_params(
            Some(&mut OsRng),
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);

        <FallbackPoStCompound<Tree>>::get_verifying_key(
            Some(&mut OsRng),
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get verifying key");
    }
}

fn cache_window_post_params<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) {
    info!("Window PoSt params");

    let post_public_params = window_post_public_params::<Tree>(post_config).unwrap();

    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);
        let _ = <FallbackPoStCompound<Tree>>::get_param_metadata(post_circuit, &post_public_params)
            .expect("failed to get metadata");
    }
    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);
        <FallbackPoStCompound<Tree>>::get_groth_params(
            Some(&mut OsRng),
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let post_circuit: FallbackPoStCircuit<Tree> =
            <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&post_public_params);

        <FallbackPoStCompound<Tree>>::get_verifying_key(
            Some(&mut OsRng),
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get verifying key");
    }
}

/// Generate and persist Groth parameters and verifying keys for filecoin-proofs.
#[derive(Debug, StructOpt)]
#[structopt(name = "paramcache")]
struct Opt {
    /// Only generate parameters for post.
    #[structopt(long)]
    only_post: bool,
    #[structopt(short = "z", long, use_delimiter = true)]
    params_for_sector_sizes: Vec<u64>,
}

fn generate_params_post(sector_size: u64) {
    with_shape!(
        sector_size,
        cache_winning_post_params,
        &PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINNING_POST_CHALLENGE_COUNT,
            sector_count: WINNING_POST_SECTOR_COUNT,
            typ: PoStType::Winning,
            priority: true,
        }
    );

    with_shape!(
        sector_size,
        cache_window_post_params,
        &PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINDOW_POST_CHALLENGE_COUNT,
            sector_count: *WINDOW_POST_SECTOR_COUNT
                .read()
                .unwrap()
                .get(&sector_size)
                .unwrap(),
            typ: PoStType::Window,
            priority: true,
        }
    );
}

fn generate_params_porep(sector_size: u64) {
    with_shape!(
        sector_size,
        cache_porep_params,
        PoRepConfig {
            sector_size: SectorSize(sector_size),
            partitions: PoRepProofPartitions(
                *POREP_PARTITIONS
                    .read()
                    .unwrap()
                    .get(&sector_size)
                    .expect("missing sector size"),
            ),
        }
    );
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    fil_logger::init();

    let opts = Opt::from_args();

    let sizes: HashSet<u64> = if opts.params_for_sector_sizes.is_empty() {
        PUBLISHED_SECTOR_SIZES.iter().cloned().collect()
    } else {
        opts.params_for_sector_sizes
            .into_iter()
            .filter(|size| {
                if PUBLISHED_SECTOR_SIZES.contains(size) {
                    return true;
                }

                warn!("ignoring invalid sector size: {}", size);
                false
            })
            .collect()
    };

    let only_post = opts.only_post;

    for sector_size in sizes {
        info!("Sector Size: {}", sector_size);

        generate_params_post(sector_size);

        if !only_post {
            generate_params_porep(sector_size);
        }
    }
}
