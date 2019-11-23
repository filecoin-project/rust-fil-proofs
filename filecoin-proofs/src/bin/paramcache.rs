#[macro_use]
extern crate log;

use clap::{values_t, App, Arg};
use paired::bls12_381::Bls12;

use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{post_public_params, public_params};
use filecoin_proofs::types::*;
use std::collections::HashSet;
use storage_proofs::circuit::election_post::{ElectionPoStCircuit, ElectionPoStCompound};
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::election_post::ElectionPoSt;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::stacked::StackedDrg;

const POREP_PROOF_PARTITION_CHOICES: [PoRepProofPartitions; 1] = [PoRepProofPartitions(2)];

const PUBLISHED_SECTOR_SIZES: [(u64, usize); 4] = [
    (SECTOR_SIZE_ONE_KIB, WINDOW_SIZE_NODES_ONE_KIB),
    (SECTOR_SIZE_16_MIB, WINDOW_SIZE_NODES_16_MIB),
    (SECTOR_SIZE_256_MIB, WINDOW_SIZE_NODES_256_MIB),
    (SECTOR_SIZE_1_GIB, WINDOW_SIZE_NODES_1_GIB),
];

fn cache_porep_params(porep_config: PoRepConfig) {
    let n = u64::from(PaddedBytesAmount::from(porep_config));
    info!(
        "begin PoRep parameter-cache check/populate routine for {}-byte sectors",
        n
    );

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.window_size_nodes,
    );

    {
        let circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        let _ = StackedCompound::get_param_metadata(circuit, &public_params);
    }
    {
        let circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        let _ = StackedCompound::get_groth_params(circuit, &public_params);
    }
    {
        let circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        let _ = StackedCompound::get_verifying_key(circuit, &public_params);
    }
}

fn cache_post_params(post_config: PoStConfig) {
    let n = u64::from(PaddedBytesAmount::from(post_config));
    info!(
        "begin PoSt parameter-cache check/populate routine for {}-byte sectors",
        n
    );

    let post_public_params = post_public_params(post_config);

    {
        let post_circuit: ElectionPoStCircuit<Bls12, PedersenHasher> =
            <ElectionPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                ElectionPoSt<PedersenHasher>,
                ElectionPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params);
        let _ = <ElectionPoStCompound<PedersenHasher>>::get_param_metadata(
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get metadata");
    }
    {
        let post_circuit: ElectionPoStCircuit<Bls12, PedersenHasher> =
            <ElectionPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                ElectionPoSt<PedersenHasher>,
                ElectionPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params);
        let _ = <ElectionPoStCompound<PedersenHasher>>::get_groth_params(
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let post_circuit: ElectionPoStCircuit<Bls12, PedersenHasher> =
            <ElectionPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                ElectionPoSt<PedersenHasher>,
                ElectionPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params);

        let _ = <ElectionPoStCompound<PedersenHasher>>::get_verifying_key(
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get verifying key");
    }
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    pretty_env_logger::init_timed();

    let matches = App::new("paramcache")
        .version("0.1")
        .about("Generate and persist Groth parameters and verifying keys")
        .arg(
            Arg::with_name("params-for-sector-sizes")
                .short("z")
                .long("params-for-sector-sizes")
                .conflicts_with("all")
                .require_delimiter(true)
                .value_delimiter(",")
                .multiple(true)
                .help("A comma-separated list of sector sizes, in bytes, for which Groth parameters will be generated")
        )
        .get_matches();

    let sizes: HashSet<(u64, usize)> = if matches.is_present("params-for-sector-sizes") {
        values_t!(matches.values_of("params-for-sector-sizes"), String)
            .unwrap()
            .into_iter()
            .map(|v| {
                let parts = v.split(':').take(2).collect::<Vec<_>>();
                assert_eq!(
                    parts.len(),
                    2,
                    "invalid param, expecting sector_size:window_size_nodes"
                );
                (parts[0].parse().unwrap(), parts[1].parse().unwrap())
            })
            .collect()
    } else {
        PUBLISHED_SECTOR_SIZES.iter().cloned().collect()
    };

    for (sector_size, window_size_nodes) in sizes {
        cache_post_params(PoStConfig {
            sector_size: SectorSize(sector_size),
            window_size_nodes,
        });

        for p in &POREP_PROOF_PARTITION_CHOICES {
            cache_porep_params(PoRepConfig {
                sector_size: SectorSize(sector_size),
                partitions: *p,
                window_size_nodes,
            });
        }
    }
}
