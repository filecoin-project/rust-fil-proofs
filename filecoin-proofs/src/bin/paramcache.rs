#[macro_use]
extern crate log;

use clap::{values_t, App, Arg};
use paired::bls12_381::Bls12;
use rand::{rngs::OsRng, SeedableRng};
use rand_xorshift::XorShiftRng;

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

const PUBLISHED_SECTOR_SIZES: [u64; 4] = [
    SECTOR_SIZE_ONE_KIB,
    SECTOR_SIZE_16_MIB,
    SECTOR_SIZE_256_MIB,
    SECTOR_SIZE_1_GIB,
];

const SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

fn cache_porep_params(is_predictable: bool, porep_config: PoRepConfig) {
    let n = u64::from(PaddedBytesAmount::from(porep_config));
    info!(
        "begin PoRep parameter-cache check/populate routine for {}-byte sectors",
        n
    );

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    )
    .unwrap();

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
        let _ = if is_predictable {
            StackedCompound::get_groth_params(
                Some(&mut XorShiftRng::from_seed(SEED)),
                circuit,
                &public_params,
            )
        } else {
            StackedCompound::get_groth_params(Some(&mut OsRng), circuit, &public_params)
        }
        .expect("failed to get groth params");
    }
    {
        let circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params);
        let _ = if is_predictable {
            StackedCompound::get_verifying_key(
                Some(&mut XorShiftRng::from_seed(SEED)),
                circuit,
                &public_params,
            )
        } else {
            StackedCompound::get_verifying_key(Some(&mut OsRng), circuit, &public_params)
        }
        .expect("failed to get verifying key");
    }
}

fn cache_post_params(is_predictable: bool, post_config: PoStConfig) {
    let n = u64::from(PaddedBytesAmount::from(post_config));
    info!(
        "begin PoSt parameter-cache check/populate routine for {}-byte sectors",
        n
    );

    let post_public_params = post_public_params(post_config).unwrap();

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
        let _ = if is_predictable {
            <ElectionPoStCompound<PedersenHasher>>::get_groth_params(
                Some(&mut XorShiftRng::from_seed(SEED)),
                post_circuit,
                &post_public_params,
            )
        } else {
            <ElectionPoStCompound<PedersenHasher>>::get_groth_params(
                Some(&mut OsRng),
                post_circuit,
                &post_public_params,
            )
        }
        .expect("failed to get groth params");
    }
    {
        let post_circuit: ElectionPoStCircuit<Bls12, PedersenHasher> =
            <ElectionPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                ElectionPoSt<PedersenHasher>,
                ElectionPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params);

        let _ = if is_predictable {
            <ElectionPoStCompound<PedersenHasher>>::get_verifying_key(
                Some(&mut XorShiftRng::from_seed(SEED)),
                post_circuit,
                &post_public_params,
            )
        } else {
            <ElectionPoStCompound<PedersenHasher>>::get_verifying_key(
                Some(&mut OsRng),
                post_circuit,
                &post_public_params,
            )
        }
        .expect("failed to get verifying key");
    }
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    fil_logger::init();

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
        .arg(
            Arg::with_name("predictable")
                .long("predictable")
                .help("When set the paramters will be seeded with a fixed value.")
        )
        .get_matches();

    let sizes: HashSet<u64> = if matches.is_present("params-for-sector-sizes") {
        values_t!(matches.values_of("params-for-sector-sizes"), u64)
            .unwrap()
            .into_iter()
            .collect()
    } else {
        PUBLISHED_SECTOR_SIZES.iter().cloned().collect()
    };

    let is_predictable = matches.is_present("predictable");
    for sector_size in sizes {
        cache_post_params(
            is_predictable,
            PoStConfig {
                sector_size: SectorSize(sector_size),
            },
        );

        for p in &POREP_PROOF_PARTITION_CHOICES {
            cache_porep_params(
                is_predictable,
                PoRepConfig {
                    sector_size: SectorSize(sector_size),
                    partitions: *p,
                },
            );
        }
    }
}
