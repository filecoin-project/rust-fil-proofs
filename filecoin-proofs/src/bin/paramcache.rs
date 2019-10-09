#[macro_use]
extern crate log;

use clap::{App, Arg};
use paired::bls12_381::Bls12;

use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{post_public_params, public_params};
use filecoin_proofs::singletons::ENGINE_PARAMS;
use filecoin_proofs::types::*;
use storage_proofs::circuit::rational_post::{RationalPoStCircuit, RationalPoStCompound};
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::rational_post::RationalPoSt;

const POREP_PROOF_PARTITION_CHOICES: [PoRepProofPartitions; 1] = [PoRepProofPartitions(2)];

const PUBLISHED_SECTOR_SIZES: [u64; 4] = [
    SECTOR_SIZE_ONE_KIB,
    SECTOR_SIZE_16_MIB,
    SECTOR_SIZE_256_MIB,
    SECTOR_SIZE_1_GIB,
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
    );

    {
        let circuit = StackedCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let _ = StackedCompound::get_param_metadata(circuit, &public_params);
    }
    {
        let circuit = StackedCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let _ = StackedCompound::get_groth_params(circuit, &public_params);
    }
    {
        let circuit = StackedCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
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
        let post_circuit: RationalPoStCircuit<Bls12, PedersenHasher> =
            <RationalPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                RationalPoSt<PedersenHasher>,
                RationalPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);
        let _ = <RationalPoStCompound<PedersenHasher>>::get_param_metadata(
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get metadata");
    }
    {
        let post_circuit: RationalPoStCircuit<Bls12, PedersenHasher> =
            <RationalPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                RationalPoSt<PedersenHasher>,
                RationalPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);
        let _ = <RationalPoStCompound<PedersenHasher>>::get_groth_params(
            post_circuit,
            &post_public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let post_circuit: RationalPoStCircuit<Bls12, PedersenHasher> =
            <RationalPoStCompound<PedersenHasher> as CompoundProof<
                Bls12,
                RationalPoSt<PedersenHasher>,
                RationalPoStCircuit<Bls12, PedersenHasher>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);

        let _ = <RationalPoStCompound<PedersenHasher>>::get_verifying_key(
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
            Arg::with_name("test-only")
                .long("test-only")
                .help("generate only Groth parameters and keys useful for testing")
                .takes_value(false),
        )
        .get_matches();

    let test_only: bool = matches.is_present("test-only");

    let smallest = vec![SECTOR_SIZE_ONE_KIB];

    let sizes: &[u64] = if test_only {
        &smallest
    } else {
        &PUBLISHED_SECTOR_SIZES
    };

    for size in sizes {
        cache_post_params(PoStConfig(SectorSize(*size)));

        for p in &POREP_PROOF_PARTITION_CHOICES {
            cache_porep_params(PoRepConfig(SectorSize(*size), *p));
        }
    }
}
