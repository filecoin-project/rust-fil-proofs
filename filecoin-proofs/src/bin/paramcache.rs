extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use filecoin_proofs::api::internal;
use filecoin_proofs::FCP_LOG;
use pairing::bls12_381::Bls12;
use sector_base::api::bytes_amount::PaddedBytesAmount;
use sector_base::api::disk_backed_storage::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

use clap::{App, Arg};
use slog::*;

fn cache_porep_params(sector_size: u64) {
    info!(FCP_LOG, "begin PoRep parameter-cache check/populate routine for {}-byte sectors", sector_size; "target" => "paramcache");

    let bytes_amount = PaddedBytesAmount(sector_size);

    let public_params = internal::public_params(bytes_amount);
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);

        let _ = ZigZagCompound::get_groth_params(circuit, &public_params);
    }
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
        let _ = ZigZagCompound::get_verifying_key(circuit, &public_params);
    }
}

fn cache_post_params(sector_size: u64) {
    info!(FCP_LOG, "begin PoSt parameter-cache check/populate routine for {}-byte sectors", sector_size; "target" => "paramcache");

    let bytes_amount = PaddedBytesAmount(sector_size);

    let post_public_params = internal::post_public_params(bytes_amount);
    {
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &internal::ENGINE_PARAMS);
        let _ = VDFPostCompound::get_groth_params(post_circuit, &post_public_params);
    }
    {
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &internal::ENGINE_PARAMS);

        let _ = VDFPostCompound::get_verifying_key(post_circuit, &post_public_params);
    }
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    let matches = App::new("paramcache")
        .version("0.1")
        .about("Generate and persist Groth parameters")
        .arg(
            Arg::with_name("test-only")
                .long("test-only")
                .help("generate only parameters useful for testing")
                .takes_value(false),
        )
        .get_matches();

    let test_only: bool = matches.is_present("test-only");

    cache_porep_params(TEST_SECTOR_SIZE);
    cache_post_params(TEST_SECTOR_SIZE);

    if !test_only {
        cache_porep_params(LIVE_SECTOR_SIZE);
        cache_post_params(LIVE_SECTOR_SIZE);
    }
}
