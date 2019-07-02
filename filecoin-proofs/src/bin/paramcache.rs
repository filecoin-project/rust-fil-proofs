use clap::{App, Arg};
use paired::bls12_381::Bls12;
use slog::*;

use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{post_public_params, public_params};
use filecoin_proofs::singletons::{ENGINE_PARAMS, FCP_LOG};
use filecoin_proofs::types::*;
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

const POREP_PROOF_PARTITION_CHOICES: [PoRepProofPartitions; 1] = [PoRepProofPartitions(2)];

fn cache_porep_params(porep_config: PoRepConfig) {
    let n = u64::from(PaddedBytesAmount::from(porep_config));
    info!(FCP_LOG, "begin PoRep parameter-cache check/populate routine for {}-byte sectors", n; "target" => "paramcache");

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );

    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let _ = ZigZagCompound::get_param_metadata(circuit, &public_params);
    }
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let _ = ZigZagCompound::get_groth_params(circuit, &public_params);
    }
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let _ = ZigZagCompound::get_verifying_key(circuit, &public_params);
    }
}

fn cache_post_params(post_config: PoStConfig) {
    let n = u64::from(PaddedBytesAmount::from(post_config));
    info!(FCP_LOG, "begin PoSt parameter-cache check/populate routine for {}-byte sectors", n; "target" => "paramcache");

    let post_public_params = post_public_params(post_config);

    {
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);
        let _ = VDFPostCompound::get_param_metadata(post_circuit, &post_public_params);
    }
    {
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);
        let _ = VDFPostCompound::get_groth_params(post_circuit, &post_public_params);
    }
    {
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &ENGINE_PARAMS);

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

    cache_porep_params(PoRepConfig(
        SectorSize(TEST_SECTOR_SIZE),
        PoRepProofPartitions(2),
    ));
    cache_post_params(PoStConfig(
        SectorSize(TEST_SECTOR_SIZE),
        PoStProofPartitions(1),
    ));

    if !test_only {
        for p in &POREP_PROOF_PARTITION_CHOICES {
            cache_porep_params(PoRepConfig(SectorSize(LIVE_SECTOR_SIZE), *p));
        }

        cache_post_params(PoStConfig(
            SectorSize(LIVE_SECTOR_SIZE),
            PoStProofPartitions(1),
        ));
    }
}
