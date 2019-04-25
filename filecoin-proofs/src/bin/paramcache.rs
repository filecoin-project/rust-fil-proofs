extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use clap::{App, Arg};
use slog::*;

use filecoin_proofs::api::internal;
use filecoin_proofs::FCP_LOG;
use pairing::bls12_381::Bls12;
use sector_base::api::bytes_amount::PaddedBytesAmount;
use sector_base::api::porep_config::PoRepConfig;
use sector_base::api::porep_proof_partitions::PoRepProofPartitions;
use sector_base::api::porep_proof_partitions::POREP_PROOF_PARTITION_CHOICES;
use sector_base::api::post_config::PoStConfig;
use sector_base::api::post_proof_partitions::PoStProofPartitions;
use sector_base::api::sector_size::SectorSize;
use sector_base::api::sector_size::SECTOR_SIZE_CHOICES;
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

fn cache_porep_params(porep_config: PoRepConfig) {
    let n = u64::from(PaddedBytesAmount::from(porep_config));
    info!(FCP_LOG, "begin PoRep parameter-cache check/populate routine for {}-byte sectors", n; "target" => "paramcache");

    let public_params = internal::public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
    );
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);

        let _ = ZigZagCompound::get_groth_params(circuit, &public_params);
    }
    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
        let _ = ZigZagCompound::get_verifying_key(circuit, &public_params);
    }
}

fn cache_post_params(post_config: PoStConfig) {
    let n = u64::from(PaddedBytesAmount::from(post_config));
    info!(FCP_LOG, "begin PoSt parameter-cache check/populate routine for {}-byte sectors", n; "target" => "paramcache");

    let post_public_params = internal::post_public_params(post_config);
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

    cache_porep_params(PoRepConfig(SectorSize::OneKiB, PoRepProofPartitions::Two));

    cache_post_params(PoStConfig(SectorSize::OneKiB, PoStProofPartitions::One));

    if !test_only {
        for p in &POREP_PROOF_PARTITION_CHOICES {
            for s in &SECTOR_SIZE_CHOICES {
                cache_porep_params(PoRepConfig(*s, *p));
            }
        }
        cache_post_params(PoStConfig(
            SectorSize::TwoHundredFiftySixMiB,
            PoStProofPartitions::One,
        ));
    }
}
