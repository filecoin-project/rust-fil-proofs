extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use filecoin_proofs::api::internal;
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

use std::env;

fn cache_porep_params(sector_size: u64) {
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

    // We can delete this guard once rust-fil-proofs issue #510 lands.
    if let Some("true") = env::args().collect().get(1).map(|x| x.as_ref()) {
        cache_post_params(TEST_SECTOR_SIZE);
        cache_post_params(LIVE_SECTOR_SIZE);
    }

    cache_porep_params(TEST_SECTOR_SIZE);
    cache_porep_params(LIVE_SECTOR_SIZE);
}
