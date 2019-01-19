extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use filecoin_proofs::api::internal;
use pairing::bls12_381::Bls12;

use sector_base::api::disk_backed_storage::{FAST_SECTOR_SIZE, REAL_SECTOR_SIZE, SLOW_SECTOR_SIZE};
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

fn cache_params(sector_size: u64) {
    let public_params = internal::public_params(sector_size as usize);
    let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
    let _ = ZigZagCompound::get_groth_params(circuit, &public_params);

    let post_public_params = internal::post_public_params(sector_size as usize);
    let post_circuit: VDFPoStCircuit<Bls12> =
        <VDFPostCompound as CompoundProof<
            Bls12,
            VDFPoSt<PedersenHasher, Sloth>,
            VDFPoStCircuit<Bls12>,
        >>::blank_circuit(&post_public_params, &internal::ENGINE_PARAMS);
    let _ = VDFPostCompound::get_groth_params(post_circuit, &post_public_params);
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    cache_params(REAL_SECTOR_SIZE);
    cache_params(FAST_SECTOR_SIZE);
    cache_params(SLOW_SECTOR_SIZE);
}
