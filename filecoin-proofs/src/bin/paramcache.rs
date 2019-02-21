extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use filecoin_proofs::api::internal;
use pairing::bls12_381::Bls12;

use sector_base::api::disk_backed_storage::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
use sector_base::api::sector_store::PaddedBytesAmount;
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::parameter_cache::CacheableParameters;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth::Sloth;

const GENERATE_POST_PARAMS: bool = false;

fn cache_params(sector_size: u64) {
    let bytes_amount = PaddedBytesAmount(sector_size);
    let public_params = internal::public_params(bytes_amount);
    let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
    let _ = ZigZagCompound::get_groth_params(circuit, &public_params);

    if GENERATE_POST_PARAMS {
        // TODO: How do we select a "sectors count" in this context?
        //
        // See: https://github.com/filecoin-project/rust-fil-proofs/issues/492
        let post_public_params = internal::post_public_params(1, bytes_amount);
        let post_circuit: VDFPoStCircuit<Bls12> =
            <VDFPostCompound as CompoundProof<
                Bls12,
                VDFPoSt<PedersenHasher, Sloth>,
                VDFPoStCircuit<Bls12>,
            >>::blank_circuit(&post_public_params, &internal::ENGINE_PARAMS);
        let _ = VDFPostCompound::get_groth_params(post_circuit, &post_public_params);
    }
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    cache_params(TEST_SECTOR_SIZE);
    cache_params(LIVE_SECTOR_SIZE);
}
