extern crate filecoin_proofs;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use rand::{SeedableRng, XorShiftRng};

use filecoin_proofs::api::internal;
use sector_base::api::disk_backed_storage::{FAST_SECTOR_SIZE, REAL_SECTOR_SIZE, SLOW_SECTOR_SIZE};
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::parameter_cache::CacheableParameters;

fn cache_params(sector_size: u64) {
    let public_params = internal::public_params(sector_size as usize);
    let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let _ = ZigZagCompound::get_groth_params(circuit, &public_params, rng);
}

// Run this from the command-line to pre-generate the groth parameters used by the API.
pub fn main() {
    cache_params(REAL_SECTOR_SIZE);
    cache_params(FAST_SECTOR_SIZE);
    cache_params(SLOW_SECTOR_SIZE);
}
