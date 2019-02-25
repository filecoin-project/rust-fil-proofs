extern crate filecoin_proofs;
extern crate phase2;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;

use rand::OsRng;
use std::env;
use std::fs::File;

use filecoin_proofs::api::internal;
use sector_base::api::bytes_amount::PaddedBytesAmount;
use sector_base::api::disk_backed_storage::LIVE_SECTOR_SIZE;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;

// Run this from the command-line, passing the path to the file to which the parameters will be written.
pub fn main() {
    let args: Vec<String> = env::args().collect();
    let out_file = &args[1];

    let public_params = internal::public_params(PaddedBytesAmount(LIVE_SECTOR_SIZE));

    let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
    let mut params = phase2::MPCParameters::new(circuit).unwrap();

    let rng = &mut OsRng::new().unwrap();
    let hash = params.contribute(rng);

    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &internal::ENGINE_PARAMS);
        let contributions = params.verify(circuit).expect("parameters should be valid!");

        // We need to check the `contributions` to see if our `hash`
        // is in it (see above, when we first contributed)
        assert!(phase2::contains_contribution(&contributions, &hash));
    }

    let mut buffer = File::create(out_file).unwrap();
    params.write(&mut buffer).unwrap();
}
