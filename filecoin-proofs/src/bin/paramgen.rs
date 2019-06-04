use std::env;
use std::fs::File;

use rand::OsRng;

use filecoin_proofs::parameters::public_params;
use filecoin_proofs::singletons::ENGINE_PARAMS;
use sector_base::api::bytes_amount::PaddedBytesAmount;
use sector_base::api::disk_backed_storage::TEST_SECTOR_SIZE;
use sector_base::api::porep_proof_partitions::PoRepProofPartitions;
use sector_base::api::sector_size::SectorSize;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::CompoundProof;

// Run this from the command-line, passing the path to the file to which the parameters will be written.
pub fn main() {
    let args: Vec<String> = env::args().collect();
    let out_file = &args[1];

    let public_params = public_params(
        PaddedBytesAmount::from(SectorSize(TEST_SECTOR_SIZE)),
        usize::from(PoRepProofPartitions(2)),
    );

    let circuit = ZigZagCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
    let mut params = phase21::MPCParameters::new(circuit).unwrap();

    let rng = &mut OsRng::new().unwrap();
    let hash = params.contribute(rng);

    {
        let circuit = ZigZagCompound::blank_circuit(&public_params, &ENGINE_PARAMS);
        let contributions = params.verify(circuit).expect("parameters should be valid!");

        // We need to check the `contributions` to see if our `hash`
        // is in it (see above, when we first contributed)
        assert!(phase21::contains_contribution(&contributions, &hash));
    }

    let mut buffer = File::create(out_file).unwrap();
    params.write(&mut buffer).unwrap();
}
