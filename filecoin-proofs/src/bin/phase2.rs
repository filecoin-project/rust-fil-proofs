use phase21 as phase2;
use std::fs::File;
use std::io::BufWriter;

use filecoin_proofs::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DEFAULT_POREP_PROOF_PARTITIONS, SECTOR_SIZE_ONE_KIB,
};
use filecoin_proofs::parameters::setup_params;
use filecoin_proofs::types::*;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::stacked::StackedDrg;

fn main() {
    let params = File::create("params").unwrap();
    let mut params = BufWriter::with_capacity(1024 * 1024, params);

    // Generate params for PoRep
    {
        // TODO: allow for different sizes
        let porep_config = PoRepConfig {
            sector_size: SectorSize(SECTOR_SIZE_ONE_KIB),
            partitions: DEFAULT_POREP_PROOF_PARTITIONS,
        };

        let setup_params = compound_proof::SetupParams {
            vanilla_params: setup_params(
                PaddedBytesAmount::from(porep_config),
                usize::from(PoRepProofPartitions::from(porep_config)),
            )
            .unwrap(),
            partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        };

        let public_params = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::setup(&setup_params)
        .expect("setup failed");
        let stacked_blank_circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params.vanilla_params);

        phase2::MPCParameters::new(stacked_blank_circuit)
            .unwrap()
            .write(&mut params)
            .unwrap();
    }

    // TODO: Generate params for PoSt
}
