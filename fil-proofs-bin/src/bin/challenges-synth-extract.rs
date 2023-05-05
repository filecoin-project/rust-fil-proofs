use anyhow::{Context, Result};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use fil_proofs_bin::cli;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::stacked::SynthChallengeGenerator;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesSynthExtractParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The number of challenges to draw from the generated challenges.
    num_challenges: usize,
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesSynthExtractOutput {
    challenges: Vec<usize>,
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ChallengesSynthExtractParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let sector_nodes = usize::try_from(params.sector_size)
        .context("sector size must be smaller than the default integer size on this platform")?
        / NODE_SIZE;
    let replica_id =
        Fr::from_repr_vartime(params.replica_id).context("must be valid field element")?;
    let comm_r = Fr::from_repr_vartime(params.comm_r).context("must be valid field element")?;
    let challenges = SynthChallengeGenerator::default(sector_nodes, &replica_id, &comm_r)
        .gen_partition_synth_indexes(params.num_challenges, &params.seed, 0);

    let output = ChallengesSynthExtractOutput { challenges };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
