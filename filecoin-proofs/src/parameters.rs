use std::sync::atomic::Ordering;

use anyhow::{ensure, Result};
use storage_proofs::election_post::{self, ElectionPoSt};
use storage_proofs::proof::ProofScheme;
use storage_proofs::stacked::{self, LayerChallenges, StackedDrg};

use crate::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DRG_DEGREE, EXP_DEGREE, LAYERS, POREP_MINIMUM_CHALLENGES,
};
use crate::types::{PaddedBytesAmount, PoStConfig};

const DRG_SEED: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27,
]; // Arbitrary, need a theory for how to vary this over time.

type PostSetupParams = election_post::SetupParams;
pub type PostPublicParams = election_post::PublicParams;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked::PublicParams<DefaultTreeHasher>> {
    StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
    )?)
}

pub fn post_public_params(post_config: PoStConfig) -> Result<PostPublicParams> {
    ElectionPoSt::<DefaultTreeHasher>::setup(&post_setup_params(post_config))
}

pub fn post_setup_params(post_config: PoStConfig) -> PostSetupParams {
    let size = PaddedBytesAmount::from(post_config);

    election_post::SetupParams {
        sector_size: size.into(),
        challenge_count: post_config.challenge_count,
        challenged_nodes: post_config.challenged_nodes,
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        *POREP_MINIMUM_CHALLENGES
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size") as usize,
        *LAYERS
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size"),
    )?;
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    Ok(stacked::SetupParams {
        nodes,
        degree: DRG_DEGREE.load(Ordering::Relaxed) as usize,
        expansion_degree: EXP_DEGREE.load(Ordering::Relaxed) as usize,
        seed: DRG_SEED,
        layer_challenges,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> Result<LayerChallenges> {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }
    Ok(guess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, 12, 11)
                .unwrap()
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(crate::PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }
}
