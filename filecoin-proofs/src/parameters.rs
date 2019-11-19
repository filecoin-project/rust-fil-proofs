use storage_proofs::drgraph::{DefaultTreeHasher, BASE_DEGREE};
use storage_proofs::election_post::{self, ElectionPoSt};
use storage_proofs::proof::ProofScheme;
use storage_proofs::stacked::{self, LayerChallenges, StackedConfig, StackedDrg, EXP_DEGREE};

use crate::constants::{
    DefaultPieceHasher, POREP_WINDOW_MINIMUM_CHALLENGES, POREP_WRAPPER_MINIMUM_CHALLENGES,
};
use crate::types::{PaddedBytesAmount, PoStConfig};

const LAYERS: usize = 4; // TODO: 10;

const DRG_SEED: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27,
]; // Arbitrary, need a theory for how to vary this over time.

type PostSetupParams = election_post::SetupParams;
pub type PostPublicParams = election_post::PublicParams;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    window_size_nodes: usize,
) -> stacked::PublicParams<DefaultTreeHasher> {
    StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
        window_size_nodes,
    ))
    .unwrap()
}

pub fn post_public_params(post_config: PoStConfig) -> PostPublicParams {
    ElectionPoSt::<DefaultTreeHasher>::setup(&post_setup_params(post_config)).unwrap()
}

pub fn post_setup_params(post_config: PoStConfig) -> PostSetupParams {
    let size = PaddedBytesAmount::from(post_config);

    election_post::SetupParams {
        sector_size: size.into(),
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    window_size_nodes: usize,
    partitions: usize,
) -> stacked::SetupParams {
    let sector_bytes = usize::from(sector_bytes);

    let window_challenges = select_challenges(partitions, POREP_WINDOW_MINIMUM_CHALLENGES, LAYERS);
    let wrapper_challenges =
        select_challenges(partitions, POREP_WRAPPER_MINIMUM_CHALLENGES, LAYERS);

    let config = StackedConfig {
        window_challenges,
        wrapper_challenges,
    };

    assert!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    assert!(
        sector_bytes % window_size_nodes * 32 == 0,
        "sector_bytes ({}) must be a multiple of the window size ({})",
        sector_bytes,
        window_size_nodes * 32
    );

    let nodes = sector_bytes / 32;
    stacked::SetupParams {
        nodes,
        degree: BASE_DEGREE,
        expansion_degree: EXP_DEGREE,
        seed: DRG_SEED,
        config,
        window_size_nodes,
    }
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> LayerChallenges {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }
    guess
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::constants::POREP_WRAPPER_MINIMUM_CHALLENGES;
    use crate::types::PoRepProofPartitions;

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, POREP_WRAPPER_MINIMUM_CHALLENGES, LAYERS)
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }
}
