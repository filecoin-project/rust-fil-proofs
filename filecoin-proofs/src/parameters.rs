use storage_proofs::drgporep::DrgParams;
use storage_proofs::drgraph::{DefaultTreeHasher, BASE_DEGREE};
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::proof::ProofScheme;
use storage_proofs::rational_post::{self, RationalPoSt};
use storage_proofs::stacked::{self, LayerChallenges, StackedDrg, EXP_DEGREE};

use crate::constants::POREP_MINIMUM_CHALLENGES;
use crate::types::{PaddedBytesAmount, PoStConfig};

const POST_CHALLENGE_COUNT: usize = 30; // TODO: correct value

const LAYERS: usize = 4; // TODO: 10;

const DRG_SEED: [u32; 7] = [1, 2, 3, 4, 5, 6, 7]; // Arbitrary, need a theory for how to vary this over time.

type PostSetupParams = rational_post::SetupParams;
pub type PostPublicParams = rational_post::PublicParams;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> stacked::PublicParams<DefaultTreeHasher> {
    StackedDrg::<DefaultTreeHasher>::setup(&setup_params(sector_bytes, partitions)).unwrap()
}

pub fn post_public_params(post_config: PoStConfig) -> PostPublicParams {
    RationalPoSt::<PedersenHasher>::setup(&post_setup_params(post_config)).unwrap()
}

pub fn post_setup_params(post_config: PoStConfig) -> PostSetupParams {
    let size = PaddedBytesAmount::from(post_config);

    rational_post::SetupParams {
        challenges_count: POST_CHALLENGE_COUNT,
        sector_size: size.into(),
    }
}

pub fn setup_params(sector_bytes: PaddedBytesAmount, partitions: usize) -> stacked::SetupParams {
    let sector_bytes = usize::from(sector_bytes);

    let challenges = select_challenges(partitions, POREP_MINIMUM_CHALLENGES, LAYERS);

    assert!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );
    let nodes = sector_bytes / 32;
    stacked::SetupParams {
        drg: DrgParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            seed: DRG_SEED,
        },
        layer_challenges: challenges,
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

    use crate::constants::POREP_MINIMUM_CHALLENGES;
    use crate::types::PoRepProofPartitions;

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, POREP_MINIMUM_CHALLENGES, LAYERS).challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }
}
