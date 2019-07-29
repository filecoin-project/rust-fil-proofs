use storage_proofs::drgporep::DrgParams;
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::hasher::pedersen::PedersenDomain;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::layered_drgporep;
use storage_proofs::layered_drgporep::LayerChallenges;
use storage_proofs::proof::ProofScheme;
use storage_proofs::vdf_post;
use storage_proofs::vdf_post::VDFPoSt;
use storage_proofs::vdf_sloth;
use storage_proofs::zigzag_drgporep::ZigZagDrgPoRep;
use storage_proofs::zigzag_graph::ZigZagBucketGraph;

use crate::constants::POREP_MINIMUM_CHALLENGES;
use crate::constants::POST_SECTORS_COUNT;
use crate::singletons::POST_VDF_KEY;
use crate::types::{PaddedBytesAmount, PoStConfig};

const POST_CHALLENGE_COUNT: usize = 30;
const POST_EPOCHS: usize = 3;

const DEGREE: usize = 5;
const EXPANSION_DEGREE: usize = 8;
const LAYERS: usize = 4; // TODO: 10;
const TAPER_LAYERS: usize = 2; // TODO: 7
const TAPER: f64 = 1.0 / 3.0;

const DRG_SEED: [u32; 7] = [1, 2, 3, 4, 5, 6, 7]; // Arbitrary, need a theory for how to vary this over time.

type PostSetupParams = vdf_post::SetupParams<PedersenDomain, vdf_sloth::Sloth>;
pub type PostPublicParams = vdf_post::PublicParams<PedersenDomain, vdf_sloth::Sloth>;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> layered_drgporep::PublicParams<DefaultTreeHasher, ZigZagBucketGraph<DefaultTreeHasher>> {
    ZigZagDrgPoRep::<DefaultTreeHasher>::setup(&setup_params(sector_bytes, partitions)).unwrap()
}

pub fn post_public_params(post_config: PoStConfig) -> PostPublicParams {
    VDFPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&post_setup_params(post_config)).unwrap()
}

pub fn post_setup_params(post_config: PoStConfig) -> PostSetupParams {
    let size = PaddedBytesAmount::from(post_config);

    vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
        challenge_count: POST_CHALLENGE_COUNT,
        sector_size: size.into(),
        post_epochs: POST_EPOCHS,
        setup_params_vdf: vdf_sloth::SetupParams { key: *POST_VDF_KEY },
        sectors_count: POST_SECTORS_COUNT,
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> layered_drgporep::SetupParams {
    let sector_bytes = usize::from(sector_bytes);

    let challenges = select_challenges(
        partitions,
        POREP_MINIMUM_CHALLENGES,
        LAYERS,
        TAPER_LAYERS,
        TAPER,
    );

    assert!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );
    let nodes = sector_bytes / 32;
    layered_drgporep::SetupParams {
        drg: DrgParams {
            nodes,
            degree: DEGREE,
            expansion_degree: EXPANSION_DEGREE,
            seed: DRG_SEED,
        },
        layer_challenges: challenges,
    }
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
    taper_layers: usize,
    taper: f64,
) -> LayerChallenges {
    let mut count = 1;
    let mut guess = LayerChallenges::Tapered {
        count,
        layers,
        taper,
        taper_layers,
    };
    while partitions * guess.total_challenges() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::Tapered {
            count,
            layers,
            taper,
            taper_layers,
        };
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
            select_challenges(
                partitions,
                POREP_MINIMUM_CHALLENGES,
                LAYERS,
                TAPER_LAYERS,
                TAPER,
            )
            .all_challenges()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(vec![1, 1, 2, 2], f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(vec![3, 3, 4, 5], f(1));
        assert_eq!(vec![1, 1, 2, 2], f(2));
        assert_eq!(vec![1, 1, 1, 1], f(4));
    }
}
