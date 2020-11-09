#[cfg(test)]
mod tests {
    use filecoin_proofs::constants::*;
    use filecoin_proofs::parameters::{select_challenges, winning_post_public_params};
    use filecoin_proofs::types::{PoStConfig, PoStType};

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, 12, 11)
                .expect("never fails")
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(filecoin_proofs::PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }

    #[test]
    fn test_winning_post_params() {
        let config = PoStConfig {
            typ: PoStType::Winning,
            priority: false,
            challenge_count: 66,
            sector_count: 1,
            sector_size: 2048u64.into(),
        };

        let params =
            winning_post_public_params::<DefaultOctLCTree>(&config).expect("failed to get params");
        assert_eq!(params.sector_count, 66);
        assert_eq!(params.challenge_count, 1);
        assert_eq!(params.sector_size, 2048);
    }
}
