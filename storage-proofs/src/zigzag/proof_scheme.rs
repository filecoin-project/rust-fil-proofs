use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::Hasher;
use crate::proof::ProofScheme;
use crate::zigzag::{
    challenges::ChallengeRequirements,
    graph::ZigZagBucketGraph,
    params::{PrivateInputs, Proof, PublicInputs, PublicParams, SetupParams},
    proof::ZigZagDrgPoRep,
};

impl<'a, 'c, H: 'static + Hasher> ProofScheme<'a> for ZigZagDrgPoRep<'c, H> {
    type PublicParams = PublicParams<H>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<H as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<H>;
    type Proof = Vec<Proof<H>>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = ZigZagBucketGraph::<H>::new_zigzag(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            0,
            sp.drg.seed,
        );

        Ok(PublicParams::new(graph, sp.layer_challenges.clone()))
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = match pub_inputs.k {
            None => 0,
            Some(k) => k,
        };

        Ok(proofs[k].to_owned())
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        trace!("prove_all_partitions");
        assert!(partition_count > 0);

        Self::prove_layers(
            &pub_params.graph,
            pub_inputs,
            &priv_inputs.p_aux,
            &priv_inputs.t_aux,
            &pub_params.layer_challenges,
            pub_params.layer_challenges.layers(),
            pub_params.layer_challenges.layers(),
            partition_count,
        )
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        trace!("verify_all_partitions");

        // generate graphs
        let graph_0 = &pub_params.graph;
        let graph_1 = Self::transform(graph_0);

        assert_eq!(graph_0.layer(), 0);
        assert_eq!(graph_1.layer(), 1);

        for (k, proofs) in partition_proofs.iter().enumerate() {
            trace!(
                "verifying partition proof {}/{}",
                k + 1,
                partition_proofs.len()
            );

            let challenges =
                pub_inputs.challenges(&pub_params.layer_challenges, graph_0.size(), Some(k));

            let valid = proofs.par_iter().enumerate().all(|(i, proof)| {
                trace!("verify challenge {}/{}", i + 1, challenges.len());

                // Validate for this challenge
                let challenge = challenges[i];

                proof.verify(pub_params, pub_inputs, challenge, graph_0, &graph_1)
            });

            if !valid {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn with_partition(pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        self::PublicInputs {
            replica_id: pub_in.replica_id,
            seed: None,
            tau: pub_in.tau,
            k,
        }
    }

    fn satisfies_requirements(
        public_params: &PublicParams<H>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges_count();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}
