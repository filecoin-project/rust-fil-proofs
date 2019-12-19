use log::trace;
use paired::bls12_381::Fr;
use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::Hasher;
use crate::proof::ProofScheme;
use crate::stacked_old::{
    challenges::ChallengeRequirements,
    graph::StackedBucketGraph,
    hash::hash2,
    params::{PrivateInputs, Proof, PublicInputs, PublicParams, SetupParams},
    proof::StackedDrg,
};

impl<'a, 'c, H: 'static + Hasher, G: 'static + Hasher> ProofScheme<'a> for StackedDrg<'c, H, G> {
    type PublicParams = PublicParams<H>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<H, G>;
    type Proof = Vec<Proof<H, G>>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = StackedBucketGraph::<H>::new_stacked(
            sp.nodes,
            sp.degree,
            sp.expansion_degree,
            sp.seed,
        )?;

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
        // Because partition proofs require a common setup, the general ProofScheme implementation,
        // which makes use of `ProofScheme::prove` cannot be used here. Instead, we need to prove all
        // partitions in one pass, as implemented by `prove_all_partitions` below.
        assert!(
            k < 1,
            "It is a programmer error to call StackedDrg::prove with more than one partition."
        );

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
        let graph = &pub_params.graph;

        let expected_comm_r = if let Some(ref tau) = pub_inputs.tau {
            &tau.comm_r
        } else {
            return Ok(false);
        };

        for (k, proofs) in partition_proofs.iter().enumerate() {
            trace!(
                "verifying partition proof {}/{}",
                k + 1,
                partition_proofs.len()
            );

            trace!("verify comm_r");
            let actual_comm_r: H::Domain = {
                let comm_c = proofs[0].comm_c();
                let comm_r_last = proofs[0].comm_r_last();
                Fr::from(hash2(comm_c, comm_r_last)).into()
            };

            if expected_comm_r != &actual_comm_r {
                return Ok(false);
            }

            let challenges =
                pub_inputs.challenges(&pub_params.layer_challenges, graph.size(), Some(k));

            let valid = proofs.par_iter().enumerate().all(|(i, proof)| {
                trace!("verify challenge {}/{}", i + 1, challenges.len());

                // Validate for this challenge
                let challenge = challenges[i];

                // make sure all proofs have the same comm_c
                if proof.comm_c() != proofs[0].comm_c() {
                    return false;
                }
                // make sure all proofs have the same comm_r_last
                if proof.comm_r_last() != proofs[0].comm_r_last() {
                    return false;
                }

                proof.verify(pub_params, pub_inputs, challenge, graph)
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
            seed: pub_in.seed,
            tau: pub_in.tau,
            k,
        }
    }

    fn satisfies_requirements(
        public_params: &PublicParams<H>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges_count_all();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}
