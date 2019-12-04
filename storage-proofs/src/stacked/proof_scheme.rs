use anyhow::ensure;
use log::trace;

use crate::error::Result;
use crate::hasher::Hasher;
use crate::proof::ProofScheme;
use crate::stacked::{
    challenges::ChallengeRequirements,
    graph::StackedBucketGraph,
    params::{PrivateInputs, Proof, PublicInputs, PublicParams, SetupParams},
    proof::StackedDrg,
};

impl<'a, 'c, H: 'static + Hasher, G: 'static + Hasher> ProofScheme<'a> for StackedDrg<'c, H, G> {
    type PublicParams = PublicParams<H>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<H, G>;
    type Proof = Proof<H, G>;
    type Requirements = ChallengeRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let window_graph = StackedBucketGraph::<H>::new_stacked(
            sp.window_size_nodes,
            sp.degree,
            sp.expansion_degree,
            sp.seed,
        )?;

        let wrapper_graph = StackedBucketGraph::<H>::new_stacked(
            sp.nodes,
            sp.degree,
            sp.expansion_degree,
            sp.seed,
        )?;

        Ok(PublicParams::new(
            window_graph,
            wrapper_graph,
            sp.config.clone(),
            sp.window_size_nodes,
        ))
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
        ensure!(
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
        ensure!(partition_count > 0, "There must be partitions.");

        let layers = pub_params.config.layers();
        ensure!(layers > 0, "No layer found.");
        ensure!(
            priv_inputs.t_aux.labels.len() == layers,
            "t_aux must match the number of layers"
        );

        (0..partition_count)
            .map(|k| {
                trace!("proving partition {}/{}", k + 1, partition_count);
                Self::prove_single_partition(&pub_params, pub_inputs, &priv_inputs.t_aux, k)
            })
            .collect()
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        trace!("verify_all_partitions");

        let expected_comm_r = if let Some(ref tau) = pub_inputs.tau {
            &tau.comm_r
        } else {
            return Ok(false);
        };

        for (k, proof) in partition_proofs.iter().enumerate() {
            trace!(
                "verifying partition proof {}/{}",
                k + 1,
                partition_proofs.len()
            );
            if !Self::verify_single_partition(pub_params, pub_inputs, proof, expected_comm_r, k)? {
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
        let window_challenges = public_params
            .config
            .window_challenges
            .challenges_count_all();
        let wrapper_challenges = public_params
            .config
            .wrapper_challenges
            .challenges_count_all();

        window_challenges * partitions >= requirements.minimum_challenges
            && wrapper_challenges * partitions >= requirements.minimum_challenges
    }
}
