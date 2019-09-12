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
    type PublicParams = PublicParams<H, ZigZagBucketGraph<H>>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<H as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<H>;
    type Proof = Proof<H>;
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
        let graph_2 = Self::transform(&graph_1);

        assert_eq!(graph_0.layer(), 0);
        assert_eq!(graph_1.layer(), 1);
        assert_eq!(graph_2.layer(), 2);

        let replica_id = &pub_inputs.replica_id;
        let layers = pub_params.layer_challenges.layers();

        let valid = partition_proofs
            .into_par_iter()
            .enumerate()
            .all(|(k, proof)| {
                trace!(
                    "verifying partition proof {}/{}",
                    k + 1,
                    partition_proofs.len()
                );

                // TODO:
                // 1. grab all comm_r_last and ensure they are the same (from inclusion proofs)
                // 2. grab all comm_c and ensure they are the same (from inclusion proofs)
                // 3. check that H(comm_c || comm_r_last) == comm_r

                let challenges =
                    pub_inputs.challenges(&pub_params.layer_challenges, graph_0.size(), Some(k));
                for i in 0..challenges.len() {
                    trace!("verify challenge {}/{}", i, challenges.len());
                    // Validate for this challenge
                    let challenge = challenges[i] % graph_0.size();

                    // Verify initial data layer
                    trace!("verify initial data layer");
                    check!(proof.comm_d_proofs[i].proves_challenge(challenge));

                    check_eq!(proof.comm_d_proofs[i].root(), &pub_inputs.tau.comm_d);

                    // Verify replica column openings
                    trace!("verify replica column openings");
                    {
                        let rco = &proof.replica_column_proofs[i];

                        trace!("  verify c_x");
                        check!(rco.c_x.verify());

                        trace!("  verify c_inv_x");
                        check!(rco.c_inv_x.verify());

                        trace!("  verify drg_parents");
                        for proof in &rco.drg_parents {
                            check!(proof.verify());
                        }

                        trace!("  verify exp_parents_even");
                        for proof in &rco.exp_parents_even {
                            check!(proof.verify());
                        }

                        trace!("  verify exp_parents_odd");
                        for proof in &rco.exp_parents_odd {
                            check!(proof.verify());
                        }
                    }

                    // Verify final replica layer openings
                    trace!("verify final replica layer openings");
                    {
                        let inv_challenge = graph_0.inv_index(challenge);

                        check!(proof.comm_r_last_proofs[i]
                            .0
                            .proves_challenge(inv_challenge));

                        let mut parents = vec![0; graph_1.degree()];
                        graph_1.parents(inv_challenge, &mut parents);

                        check_eq!(parents.len(), proof.comm_r_last_proofs[i].1.len());

                        for (p, parent) in proof.comm_r_last_proofs[i]
                            .1
                            .iter()
                            .zip(parents.into_iter())
                        {
                            check!(p.proves_challenge(parent));
                        }
                    }

                    // Verify Encoding Layer 1
                    trace!("verify encoding (layer: 1)");
                    let rpc = &proof.replica_column_proofs[i];
                    let comm_d = &proof.comm_d_proofs[i];

                    check!(proof.encoding_proof_1[i].verify(
                        replica_id,
                        rpc.c_x.get_node_at_layer(1),
                        comm_d.leaf()
                    ));

                    // Verify Encoding Layer 2..layers - 1
                    {
                        assert_eq!(proof.encoding_proofs[i].len(), layers - 2);
                        for (j, encoding_proof) in proof.encoding_proofs[i].iter().enumerate() {
                            let layer = j + 2;
                            trace!("verify encoding (layer: {})", layer);;

                            let encoded_node = rpc.c_x.get_node_at_layer(layer);
                            let decoded_node = rpc.c_inv_x.get_node_at_layer(layer - 1);

                            check!(encoding_proof.verify(replica_id, encoded_node, decoded_node));
                        }
                    }
                }

                true
            });

        Ok(valid)
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
        public_params: &PublicParams<H, ZigZagBucketGraph<H>>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges_count();

        partition_challenges * partitions >= requirements.minimum_challenges
    }
}
