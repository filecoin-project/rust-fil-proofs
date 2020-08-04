use anyhow::{ensure, Result};
use bellperson::Circuit;
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    fr32::u64_into_fr,
    gadgets::por::generate_inclusion_inputs,
    hasher::Hasher,
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
};

use super::{LayerProof, NseCircuit};
use crate::nse::vanilla::{ButterflyGraph, Challenges, ExpanderGraph, NarrowStackedExpander};

#[derive(Debug)]
pub struct NseCompound {}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata> CacheableParameters<C, P> for NseCompound {
    fn cache_prefix() -> String {
        format!("nse-proof-of-replication",)
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>
    CompoundProof<'a, NarrowStackedExpander<'a, Tree, G>, NseCircuit<'a, Tree, G>> for NseCompound
{
    fn generate_public_inputs(
        public_inputs: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicInputs,
        public_params: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let config = &public_params.config;

        let mut inputs = Vec::new();

        // replica id
        inputs.push(public_inputs.replica_id.into());

        // comm_d
        inputs.push(public_inputs.tau.comm_d.into());

        // comm_r
        inputs.push(public_inputs.tau.comm_r.into());

        let por_setup_params = por::SetupParams {
            leaves: config.num_nodes_sector(),
            private: true,
        };
        let por_params = por::PoR::<Tree>::setup(&por_setup_params)?;
        let por_params_d = por::PoR::<BinaryMerkleTree<G>>::setup(&por_setup_params)?;
        let challenges = Challenges::new(
            config,
            public_params.num_layer_challenges,
            &public_inputs.replica_id,
            public_inputs.seed,
        );

        let data_inclusion_inputs =
            |c: u64| generate_inclusion_inputs::<BinaryMerkleTree<G>>(&por_params_d, c as usize, k);
        let layer_inclusion_inputs =
            |c: u64| generate_inclusion_inputs::<Tree>(&por_params, c as usize, k);
        let parent_inclusion_inputs =
            |c: usize| generate_inclusion_inputs::<Tree>(&por_params, c as usize, k);

        // layer proofs
        for layer_challenge in challenges {
            // -- first layer
            {
                let c = layer_challenge.first_layer_challenge.absolute_index;

                // challenge input
                inputs.push(u64_into_fr(c));

                // comm_d inclusion proof for the data leaf
                inputs.extend(data_inclusion_inputs(c)?);

                // layer_inclusion proof
                inputs.extend(layer_inclusion_inputs(c)?);
            }

            // -- expander layers
            for challenge in &layer_challenge.expander_challenges {
                let c = challenge.absolute_index;

                // challenge input
                inputs.push(u64_into_fr(c));

                // comm_d inclusion proof for the data leaf
                inputs.extend(data_inclusion_inputs(c)?);

                // layer_inclusion proof
                inputs.extend(layer_inclusion_inputs(c)?);

                // parent_inclusion proofs
                let parents: ExpanderGraph = config.into();
                for p in parents.expanded_parents(challenge.relative_index) {
                    let parent = challenge.window as usize * config.num_nodes_window + p as usize;
                    inputs.extend(parent_inclusion_inputs(parent)?);
                }
            }

            // -- butterfly layers
            for (i, challenge) in layer_challenge.butterfly_challenges.iter().enumerate() {
                let layer = i + config.num_expander_layers + 1;
                let c = challenge.absolute_index;

                // challenge input
                inputs.push(u64_into_fr(c));

                // comm_d inclusion proof for the data leaf
                inputs.extend(data_inclusion_inputs(c)?);

                // layer_inclusion proof
                inputs.extend(layer_inclusion_inputs(c)?);

                // parent_inclusion proofs
                let parents: ButterflyGraph = config.into();
                for p in parents.parents(challenge.relative_index, layer as u32) {
                    let parent = challenge.window as usize * config.num_nodes_window + p as usize;
                    inputs.extend(parent_inclusion_inputs(parent)?);
                }
            }

            // -- last layer
            {
                let layer = config.num_layers();
                let challenge = layer_challenge.last_layer_challenge;
                let c = challenge.absolute_index;

                // challenge input
                inputs.push(u64_into_fr(c));

                // comm_d inclusion proof for the data leaf

                // comm_d inclusion proof for the data leaf
                inputs.extend(data_inclusion_inputs(c)?);

                // layer_inclusion proof
                inputs.extend(layer_inclusion_inputs(c)?);

                // parent_inclusion proofs
                let parents: ButterflyGraph = config.into();
                for p in parents.parents(challenge.relative_index, layer as u32) {
                    let parent = challenge.window as usize * config.num_nodes_window + p as usize;
                    inputs.extend(parent_inclusion_inputs(parent)?);
                }
            }
        }

        Ok(inputs)
    }

    fn circuit<'b>(
        public_inputs: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicInputs,
        _component_private_inputs: <NseCircuit<Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::Proof,
        public_params: &'b <NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<NseCircuit<'a, Tree, G>> {
        ensure!(
            !vanilla_proof.layer_proofs.is_empty(),
            "Cannot create a circuit with no vanilla proofs"
        );

        Ok(NseCircuit {
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_r: Some(public_inputs.tau.comm_r),
            comm_d: Some(public_inputs.tau.comm_d),
            layer_proofs: vanilla_proof
                .layer_proofs
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            comm_layers: vanilla_proof
                .comm_layers
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        })
    }

    fn blank_circuit(
        public_params: &<NarrowStackedExpander<Tree, G> as ProofScheme>::PublicParams,
    ) -> NseCircuit<'a, Tree, G> {
        let config = &public_params.config;

        NseCircuit {
            public_params: public_params.clone(),
            replica_id: None,
            comm_r: None,
            comm_d: None,
            layer_proofs: (0..public_params.num_layer_challenges)
                .map(|_| LayerProof::blank(config))
                .collect(),
            comm_layers: (0..config.num_layers()).map(|_| None).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem};
    use ff::Field;
    use generic_array::typenum::{Unsigned, U0, U4, U8};
    use merkletree::store::StoreConfig;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        cache_key::CacheKey,
        compound_proof,
        fr32::fr_into_bytes,
        hasher::{Hasher, PoseidonHasher, Sha256Hasher},
        merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
        test_helper::setup_replica,
        util::default_rows_to_discard,
    };

    use crate::nse::vanilla::{
        ChallengeRequirements, Config, PrivateInputs, PublicInputs, SetupParams, TemporaryAux,
        TemporaryAuxCache,
    };
    use crate::PoRep;

    #[test]
    #[ignore]
    fn test_nse_compound_poseidon_sub_8_4() {
        nse_test_compound::<DiskTree<PoseidonHasher, U8, U4, U0>>();
    }

    #[test]
    #[ignore]
    fn test_nse_compound_poseidon_sub_8_8() {
        nse_test_compound::<DiskTree<PoseidonHasher, U8, U8, U0>>();
    }

    fn nse_test_compound<Tree: 'static + MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let nodes = 8 * get_base_tree_count::<Tree>();
        let windows = Tree::SubTreeArity::to_usize();

        let replica_id: Fr = Fr::random(rng);
        let config = Config {
            k: 2,
            num_nodes_window: nodes / windows,
            degree_expander: 4,
            degree_butterfly: 2,
            num_expander_layers: 3,
            num_butterfly_layers: 2,
            sector_size: nodes * 32,
        };

        let data: Vec<u8> = (0..config.num_nodes_sector())
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let partition_count = 1;

        let setup_params = compound_proof::SetupParams {
            vanilla_params: SetupParams {
                config: config.clone(),
                num_layer_challenges: 2,
            },
            partitions: Some(partition_count),
            priority: false,
        };

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(config.num_nodes_sector(), 2),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let public_params = NseCompound::setup(&setup_params).expect("setup failed");
        let (tau, (p_aux, t_aux)) = NarrowStackedExpander::<Tree, _>::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            store_config,
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let seed = rng.gen();
        let public_inputs =
            PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
                replica_id: replica_id.into(),
                seed,
                tau,
                k: None,
            };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, _>::new(&config, &t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let private_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

        {
            let (circuit, inputs) =
                NseCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                    .unwrap();

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            if !cs.is_satisfied() {
                panic!(
                    "failed to satisfy: {:?}",
                    cs.which_is_unsatisfied().unwrap()
                );
            }
            assert!(
                cs.verify(&inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }

        // Use this to debug differences between blank and regular circuit generation.
        {
            let (circuit1, _inputs) =
                NseCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                    .unwrap();
            let blank_circuit = <NseCompound as CompoundProof<
                NarrowStackedExpander<Tree, Sha256Hasher>,
                _,
            >>::blank_circuit(&public_params.vanilla_params);

            let mut cs_blank = MetricCS::new();
            blank_circuit
                .synthesize(&mut cs_blank)
                .expect("failed to synthesize");

            let a = cs_blank.pretty_print_list();

            let mut cs1 = TestConstraintSystem::new();
            circuit1.synthesize(&mut cs1).expect("failed to synthesize");
            let b = cs1.pretty_print_list();

            for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq!(a, b, "failed at chunk {}", i);
            }
        }

        let blank_groth_params = <NseCompound as CompoundProof<
            NarrowStackedExpander<Tree, Sha256Hasher>,
            _,
        >>::groth_params(Some(rng), &public_params.vanilla_params)
        .expect("failed to generate groth params");

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        let proof = NseCompound::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = NseCompound::verify(
            &public_params,
            &public_inputs,
            &proof,
            &ChallengeRequirements {
                minimum_challenges: 1,
            },
        )
        .expect("failed while verifying");

        assert!(verified);

        cache_dir.close().expect("Failed to remove cache dir");
    }
}
