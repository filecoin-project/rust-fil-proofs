use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::Graph,
    error::Result,
    fr32::u64_into_fr,
    gadgets::constraint,
    gadgets::por::PoRCompound,
    hasher::{HashFunction, Hasher},
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
    util::fixup_bits,
};

use super::params::Proof;
use crate::stacked::StackedDrg;

/// Stacked DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
pub struct StackedCircuit<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> {
    public_params: <StackedDrg<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
    replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_d: Option<G::Domain>,
    comm_r: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_r_last: Option<<Tree::Hasher as Hasher>::Domain>,
    comm_c: Option<<Tree::Hasher as Hasher>::Domain>,

    // one proof per challenge
    proofs: Vec<Proof<Tree, G>>,
}

impl<'a, Tree: MerkleTreeTrait, G: Hasher> CircuitComponent for StackedCircuit<'a, Tree, G> {
    type ComponentPrivateInputs = ();
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> StackedCircuit<'a, Tree, G> {
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        public_params: <StackedDrg<'a, Tree, G> as ProofScheme<'a>>::PublicParams,
        replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_d: Option<G::Domain>,
        comm_r: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_r_last: Option<<Tree::Hasher as Hasher>::Domain>,
        comm_c: Option<<Tree::Hasher as Hasher>::Domain>,
        proofs: Vec<Proof<Tree, G>>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = StackedCircuit::<'a, Tree, G> {
            public_params,
            replica_id,
            comm_d,
            comm_r,
            comm_r_last,
            comm_c,
            proofs,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, Tree: MerkleTreeTrait, G: Hasher> Circuit<Bls12> for StackedCircuit<'a, Tree, G> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let StackedCircuit {
            public_params,
            proofs,
            replica_id,
            comm_r,
            comm_d,
            comm_r_last,
            comm_c,
            ..
        } = self;

        // Allocate replica_id
        let replica_id_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            replica_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make replica_id a public input
        replica_id_num.inputize(cs.namespace(|| "replica_id_input"))?;

        let replica_id_bits =
            fixup_bits(replica_id_num.to_bits_le(cs.namespace(|| "replica_id_bits"))?);

        // Allocate comm_d as Fr
        let comm_d_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_d"), || {
            comm_d
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make comm_d a public input
        comm_d_num.inputize(cs.namespace(|| "comm_d_input"))?;

        // Allocate comm_r as Fr
        let comm_r_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            comm_r
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make comm_r a public input
        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        // Allocate comm_r_last as Fr
        let comm_r_last_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_r_last"), || {
            comm_r_last
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // Allocate comm_c as Fr
        let comm_c_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // Verify comm_r = H(comm_c || comm_r_last)
        {
            let hash_num = <Tree::Hasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                &comm_c_num,
                &comm_r_last_num,
            )?;

            // Check actual equality
            constraint::equal(
                cs,
                || "enforce comm_r = H(comm_c || comm_r_last)",
                &comm_r_num,
                &hash_num,
            );
        }

        for (i, proof) in proofs.into_iter().enumerate() {
            proof.synthesize(
                &mut cs.namespace(|| format!("challenge_{}", i)),
                public_params.layer_challenges.layers(),
                &comm_d_num,
                &comm_c_num,
                &comm_r_last_num,
                &replica_id_bits,
            )?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub struct StackedCompound<Tree: MerkleTreeTrait, G: Hasher> {
    partitions: Option<usize>,
    _t: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait, G: Hasher>
    CacheableParameters<C, P> for StackedCompound<Tree, G>
{
    fn cache_prefix() -> String {
        format!(
            "stacked-proof-of-replication-{}-{}",
            Tree::display(),
            G::name()
        )
    }
}

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher>
    CompoundProof<'a, StackedDrg<'a, Tree, G>, StackedCircuit<'a, Tree, G>>
    for StackedCompound<Tree, G>
{
    fn generate_public_inputs(
        pub_in: &<StackedDrg<Tree, G> as ProofScheme>::PublicInputs,
        pub_params: &<StackedDrg<Tree, G> as ProofScheme>::PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let graph = &pub_params.graph;

        let mut inputs = Vec::new();

        let replica_id = pub_in.replica_id;
        inputs.push(replica_id.into());

        let comm_d = pub_in.tau.as_ref().expect("missing tau").comm_d;
        inputs.push(comm_d.into());

        let comm_r = pub_in.tau.as_ref().expect("missing tau").comm_r;
        inputs.push(comm_r.into());

        let por_setup_params = por::SetupParams {
            leaves: graph.size(),
            private: true,
        };

        let por_params = por::PoR::<Tree>::setup(&por_setup_params)?;
        let por_params_d = por::PoR::<BinaryMerkleTree<G>>::setup(&por_setup_params)?;

        let all_challenges = pub_in.challenges(&pub_params.layer_challenges, graph.size(), k);

        for challenge in all_challenges.into_iter() {
            // comm_d inclusion proof for the data leaf
            inputs.extend(generate_inclusion_inputs::<BinaryMerkleTree<G>>(
                &por_params_d,
                challenge,
                k,
            )?);

            // drg parents
            let mut drg_parents = vec![0; graph.base_graph().degree()];
            graph.base_graph().parents(challenge, &mut drg_parents)?;

            // Inclusion Proofs: drg parent node in comm_c
            for parent in drg_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs::<Tree>(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            // exp parents
            let mut exp_parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(challenge, &mut exp_parents);

            // Inclusion Proofs: expander parent node in comm_c
            for parent in exp_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs::<Tree>(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            inputs.push(u64_into_fr(challenge as u64));

            // Inclusion Proof: encoded node in comm_r_last
            inputs.extend(generate_inclusion_inputs::<Tree>(
                &por_params,
                challenge,
                k,
            )?);

            // Inclusion Proof: column hash of the challenged node in comm_c
            inputs.extend(generate_inclusion_inputs::<Tree>(
                &por_params,
                challenge,
                k,
            )?);
        }

        Ok(inputs)
    }

    fn circuit<'b>(
        public_inputs: &'b <StackedDrg<Tree, G> as ProofScheme>::PublicInputs,
        _component_private_inputs: <StackedCircuit<'a, Tree, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <StackedDrg<Tree, G> as ProofScheme>::Proof,
        public_params: &'b <StackedDrg<Tree, G> as ProofScheme>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<StackedCircuit<'a, Tree, G>> {
        ensure!(
            !vanilla_proof.is_empty(),
            "Cannot create a circuit with no vanilla proofs"
        );

        let comm_r_last = vanilla_proof[0].comm_r_last();
        let comm_c = vanilla_proof[0].comm_c();

        // ensure consistency
        ensure!(
            vanilla_proof.iter().all(|p| p.comm_r_last() == comm_r_last),
            "inconsistent comm_r_lasts"
        );
        ensure!(
            vanilla_proof.iter().all(|p| p.comm_c() == comm_c),
            "inconsistent comm_cs"
        );

        Ok(StackedCircuit {
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_d: public_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: public_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(comm_r_last),
            comm_c: Some(comm_c),
            proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
        })
    }

    fn blank_circuit(
        public_params: &<StackedDrg<Tree, G> as ProofScheme>::PublicParams,
    ) -> StackedCircuit<'a, Tree, G> {
        StackedCircuit {
            public_params: public_params.clone(),
            replica_id: None,
            comm_d: None,
            comm_r: None,
            comm_r_last: None,
            comm_c: None,
            proofs: (0..public_params.layer_challenges.challenges_count_all())
                .map(|_challenge_index| Proof::empty(public_params))
                .collect(),
        }
    }
}

/// Helper to generate public inputs for inclusion proofs.
fn generate_inclusion_inputs<Tree: 'static + MerkleTreeTrait>(
    por_params: &por::PublicParams,
    challenge: usize,
    k: Option<usize>,
) -> Result<Vec<Fr>> {
    let pub_inputs = por::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        challenge,
        commitment: None,
    };

    PoRCompound::<Tree>::generate_public_inputs(&pub_inputs, por_params, k)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use generic_array::typenum::{U0, U2, U4, U8};
    use merkletree::store::StoreConfig;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{
        cache_key::CacheKey,
        compound_proof,
        drgraph::{new_seed, BASE_DEGREE},
        fr32::fr_into_bytes,
        gadgets::{MetricCS, TestConstraintSystem},
        hasher::{Hasher, PedersenHasher, PoseidonHasher, Sha256Hasher},
        merkle::{get_base_tree_count, BinaryMerkleTree, DiskTree, MerkleTreeTrait},
        proof::ProofScheme,
        test_helper::setup_replica,
    };

    use crate::stacked::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, PublicInputs, SetupParams,
        TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    };
    use crate::PoRep;

    #[test]
    fn stacked_input_circuit_pedersen_base_2() {
        stacked_input_circuit::<DiskTree<PedersenHasher, U2, U0, U0>>(22, 1_258_195);
    }

    #[test]
    fn stacked_input_circuit_poseidon_base_2() {
        stacked_input_circuit::<DiskTree<PoseidonHasher, U2, U0, U0>>(22, 1_206_402);
    }

    #[test]
    fn stacked_input_circuit_poseidon_base_8() {
        stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U0, U0>>(22, 1_200_258);
    }

    #[test]
    fn stacked_input_circuit_poseidon_sub_8_4() {
        stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U4, U0>>(22, 1_297_326);
    }

    #[test]
    fn stacked_input_circuit_poseidon_top_8_4_2() {
        stacked_input_circuit::<DiskTree<PoseidonHasher, U8, U4, U2>>(22, 1_347_780);
    }

    fn stacked_input_circuit<Tree: MerkleTreeTrait + 'static>(
        expected_inputs: usize,
        expected_constraints: usize,
    ) {
        let nodes = 8 * get_base_tree_count::<Tree>();
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new(num_layers, 1);

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: Fr = Fr::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: layer_challenges.clone(),
        };

        let pp = StackedDrg::<Tree, Sha256Hasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher>::replicate(
            &pp,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let seed = rng.gen();

        let pub_inputs =
            PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
                replica_id: replica_id.into(),
                seed,
                tau: Some(tau.into()),
                k: None,
            };

        // Store copy of original t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher>::new(&t_aux, replica_path.clone())
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs::<Tree, Sha256Hasher> {
            p_aux: p_aux.into(),
            t_aux: t_aux.into(),
        };

        let proofs = StackedDrg::<Tree, Sha256Hasher>::prove_all_partitions(
            &pp,
            &pub_inputs,
            &priv_inputs,
            1,
        )
        .expect("failed to generate partition proofs");

        let proofs_are_valid =
            StackedDrg::<Tree, Sha256Hasher>::verify_all_partitions(&pp, &pub_inputs, &proofs)
                .expect("failed to verify partition proofs");

        assert!(proofs_are_valid);

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        {
            // Verify that MetricCS returns the same metrics as TestConstraintSystem.
            let mut cs = MetricCS::<Bls12>::new();

            StackedCompound::<Tree, Sha256Hasher>::circuit(
                &pub_inputs,
                <StackedCircuit<Tree, Sha256Hasher> as CircuitComponent>::ComponentPrivateInputs::default(),
                &proofs[0],
                &pp,
                None,
            )
            .expect("circuit failed")
            .synthesize(&mut cs.namespace(|| "stacked drgporep"))
            .expect("failed to synthesize circuit");

            assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                expected_constraints,
                "wrong number of constraints"
            );
        }
        let mut cs = TestConstraintSystem::<Bls12>::new();

        StackedCompound::<Tree, Sha256Hasher>::circuit(
            &pub_inputs,
            <StackedCircuit<Tree, Sha256Hasher> as CircuitComponent>::ComponentPrivateInputs::default(),
            &proofs[0],
            &pp,
            None,
        )
        .expect("circuit failed")
        .synthesize(&mut cs.namespace(|| "stacked drgporep"))
        .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
            StackedDrg<Tree, Sha256Hasher>,
            _,
        >>::generate_public_inputs(&pub_inputs, &pp, None)
        .expect("failed to generate public inputs");
        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input) in
            expected_inputs.iter().skip(1).zip(generated_inputs.iter())
        {
            assert_eq!(input, generated_input, "{}", label);
        }

        assert_eq!(
            generated_inputs.len(),
            expected_inputs.len() - 1,
            "inputs are not the same length"
        );

        cache_dir.close().expect("Failed to remove cache dir");
    }

    #[test]
    #[ignore]
    fn test_stacked_compound_pedersen() {
        stacked_test_compound::<BinaryMerkleTree<PedersenHasher>>();
    }

    #[test]
    #[ignore]
    fn test_stacked_compound_poseidon_base_8() {
        stacked_test_compound::<DiskTree<PoseidonHasher, U8, U0, U0>>();
    }

    #[test]
    #[ignore]
    fn test_stacked_compound_poseidon_sub_8_4() {
        stacked_test_compound::<DiskTree<PoseidonHasher, U8, U4, U0>>();
    }

    #[test]
    #[ignore]
    fn test_stacked_compound_poseidon_top_8_4_2() {
        stacked_test_compound::<DiskTree<PoseidonHasher, U8, U4, U2>>();
    }

    fn stacked_test_compound<Tree: 'static + MerkleTreeTrait>() {
        let nodes = 8 * get_base_tree_count::<Tree>();

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new(num_layers, 1);
        let partition_count = 1;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: Fr = Fr::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: SetupParams {
                nodes,
                degree,
                expansion_degree,
                seed: new_seed(),
                layer_challenges: layer_challenges.clone(),
            },
            partitions: Some(partition_count),
            priority: false,
        };

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_rows_to_discard(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");

        // create a copy, so we can compare roundtrips
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let public_params = StackedCompound::setup(&setup_params).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, _>::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            config,
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
                tau: Some(tau),
                k: None,
            };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, _>::new(&t_aux, replica_path.clone())
            .expect("failed to restore contents of t_aux");

        let private_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

        {
            let (circuit, inputs) =
                StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
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
                StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                    .unwrap();
            let blank_circuit = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
                StackedDrg<Tree, Sha256Hasher>,
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

        let blank_groth_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
            StackedDrg<Tree, Sha256Hasher>,
            _,
        >>::groth_params(Some(rng), &public_params.vanilla_params)
        .expect("failed to generate groth params");

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        let proof = StackedCompound::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = StackedCompound::verify(
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
