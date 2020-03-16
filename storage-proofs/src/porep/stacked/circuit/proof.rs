use std::marker::PhantomData;

use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use super::params::Proof;

use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::fr_into_bytes;
use crate::gadgets::constraint;
use crate::gadgets::por::PoRCompound;
use crate::hasher::{HashFunction, Hasher};
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::por;
use crate::porep::stacked::StackedDrg;
use crate::proof::ProofScheme;
use crate::util::bytes_into_boolean_vec_be;

/// Stacked DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
pub struct StackedCircuit<'a, E: JubjubEngine, H: 'static + Hasher, G: 'static + Hasher> {
    params: &'a E::Params,
    public_params: <StackedDrg<'a, H, G> as ProofScheme<'a>>::PublicParams,
    replica_id: Option<H::Domain>,
    comm_d: Option<G::Domain>,
    comm_r: Option<H::Domain>,
    comm_r_last: Option<H::Domain>,
    comm_c: Option<H::Domain>,

    // one proof per challenge
    proofs: Vec<Proof<H, G>>,

    _e: PhantomData<E>,
}

impl<'a, E: JubjubEngine, H: Hasher, G: Hasher> CircuitComponent for StackedCircuit<'a, E, H, G> {
    type ComponentPrivateInputs = ();
}

impl<'a, H: Hasher, G: 'static + Hasher> StackedCircuit<'a, Bls12, H, G> {
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <StackedDrg<'a, H, G> as ProofScheme<'a>>::PublicParams,
        replica_id: Option<H::Domain>,
        comm_d: Option<G::Domain>,
        comm_r: Option<H::Domain>,
        comm_r_last: Option<H::Domain>,
        comm_c: Option<H::Domain>,
        proofs: Vec<Proof<H, G>>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = StackedCircuit::<'a, Bls12, H, G> {
            params,
            public_params,
            replica_id,
            comm_d,
            comm_r,
            comm_r_last,
            comm_c,
            proofs,
            _e: PhantomData,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, H: Hasher, G: Hasher> Circuit<Bls12> for StackedCircuit<'a, Bls12, H, G> {
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

        let params = &self.params;

        // Allocate replica_id
        let replica_id_fr: Option<Fr> = replica_id.map(Into::into);
        let replica_id_bits = match replica_id_fr {
            Some(val) => {
                let bytes = fr_into_bytes::<Bls12>(&val);
                bytes_into_boolean_vec_be(cs.namespace(|| "replica_id_bits"), Some(&bytes), 256)
            }
            None => bytes_into_boolean_vec_be(cs.namespace(|| "replica_id_bits"), None, 256),
        }?;

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
            let hash_num = H::Function::hash2_circuit(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                &comm_c_num,
                &comm_r_last_num,
                params,
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
                &self.params,
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
pub struct StackedCompound<H: Hasher, G: Hasher> {
    partitions: Option<usize>,
    _h: PhantomData<H>,
    _g: PhantomData<G>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher, G: Hasher>
    CacheableParameters<E, C, P> for StackedCompound<H, G>
{
    fn cache_prefix() -> String {
        format!("stacked-proof-of-replication-{}-{}", H::name(), G::name())
    }
}

impl<'a, H: 'static + Hasher, G: 'static + Hasher>
    CompoundProof<'a, Bls12, StackedDrg<'a, H, G>, StackedCircuit<'a, Bls12, H, G>>
    for StackedCompound<H, G>
{
    fn generate_public_inputs(
        pub_in: &<StackedDrg<H, G> as ProofScheme>::PublicInputs,
        pub_params: &<StackedDrg<H, G> as ProofScheme>::PublicParams,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let graph = &pub_params.graph;

        let mut inputs = Vec::new();

        let comm_d = pub_in.tau.as_ref().expect("missing tau").comm_d;
        inputs.push(comm_d.into());

        let comm_r = pub_in.tau.as_ref().expect("missing tau").comm_r;
        inputs.push(comm_r.into());

        let por_params = por::PoR::<H, typenum::U2>::setup(&por::SetupParams {
            leaves: graph.size(),
            private: true,
        })?;

        let generate_inclusion_inputs = |c: usize| {
            let pub_inputs = por::PublicInputs::<H::Domain> {
                challenge: c,
                commitment: None,
            };

            PoRCompound::<H, typenum::U8>::generate_public_inputs(&pub_inputs, &por_params, k)
        };

        let all_challenges = pub_in.challenges(&pub_params.layer_challenges, graph.size(), k);

        for challenge in all_challenges.into_iter() {
            // comm_d_proof
            let pub_inputs = por::PublicInputs::<H::Domain> {
                challenge,
                commitment: None,
            };

            inputs.extend(PoRCompound::<H, typenum::U2>::generate_public_inputs(
                &pub_inputs,
                &por_params,
                k,
            )?);

            // replica column proof
            {
                // c_x
                inputs.extend(generate_inclusion_inputs(challenge)?);

                // drg parents
                let mut drg_parents = vec![0; graph.base_graph().degree()];
                graph.base_graph().parents(challenge, &mut drg_parents)?;

                for parent in drg_parents.into_iter() {
                    inputs.extend(generate_inclusion_inputs(parent as usize)?);
                }

                // exp parents
                let mut exp_parents = vec![0; graph.expansion_degree()];
                graph.expanded_parents(challenge, &mut exp_parents);
                for parent in exp_parents.into_iter() {
                    inputs.extend(generate_inclusion_inputs(parent as usize)?);
                }
            }

            // final replica layer
            inputs.extend(generate_inclusion_inputs(challenge)?);
        }

        Ok(inputs)
    }

    fn circuit<'b>(
        public_inputs: &'b <StackedDrg<H, G> as ProofScheme>::PublicInputs,
        _component_private_inputs: <StackedCircuit<'a, Bls12, H, G> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <StackedDrg<H, G> as ProofScheme>::Proof,
        public_params: &'b <StackedDrg<H, G> as ProofScheme>::PublicParams,
    ) -> Result<StackedCircuit<'a, Bls12, H, G>> {
        assert!(
            !vanilla_proof.is_empty(),
            "Cannot create a circuit with no vanilla proofs"
        );

        let comm_r_last = *vanilla_proof[0].comm_r_last();
        let comm_c = *vanilla_proof[0].comm_c();

        // ensure consistency
        assert!(vanilla_proof
            .iter()
            .all(|p| p.comm_r_last() == &comm_r_last));
        assert!(vanilla_proof.iter().all(|p| p.comm_c() == &comm_c));

        Ok(StackedCircuit {
            params: &*JJ_PARAMS,
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_d: public_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: public_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(comm_r_last),
            comm_c: Some(comm_c),
            proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
            _e: PhantomData,
        })
    }

    fn blank_circuit(
        public_params: &<StackedDrg<H, G> as ProofScheme>::PublicParams,
    ) -> StackedCircuit<'a, Bls12, H, G> {
        StackedCircuit {
            params: &*JJ_PARAMS,
            public_params: public_params.clone(),
            replica_id: None,
            comm_d: None,
            comm_r: None,
            comm_r_last: None,
            comm_c: None,
            proofs: (0..public_params.layer_challenges.challenges_count_all())
                .map(|_challenge_index| Proof::empty(public_params))
                .collect(),
            _e: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cache_key::CacheKey;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::gadgets::{MetricCS, TestConstraintSystem};
    use crate::hasher::{Hasher, PedersenHasher, PoseidonHasher, Sha256Hasher};
    use crate::porep::stacked::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, PublicInputs, SetupParams,
        TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    };
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;

    use ff::Field;
    use merkletree::store::StoreConfig;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn stacked_input_circuit_pedersen() {
        stacked_input_circuit::<PedersenHasher>(2_184_211);
    }

    #[test]
    fn stacked_input_circuit_poseidon() {
        stacked_input_circuit::<PoseidonHasher>(1_891_634);
    }

    fn stacked_input_circuit<H: Hasher + 'static>(expected_constraints: usize) {
        let nodes = 64;
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new(num_layers, 1);

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: Fr = Fr::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let sp = SetupParams {
            nodes,
            degree,
            expansion_degree,
            seed: new_seed(),
            layer_challenges: layer_challenges.clone(),
        };

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("stacked-input-circuit").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        let pp = StackedDrg::<H, Sha256Hasher>::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::<H, Sha256Hasher>::replicate(
            &pp,
            &replica_id.into(),
            (&mut data_copy[..]).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");
        assert_ne!(data, data_copy);

        let seed = rng.gen();

        let pub_inputs = PublicInputs::<<H as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau.into()),
            k: None,
        };

        // Store copy of original t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::new(&t_aux, replica_path.clone())
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs::<H, Sha256Hasher> {
            p_aux: p_aux.into(),
            t_aux: t_aux.into(),
        };

        let proofs =
            StackedDrg::<H, Sha256Hasher>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1)
                .expect("failed to generate partition proofs");

        let proofs_are_valid = StackedDrg::verify_all_partitions(&pp, &pub_inputs, &proofs)
            .expect("failed to verify partition proofs");

        assert!(proofs_are_valid);

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<H, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        let expected_inputs = 20;

        {
            // Verify that MetricCS returns the same metrics as TestConstraintSystem.
            let mut cs = MetricCS::<Bls12>::new();

            StackedCompound::circuit(
                &pub_inputs,
                <StackedCircuit<Bls12, H, Sha256Hasher> as CircuitComponent>::ComponentPrivateInputs::default(),
                &proofs[0],
                &pp,
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

        StackedCompound::circuit(
            &pub_inputs,
            <StackedCircuit<Bls12, H, Sha256Hasher> as CircuitComponent>::ComponentPrivateInputs::default(),
            &proofs[0],
            &pp,
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

        let generated_inputs = <StackedCompound<H, Sha256Hasher> as CompoundProof<
            _,
            StackedDrg<H, Sha256Hasher>,
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
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_stacked_compound_pedersen() {
        stacked_test_compound::<PedersenHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_stacked_compound_poseidon() {
        stacked_test_compound::<PoseidonHasher>();
    }

    fn stacked_test_compound<H: 'static + Hasher>() {
        let nodes = 8;

        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new(num_layers, 1);
        let partition_count = 1;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: Fr = Fr::random(rng);
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

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
            StoreConfig::default_cached_above_base_layer(nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("stacked-test-compound").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        let public_params = StackedCompound::setup(&setup_params).expect("setup failed");
        let (tau, (p_aux, t_aux)) = StackedDrg::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            (&mut data_copy[..]).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        let seed = rng.gen();

        let public_inputs = PublicInputs::<H::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau),
            k: None,
        };

        // Store a copy of the t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::new(&t_aux, replica_path.clone())
            .expect("failed to restore contents of t_aux");

        let private_inputs = PrivateInputs::<H, Sha256Hasher> { p_aux, t_aux };

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
            let blank_circuit = <StackedCompound<H, Sha256Hasher> as CompoundProof<
                _,
                StackedDrg<H, Sha256Hasher>,
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

        let blank_groth_params = <StackedCompound<H, Sha256Hasher> as CompoundProof<
            _,
            StackedDrg<H, Sha256Hasher>,
            _,
        >>::groth_params(Some(rng), &public_params.vanilla_params)
        .expect("failed to generate groth params");

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<H, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

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
    }
}
