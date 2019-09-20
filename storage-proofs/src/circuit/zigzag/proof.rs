use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean::Boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::por::PoRCompound;
use crate::circuit::{
    constraint,
    zigzag::{hash::hash2, params::Proof},
};
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::{Graph, BASE_DEGREE};
use crate::hasher::Hasher;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::zigzag::{ZigZagDrgPoRep, EXP_DEGREE};

/// ZigZag DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
pub struct ZigZagCircuit<'a, E: JubjubEngine, H: 'static + Hasher> {
    params: &'a E::Params,
    public_params: <ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicParams,
    replica_id: Option<H::Domain>,
    comm_d: Option<H::Domain>,
    comm_r: Option<H::Domain>,
    comm_r_last: Option<H::Domain>,
    comm_c: Option<H::Domain>,

    // one proof per challenge
    proofs: Vec<Proof<H>>,

    _e: PhantomData<E>,
}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for ZigZagCircuit<'a, E, H> {
    type ComponentPrivateInputs = ();
}

impl<'a, H: Hasher> ZigZagCircuit<'a, Bls12, H> {
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicParams,
        replica_id: Option<H::Domain>,
        comm_d: Option<H::Domain>,
        comm_r: Option<H::Domain>,
        comm_r_last: Option<H::Domain>,
        comm_c: Option<H::Domain>,
        proofs: Vec<Proof<H>>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = ZigZagCircuit::<'a, Bls12, H> {
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

impl<'a, H: Hasher> Circuit<Bls12> for ZigZagCircuit<'a, Bls12, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let ZigZagCircuit {
            public_params,
            proofs,
            replica_id,
            comm_r,
            comm_d,
            comm_r_last,
            comm_c,
            ..
        } = self;

        let graph = &public_params.graph;
        let params = &self.params;
        // In most cases (the exception being during testing) we want to ensure that the base and
        // expansion degrees are the optimal values.
        if !cfg!(feature = "unchecked-degrees") {
            assert_eq!(graph.base_graph().degree(), BASE_DEGREE);
            assert_eq!(graph.expansion_degree(), EXP_DEGREE);
        }

        // Allocate replica_id
        let replica_id_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id_num"), || {
            replica_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let mut replica_id_bits =
            replica_id_num.into_bits_le(cs.namespace(|| "replica_id_bits"))?;
        // pad
        while replica_id_bits.len() % 8 > 0 {
            replica_id_bits.push(Boolean::Constant(false));
        }

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

        // Allocate comm_r_last as booleans
        let comm_r_last_bits = comm_r_last_num.into_bits_le(cs.namespace(|| "comm_r_last_bits"))?;

        // Allocate comm_c as Fr
        let comm_c_num = num::AllocatedNum::alloc(cs.namespace(|| "comm_c"), || {
            comm_c
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // Allocate comm_c as booleans
        let comm_c_bits = comm_c_num.into_bits_le(cs.namespace(|| "comm_c_bits"))?;

        // Verify comm_r = H(comm_c || comm_r_last)
        {
            let hash_num = hash2(
                cs.namespace(|| "H_comm_c_comm_r_last"),
                params,
                &comm_c_bits,
                &comm_r_last_bits,
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
                &comm_d_num,
                &comm_c_num,
                &comm_r_last_num,
                &replica_id_bits,
                graph.degree(),
            )?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub struct ZigZagCompound {
    partitions: Option<usize>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata> CacheableParameters<E, C, P>
    for ZigZagCompound
{
    fn cache_prefix() -> String {
        String::from("zigzag-proof-of-replication")
    }
}

impl<'a, H: 'static + Hasher>
    CompoundProof<'a, Bls12, ZigZagDrgPoRep<'a, H>, ZigZagCircuit<'a, Bls12, H>>
    for ZigZagCompound
{
    fn generate_public_inputs(
        pub_in: &<ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs,
        pub_params: &<ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        k: Option<usize>,
    ) -> Vec<Fr> {
        let graph_0 = &pub_params.graph;
        let graph_1 = ZigZagDrgPoRep::transform(graph_0);
        let graph_2 = ZigZagDrgPoRep::transform(&graph_1);

        let mut inputs = Vec::new();

        let comm_d = pub_in.tau.as_ref().expect("missing tau").comm_d;
        inputs.push(comm_d.into());

        let comm_r = pub_in.tau.as_ref().expect("missing tau").comm_r;
        inputs.push(comm_r.into());

        let challenges = pub_in.challenges(&pub_params.layer_challenges, graph_0.size(), k);
        let por_params = merklepor::MerklePoR::<H>::setup(&merklepor::SetupParams {
            leaves: graph_1.size(),
            private: true,
        })
        .expect("setup failed");

        let generate_inclusion_inputs = |c: usize| {
            let pub_inputs = merklepor::PublicInputs::<H::Domain> {
                challenge: c,
                commitment: None,
            };

            PoRCompound::<H>::generate_public_inputs(&pub_inputs, &por_params, k)
        };

        for challenge in challenges.into_iter() {
            // comm_d_proof
            inputs.extend(generate_inclusion_inputs(challenge));

            // replica column proof
            {
                // c_x
                inputs.extend(generate_inclusion_inputs(challenge));

                // c_inv_x
                inputs.extend(generate_inclusion_inputs(graph_0.inv_index(challenge)));

                // drg parents
                let mut drg_parents = vec![0; graph_0.base_graph().degree()];
                graph_0.base_graph().parents(challenge, &mut drg_parents);

                for parent in drg_parents.into_iter() {
                    inputs.extend(generate_inclusion_inputs(parent));
                }

                // exp parents even
                let exp_parents_even =
                    graph_1.expanded_parents(graph_1.inv_index(challenge), |p| p.clone());
                for parent in exp_parents_even.into_iter() {
                    inputs.extend(generate_inclusion_inputs(
                        graph_1.inv_index(parent as usize),
                    ));
                }

                // exp parents odd
                let exp_parents_odd = graph_2.expanded_parents(challenge, |p| p.clone());
                for parent in exp_parents_odd.into_iter() {
                    inputs.extend(generate_inclusion_inputs(parent as usize));
                }
            }

            // final replica layer
            {
                inputs.extend(generate_inclusion_inputs(graph_0.inv_index(challenge)));

                let mut parents = vec![0; graph_1.degree()];
                graph_1.parents(graph_0.inv_index(challenge), &mut parents);
                for parent in parents.into_iter() {
                    inputs.extend(generate_inclusion_inputs(parent as usize));
                }
            }
        }

        inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs,
        _component_private_inputs: <ZigZagCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep<H> as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, H> {
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

        ZigZagCircuit {
            params: engine_params,
            public_params: public_params.clone(),
            replica_id: Some(public_inputs.replica_id),
            comm_d: public_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: public_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(comm_r_last),
            comm_c: Some(comm_c),
            proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
            _e: PhantomData,
        }
    }

    fn blank_circuit(
        public_params: &<ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, H> {
        ZigZagCircuit {
            params,
            public_params: public_params.clone(),
            replica_id: None,
            comm_d: None,
            comm_r: None,
            comm_r_last: None,
            comm_c: None,
            proofs: vec![
                Proof::empty(public_params);
                public_params.layer_challenges.challenges_count()
            ],
            _e: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::metric::*;
    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgporep;
    use crate::drgraph::{new_seed, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;
    use crate::settings;
    use crate::zigzag::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, PublicInputs, SetupParams,
        EXP_DEGREE,
    };

    use ff::Field;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn zigzag_input_circuit_with_bls12_381() {
        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);
        let nodes = 5;
        let degree = BASE_DEGREE;
        let expansion_degree = EXP_DEGREE;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_fixed(num_layers, 1);

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Fr = rng.gen();
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            layer_challenges: layer_challenges.clone(),
        };

        let pp = ZigZagDrgPoRep::setup(&sp).expect("setup failed");
        let (tau, (p_aux, t_aux)) =
            ZigZagDrgPoRep::replicate(&pp, &replica_id.into(), data_copy.as_mut_slice(), None)
                .expect("replication failed");
        assert_ne!(data, data_copy);

        let pub_inputs = PublicInputs::<<PedersenHasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed: None,
            tau: Some(tau.into()),
            k: None,
        };

        let priv_inputs = PrivateInputs::<PedersenHasher> {
            p_aux: p_aux.into(),
            t_aux: t_aux.into(),
        };

        let proofs = ZigZagDrgPoRep::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1)
            .expect("failed to generate partition proofs");

        let proofs_are_valid = ZigZagDrgPoRep::verify_all_partitions(&pp, &pub_inputs, &proofs)
            .expect("failed to verify partition proofs");

        assert!(proofs_are_valid);

        let expected_inputs = 67; // was 39 with "old" zigzag all pedersen
        let expected_constraints = 599_035; // was 432_312 with "old" zigzag all pedersen

        {
            // Verify that MetricCS returns the same metrics as TestConstraintSystem.
            let mut cs = MetricCS::<Bls12>::new();

            ZigZagCompound::circuit(
            &pub_inputs,
            <ZigZagCircuit<Bls12, PedersenHasher> as CircuitComponent>::ComponentPrivateInputs::default(),
            &proofs[0],
            &pp,
            params,
        )
            .synthesize(&mut cs.namespace(|| "zigzag drgporep"))
            .expect("failed to synthesize circuit");

            assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                expected_constraints,
                "wrong number of constraints"
            );
        }
        let mut cs = TestConstraintSystem::<Bls12>::new();

        ZigZagCompound::circuit(
            &pub_inputs,
            <ZigZagCircuit<Bls12, PedersenHasher> as CircuitComponent>::ComponentPrivateInputs::default(),
            &proofs[0],
            &pp,
            params,
        )
        .synthesize(&mut cs.namespace(|| "zigzag drgporep"))
        .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs = ZigZagCompound::generate_public_inputs(&pub_inputs, &pp, None);
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
    fn test_zigzag_compound_pedersen() {
        zigzag_test_compound::<PedersenHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_zigzag_compound_blake2s() {
        zigzag_test_compound::<Blake2sHasher>();
    }

    fn zigzag_test_compound<H: 'static + Hasher>() {
        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let params = &JubjubBls12::new_with_window_size(window_size);
        let nodes = 5;
        let degree = 3;
        let expansion_degree = 2;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_fixed(num_layers, 3);
        let partition_count = 1;

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Fr = rng.gen();
        let data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let setup_params = compound_proof::SetupParams {
            engine_params: params,
            vanilla_params: &SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree,
                    seed: new_seed(),
                },
                layer_challenges: layer_challenges.clone(),
            },
            partitions: Some(partition_count),
        };

        let public_params = ZigZagCompound::setup(&setup_params).expect("setup failed");
        let (tau, (p_aux, t_aux)) = ZigZagDrgPoRep::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data_copy.as_mut_slice(),
            None,
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        let public_inputs = PublicInputs::<H::Domain> {
            replica_id: replica_id.into(),
            seed: None,
            tau: Some(tau),
            k: None,
        };
        let private_inputs = PrivateInputs::<H> { p_aux, t_aux };

        {
            let (circuit, inputs) =
                ZigZagCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

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
        // {
        //     let (circuit1, _inputs) =
        //         ZigZagCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);
        //     let blank_circuit =
        //         ZigZagCompound::blank_circuit(&public_params.vanilla_params, params);

        //     let mut cs_blank = TestConstraintSystem::new();
        //     blank_circuit
        //         .synthesize(&mut cs_blank)
        //         .expect("failed to synthesize");

        //     let a = cs_blank.pretty_print_list();

        //     let mut cs1 = TestConstraintSystem::new();
        //     circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        //     let b = cs1.pretty_print_list();

        //     for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
        //         assert_eq!(a, b, "failed at chunk {}", i);
        //     }
        // }

        let blank_groth_params =
            ZigZagCompound::groth_params(&public_params.vanilla_params, params)
                .expect("failed to generate groth params");

        let proof = ZigZagCompound::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = ZigZagCompound::verify(
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
