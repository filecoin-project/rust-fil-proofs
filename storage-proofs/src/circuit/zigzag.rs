use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
// use fil_sapling_crypto::circuit::{boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

// use crate::circuit::constraint;
// use crate::circuit::drgporep::{ComponentPrivateInputs, DrgPoRepCompound};
// use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::{Graph, BASE_DEGREE};
use crate::hasher::Hasher;
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
    public_inputs: Option<<ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicInputs>,
    vanilla_proof: Option<<ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::Proof>,
    _e: PhantomData<E>,
}

// TODO: create `Option` version of the different inputs

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for ZigZagCircuit<'a, E, H> {
    type ComponentPrivateInputs = ();
}

impl<'a, H: Hasher> ZigZagCircuit<'a, Bls12, H> {
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicParams,
        public_inputs: Option<<ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicInputs>,
        vanilla_proof: Option<<ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::Proof>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = ZigZagCircuit::<'a, Bls12, H> {
            params,
            public_params,
            public_inputs,
            vanilla_proof,
            _e: PhantomData,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, H: Hasher> Circuit<Bls12> for ZigZagCircuit<'a, Bls12, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let graph = &self.public_params.graph;
        // let layer_challenges = &self.public_params.layer_challenges;

        // In most cases (the exception being during testing) we want to ensure that the base and
        // expansion degrees are the optimal values.
        if !cfg!(feature = "unchecked-degrees") {
            assert_eq!(graph.base_graph().degree(), BASE_DEGREE);
            assert_eq!(graph.expansion_degree(), EXP_DEGREE);
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
        unimplemented!()
        // let mut inputs = Vec::new();

        // let comm_d = pub_in.tau.expect("missing tau").comm_d.into();
        // inputs.push(comm_d);

        // let comm_r = pub_in.tau.expect("missing tau").comm_r.into();
        // inputs.push(comm_r);

        // let mut current_graph = Some(pub_params.graph.clone());
        // let layers = pub_params.layer_challenges.layers();
        // for layer in 0..layers {
        //     let drgporep_pub_params = drgporep::PublicParams::new(
        //         current_graph.take().unwrap(),
        //         true,
        //         pub_params.layer_challenges.challenges(),
        //     );

        //     let drgporep_pub_inputs = drgporep::PublicInputs {
        //         replica_id: Some(pub_in.replica_id),
        //         challenges: pub_in.challenges(
        //             &pub_params.layer_challenges,
        //             pub_params.graph.size(),
        //             k,
        //         ),
        //         tau: None,
        //     };

        //     let drgporep_inputs = DrgPoRepCompound::generate_public_inputs(
        //         &drgporep_pub_inputs,
        //         &drgporep_pub_params,
        //         None,
        //     );
        //     inputs.extend(drgporep_inputs);

        //     current_graph = Some(<ZigZagDrgPoRep<H> as zigzag_drgporep::Layers>::transform(
        //         &drgporep_pub_params.graph,
        //     ));
        // }
        // inputs.push(pub_in.comm_r_star.into());
        // inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs,
        _component_private_inputs: <ZigZagCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep<H> as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, H> {
        ZigZagCircuit {
            params: engine_params,
            public_params: public_params.clone(),
            public_inputs: Some(public_inputs.clone()),
            vanilla_proof: Some(vanilla_proof.clone()),
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
            public_inputs: None,
            vanilla_proof: None,
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
    fn zigzag_drgporep_input_circuit_with_bls12_381() {
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

        let n = nodes; // FIXME: Consolidate variable names.

        // TODO: The code in this section was copied directly from zizag_drgporep::tests::prove_verify.
        // We should refactor to share the code – ideally in such a way that we can just add
        // methods and get the assembled tests for free.
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Fr = rng.gen();
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let sp = SetupParams {
            drg: drgporep::DrgParams {
                nodes: n,
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

        // End copied section.

        let expected_inputs = 36;
        let expected_constraints = 432312;
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

        // This test was modeled on equivalent from drgporep circuit.
        // TODO: add add assertions about other inputs.
    }

    // Thist test is broken. empty proofs do not validate
    //
    // #[test]
    // fn zigzag_input_circuit_num_constraints_fixed() {
    //     let window_size = settings::SETTINGS.lock().unwrap().pedersen_hash_exp_window_size;
    //     let params = &JubjubBls12::new_with_window_size(window_size);
    //     let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    //     // 1 GB
    //     let n = (1 << 30) / 32;
    //     let num_layers = 2;
    //     let base_degree = 2;
    //     let expansion_degree = 2;
    //     let layer_challenges = LayerChallenges::new_fixed(num_layers, 1);
    //     let challenge = 1;
    //     let replica_id: Fr = rng.gen();

    //     let mut cs = TestConstraintSystem::<Bls12>::new();
    //     let graph = ZigZagGraph::new_zigzag(n, base_degree, expansion_degree, new_seed());
    //     let height = graph.merkle_tree_depth() as usize;

    //     let layers = (0..num_layers)
    //         .map(|l| {
    //             // l is ignored because we assume uniform layers here.
    //             let public_inputs = drgporep::PublicInputs {
    //                 replica_id: replica_id.into(),
    //                 challenges: vec![challenge],
    //                 tau: None,
    //             };
    //             let proof = drgporep::Proof::new_empty(
    //                 height,
    //                 graph.degree(),
    //                 layer_challenges.challenges_for_layer(l),
    //             );
    //             Some((public_inputs, proof))
    //         })
    //         .collect();
    //     let public_params =
    //         PublicParams::new(graph, layer_challenges);

    //     ZigZagCircuit::<Bls12, PedersenHasher>::synthesize(
    //         cs.namespace(|| "zigzag_drgporep"),
    //         params,
    //         public_params,
    //         layers,
    //         Some(porep::Tau {
    //             comm_r: rng.gen(),
    //             comm_d: rng.gen(),
    //         }),
    //         rng.gen(),
    //     )
    //     .expect("failed to synthesize circuit");
    //     assert!(cs.is_satisfied(), "TestContraintSystem was not satisfied");

    //     assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
    //     assert_eq!(cs.num_constraints(), 547539, "wrong number of constraints");
    // }

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
        let degree = 2;
        let expansion_degree = 1;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_fixed(num_layers, 3);
        let partition_count = 1;

        let n = nodes; // FIXME: Consolidate variable names.

        // TODO: The code in this section was copied directly from zizag_drgporep::tests::prove_verify.
        // We should refactor to share the code – ideally in such a way that we can just add
        // methods and get the assembled tests for free.
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Fr = rng.gen();
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let setup_params = compound_proof::SetupParams {
            engine_params: params,
            vanilla_params: &SetupParams {
                drg: drgporep::DrgParams {
                    nodes: n,
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

        // TOOD: Move this to e.g. circuit::test::compound_helper and share between all compound proofs.
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
        // let blank_circuit = ZigZagCompound::blank_circuit(&public_params.vanilla_params, params);
        // let (circuit1, _inputs) =
        // ZigZagCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

        // {
        //     let mut cs_blank = TestConstraintSystem::new();
        //     blank_circuit
        //         .synthesize(&mut cs_blank)
        //         .expect("failed to synthesize");

        //     let a = cs_blank.pretty_print();

        //     let mut cs1 = TestConstraintSystem::new();
        //     circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        //     let b = cs1.pretty_print();

        //     let a_vec = a.split("\n").collect::<Vec<_>>();
        //     let b_vec = b.split("\n").collect::<Vec<_>>();

        //     for (i, (a, b)) in a_vec.chunks(100).zip(b_vec.chunks(100)).enumerate() {
        //         println!("chunk {}", i);
        //         assert_eq!(a, b);
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
