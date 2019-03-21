use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::circuit::{boolean, num};
use sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::constraint;
use crate::circuit::drgporep::{ComponentPrivateInputs, DrgPoRepCompound};
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::hasher::{HashFunction, Hasher};
use crate::layered_drgporep::{self, Layers as LayersTrait};
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::porep;
use crate::proof::ProofScheme;
use crate::zigzag_drgporep::ZigZagDrgPoRep;

type Layers<'a, H, G> = Vec<
    Option<(
        <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        <DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof,
    )>,
>;

/// ZigZag DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
/// * `public_params` - ZigZagDrgPoRep public parameters.
/// * 'layers' - A vector of Layers – each representing a DrgPoRep proof (see Layers type definition).
///
pub struct ZigZagCircuit<'a, E: JubjubEngine, H: 'static + Hasher> {
    params: &'a E::Params,
    public_params: <ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicParams,
    layers: Layers<
        'a,
        <ZigZagDrgPoRep<'a, H> as LayersTrait>::Hasher,
        <ZigZagDrgPoRep<'a, H> as LayersTrait>::Graph,
    >,
    tau: Option<porep::Tau<<<ZigZagDrgPoRep<'a, H> as LayersTrait>::Hasher as Hasher>::Domain>>,
    comm_r_star: Option<H::Domain>,
    _e: PhantomData<E>,
}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for ZigZagCircuit<'a, E, H> {
    type ComponentPrivateInputs = ();
}

impl<'a, H: Hasher> ZigZagCircuit<'a, Bls12, H> {
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <ZigZagDrgPoRep<'a, H> as ProofScheme<'a>>::PublicParams,
        layers: Layers<
            'a,
            <ZigZagDrgPoRep<H> as LayersTrait>::Hasher,
            <ZigZagDrgPoRep<H> as LayersTrait>::Graph,
        >,
        tau: Option<porep::Tau<<<ZigZagDrgPoRep<H> as LayersTrait>::Hasher as Hasher>::Domain>>,
        comm_r_star: Option<H::Domain>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = ZigZagCircuit::<'a, Bls12, H> {
            params,
            public_params,
            layers,
            tau,
            comm_r_star,
            _e: PhantomData,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, H: Hasher> Circuit<Bls12> for ZigZagCircuit<'a, Bls12, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let graph = &self.public_params.graph;
        let layer_challenges = &self.public_params.layer_challenges;
        let sloth_iter = self.public_params.sloth_iter;

        assert_eq!(layer_challenges.layers(), self.layers.len());

        let mut comm_rs: Vec<num::AllocatedNum<_>> = Vec::with_capacity(self.layers.len());

        // allocate replica id
        let replica_id = self.layers[0].as_ref().and_then(|l| l.0.replica_id);
        let replica_id_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            replica_id
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // allocate comm_d
        let public_comm_d = num::AllocatedNum::alloc(cs.namespace(|| "public_comm_d"), || {
            let opt: Option<_> = self.tau.map(|t| t.comm_d.into());
            opt.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make comm_d a public input
        public_comm_d.inputize(cs.namespace(|| "zigzag_comm_d"))?;

        // allocate comm_r
        let public_comm_r = num::AllocatedNum::alloc(cs.namespace(|| "public_comm_r"), || {
            let opt: Option<_> = self.tau.map(|t| t.comm_r.into());
            opt.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // make comm_r a public input
        public_comm_r.inputize(cs.namespace(|| "zigzag_comm_r"))?;

        let height = graph.merkle_tree_depth() as usize;

        for (l, v) in self.layers.iter().enumerate() {
            let public_inputs = v.as_ref().map(|v| &v.0);
            let layer_proof = v.as_ref().map(|v| &v.1);

            let is_first_layer = l == 0;
            let is_last_layer = l == self.layers.len() - 1;

            // Get the matching proof for this layer.
            let proof = match layer_proof {
                Some(wrapped_proof) => {
                    let typed_proof: drgporep::Proof<<ZigZagDrgPoRep<H> as LayersTrait>::Hasher> =
                        wrapped_proof.into();
                    typed_proof
                }
                None => drgporep::Proof::new_empty(
                    height,
                    graph.degree(),
                    layer_challenges.challenges_for_layer(l),
                ),
            };

            // Get the comm_d for this layer.
            let comm_d = if is_first_layer {
                // On the first layer this is the publicly input comm_d.
                public_comm_d.clone()
            } else {
                // On all other layers this is the comm_r from the previous layer.
                comm_rs[l - 1].clone()
            };

            // Get the comm_r for this layer.
            let comm_r = if is_last_layer {
                // On the last layer this is the publicly input comm_r.
                public_comm_r.clone()
            } else {
                // On all other layers this is the replica root from current layer proof.
                num::AllocatedNum::alloc(
                    &mut cs.namespace(|| format!("layer {} comm_r", l)),
                    || {
                        layer_proof
                            .map(|proof| proof.replica_root.into())
                            .ok_or_else(|| SynthesisError::AssignmentMissing)
                    },
                )?
            };

            // Store the comm_r so we can use it in for the next layer, as well as when calculating comm_r_star.
            comm_rs.push(comm_r.clone());

            // TODO: As an optimization, we may be able to skip proving the original data
            // on some (50%?) of challenges.

            // Construct the public parameters for DrgPoRep.
            let porep_params = drgporep::PublicParams::new(
                graph.clone(), // TODO: avoid
                sloth_iter,
                true,
                layer_challenges.challenges_for_layer(l),
            );

            assert_eq!(layer_proof.is_none(), public_inputs.is_none());

            // Construct the DrgPoRep circut.
            let public_inputs = match public_inputs {
                Some(inputs) => inputs.clone(), // FIXME: avoid cloning
                None => drgporep::PublicInputs {
                    replica_id: None,
                    // These are ignored, so fine to pass `0` through.
                    challenges: vec![0; layer_challenges.challenges_for_layer(l)],
                    tau: None,
                },
            };
            let circuit = DrgPoRepCompound::circuit(
                &public_inputs,
                ComponentPrivateInputs {
                    comm_d: Some(Root::Var(comm_d)),
                    comm_r: Some(Root::Var(comm_r)),
                },
                &proof,
                &porep_params,
                self.params,
            );

            // Synthesize the constructed DrgPoRep circuit.
            circuit.synthesize(&mut cs.namespace(|| format!("zigzag_layer_#{}", l)))?;
        }

        // Compute CommRStar = Hash(replica_id | comm_r_0 | ... | comm_r_l).
        {
            // Collect the bits to be hashed into crs_boolean.
            let mut crs_boolean =
                replica_id_num.into_bits_le(cs.namespace(|| "replica_id_bits"))?;

            // sad padding is sad
            while crs_boolean.len() % 256 != 0 {
                crs_boolean.push(boolean::Boolean::Constant(false));
            }

            for (i, comm_r) in comm_rs.into_iter().enumerate() {
                crs_boolean
                    .extend(comm_r.into_bits_le(cs.namespace(|| format!("comm_r-bits-{}", i)))?);
                // sad padding is sad
                while crs_boolean.len() % 256 != 0 {
                    crs_boolean.push(boolean::Boolean::Constant(false));
                }
            }

            // Calculate the pedersen hash.
            let computed_comm_r_star = H::Function::hash_circuit(
                cs.namespace(|| "comm_r_star"),
                &crs_boolean[..],
                self.params,
            )?;

            // Allocate the resulting hash.
            let public_comm_r_star =
                num::AllocatedNum::alloc(cs.namespace(|| "public comm_r_star value"), || {
                    self.comm_r_star
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                        .map(Into::into)
                })?;

            // Enforce that the passed in comm_r_star is equal to the computed one.
            constraint::equal(
                cs,
                || "enforce comm_r_star is correct",
                &computed_comm_r_star,
                &public_comm_r_star,
            );

            // Make it a public input.
            public_comm_r_star.inputize(cs.namespace(|| "zigzag comm_r_star"))?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub struct ZigZagCompound {
    partitions: Option<usize>,
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
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
        let mut inputs = Vec::new();

        let comm_d = pub_in.tau.expect("missing tau").comm_d.into();
        inputs.push(comm_d);

        let comm_r = pub_in.tau.expect("missing tau").comm_r.into();
        inputs.push(comm_r);

        let mut current_graph = Some(pub_params.graph.clone());
        let layers = pub_params.layer_challenges.layers();
        for layer in 0..layers {
            let drgporep_pub_params = drgporep::PublicParams::new(
                current_graph.take().unwrap(),
                pub_params.sloth_iter,
                true,
                pub_params.layer_challenges.challenges_for_layer(layer),
            );

            let drgporep_pub_inputs = drgporep::PublicInputs {
                replica_id: Some(pub_in.replica_id),
                challenges: pub_in.challenges(
                    &pub_params.layer_challenges,
                    pub_params.graph.size(),
                    layer as u8,
                    k,
                ),
                tau: None,
            };

            let drgporep_inputs = DrgPoRepCompound::generate_public_inputs(
                &drgporep_pub_inputs,
                &drgporep_pub_params,
                None,
            );
            inputs.extend(drgporep_inputs);

            current_graph = Some(<ZigZagDrgPoRep<H> as layered_drgporep::Layers>::transform(
                &drgporep_pub_params.graph,
            ));
        }
        inputs.push(pub_in.comm_r_star.into());
        inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs,
        _component_private_inputs: <ZigZagCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep<H> as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, H> {
        let layers = (0..(vanilla_proof.encoding_proofs.len()))
            .map(|l| {
                let layer_public_inputs = drgporep::PublicInputs {
                    replica_id: Some(public_inputs.replica_id),
                    // Challenges are not used in circuit synthesis. Don't bother generating.
                    challenges: vec![],
                    tau: None,
                };
                let layer_proof = vanilla_proof.encoding_proofs[l].clone();
                Some((layer_public_inputs, layer_proof))
            })
            .collect();

        let pp: <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams = public_params.into();

        ZigZagCircuit {
            params: engine_params,
            public_params: pp,
            tau: public_inputs.tau,
            comm_r_star: Some(public_inputs.comm_r_star),
            layers,
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
            tau: None,
            comm_r_star: None,
            layers: vec![None; public_params.layer_challenges.layers()],
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
    use crate::drgraph::new_seed;
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::layered_drgporep::{self, LayerChallenges};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;

    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    #[test]
    fn zigzag_drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let nodes = 5;
        let degree = 1;
        let expansion_degree = 2;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_fixed(num_layers, 1);
        let sloth_iter = 1;

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
        let sp = layered_drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes: n,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            sloth_iter,
            layer_challenges: layer_challenges.clone(),
        };

        let pp = ZigZagDrgPoRep::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, &replica_id.into(), data_copy.as_mut_slice(), None)
                .unwrap();
        assert_ne!(data, data_copy);

        let simplified_tau = tau.clone().simplify();

        let pub_inputs = layered_drgporep::PublicInputs::<<PedersenHasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star.into(),
            k: None,
        };

        let priv_inputs = layered_drgporep::PrivateInputs::<PedersenHasher> {
            aux: aux.into(),
            tau: tau.layer_taus.into(),
        };

        let proofs =
            ZigZagDrgPoRep::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1).unwrap();
        assert!(ZigZagDrgPoRep::verify_all_partitions(&pp, &pub_inputs, &proofs).unwrap());

        // End copied section.

        let expected_inputs = 16;
        let expected_constraints = 131094;
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

        assert_eq!(
            cs.get_input(1, "zigzag drgporep/zigzag_comm_d/input variable"),
            simplified_tau.comm_d.into(),
        );

        assert_eq!(
            cs.get_input(2, "zigzag drgporep/zigzag_comm_r/input variable"),
            simplified_tau.comm_r.into(),
        );

        assert_eq!(
            cs.get_input(3, "zigzag drgporep/zigzag_layer_#0/replica_id/input 0"),
            replica_id.into(),
        );

        // This test was modeled on equivalent from drgporep circuit.
        // TODO: add add assertions about other inputs.
    }

    // Thist test is broken. empty proofs do not validate
    //
    // #[test]
    // fn zigzag_input_circuit_num_constraints_fixed() {
    //     let params = &JubjubBls12::new();
    //     let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    //     // 1 GB
    //     let n = (1 << 30) / 32;
    //     let num_layers = 2;
    //     let base_degree = 2;
    //     let expansion_degree = 2;
    //     let layer_challenges = LayerChallenges::new_fixed(num_layers, 1);
    //     let sloth_iter = 2;
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
    //         layered_drgporep::PublicParams::new(graph, sloth_iter, layer_challenges);

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
        let params = &JubjubBls12::new();
        let nodes = 5;
        let degree = 2;
        let expansion_degree = 1;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_tapered(num_layers, 3, num_layers, 1.0 / 3.0);
        let sloth_iter = 1;
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
            vanilla_params: &layered_drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes: n,
                    degree,
                    expansion_degree,
                    seed: new_seed(),
                },
                sloth_iter,
                layer_challenges: layer_challenges.clone(),
            },
            partitions: Some(partition_count),
        };

        let public_params = ZigZagCompound::setup(&setup_params).unwrap();
        let (tau, aux) = ZigZagDrgPoRep::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data_copy.as_mut_slice(),
            None,
        )
        .unwrap();
        assert_ne!(data, data_copy);

        let public_inputs = layered_drgporep::PublicInputs::<H::Domain> {
            replica_id: replica_id.into(),
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };
        let private_inputs = layered_drgporep::PrivateInputs::<H> {
            aux,
            tau: tau.layer_taus,
        };

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
            ZigZagCompound::groth_params(&public_params.vanilla_params, params).unwrap();

        let proof = ZigZagCompound::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = ZigZagCompound::verify(&public_params, &public_inputs, &proof)
            .expect("failed while verifying");

        assert!(verified);
    }
}
