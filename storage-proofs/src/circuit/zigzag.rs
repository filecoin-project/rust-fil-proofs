use std::marker::PhantomData;

use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::circuit::num::AllocatedNum;
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::alloc::alloc_priv_num;
use crate::circuit::constraint;
use crate::circuit::drgporep::{ComponentPrivateInputs, DrgPoRepCompound};
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::hasher::{HashFunction, Hasher};
use crate::layered_drgporep::{self, Layers as LayersTrait};
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::porep;
use crate::proof::ProofScheme;
use crate::zigzag_drgporep::ZigZagDrgPoRep;

type Layers<'a, AH, BH, G> = Vec<
    Option<(
        <DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::PublicInputs,
        <DrgPoRep<'a, AH, BH, G> as ProofScheme<'a>>::Proof,
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
#[allow(clippy::type_complexity)]
pub struct ZigZagCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: 'static + Hasher,
    BH: 'static + Hasher,
{
    params: &'a E::Params,
    public_params: <ZigZagDrgPoRep<'a, AH, BH> as ProofScheme<'a>>::PublicParams,
    layers: Layers<
        'a,
        <ZigZagDrgPoRep<'a, AH, BH> as LayersTrait>::AlphaHasher,
        <ZigZagDrgPoRep<'a, AH, BH> as LayersTrait>::BetaHasher,
        <ZigZagDrgPoRep<'a, AH, BH> as LayersTrait>::Graph,
    >,
    tau: Option<
        porep::Tau<<<ZigZagDrgPoRep<'a, AH, BH> as LayersTrait>::AlphaHasher as Hasher>::Domain>,
    >,
    comm_r_star: Option<AH::Domain>,
    _e: PhantomData<E>,
}

impl<'a, E, AH, BH> CircuitComponent for ZigZagCircuit<'a, E, AH, BH>
where
    E: JubjubEngine,
    AH: Hasher,
    BH: Hasher,
{
    type ComponentPrivateInputs = ();
}

impl<'a, AH, BH> ZigZagCircuit<'a, Bls12, AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <ZigZagDrgPoRep<'a, AH, BH> as ProofScheme<'a>>::PublicParams,
        layers: Layers<
            'a,
            <ZigZagDrgPoRep<AH, BH> as LayersTrait>::AlphaHasher,
            <ZigZagDrgPoRep<AH, BH> as LayersTrait>::BetaHasher,
            <ZigZagDrgPoRep<AH, BH> as LayersTrait>::Graph,
        >,
        tau: Option<
            porep::Tau<<<ZigZagDrgPoRep<AH, BH> as LayersTrait>::AlphaHasher as Hasher>::Domain>,
        >,
        comm_r_star: Option<AH::Domain>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let circuit = ZigZagCircuit {
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

impl<'a, AH, BH> Circuit<Bls12> for ZigZagCircuit<'a, Bls12, AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    fn synthesize<CS>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let graph = &self.public_params.graph;
        let sloth_iter = self.public_params.sloth_iter;
        let layer_challenges = &self.public_params.layer_challenges;
        let n_layers = self.layers.len();

        assert_eq!(layer_challenges.layers(), n_layers);

        // Stores each layer's comm_r to be used as the next layer's comm_d and for calculating
        // comm_r_star.
        let mut comm_rs: Vec<AllocatedNum<Bls12>> = Vec::with_capacity(n_layers);

        // Allocate the replica-id.
        let replica_id = self.layers[0]
            .as_ref()
            .and_then(|layer_info| layer_info.0.replica_id)
            .map(|replica_id| alloc_priv_num(cs, "replica_id", replica_id))
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Allocate comm_d and comm_r_last.
        let (comm_d, comm_r_last) = match self.tau {
            Some(tau) => {
                let comm_d = alloc_priv_num(cs, "public_comm_d", tau.comm_d);
                let comm_r_last = alloc_priv_num(cs, "public_comm_r", tau.comm_r);
                (comm_d, comm_r_last)
            }
            None => return Err(SynthesisError::AssignmentMissing),
        };

        // Make comm_d and comm_r_last public inputs.
        comm_d.inputize(cs.namespace(|| "zigzag_comm_d"))?;
        comm_r_last.inputize(cs.namespace(|| "zigzag_comm_r"))?;

        for (layer_index, opt) in self.layers.iter().enumerate() {
            let (pub_inputs, proof) = opt.as_ref().ok_or(SynthesisError::AssignmentMissing)?;

            let is_first_layer = layer_index == 0;
            let is_last_layer = layer_index == n_layers - 1;

            // Get this layer's comm_d. For the first layer, this is the publicly input comm_d, for
            // all other layers this is the previous layer's comm_r.
            let comm_d_layer = if is_first_layer {
                comm_d.clone()
            } else {
                comm_rs[layer_index - 1].clone()
            };

            // Get this layer's comm_r. For the last layer this is comm_r_last, for every other
            // layer it is the replica tree's root found in the layer's proof.
            let comm_r_layer = if is_last_layer {
                comm_r_last.clone()
            } else {
                let annotation = format!("layer {} comm_r", layer_index);
                alloc_priv_num(cs, &annotation, proof.replica_root)
            };

            comm_rs.push(comm_r_layer.clone());

            // TODO: As an optimization, we may be able to skip proving the original data on some
            // (50%?) of challenges.

            // Construct the public parameters for `DrgPoRep`.
            let drgporep_pub_params = drgporep::PublicParams::new(
                graph.clone(), // TODO: avoid
                sloth_iter,
                true,
                layer_challenges.challenges_for_layer(layer_index),
            );

            // Construct the `DrgPoRep` circut.
            let circuit = DrgPoRepCompound::circuit(
                &pub_inputs,
                ComponentPrivateInputs {
                    comm_d: Some(Root::Var(comm_d_layer)),
                    comm_r: Some(Root::Var(comm_r_layer)),
                },
                &proof,
                &drgporep_pub_params,
                self.params,
            );

            // Synthesize the DrgPoRep circuit.
            circuit.synthesize(&mut cs.namespace(|| format!("zigzag_layer_#{}", layer_index)))?;
        }

        let add_padding = |bits: &mut Vec<Boolean>| {
            let len = bits.len();
            let pad_len = 256 - len % 256;
            let new_len = len + pad_len;
            bits.resize(new_len, Boolean::Constant(false));
        };

        // Compute comm_r_star := Hash(replica_id | comm_r_0 | ... | comm_r_l), where replica_id,
        // comm_r_0, .., comm_r_l are allocated as bits in the constaint system. These bit vectors
        // are concatenated together into a single preimage then hashed to yield comm_r_star.
        let mut comm_r_star_bits = replica_id.into_bits_le(cs.namespace(|| "replica_id_bits"))?;
        add_padding(&mut comm_r_star_bits);

        for (layer_index, comm_r_layer) in comm_rs.iter().enumerate() {
            let comm_r_layer_bits = comm_r_layer
                .into_bits_le(cs.namespace(|| format!("comm_r-bits-{}", layer_index)))?;
            comm_r_star_bits.extend(comm_r_layer_bits);
            add_padding(&mut comm_r_star_bits);
        }

        let computed_comm_r_star = AH::Function::hash_circuit(
            cs.namespace(|| "comm_r_star"),
            &comm_r_star_bits,
            self.params,
        )?;

        // Allocate the passed in comm_r_star.
        let comm_r_star = match self.comm_r_star {
            Some(comm_r_star) => alloc_priv_num(cs, "public comm_r_star value", comm_r_star),
            None => return Err(SynthesisError::AssignmentMissing),
        };

        // Enforce that the passed in comm_r_star is equal to the computed comm_r_star.
        constraint::equal(
            cs,
            || "enforce comm_r_star is correct",
            &computed_comm_r_star,
            &comm_r_star,
        );

        // Make comm_r_star a public input.
        comm_r_star.inputize(cs.namespace(|| "zigzag comm_r_star"))?;

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

impl<'a, AH, BH>
    CompoundProof<'a, Bls12, ZigZagDrgPoRep<'a, AH, BH>, ZigZagCircuit<'a, Bls12, AH, BH>>
    for ZigZagCompound
where
    AH: 'static + Hasher,
    BH: 'static + Hasher,
{
    fn generate_public_inputs(
        pub_in: &<ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicInputs,
        pub_params: &<ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicParams,
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

            current_graph = Some(
                <ZigZagDrgPoRep<AH, BH> as layered_drgporep::Layers>::transform(
                    &drgporep_pub_params.graph,
                ),
            );
        }
        inputs.push(pub_in.comm_r_star.into());
        inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicInputs,
        _component_private_inputs: <ZigZagCircuit<'a, Bls12, AH, BH> as CircuitComponent>::ComponentPrivateInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep<AH, BH> as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, AH, BH> {
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

        let pp: <ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicParams = public_params.into();

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
        public_params: &<ZigZagDrgPoRep<AH, BH> as ProofScheme>::PublicParams,
        params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, AH, BH> {
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
    use crate::hasher::blake2s::Blake2sDomain;
    use crate::hasher::pedersen::PedersenDomain;
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::hybrid_merkle::MIN_N_LEAVES;
    use crate::layered_drgporep::{self, ChallengeRequirements, LayerChallenges};
    use crate::porep::PoRep;
    use crate::proof::ProofScheme;

    use ff::Field;
    use fil_sapling_crypto::jubjub::JubjubBls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn zigzag_drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let n_nodes = MIN_N_LEAVES;
        let degree = 1;
        let expansion_degree = 2;
        let num_layers = 2;
        let layer_challenges = LayerChallenges::new_fixed(num_layers, 1);
        let sloth_iter = 1;

        // TODO: The code in this section was copied directly from zizag_drgporep::tests::prove_verify.
        // We should refactor to share the code – ideally in such a way that we can just add
        // methods and get the assembled tests for free.
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Fr = rng.gen();
        let data: Vec<u8> = (0..n_nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();
        let sp = layered_drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes: n_nodes,
                degree,
                expansion_degree,
                seed: new_seed(),
            },
            sloth_iter,
            layer_challenges: layer_challenges.clone(),
        };

        let pp = ZigZagDrgPoRep::setup(&sp).expect("setup failed");
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, &replica_id.into(), data_copy.as_mut_slice(), None)
                .expect("replication failed");
        assert_ne!(data, data_copy);

        let simplified_tau = tau.clone().simplify();

        let pub_inputs = layered_drgporep::PublicInputs::<PedersenDomain, Blake2sDomain> {
            replica_id: replica_id.into(),
            seed: None,
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star.into(),
            k: None,
        };

        let priv_inputs = layered_drgporep::PrivateInputs::<PedersenHasher, Blake2sHasher> {
            aux: aux.into(),
            tau: tau.layer_taus.into(),
        };

        let proofs = ZigZagDrgPoRep::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1)
            .expect("failed to generate partition proofs");

        let proofs_are_valid = ZigZagDrgPoRep::verify_all_partitions(&pp, &pub_inputs, &proofs)
            .expect("failed to verify partition proofs");

        assert!(proofs_are_valid);

        // End copied section.

        let expected_inputs = 16;
        let expected_constraints = 560844;
        {
            // Verify that MetricCS returns the same metrics as TestConstraintSystem.
            let mut cs = MetricCS::<Bls12>::new();

            ZigZagCompound::circuit(
            &pub_inputs,
            <ZigZagCircuit<Bls12, PedersenHasher, Blake2sHasher> as CircuitComponent>::ComponentPrivateInputs::default(),
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
            <ZigZagCircuit<Bls12, PedersenHasher, Blake2sHasher> as CircuitComponent>::ComponentPrivateInputs::default(),
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
        zigzag_test_compound::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_zigzag_compound_blake2s() {
        zigzag_test_compound::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_zigzag_compound_pedersen_blake2s() {
        zigzag_test_compound::<PedersenHasher, Blake2sHasher>();
    }

    fn zigzag_test_compound<AH, BH>()
    where
        AH: 'static + Hasher,
        BH: 'static + Hasher,
    {
        let params = &JubjubBls12::new();
        let nodes = MIN_N_LEAVES;
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

        let public_params = ZigZagCompound::setup(&setup_params).expect("setup failed");
        let (tau, aux) = ZigZagDrgPoRep::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data_copy.as_mut_slice(),
            None,
        )
        .expect("replication failed");

        assert_ne!(data, data_copy);

        let public_inputs = layered_drgporep::PublicInputs::<AH::Domain, BH::Domain> {
            replica_id: replica_id.into(),
            seed: None,
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };
        let private_inputs = layered_drgporep::PrivateInputs::<AH, BH> {
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
