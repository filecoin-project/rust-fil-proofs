use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::circuit::num;
use sapling_crypto::jubjub::JubjubEngine;

use circuit::constraint;
use circuit::pedersen::pedersen_md_no_padding;
use circuit::private_drgporep::PrivateDrgPoRepCompound;
use compound_proof::CompoundProof;
use drgporep::{self, DrgPoRep};
use drgraph::{graph_height, Graph};
use hasher::{Domain, Hasher};
use layered_drgporep::{self, Layers as LayersTrait};
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use porep;
use proof::ProofScheme;
use util::bytes_into_boolean_vec;
use zigzag_drgporep::ZigZagDrgPoRep;

type Layers<'a, H, G> = Vec<(
    <DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
    Option<<DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof>,
)>;

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
    tau: porep::Tau<<<ZigZagDrgPoRep<'a, H> as LayersTrait>::Hasher as Hasher>::Domain>,
    comm_r_star: H::Domain,
    _e: PhantomData<E>,
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
        tau: porep::Tau<<<ZigZagDrgPoRep<H> as LayersTrait>::Hasher as Hasher>::Domain>,
        comm_r_star: H::Domain,
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
        let graph = self.public_params.drg_porep_public_params.graph.clone();
        let mut crs_input = vec![0u8; 32 * (self.layers.len() + 1)];

        self.layers[0]
            .0
            .replica_id
            .write_bytes(&mut crs_input[0..32])
            .expect("failed to write vec");

        for (l, (public_inputs, layer_proof)) in self.layers.iter().enumerate() {
            let first_layer = l == 0;
            let last_layer = l == self.layers.len() - 1;

            let height = graph_height(graph.size());
            let proof = match layer_proof {
                Some(wrapped_proof) => {
                    let typed_proof: drgporep::Proof<
                        <ZigZagDrgPoRep<H> as LayersTrait>::Hasher,
                    > = wrapped_proof.into();
                    typed_proof
                }
                // Synthesize a default drgporep if none is supplied – for use in tests, etc.
                None => drgporep::Proof::new_empty(height, graph.degree()),
            };

            let comm_d = proof.nodes[0].proof.root;
            let comm_r = proof.replica_nodes[0].proof.root;
            comm_r
                .write_bytes(&mut crs_input[(l + 1) * 32..(l + 2) * 32])
                .expect("failed to write vec");

            // FIXME: Using a normal DrgPoRep circuit here performs a redundant test at each layer.
            // We don't need to verify merkle inclusion of the 'data' except in the first layer.
            // In subsequent layers, we already proved this and just need to assert (by constraint)
            // that the decoded data has the value which was previously proved.
            let circuit = PrivateDrgPoRepCompound::circuit(
                public_inputs,
                &proof,
                &self.public_params.drg_porep_public_params,
                self.params,
                None,
            );
            circuit.synthesize(&mut cs.namespace(|| format!("zigzag layer {}", l)))?;

            if first_layer {
                // Constrain first layer's comm_d to be equal to overall tau.comm_d.

                let fcd = comm_d.into();
                let first_comm_d =
                    num::AllocatedNum::alloc(cs.namespace(|| "first comm_d"), || Ok(fcd))?;

                let public_comm_d =
                    num::AllocatedNum::alloc(cs.namespace(|| "public comm_d value"), || {
                        Ok(self.tau.comm_d.into())
                    })?;

                constraint::equal(
                    cs,
                    || "enforce comm_d is correct",
                    &first_comm_d,
                    &public_comm_d,
                );
                public_comm_d.inputize(cs.namespace(|| "zigzag comm_d"))?;
            }

            if last_layer {
                // Constrain last layer's comm_r to be equal to overall tau.comm_r.

                let lcr = comm_r.into();
                let last_comm_r =
                    num::AllocatedNum::alloc(cs.namespace(|| "last comm_r"), || Ok(lcr))?;

                let public_comm_r =
                    num::AllocatedNum::alloc(cs.namespace(|| "public comm_r value"), || {
                        Ok(self.tau.comm_r.into())
                    })?;

                constraint::equal(
                    cs,
                    || "enforce comm_r is correct",
                    &last_comm_r,
                    &public_comm_r,
                );

                public_comm_r.inputize(cs.namespace(|| "zigzag comm_r"))?;
            }
        }

        let crs_boolean = bytes_into_boolean_vec(
            cs.namespace(|| "comm_r_star boolean"),
            Some(&crs_input),
            8 * crs_input.len(),
        )?;

        let computed_comm_r_star =
            pedersen_md_no_padding(cs.namespace(|| "comm_r_star"), self.params, &crs_boolean)?;

        let public_comm_r_star =
            num::AllocatedNum::alloc(cs.namespace(|| "public comm_r_star value"), || {
                Ok(self.comm_r_star.into())
            })?;

        constraint::equal(
            cs,
            || "enforce comm_r_star is correct",
            &computed_comm_r_star,
            &public_comm_r_star,
        );

        public_comm_r_star.inputize(cs.namespace(|| "zigzag comm_r_star"))?;

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

        let mut drgporep_pub_params = drgporep::PublicParams::new(
            pub_params.drg_porep_public_params.lambda,
            pub_params.drg_porep_public_params.graph.clone(),
            pub_params.drg_porep_public_params.sloth_iter,
        );

        for i in 0..pub_params.layers {
            let first_layer = i == 0;
            let last_layer = i == pub_params.layers - 1;

            let drgporep_pub_inputs = drgporep::PublicInputs {
                replica_id: pub_in.replica_id,
                challenges: pub_in.challenges(
                    pub_params.drg_porep_public_params.graph.size(),
                    i as u8,
                    k,
                ),
                tau: None,
            };
            let drgporep_inputs = PrivateDrgPoRepCompound::generate_public_inputs(
                &drgporep_pub_inputs,
                &drgporep_pub_params,
                None,
            );
            inputs.extend(drgporep_inputs);

            drgporep_pub_params = <ZigZagDrgPoRep<H> as layered_drgporep::Layers>::transform(
                &drgporep_pub_params,
                i,
                pub_params.layers,
            );

            if first_layer {
                let comm_d = pub_in.tau.unwrap().comm_d.into();
                inputs.push(comm_d);
            };

            if last_layer {
                let comm_r = pub_in.tau.unwrap().comm_r.into();
                inputs.push(comm_r);
            };
        }
        inputs.push(pub_in.comm_r_star.into());
        inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep<H> as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
        k: Option<usize>,
    ) -> ZigZagCircuit<'a, Bls12, H> {
        let layers = (0..(vanilla_proof.encoding_proofs.len()))
            .map(|l| {
                let layer_public_inputs = drgporep::PublicInputs {
                    replica_id: public_inputs.replica_id,
                    challenges: public_inputs.challenges(
                        public_params.drg_porep_public_params.graph.size(),
                        l as u8,
                        k,
                    ),
                    tau: None,
                };
                let layer_proof = vanilla_proof.encoding_proofs[l].clone();
                (layer_public_inputs, Some(layer_proof))
            })
            .collect();

        let pp: <ZigZagDrgPoRep<H> as ProofScheme>::PublicParams = public_params.into();

        ZigZagCircuit {
            params: engine_params,
            public_params: pp,
            tau: public_inputs.tau.unwrap(),
            comm_r_star: public_inputs.comm_r_star,
            layers,
            _e: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use compound_proof;
    use drgporep;
    use drgraph::new_seed;
    use fr32::fr_into_bytes;
    use hasher::pedersen::*;
    use layered_drgporep;
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use zigzag_graph::ZigZagGraph;

    #[test]
    fn zigzag_drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let lambda = 32;
        let nodes = 5;
        let degree = 1;
        let expansion_degree = 2;
        let challenge_count = 1;
        let num_layers = 2;
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
            drg_porep_setup_params: drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes: n,
                    degree,
                    expansion_degree,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            layers: num_layers,
            challenge_count,
        };

        let pp = ZigZagDrgPoRep::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, &replica_id.into(), data_copy.as_mut_slice()).unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = layered_drgporep::PublicInputs::<PedersenDomain> {
            replica_id: replica_id.into(),
            challenge_count,
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star.into(),
            k: None,
        };

        let priv_inputs = layered_drgporep::PrivateInputs::<PedersenHasher> {
            replica: data.as_slice(),
            aux: aux.into(),
            tau: tau.layer_taus.into(),
        };

        let proofs =
            ZigZagDrgPoRep::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1).unwrap();
        assert!(ZigZagDrgPoRep::verify_all_partitions(&pp, &pub_inputs, &proofs).unwrap());

        // End copied section.

        let mut cs = TestConstraintSystem::<Bls12>::new();

        ZigZagCompound::circuit(&pub_inputs, &proofs[0], &pp, params, None)
            .synthesize(&mut cs.namespace(|| "zigzag drgporep"))
            .expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 16, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 59523, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "zigzag drgporep/zigzag layer 0/prover_id/input 0"),
            replica_id.into(),
        );

        // This test was modeled on equivalent from drgporep circuit.
        // TODO: add add assertions about other inputs.
    }

    #[test]
    fn zigzag_input_circuit_num_constraints() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // 32 bytes per node
        let lambda = 32;
        // 1 GB
        let n = (1 << 30) / 32;
        let num_layers = 2;
        let base_degree = 2;
        let expansion_degree = 2;
        let replica_id: Fr = rng.gen();
        let challenge_count = 1;
        let challenge = 1;
        let sloth_iter = 2;

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let layers = (0..num_layers)
            .map(|_l| {
                // l is ignored because we assume uniform layers here.
                let public_inputs = drgporep::PublicInputs {
                    replica_id: replica_id.into(),
                    challenges: vec![challenge],
                    tau: None,
                };
                let proof = None;
                (public_inputs, proof)
            })
            .collect();

        let public_params = layered_drgporep::PublicParams {
            drg_porep_public_params: drgporep::PublicParams::new(
                lambda,
                ZigZagGraph::new(n, base_degree, expansion_degree, new_seed()),
                sloth_iter,
            ),
            layers: num_layers,
            challenge_count,
        };

        ZigZagCircuit::<Bls12, PedersenHasher>::synthesize(
            cs.namespace(|| "zigzag_drgporep"),
            params,
            public_params,
            layers,
            porep::Tau {
                comm_r: rng.gen(),
                comm_d: rng.gen(),
            },
            rng.gen(),
        )
        .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 436831, "wrong number of constraints");
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn zigzag_test_compound() {
        let params = &JubjubBls12::new();
        let lambda = 32;
        let nodes = 5;
        let degree = 2;
        let expansion_degree = 2;
        let challenge_count = 1;
        let num_layers = 2;
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

        let setup_params = compound_proof::SetupParams {
            engine_params: params,
            vanilla_params: &layered_drgporep::SetupParams {
                drg_porep_setup_params: drgporep::SetupParams {
                    lambda,
                    drg: drgporep::DrgParams {
                        nodes: n,
                        degree,
                        expansion_degree,
                        seed: new_seed(),
                    },
                    sloth_iter,
                },
                layers: num_layers,
                challenge_count,
            },
            partitions: None,
        };

        let public_params = ZigZagCompound::setup(&setup_params).unwrap();
        let (tau, aux) = ZigZagDrgPoRep::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data_copy.as_mut_slice(),
        )
        .unwrap();
        assert_ne!(data, data_copy);

        let public_inputs = layered_drgporep::PublicInputs::<PedersenDomain> {
            replica_id: replica_id.into(),
            challenge_count,
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: None,
        };
        let private_inputs = layered_drgporep::PrivateInputs::<PedersenHasher> {
            replica: data.as_slice(),
            aux,
            tau: tau.layer_taus,
        };

        // TOOD: Move this to e.g. circuit::test::compound_helper and share between all compound proo fs.
        // FIXME: Uncomment and make this work again.
        //        {
        //            let (circuit, inputs) =
        //                ZigZagCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);
        //
        //            let mut cs = TestConstraintSystem::new();
        //
        //            let _ = circuit.synthesize(&mut cs);
        //
        //            assert!(cs.is_satisfied(), "TestContraintSystem was not satisfied");
        //            assert!(
        //                cs.verify(&inputs),
        //                "failed while verifying with TestContraintSystem and generated inputs"
        //            );
        //        }

        let proof = ZigZagCompound::prove(&public_params, &public_inputs, &private_inputs)
            .expect("failed while proving");

        let verified = ZigZagCompound::verify(&public_params.vanilla_params, &public_inputs, proof)
            .expect("failed while verifying");

        assert!(verified);
    }
}
