use bellman::{Circuit, ConstraintSystem, SynthesisError};
use circuit::private_drgporep::PrivateDrgPoRepCompound;
use compound_proof::CompoundProof;
use drgporep::{self, DrgPoRep};
use drgraph::{graph_height, Graph};
use layered_drgporep::{self, Layerable};
use pairing::bls12_381::{Bls12, Fr};
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use proof::ProofScheme;
use sapling_crypto::jubjub::JubjubEngine;
use zigzag_drgporep::ZigZagDrgPoRep;
use zigzag_graph::ZigZagBucketGraph;

use std::marker::PhantomData;

type Layers<'a, G> = Vec<(
    <DrgPoRep<G> as ProofScheme<'a>>::PublicInputs,
    Option<<DrgPoRep<G> as ProofScheme<'a>>::Proof>,
)>;

/// ZigZag DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
/// * `public_params` - ZigZagDrgPoRep public parameters.
/// * 'layers' - A vector of Layers – each representing a DrgPoRep proof (see Layers type definition).
///
pub struct ZigZagCircuit<'a, E: JubjubEngine, G: Layerable>
where
    G: 'a + ParameterSetIdentifier,
{
    params: &'a E::Params,
    public_params: <ZigZagDrgPoRep as ProofScheme<'a>>::PublicParams,
    layers: Layers<'a, G>,
    phantom: PhantomData<E>,
}

impl<'a, G: Layerable> ZigZagCircuit<'a, Bls12, G>
where
    G: ParameterSetIdentifier,
{
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &'a <Bls12 as JubjubEngine>::Params,
        public_params: <ZigZagDrgPoRep as ProofScheme<'a>>::PublicParams,
        layers: Layers<G>,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
        G: 'a,
    {
        let circuit = ZigZagCircuit::<'a, Bls12, G> {
            params,
            public_params,
            layers,
            phantom: PhantomData,
        };

        circuit.synthesize(&mut cs)
    }
}

impl<'a, G: Layerable> Circuit<Bls12> for ZigZagCircuit<'a, Bls12, G>
where
    G: ParameterSetIdentifier,
{
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let graph = self.public_params.drg_porep_public_params.graph.clone();
        for (l, (public_inputs, layer_proof)) in self.layers.iter().enumerate() {
            let height = graph_height(graph.size());
            let proof = match layer_proof {
                Some(wrapped_proof) => {
                    let typed_proof: drgporep::Proof = wrapped_proof.into();
                    typed_proof
                }
                // Synthesize a default drgporep if none is supplied – for use in tests, etc.
                None => drgporep::Proof::default(height, graph.degree()),
            };
            // FIXME: Using a normal DrgPoRep circuit here performs a redundant test at each layer.
            // We don't need to verify merkle inclusion of the 'data' except in the first layer.
            // In subsequent layers, we already proved this and just need to assert (by constraint)
            // that the decoded data has the value which was previously proved.
            let circuit = PrivateDrgPoRepCompound::circuit(
                public_inputs,
                &proof,
                &self.public_params.drg_porep_public_params,
                self.params,
            );
            circuit.synthesize(&mut cs.namespace(|| format!("zigzag layer {}", l)))?
        }

        // TODO: We need to add an aggregated commitment to the inputs, then compute a it as a
        // witness to the circuit and constrain the input to be equal to that.
        // This uber-root is: H(replica_id|comm_r[0]|comm_r[1]|…comm_r[n]).
        Ok(())
    }
}

#[allow(dead_code)]
pub struct ZigZagCompound {}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier> CacheableParameters<E, C, P>
    for ZigZagCompound
{
    fn cache_prefix() -> String {
        String::from("zigzag-proof-of-replication")
    }
}

impl<'a> CompoundProof<'a, Bls12, ZigZagDrgPoRep, ZigZagCircuit<'a, Bls12, ZigZagBucketGraph>>
    for ZigZagCompound
{
    fn generate_public_inputs(
        pub_in: &<ZigZagDrgPoRep as ProofScheme>::PublicInputs,
        pub_params: &<ZigZagDrgPoRep as ProofScheme>::PublicParams,
    ) -> Vec<Fr> {
        let mut inputs = Vec::new();

        let mut drgporep_pub_params = drgporep::PublicParams {
            lambda: pub_params.drg_porep_public_params.lambda,
            graph: pub_params.drg_porep_public_params.graph.clone(),
            sloth_iter: pub_params.drg_porep_public_params.sloth_iter,
        };

        for i in 0..pub_params.layers {
            let drgporep_pub_inputs = drgporep::PublicInputs {
                replica_id: pub_in.replica_id,
                challenges: pub_in.challenges.clone(),
                tau: None,
            };
            let drgporep_inputs = PrivateDrgPoRepCompound::generate_public_inputs(
                &drgporep_pub_inputs,
                &drgporep_pub_params,
            );
            inputs.extend(drgporep_inputs);

            drgporep_pub_params = <ZigZagDrgPoRep as layered_drgporep::Layers>::transform(
                &drgporep_pub_params,
                i,
                pub_params.layers,
            );
        }
        inputs
    }

    fn circuit<'b>(
        public_inputs: &'b <ZigZagDrgPoRep as ProofScheme>::PublicInputs,
        vanilla_proof: &'b <ZigZagDrgPoRep as ProofScheme>::Proof,
        public_params: &'b <ZigZagDrgPoRep as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> ZigZagCircuit<'a, Bls12, ZigZagBucketGraph> {
        let layers = (0..(vanilla_proof.encoding_proofs.len()))
            .map(|l| {
                let layer_public_inputs = drgporep::PublicInputs {
                    replica_id: public_inputs.replica_id,
                    // FIXME: add multiple challenges to public inputs.
                    challenges: public_inputs.challenges.clone(),
                    tau: None,
                };
                let layer_proof = vanilla_proof.encoding_proofs[l].clone();
                (layer_public_inputs, Some(layer_proof))
            }).collect();

        let pp: <ZigZagDrgPoRep as ProofScheme>::PublicParams = public_params.into();

        ZigZagCircuit {
            params: engine_params,
            public_params: pp,
            layers,
            phantom: PhantomData,
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
    use fr32::{bytes_into_fr, fr_into_bytes};
    use layered_drgporep::{self, simplify_tau};
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::Rand;
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
        let challenges = vec![2];
        let num_layers = 2;
        let sloth_iter = 1;

        let n = nodes; // FIXME: Consolidate variable names.

        // TODO: The code in this section was copied directly from zizag_drgporep::tests::prove_verify.
        // We should refactor to share the code – ideally in such a way that we can just add
        // methods and get the assembled tests for free.
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let replica_id_fr = bytes_into_fr::<Bls12>(replica_id.as_slice()).unwrap();
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
        };

        let pp = ZigZagDrgPoRep::setup(&sp).unwrap();
        let (tau, aux) =
            ZigZagDrgPoRep::replicate(&pp, replica_id.as_slice(), data_copy.as_mut_slice())
                .unwrap();
        assert_ne!(data, data_copy);

        let pub_inputs = layered_drgporep::PublicInputs {
            replica_id: replica_id_fr,
            challenges,
            tau: Some(simplify_tau(&tau)),
        };

        let priv_inputs = layered_drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux,
            tau,
        };

        let proof = ZigZagDrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(ZigZagDrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());

        // End copied section.

        let mut cs = TestConstraintSystem::<Bls12>::new();

        ZigZagCompound::circuit(&pub_inputs, &proof, &pp, params)
            .synthesize(&mut cs.namespace(|| "zigzag drgporep"))
            .expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 13, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 56750, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "zigzag drgporep/zigzag layer 0/replica_id/input 0"),
            replica_id_fr,
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
        let replica_id = Fr::rand(rng);
        let challenge = 1;
        let sloth_iter = 2;

        let mut cs = TestConstraintSystem::<Bls12>::new();
        let layers = (0..num_layers)
            .map(|_l| {
                // l is ignored because we assume uniform layers here.
                let public_inputs = drgporep::PublicInputs {
                    replica_id,
                    challenges: vec![challenge],
                    tau: None,
                };
                let proof = None;
                (public_inputs, proof)
            }).collect();

        let public_params = layered_drgporep::PublicParams {
            drg_porep_public_params: drgporep::PublicParams {
                lambda,
                graph: ZigZagGraph::new(n, base_degree, expansion_degree, new_seed()),
                sloth_iter,
            },
            layers: num_layers,
        };

        ZigZagCircuit::<Bls12, ZigZagBucketGraph>::synthesize(
            cs.namespace(|| "zigzag_drgporep"),
            params,
            public_params,
            layers,
        ).expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 15, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 434058, "wrong number of constraints");
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn zigzag_test_compound() {
        let params = &JubjubBls12::new();
        let lambda = 32;
        let nodes = 5;
        let degree = 2;
        let expansion_degree = 2;
        let challenges = vec![1];
        let num_layers = 2;
        let sloth_iter = 1;

        let n = nodes; // FIXME: Consolidate variable names.

        // TODO: The code in this section was copied directly from zizag_drgporep::tests::prove_verify.
        // We should refactor to share the code – ideally in such a way that we can just add
        // methods and get the assembled tests for free.
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let replica_id: Vec<u8> = fr_into_bytes::<Bls12>(&rng.gen());
        let replica_id_fr = bytes_into_fr::<Bls12>(replica_id.as_slice()).unwrap();
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
            },
        };

        let public_params = ZigZagCompound::setup(&setup_params).unwrap();
        let (tau, aux) = ZigZagDrgPoRep::replicate(
            &public_params.vanilla_params,
            replica_id.as_slice(),
            data_copy.as_mut_slice(),
        ).unwrap();
        assert_ne!(data, data_copy);

        let public_inputs = layered_drgporep::PublicInputs {
            replica_id: replica_id_fr,
            challenges,
            tau: Some(simplify_tau(&tau)),
        };

        let private_inputs = layered_drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux,
            tau,
        };

        // TOOD: Move this to e.g. circuit::test::compound_helper and share between all compound proofs.
        {
            let (circuit, inputs) =
                ZigZagCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs);

            let mut cs = TestConstraintSystem::new();

            let _ = circuit.synthesize(&mut cs);

            assert!(cs.is_satisfied(), "TestContraintSystem was not satisfied");
            assert!(
                cs.verify(&inputs),
                "failed while verifying with TestContraintSystem and generated inputs"
            );
        }
        let proof = ZigZagCompound::prove(&public_params, &public_inputs, &private_inputs)
            .expect("failed while proving");

        let verified = ZigZagCompound::verify(&public_params.vanilla_params, &public_inputs, proof)
            .expect("failed while verifying");

        assert!(verified);
    }
}
