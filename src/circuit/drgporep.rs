use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::circuit::boolean::{self, Boolean};
use sapling_crypto::circuit::{multipack, num};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::kdf::kdf;
use circuit::por::{synthesize_proof_of_retrievability, PoRCompound};
use circuit::sloth;
use compound_proof::CompoundProof;
use drgporep::DrgPoRep;
use drgraph::Graph;
use fr32::fr_into_bytes;
use merklepor;
use proof::ProofScheme;
use std::marker::PhantomData;
use util::{bytes_into_bits, bytes_into_boolean_vec};

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
/// * `lambda` - The size of the individual data leaves in bits.
/// * `sloth_iter` - How many rounds sloth should run for.
///
/// ----> Private `replica_node` - The replica node being proven.
///
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
///
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
///
/// ----> Private `data_node` - The data node being proven.
///
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `prover_id` - The id of the prover.
/// * `degree` - The degree of the graph.
///

pub struct DrgPoRepCircuit<'a, E: JubjubEngine> {
    params: &'a E::Params,
    lambda: usize,
    sloth_iter: usize,
    replica_nodes: Vec<Option<E::Fr>>,
    replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Vec<Option<E::Fr>>>,
    replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    data_nodes: Vec<Option<E::Fr>>,
    data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    data_root: Option<E::Fr>,
    prover_id: Option<E::Fr>,
    degree: usize,
}

impl<'a> Default for DrgPoRepCircuit<'a, Bls12> {
    fn default() -> DrgPoRepCircuit<'a, Bls12> {
        //params: Bls12::new
        unimplemented!();
    }
}

pub struct DrgPoRepCompound<G: Graph> {
    phantom: PhantomData<G>,
}

impl<'a, G: Graph> CompoundProof<'a, Bls12, DrgPoRep<G>, DrgPoRepCircuit<'a, Bls12>>
    for DrgPoRepCompound<G>
{
    fn generate_public_inputs(
        pub_in: &<DrgPoRep<G> as ProofScheme>::PublicInputs,
        pub_params: &<DrgPoRep<G> as ProofScheme>::PublicParams,
    ) -> Vec<Fr> {
        let prover_id = pub_in.prover_id;
        let challenges = &pub_in.challenges;
        let tau = pub_in.tau;
        let comm_r = tau.comm_r;
        let comm_d = tau.comm_d;

        let lambda = pub_params.lambda;
        let leaves = pub_params.graph.size();

        let prover_id_bits = bytes_into_bits(&fr_into_bytes::<Bls12>(&prover_id));

        let packed_prover_id = multipack::compute_multipacking::<Bls12>(&prover_id_bits);

        let por_pub_params = merklepor::PublicParams { lambda, leaves };

        challenges
            .iter()
            .map(|challenge| {
                let mut input = Vec::new();
                input.extend(packed_prover_id.clone());

                let mut por_nodes = vec![*challenge];
                let parents = pub_params.graph.parents(*challenge);
                por_nodes.extend(parents);

                for node in por_nodes {
                    let por_pub_inputs = merklepor::PublicInputs {
                        commitment: comm_r,
                        challenge: node,
                    };
                    let por_inputs =
                        PoRCompound::generate_public_inputs(&por_pub_inputs, &por_pub_params);
                    input.extend(por_inputs);
                }

                let por_pub_inputs = merklepor::PublicInputs {
                    commitment: comm_d,
                    challenge: *challenge,
                };
                let por_inputs =
                    PoRCompound::generate_public_inputs(&por_pub_inputs, &por_pub_params);
                input.extend(por_inputs);

                input
            }).collect::<Vec<Vec<_>>>()
            .concat()
    }

    fn circuit<'b>(
        public_inputs: &'b <DrgPoRep<G> as ProofScheme>::PublicInputs,
        proof: &'b <DrgPoRep<G> as ProofScheme>::Proof,
        public_params: &'b <DrgPoRep<G> as ProofScheme>::PublicParams,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
    ) -> DrgPoRepCircuit<'a, Bls12> {
        let lambda = public_params.lambda;
        let _arity = public_inputs.challenges.len();

        let replica_nodes = proof
            .replica_nodes
            .iter()
            .map(|node| Some(node.data))
            .collect();

        let replica_nodes_paths = proof
            .replica_nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        let replica_root = Some(proof.replica_nodes[0].proof.root().into());

        let replica_parents = proof
            .replica_parents
            .iter()
            .map(|parents| {
                parents
                    .iter()
                    .map(|(_, parent)| Some(parent.data))
                    .collect()
            }).collect();

        let replica_parents_paths: Vec<Vec<_>> = proof
            .replica_parents
            .iter()
            .map(|parents| {
                let p: Vec<_> = parents
                    .iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect();
                p
            }).collect();

        let data_nodes = proof.nodes.iter().map(|node| Some(node.data)).collect();

        let data_nodes_paths = proof
            .nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        let data_root = Some(proof.nodes[0].proof.root().into());
        let prover_id = Some(public_inputs.prover_id);

        DrgPoRepCircuit {
            params: engine_params,
            lambda,
            sloth_iter: public_params.sloth_iter,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            prover_id,
            degree: public_params.graph.degree(),
        }
    }
}

pub fn synthesize_drgporep<E, CS>(
    mut cs: CS,
    params: &E::Params,
    lambda: usize,
    sloth_iter: usize,
    replica_nodes: Vec<Option<E::Fr>>,
    replica_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    replica_root: Option<E::Fr>,
    replica_parents: Vec<Vec<Option<E::Fr>>>,
    replica_parents_paths: Vec<Vec<Vec<Option<(E::Fr, bool)>>>>,
    data_nodes: Vec<Option<E::Fr>>,
    data_nodes_paths: Vec<Vec<Option<(E::Fr, bool)>>>,
    data_root: Option<E::Fr>,
    prover_id: Option<E::Fr>,
    degree: usize,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    DrgPoRepCircuit {
        params,
        lambda,
        sloth_iter,
        replica_nodes,
        replica_nodes_paths,
        replica_root,
        replica_parents,
        replica_parents_paths,
        data_nodes,
        data_nodes_paths,
        data_root,
        prover_id,
        degree,
    }.synthesize(&mut cs)
}

///
/// # Public Inputs
///
///  // TODO: We should make prover_id be only a single Fr input
/// * [0] prover_id/0
/// * [1] prover_id/1
/// * [2] replica auth_path_bits
/// * [3] replica commitment (root hash)
/// * for i in 0..replica_parents.len()
///   * [ ] replica parent auth_path_bits
///   * [ ] replica parent commitment (root hash) // Same for all.
/// * [r + 1] data auth_path_bits
/// * [r + 2] data commitment (root hash)
///
///  Total = 6 + (2 * replica_parents.len())
/// # Private Inputs
///
/// * [ ] replica value/0
/// * for i in 0..replica_parents.len()
///  * [ ] replica parent value/0
/// * [ ] data value/
///
/// Total = 2 + replica_parents.len()
///
impl<'a, E: JubjubEngine> Circuit<E> for DrgPoRepCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
    {
        let params = self.params;
        let lambda = self.lambda;

        let prover_id = self.prover_id;
        let replica_root = self.replica_root;
        let data_root = self.data_root;

        let degree = self.degree;

        let raw_bytes; // Need let here so borrow in match lives long enough.
        let prover_id_bytes = match prover_id {
            Some(prover_id) => {
                raw_bytes = fr_into_bytes::<E>(&prover_id);
                Some(raw_bytes.as_slice())
            }
            // Used in parameter generation or when circuit is created only for
            // structure and input count.
            None => None,
        };

        // get the prover_id in bits
        let prover_id_bits =
            bytes_into_boolean_vec(cs.namespace(|| "prover_id bits"), prover_id_bytes, lambda)?;

        multipack::pack_into_inputs(cs.namespace(|| "prover_id"), &prover_id_bits)?;

        for i in 0..self.data_nodes.len() {
            // ensure that all inputs are well formed
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents_paths = &self.replica_parents_paths[i];
            let data_node_path = &self.data_nodes_paths[i];

            let replica_node = &self.replica_nodes[i];
            let replica_parents = &self.replica_parents[i];
            let data_node = &self.data_nodes[i];

            if data_node.is_some() && replica_node.is_some() {
                assert_ne!(data_node, replica_node);
            };
            assert_eq!(data_node_path.len(), replica_node_path.len());

            synthesize_proof_of_retrievability(
                cs.namespace(|| "replica_node merkle proof"),
                &params,
                *replica_node,
                replica_node_path.clone(),
                replica_root,
            )?;

            // validate each replica_parents merkle proof
            {
                for i in 0..replica_parents.len() {
                    synthesize_proof_of_retrievability(
                        cs.namespace(|| format!("replica parent: {}", i)),
                        &params,
                        replica_parents[i],
                        replica_parents_paths[i].clone(),
                        replica_root,
                    )?;
                }
            }

            // validate data node commitment
            synthesize_proof_of_retrievability(
                cs.namespace(|| "data node commitment"),
                &params,
                *data_node,
                data_node_path.clone(),
                data_root,
            )?;

            // get the parents into bits
            let parents_bits: Vec<Vec<Boolean>> = {
                let mut cs = cs.namespace(|| "parents to bits");
                replica_parents
                    .into_iter()
                    .enumerate()
                    .map(|(i, val)| -> Result<Vec<Boolean>, SynthesisError> {
                        let mut v = boolean::field_into_boolean_vec_le(
                            cs.namespace(|| format!("parent {}", i)),
                            *val,
                        )?;
                        // sad padding is sad
                        while v.len() < 256 {
                            v.push(boolean::Boolean::Constant(false));
                        }
                        Ok(v)
                    }).collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?
            };

            // generate the encryption key
            let key = kdf(
                cs.namespace(|| "kdf"),
                &params,
                prover_id_bits.clone(),
                parents_bits,
                degree,
            )?;

            let decoded = sloth::decode(
                cs.namespace(|| "decode replica node commitment"),
                &key,
                *replica_node,
                self.sloth_iter,
            )?;

            let expected = num::AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                data_node.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            // ensure the encrypted data and data_node match
            {
                // expected * 1 = decoded
                cs.enforce(
                    || "encrypted matches data_node constraint",
                    |lc| lc + expected.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + decoded.get_variable(),
                );
            }
        }
        // profit!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use compound_proof;
    use drgporep;
    use drgraph::{graph_height, new_seed, BucketGraph};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::Rand;
    use rand::{SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let nodes = 12;
        let degree = 6;
        let challenge = 2;
        let sloth_iter = 1;

        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&Fr::rand(rng));

        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        // TODO: don't clone everything
        let original_data = data.clone();
        let data_node = Some(
            bytes_into_fr::<Bls12>(
                data_at_node(&original_data, challenge, lambda)
                    .expect("failed to read original data"),
            ).unwrap(),
        );

        let sp = drgporep::SetupParams {
            lambda,
            drg: drgporep::DrgParams {
                nodes: nodes,
                degree,
                seed: new_seed(),
            },
            sloth_iter,
        };

        let pp =
            drgporep::DrgPoRep::<BucketGraph>::setup(&sp).expect("failed to create drgporep setup");
        let (tau, aux) =
            drgporep::DrgPoRep::replicate(&pp, prover_id.as_slice(), data.as_mut_slice())
                .expect("failed to replicate");

        let prover_id_fr = bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap();
        let pub_inputs = drgporep::PublicInputs {
            prover_id: prover_id_fr,
            challenges: vec![challenge],
            tau: &tau,
        };
        let priv_inputs = drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof_nc =
            drgporep::DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::verify(&pp, &pub_inputs, &proof_nc).expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node = Some(proof_nc.replica_nodes[0].data);

        let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
        let replica_root = Some(proof_nc.replica_nodes[0].proof.root().into());
        let replica_parents = proof_nc.replica_parents[0]
            .iter()
            .map(|(_, parent)| Some(parent.data))
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc.replica_parents[0]
            .iter()
            .map(|(_, parent)| parent.proof.as_options())
            .collect();

        let data_node_path = proof_nc.nodes[0].proof.as_options();
        let data_root = Some(proof_nc.nodes[0].proof.root().into());
        let prover_id = Some(prover_id_fr);

        assert!(
            proof_nc.nodes[0].proof.validate(challenge),
            "failed to verify data commitment"
        );
        assert!(
            proof_nc.nodes[0].proof.validate_data(&data_node.unwrap()),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        synthesize_drgporep(
            cs.namespace(|| "drgporep"),
            params,
            lambda,
            sloth_iter,
            vec![replica_node],
            vec![replica_node_path],
            replica_root,
            vec![replica_parents],
            vec![replica_parents_paths],
            vec![data_node],
            vec![data_node_path],
            data_root,
            prover_id,
            degree,
        ).expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 19, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 58118, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(cs.get_input(1, "drgporep/prover_id/input 0"), prover_id_fr,);
    }

    #[test]
    fn drgporep_input_circuit_num_constraints() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // 32 bytes per node
        let lambda = 32;
        // 1 GB
        let n = (1 << 30) / 32;
        let m = 6;
        let tree_depth = graph_height(n);
        let sloth_iter = 1;

        let mut cs = TestConstraintSystem::<Bls12>::new();
        synthesize_drgporep(
            cs.namespace(|| "drgporep"),
            params,
            lambda * 8,
            sloth_iter,
            vec![Some(Fr::rand(rng)); 1],
            vec![vec![Some((Fr::rand(rng), false)); tree_depth]; 1],
            Some(Fr::rand(rng)),
            vec![vec![Some(Fr::rand(rng)); m]; 1],
            vec![vec![vec![Some((Fr::rand(rng), false)); tree_depth]; m]; 1],
            vec![Some(Fr::rand(rng)); 1],
            vec![vec![Some((Fr::rand(rng), false)); tree_depth]; 1],
            Some(Fr::rand(rng)),
            Some(Fr::rand(rng)),
            m,
        ).expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 19, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 290294, "wrong number of constraints");
    }

    #[test]
    fn test_compound() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let nodes = 2;
        let degree = 2;
        let challenge = 1;
        let sloth_iter = 1;

        let prover_id: Vec<u8> = fr_into_bytes::<Bls12>(&Fr::rand(rng));
        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes: nodes,
                    degree,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            engine_params: params,
        };

        let public_params =
            DrgPoRepCompound::<BucketGraph>::setup(&setup_params).expect("setup failed");

        let (tau, aux) = drgporep::DrgPoRep::replicate(
            &public_params.vanilla_params,
            prover_id.as_slice(),
            data.as_mut_slice(),
        ).expect("failed to replicate");

        let prover_id_fr = bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap();

        let public_inputs = drgporep::PublicInputs {
            prover_id: prover_id_fr,
            challenges: vec![challenge],
            tau: &tau,
        };
        let private_inputs = drgporep::PrivateInputs {
            replica: data.as_slice(),
            aux: &aux,
        };

        // This duplication is necessary so public_params don't outlive public_inputs and private_inputs.
        // TODO: Abstract it.
        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes: nodes,
                    degree,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            engine_params: params,
        };

        let public_params =
            DrgPoRepCompound::<BucketGraph>::setup(&setup_params).expect("setup failed");

        // FIXME: Uncommenting causes &tau and &aux not to live long enough, for some reason.
        let proof = DrgPoRepCompound::prove(&public_params, &public_inputs, &private_inputs)
            .expect("failed while proving");

        let verified =
            DrgPoRepCompound::verify(&public_params.vanilla_params, &public_inputs, proof)
                .expect("failed while verifying");

        assert!(verified);
    }
}
