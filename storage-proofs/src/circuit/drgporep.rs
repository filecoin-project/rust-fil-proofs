use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use pairing::PrimeField;
use sapling_crypto::circuit::boolean::{self, Boolean};
use sapling_crypto::circuit::{multipack, num};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::constraint;
use circuit::kdf::kdf;
use circuit::sloth;
use compound_proof::CompoundProof;
use drgporep::DrgPoRep;
use drgraph::Graph;
use fr32::fr_into_bytes;
use merklepor;
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
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
/// * `replica_id` - The id of the replica.
/// * `degree` - The degree of the graph.
///

implement_drgporep!(
    DrgPoRepCircuit,
    DrgPoRepCompound,
    "drg-proof-of-replication",
    false
);

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use compound_proof;
    use drgporep;
    use drgraph::{graph_height, new_seed, BucketGraph};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use hasher::pedersen::*;
    use pairing::Field;
    use porep::PoRep;
    use proof::ProofScheme;
    use rand::Rand;
    use rand::{Rng, SeedableRng, XorShiftRng};
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

        let replica_id: Fr = rng.gen();

        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        // TODO: don't clone everything
        let original_data = data.clone();
        let data_node: Option<Fr> = Some(
            bytes_into_fr::<Bls12>(
                data_at_node(&original_data, challenge, lambda)
                    .expect("failed to read original data"),
            )
            .unwrap(),
        );

        let sp = drgporep::SetupParams {
            lambda,
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                seed: new_seed(),
            },
            sloth_iter,
        };

        let pp = drgporep::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp)
            .expect("failed to create drgporep setup");
        let (tau, aux) = drgporep::DrgPoRep::<PedersenHasher, _>::replicate(
            &pp,
            &replica_id.into(),
            data.as_mut_slice(),
        )
        .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            replica_id: replica_id.into(),
            challenges: vec![challenge],
            tau: Some(tau.into()),
        };
        let priv_inputs = drgporep::PrivateInputs::<PedersenHasher> {
            replica: data.as_slice(),
            aux: &aux,
        };

        let proof_nc =
            drgporep::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
                .expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc)
                .expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node: Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

        let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
        let replica_root: Option<Fr> = Some((*proof_nc.replica_nodes[0].proof.root()).into());
        let replica_parents = proof_nc.replica_parents[0]
            .iter()
            .map(|(_, parent)| Some(parent.data.into()))
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc.replica_parents[0]
            .iter()
            .map(|(_, parent)| parent.proof.as_options())
            .collect();

        let data_node_path = proof_nc.nodes[0].proof.as_options();
        let data_root = Some((*proof_nc.nodes[0].proof.root()).into());
        let replica_id = Some(replica_id);

        assert!(
            proof_nc.nodes[0].proof.validate(challenge),
            "failed to verify data commitment"
        );
        assert!(
            proof_nc.nodes[0]
                .proof
                .validate_data(&fr_into_bytes::<Bls12>(&data_node.unwrap())),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::synthesize(
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
            replica_id,
            degree,
        )
        .expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 52541, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "drgporep/prover_id/input 0"),
            replica_id.unwrap()
        );
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
        DrgPoRepCircuit::synthesize(
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
        )
        .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 284717, "wrong number of constraints");
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn drgporep_test_compound() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let nodes = 2;
        let degree = 2;
        let challenge = 1;
        let sloth_iter = 1;

        let replica_id: Fr = rng.gen();
        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::rand(rng)))
            .collect();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: &drgporep::SetupParams {
                lambda,
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            engine_params: params,
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<PedersenHasher, BucketGraph<_>>::setup(&setup_params)
                .expect("setup failed");

        let (tau, aux) = drgporep::DrgPoRep::<PedersenHasher, _>::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data.as_mut_slice(),
        )
        .expect("failed to replicate");

        let public_inputs = drgporep::PublicInputs::<PedersenDomain> {
            replica_id: replica_id.into(),
            challenges: vec![challenge],
            tau: Some(tau),
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
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed: new_seed(),
                },
                sloth_iter,
            },
            engine_params: params,
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<PedersenHasher, BucketGraph<_>>::setup(&setup_params)
                .expect("setup failed");

        let proof = DrgPoRepCompound::<PedersenHasher, _>::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
        )
        .expect("failed while proving");

        let (circuit, inputs) = DrgPoRepCompound::<PedersenHasher, _>::circuit_for_test(
            &public_params,
            &public_inputs,
            &private_inputs,
        );

        let mut cs = TestConstraintSystem::new();

        let _ = circuit.synthesize(&mut cs);
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));

        let verified =
            DrgPoRepCompound::<PedersenHasher, _>::verify(&public_params, &public_inputs, proof)
                .expect("failed while verifying");

        assert!(verified);
    }
}
