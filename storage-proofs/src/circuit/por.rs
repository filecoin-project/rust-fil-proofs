use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::circuit::{boolean, multipack, num, pedersen_hash};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use circuit::constraint;
use compound_proof::CompoundProof;
use drgraph::graph_height;
use merklepor::MerklePoR;
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use proof::ProofScheme;

/// Proof of retrievability.
///
/// # Fields
///
/// * `params` - The params for the bls curve.
/// * `value` - The value of the leaf.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
///

implement_por!(PoRCircuit, PoRCompound, "proof-of-retrievability", false);

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::multipack;
    use sapling_crypto::jubjub::JubjubBls12;

    use circuit::test::*;
    use compound_proof;
    use drgraph::{new_seed, BucketGraph, Graph};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use hasher::pedersen::*;
    use merklepor;
    use proof::ProofScheme;
    use util::data_at_node;

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_compound() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let leaves = 6;
        let lambda = 32;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<PedersenHasher>::new(leaves, 16, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &merklepor::SetupParams { lambda, leaves },
                engine_params: &JubjubBls12::new(),
            };
            let public_params =
                PoRCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

            let private_inputs = merklepor::PrivateInputs::<PedersenHasher>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(
                        data.as_slice(),
                        public_inputs.challenge,
                        public_params.vanilla_params.lambda,
                    )
                    .unwrap(),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            let proof = PoRCompound::<PedersenHasher>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
            )
            .expect("failed while proving");

            let verified = PoRCompound::<PedersenHasher>::verify(
                &public_params.vanilla_params,
                &public_inputs,
                proof,
            )
            .expect("failed while verifying");
            assert!(verified);

            let (circuit, inputs) = PoRCompound::<PedersenHasher>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            );

            let mut cs = TestConstraintSystem::new();

            let _ = circuit.synthesize(&mut cs);
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 6;
        let lambda = 32;

        for i in 0..6 {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::<PedersenHasher>::new(leaves, 16, 0, new_seed());
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams { lambda, leaves };
            let pub_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root().into()),
            };

            let priv_inputs = merklepor::PrivateInputs::<PedersenHasher>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), pub_inputs.challenge, pub_params.lambda).unwrap(),
                )
                .unwrap()
                .into(),
                &tree,
            );

            // create a non circuit proof
            let proof = merklepor::MerklePoR::<PedersenHasher>::prove(
                &pub_params,
                &pub_inputs,
                &priv_inputs,
            )
            .unwrap();

            // make sure it verifies
            assert!(
                merklepor::MerklePoR::<PedersenHasher>::verify(&pub_params, &pub_inputs, &proof)
                    .unwrap(),
                "failed to verify merklepor proof"
            );

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<Bls12> {
                params,
                value: Some(proof.data.into()),
                auth_path: proof.proof.as_options(),
                root: Some(pub_inputs.commitment.unwrap().into()),
            };

            por.synthesize(&mut cs).unwrap();

            assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4846, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = Vec::new();
            expected_inputs.extend(packed_auth_path);
            expected_inputs.push(pub_inputs.commitment.unwrap().into());

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "path/input 0"),
                expected_inputs[0],
                "wrong packed_auth_path"
            );

            assert_eq!(
                cs.get_input(2, "root/input variable"),
                expected_inputs[1],
                "wrong root input"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }
}
