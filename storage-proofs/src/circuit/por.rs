use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::circuit::{boolean, multipack, num};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use crate::circuit::constraint;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::hasher::{HashFunction, Hasher};
use crate::merklepor::MerklePoR;
use crate::parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use crate::proof::ProofScheme;

/// Proof of retrievability.
///
/// # Fields
///
/// * `params` - The params for the bls curve.
/// * `value` - The value of the leaf.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
///
pub struct PoRCircuit<'a, E: JubjubEngine, H: Hasher> {
    params: &'a E::Params,
    value: Option<E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Root<E>,
    private: bool,
    _h: PhantomData<H>,
}

impl<'a, E: JubjubEngine, H: Hasher> CircuitComponent for PoRCircuit<'a, E, H> {
    type ComponentPrivateInputs = Option<Root<E>>;
}

pub struct PoRCompound<H: Hasher> {
    _h: PhantomData<H>,
}

pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
    let height = graph_height(leaves);
    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n & 1 == 1);
        n >>= 1;
    }
    bits
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetIdentifier, H: Hasher>
    CacheableParameters<E, C, P> for PoRCompound<H>
{
    fn cache_prefix() -> String {
        format!("proof-of-retrievability-{}", H::name())
    }
}

// can only implment for Bls12 because merklepor is not generic over the engine.
impl<'a, H> CompoundProof<'a, Bls12, MerklePoR<H>, PoRCircuit<'a, Bls12, H>> for PoRCompound<H>
where
    H: 'a + Hasher,
{
    fn circuit<'b>(
        public_inputs: &<MerklePoR<H> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCircuit<'a, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <MerklePoR<H> as ProofScheme<'a>>::Proof,
        public_params: &'b <MerklePoR<H> as ProofScheme<'a>>::PublicParams,
        engine_params: &'a JubjubBls12,
    ) -> PoRCircuit<'a, Bls12, H> {
        let (root, private) = match (*public_inputs).commitment {
            None => (Root::Val(Some(proof.proof.root.into())), true),
            Some(commitment) => (Root::Val(Some(commitment.into())), false),
        };

        // Ensure inputs are consistent with public params.
        assert_eq!(private, public_params.private);

        PoRCircuit::<Bls12, H> {
            params: engine_params,
            value: Some(proof.data.into()),
            auth_path: proof.proof.as_options(),
            root,
            private,
            _h: Default::default(),
        }
    }

    fn blank_circuit(
        public_params: &<MerklePoR<H> as ProofScheme<'a>>::PublicParams,
        params: &'a JubjubBls12,
    ) -> PoRCircuit<'a, Bls12, H> {
        PoRCircuit::<Bls12, H> {
            params,
            value: None,
            auth_path: vec![None; graph_height(public_params.leaves)],
            root: Root::Val(None),
            private: public_params.private,
            _h: Default::default(),
        }
    }

    fn generate_public_inputs(
        pub_inputs: &<MerklePoR<H> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<MerklePoR<H> as ProofScheme<'a>>::PublicParams,
        _k: Option<usize>,
    ) -> Vec<Fr> {
        let auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut inputs = Vec::new();
        inputs.extend(packed_auth_path);

        if let Some(commitment) = pub_inputs.commitment {
            assert!(!pub_params.private);
            inputs.push(commitment.into());
        } else {
            assert!(pub_params.private);
        }

        inputs
    }
}

impl<'a, E: JubjubEngine, H: Hasher> Circuit<E> for PoRCircuit<'a, E, H> {
    /// # Public Inputs
    ///
    /// This circuit expects the following public inputs.
    ///
    /// * [0] - packed version of the `is_right` components of the auth_path.
    /// * [1] - the merkle root of the tree.
    ///
    /// This circuit derives the following private inputs from its fields:
    /// * value_num - packed version of `value` as bits. (might be more than one Fr)
    ///
    /// Note: All public inputs must be provided as `E::Fr`.
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
    {
        let params = self.params;
        let value = self.value;
        let auth_path = self.auth_path;
        let root = self.root;

        {
            let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
                value.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            let mut cur = value_num;

            let mut auth_path_bits = Vec::with_capacity(auth_path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in auth_path.into_iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

                // Determines if the current subtree is the "right" leaf at this
                // depth of the tree.
                let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| "position bit"),
                    e.map(|e| e.1),
                )?);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_element =
                    num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
                        Ok(e.ok_or(SynthesisError::AssignmentMissing)?.0)
                    })?;

                // Swap the two if the current subtree is on the right
                let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage"),
                    &cur,
                    &path_element,
                    &cur_is_right,
                )?;

                let xl_bits = xl.into_bits_le(cs.namespace(|| "xl into bits"))?;
                let xr_bits = xr.into_bits_le(cs.namespace(|| "xr into bits"))?;

                // Compute the new subtree value
                cur = H::Function::hash_leaf_circuit(
                    cs.namespace(|| "computation of pedersen hash"),
                    &xl_bits,
                    &xr_bits,
                    i,
                    params,
                )?;
                auth_path_bits.push(cur_is_right);
            }

            // allocate input for is_right auth_path
            multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits)?;

            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.

                let rt = root.allocated(cs.namespace(|| "root_value"))?;
                constraint::equal(cs, || "enforce root is correct", &cur, &rt);

                if !self.private {
                    // Expose the root
                    rt.inputize(cs.namespace(|| "root"))?;
                }
            }

            Ok(())
        }
    }
}

impl<'a, E: JubjubEngine, H: Hasher> PoRCircuit<'a, E, H> {
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &E::Params,
        value: Option<E::Fr>,
        auth_path: Vec<Option<(E::Fr, bool)>>,
        root: Root<E>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let por = PoRCircuit::<E, H> {
            params,
            value,
            auth_path,
            root,
            private,
            _h: Default::default(),
        };

        por.synthesize(&mut cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proof::NoRequirements;
    use ff::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::multipack;
    use sapling_crypto::jubjub::JubjubBls12;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::hasher::{Blake2sHasher, Domain, Hasher, PedersenHasher};
    use crate::merklepor;
    use crate::proof::ProofScheme;
    use crate::util::data_at_node;

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn por_test_compound() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let leaves = 6;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<PedersenHasher>::new(leaves, 16, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &merklepor::SetupParams {
                    leaves,
                    private: false,
                },
                engine_params: &JubjubBls12::new(),
                partitions: None,
            };
            let public_params =
                PoRCompound::<PedersenHasher>::setup(&setup_params).expect("setup failed");

            let private_inputs = merklepor::PrivateInputs::<PedersenHasher>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), public_inputs.challenge).unwrap(),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            let gparams = PoRCompound::<PedersenHasher>::groth_params(
                &public_params.vanilla_params,
                setup_params.engine_params,
            )
            .unwrap();
            let proof = PoRCompound::<PedersenHasher>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = PoRCompound::<PedersenHasher>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");
            assert!(verified);

            let (circuit, inputs) = PoRCompound::<PedersenHasher>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            );

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher>(4149);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher>(128928);
    }

    fn test_por_input_circuit_with_bls12_381<H: Hasher>(num_constraints: usize) {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 6;

        for i in 0..6 {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, 16, 0, new_seed());
            let tree = graph.merkle_tree(data.as_slice()).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = merklepor::PublicInputs::<H::Domain> {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let priv_inputs = merklepor::PrivateInputs::<H>::new(
                H::Domain::try_from_bytes(
                    data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
                )
                .unwrap(),
                &tree,
            );

            // create a non circuit proof
            let proof =
                merklepor::MerklePoR::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

            // make sure it verifies
            assert!(
                merklepor::MerklePoR::<H>::verify(&pub_params, &pub_inputs, &proof).unwrap(),
                "failed to verify merklepor proof"
            );

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let por = PoRCircuit::<Bls12, H> {
                params,
                value: Some(proof.data.into()),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(pub_inputs.commitment.unwrap().into())),
                private: false,
                _h: Default::default(),
            };

            por.synthesize(&mut cs).unwrap();
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );

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

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_pedersen() {
        private_por_test_compound::<PedersenHasher>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_blake2s() {
        private_por_test_compound::<Blake2sHasher>();
    }

    fn private_por_test_compound<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let leaves = 6;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let graph = BucketGraph::<H>::new(leaves, 16, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: &merklepor::SetupParams {
                    leaves,
                    private: true,
                },
                engine_params: &JubjubBls12::new(),
                partitions: None,
            };
            let public_params = PoRCompound::<H>::setup(&setup_params).expect("setup failed");

            let private_inputs = merklepor::PrivateInputs::<H>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), public_inputs.challenge).unwrap(),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            let gparams = PoRCompound::<H>::groth_params(
                &public_params.vanilla_params,
                setup_params.engine_params,
            )
            .unwrap();

            let proof =
                PoRCompound::<H>::prove(&public_params, &public_inputs, &private_inputs, &gparams)
                    .expect("failed while proving");

            {
                let (circuit, inputs) = PoRCompound::<H>::circuit_for_test(
                    &public_params,
                    &public_inputs,
                    &private_inputs,
                );

                let mut cs = TestConstraintSystem::new();

                circuit.synthesize(&mut cs).expect("failed to synthesize");

                assert!(cs.is_satisfied());
                assert!(cs.verify(&inputs));
            }

            let verified =
                PoRCompound::<H>::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                    .expect("failed while verifying");
            assert!(verified);
        }
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 6;

        for i in 0..6 {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::<PedersenHasher>::new(leaves, 16, 0, new_seed());
            let tree = graph.merkle_tree(data.as_slice()).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let priv_inputs = merklepor::PrivateInputs::<PedersenHasher>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
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

            let por = PoRCircuit::<Bls12, PedersenHasher> {
                params,
                value: Some(proof.data.into()),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(tree.root().into())),
                private: true,
                _h: Default::default(),
            };

            por.synthesize(&mut cs).unwrap();
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4148, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = Vec::new();
            expected_inputs.extend(packed_auth_path);

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "path/input 0"),
                expected_inputs[0],
                "wrong packed_auth_path"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }
}
