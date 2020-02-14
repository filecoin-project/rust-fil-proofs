use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::gadgets::boolean::{AllocatedBit, Boolean};
use bellperson::gadgets::{multipack, num};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::insertion::insert;
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgraph::graph_height;
use crate::error::Result;
use crate::hasher::{HashFunction, Hasher, PoseidonEngine};
use crate::merklepor::MerklePoR;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
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
pub struct PoRCircuit<'a, U, E: JubjubEngine + PoseidonEngine<U>, H: Hasher>
where
    U: 'static
        + typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    params: &'a E::Params,
    value: Root<E>,
    auth_path: Vec<(Vec<Option<E::Fr>>, Option<usize>)>,
    root: Root<E>,
    private: bool,
    _h: PhantomData<H>,
    _u: PhantomData<U>,
}

impl<'a, U, E: JubjubEngine + PoseidonEngine<U>, H: Hasher> CircuitComponent
    for PoRCircuit<'a, U, E, H>
where
    U: typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    type ComponentPrivateInputs = Option<Root<E>>;
}

pub struct PoRCompound<H: Hasher, U: typenum::Unsigned> {
    _h: PhantomData<H>,
    _u: PhantomData<U>,
}

pub fn challenge_into_auth_path_bits<U: typenum::Unsigned>(
    challenge: usize,
    leaves: usize,
) -> Vec<bool> {
    assert_eq!(U::to_usize(), 2, "unsupported arity");

    // FIXME: this needs to return Vec<usize> and support larger than arity 2
    let height = graph_height::<U>(leaves);
    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n & 1 == 1);
        n >>= 1;
    }
    bits
}

impl<E: JubjubEngine, C: Circuit<E>, P: ParameterSetMetadata, H: Hasher, U: typenum::Unsigned>
    CacheableParameters<E, C, P> for PoRCompound<H, U>
{
    fn cache_prefix() -> String {
        format!("proof-of-retrievability-{}-{}", H::name(), U::to_usize())
    }
}

// can only implment for Bls12 because merklepor is not generic over the engine.
impl<'a, H, U> CompoundProof<'a, Bls12, MerklePoR<H, U>, PoRCircuit<'a, U, Bls12, H>>
    for PoRCompound<H, U>
where
    H: 'a + Hasher,
    U: 'a
        + Clone
        + Sync
        + Send
        + typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    Bls12: PoseidonEngine<U>,
    typenum::Add1<U>: generic_array::ArrayLength<Fr>,
{
    fn circuit<'b>(
        public_inputs: &<MerklePoR<H, U> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCircuit<'a, U, Bls12, H> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <MerklePoR<H, U> as ProofScheme<'a>>::Proof,
        public_params: &'b <MerklePoR<H, U> as ProofScheme<'a>>::PublicParams,
    ) -> Result<PoRCircuit<'a, U, Bls12, H>> {
        let (root, private) = match (*public_inputs).commitment {
            None => (Root::Val(Some(proof.proof.root.into())), true),
            Some(commitment) => (Root::Val(Some(commitment.into())), false),
        };

        ensure!(
            private == public_params.private,
            "Inputs must be consistent with public params"
        );

        Ok(PoRCircuit::<U, Bls12, H> {
            params: &*JJ_PARAMS,
            value: Root::Val(Some(proof.data.into())),
            auth_path: proof.proof.as_options(),
            root,
            private,
            _h: PhantomData,
            _u: PhantomData,
        })
    }

    fn blank_circuit(
        public_params: &<MerklePoR<H, U> as ProofScheme<'a>>::PublicParams,
    ) -> PoRCircuit<'a, U, Bls12, H> {
        PoRCircuit::<U, Bls12, H> {
            params: &*JJ_PARAMS,
            value: Root::Val(None),
            auth_path: vec![
                (vec![None; U::to_usize() - 1], None);
                graph_height::<U>(public_params.leaves)
            ],
            root: Root::Val(None),
            private: public_params.private,
            _h: PhantomData,
            _u: PhantomData,
        }
    }

    fn generate_public_inputs(
        pub_inputs: &<MerklePoR<H, U> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<MerklePoR<H, U> as ProofScheme<'a>>::PublicParams,
        _k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let auth_path_bits =
            challenge_into_auth_path_bits::<U>(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut inputs = Vec::new();
        inputs.extend(packed_auth_path);

        if let Some(commitment) = pub_inputs.commitment {
            ensure!(!pub_params.private, "Params must be public");
            inputs.push(commitment.into());
        } else {
            ensure!(pub_params.private, "Params must be private");
        }

        Ok(inputs)
    }
}

impl<'a, U, E: JubjubEngine + PoseidonEngine<U>, H: Hasher> Circuit<E> for PoRCircuit<'a, U, E, H>
where
    U: typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
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

        let arity = U::to_usize();
        assert_eq!(1, arity.count_ones());
        let log_arity = arity.trailing_zeros();

        dbg!(&auth_path, &auth_path.len());
        {
            let value_num = value.allocated(cs.namespace(|| "value"))?;

            let mut cur = value_num;

            let mut auth_path_bits = Vec::with_capacity(auth_path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in auth_path.into_iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));
                let index_bits = (0..log_arity)
                    .map(|i| -> Result<Boolean, SynthesisError> {
                        let bit =
                            AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                                let index = e.1.ok_or_else(|| SynthesisError::AssignmentMissing)?;
                                let bit = ((index >> i) & 1) == 1;
                                Some(bit)
                            })?;
                        Ok(Boolean::from(bit))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                index_bits
                    .iter()
                    .for_each(|b| auth_path_bits.push(b.clone()));

                // Witness the authentication path element adjacent
                // at this depth.
                let path_elements =
                    e.0.iter()
                        .enumerate()
                        .map(|(i, elt)| {
                            num::AllocatedNum::alloc(
                                cs.namespace(|| format!("path element {}", i)),
                                || elt.ok_or_else(|| SynthesisError::AssignmentMissing),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                let inserted = insert(cs, &cur, &index_bits, &path_elements)?;
                // Swap the two if the current subtree is on the right
                // let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                //     cs.namespace(|| "conditional reversal of preimage"),
                //     &cur,
                //     &path_element,
                //     &cur_is_right,
                // )?;

                // Compute the new subtree value
                cur = H::Function::hash_multi_leaf_circuit(
                    cs.namespace(|| "computation of commitment hash"),
                    &inserted,
                    i,
                    params,
                )?;
                //                auth_path_bits.push(cur_is_right);
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

impl<'a, U, E: JubjubEngine + PoseidonEngine<U>, H: Hasher> PoRCircuit<'a, U, E, H>
where
    U: 'static
        + typenum::Unsigned
        + std::ops::Add<typenum::B1>
        + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
    typenum::Add1<U>: generic_array::ArrayLength<E::Fr>,
{
    pub fn synthesize<CS>(
        mut cs: CS,
        params: &E::Params,
        value: Root<E>,
        auth_path: Vec<(Vec<Option<E::Fr>>, Option<usize>)>,
        root: Root<E>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        E: JubjubEngine,
        CS: ConstraintSystem<E>,
    {
        let por = PoRCircuit::<U, E, H> {
            params,
            value,
            auth_path,
            root,
            private,
            _h: PhantomData,
            _u: PhantomData,
        };

        por.synthesize(&mut cs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proof::NoRequirements;
    use bellperson::gadgets::multipack;
    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::hasher::{Blake2sHasher, Domain, Hasher, PedersenHasher, PoseidonHasher};
    use crate::merklepor;
    use crate::proof::ProofScheme;
    use crate::util::data_at_node;

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn por_test_compound() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let leaves = 8;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let graph = BucketGraph::<PedersenHasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: merklepor::SetupParams {
                    leaves,
                    private: false,
                },
                partitions: None,
            };
            let public_params = PoRCompound::<PedersenHasher, typenum::U2>::setup(&setup_params)
                .expect("setup failed");

            let private_inputs = merklepor::PrivateInputs::<PedersenHasher, typenum::U2>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), public_inputs.challenge).unwrap(),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            let gparams = PoRCompound::<PedersenHasher, typenum::U2>::groth_params(
                &public_params.vanilla_params,
            )
            .expect("failed to generate groth params");

            let proof = PoRCompound::<PedersenHasher, typenum::U2>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = PoRCompound::<PedersenHasher, typenum::U2>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");
            assert!(verified);

            let (circuit, inputs) = PoRCompound::<PedersenHasher, typenum::U2>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            )
            .unwrap();

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));
        }
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_binary() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher, typenum::U2>(6_873 /*4125*/);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_binary() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U2>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_binary() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U2>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_binary() {
        test_por_input_circuit_with_bls12_381::<PoseidonHasher, typenum::U2>(1_290);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_quad() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher, typenum::U4>(6_873 /*4125*/);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_quad() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U4>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_quad() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U4>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_quad() {
        test_por_input_circuit_with_bls12_381::<PoseidonHasher, typenum::U4>(1_869);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_oct() {
        test_por_input_circuit_with_bls12_381::<PedersenHasher, typenum::U8>(6_873 /*4125*/);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_oct() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U8>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_oct() {
        test_por_input_circuit_with_bls12_381::<Blake2sHasher, typenum::U8>(
            107_613, /*64_569*/
        );
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_oct() {
        test_por_input_circuit_with_bls12_381::<PoseidonHasher, typenum::U8>(1_869);
    }

    fn test_por_input_circuit_with_bls12_381<H: Hasher, U>(num_constraints: usize)
    where
        U: typenum::Unsigned
            + 'static
            + Sync
            + Send
            + Clone
            + std::ops::Add<typenum::B1>
            + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
        Bls12: PoseidonEngine<U>,
        typenum::Add1<U>: generic_array::ArrayLength<Fr>,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let arity = U::to_usize();
        assert_eq!(1, arity.count_ones());
        let arity_log = arity.trailing_zeros();

        // Ensure arity will evenly fill tree.
        let leaves = 8 << arity_log + 1;

        for i in 0..leaves {
            // Force a chosen challenge for quad tests. FIXME: Remove
            if arity == 4 && i != 3 {
                continue;
            }
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = merklepor::PublicInputs::<H::Domain> {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let priv_inputs = merklepor::PrivateInputs::<H, U>::new(
                H::Domain::try_from_bytes(
                    data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
                )
                .unwrap(),
                &tree,
            );

            // create a non circuit proof
            let proof = merklepor::MerklePoR::<H, U>::prove(&pub_params, &pub_inputs, &priv_inputs)
                .expect("proving failed");

            // make sure it verifies
            let is_valid = merklepor::MerklePoR::<H, U>::verify(&pub_params, &pub_inputs, &proof)
                .expect("verification failed");
            assert!(is_valid, "failed to verify merklepor proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let por = PoRCircuit::<U, Bls12, H> {
                params: &JJ_PARAMS,
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(pub_inputs.commitment.unwrap().into())),
                private: false,
                _h: PhantomData,
                _u: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
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
                .map(|(_, is_right)| match is_right {
                    0 => false,
                    1 => true,
                    _ => panic!("unsupported arity"),
                })
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
    fn test_private_por_compound_pedersen_binary() {
        private_por_test_compound::<PedersenHasher, typenum::U2>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_binary() {
        private_por_test_compound::<PoseidonHasher, typenum::U2>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_quad() {
        private_por_test_compound::<PoseidonHasher, typenum::U4>();
    }

    fn private_por_test_compound<H: Hasher, U>()
    where
        U: typenum::Unsigned
            + 'static
            + Sync
            + Send
            + Clone
            + std::ops::Add<typenum::B1>
            + std::ops::Add<typenum::UInt<typenum::UTerm, typenum::B1>>,
        Bls12: PoseidonEngine<U>,
        typenum::Add1<U>: generic_array::ArrayLength<Fr>,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let leaves = 8;
        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

        for i in 0..3 {
            let public_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: merklepor::SetupParams {
                    leaves,
                    private: true,
                },
                partitions: None,
            };
            let public_params = PoRCompound::<H, U>::setup(&setup_params).expect("setup failed");

            let private_inputs = merklepor::PrivateInputs::<H, U>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), public_inputs.challenge).unwrap(),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            let groth_params = PoRCompound::<H, U>::groth_params(&public_params.vanilla_params)
                .expect("failed to generate groth params");

            let proof = PoRCompound::<H, U>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &groth_params,
            )
            .expect("proving failed");

            {
                let (circuit, inputs) = PoRCompound::<H, U>::circuit_for_test(
                    &public_params,
                    &public_inputs,
                    &private_inputs,
                )
                .unwrap();

                let mut cs = TestConstraintSystem::new();

                circuit.synthesize(&mut cs).expect("failed to synthesize");

                assert!(cs.is_satisfied());
                assert!(cs.verify(&inputs));
            }

            let verified = PoRCompound::<H, U>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");
            assert!(verified);
        }
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 8;

        for i in 0..leaves {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph =
                BucketGraph::<PedersenHasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let priv_inputs = merklepor::PrivateInputs::<PedersenHasher, typenum::U2>::new(
                bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
                )
                .unwrap()
                .into(),
                &tree,
            );

            // create a non circuit proof
            let proof = merklepor::MerklePoR::<PedersenHasher, typenum::U2>::prove(
                &pub_params,
                &pub_inputs,
                &priv_inputs,
            )
            .expect("proving failed");

            // make sure it verifies
            let is_valid = merklepor::MerklePoR::<PedersenHasher, typenum::U2>::verify(
                &pub_params,
                &pub_inputs,
                &proof,
            )
            .expect("verification failed");
            assert!(is_valid, "failed to verify merklepor proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<typenum::U2, Bls12, PedersenHasher> {
                params: &JJ_PARAMS,
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(tree.root().into())),
                private: true,
                _h: PhantomData,
                _u: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4124, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| match is_right {
                    0 => false,
                    1 => true,
                    _ => panic!("unsupported arity"),
                })
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
