use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::gadgets::boolean::{AllocatedBit, Boolean};
use bellperson::gadgets::{multipack, num};
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use generic_array::typenum::{self, Unsigned};
use paired::bls12_381::{Bls12, Fr};

use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::drgraph::graph_height;
use crate::error::Result;
use crate::gadgets::constraint;
use crate::gadgets::insertion::insert;
use crate::gadgets::variables::Root;
use crate::hasher::{HashFunction, Hasher};
use crate::merkle::{MerkleProofTrait, MerkleTreeTrait};
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::por::PoR;
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
pub struct PoRCircuit<Tree: MerkleTreeTrait> {
    value: Root<Bls12>,
    #[allow(clippy::type_complexity)]
    auth_path: Vec<(Vec<Option<Fr>>, Option<usize>)>,
    root: Root<Bls12>,
    private: bool,
    _tree: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait> CircuitComponent for PoRCircuit<Tree> {
    type ComponentPrivateInputs = Option<Root<Bls12>>;
}

pub struct PoRCompound<Tree: MerkleTreeTrait> {
    _tree: PhantomData<Tree>,
}

pub fn challenge_into_auth_path_bits<U: typenum::Unsigned>(
    challenge: usize,
    leaves: usize,
) -> Vec<bool> {
    assert_eq!(leaves.count_ones(), 1, "leaves must be a power of two");
    let height = leaves.trailing_zeros() as usize;

    let mut bits = Vec::new();
    let mut n = challenge;
    for _ in 0..height {
        bits.push(n % 2 == 1);
        n >>= 1;
    }
    bits
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for PoRCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-retrievability-{}", Tree::display())
    }
}

// can only implment for Bls12 because por is not generic over the engine.
impl<'a, Tree: 'a + MerkleTreeTrait> CompoundProof<'a, PoR<Tree>, PoRCircuit<Tree>>
    for PoRCompound<Tree>
{
    fn circuit<'b>(
        public_inputs: &<PoR<Tree> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <PoR<Tree> as ProofScheme<'a>>::Proof,
        public_params: &'b <PoR<Tree> as ProofScheme<'a>>::PublicParams,
    ) -> Result<PoRCircuit<Tree>> {
        let (root, private) = match (*public_inputs).commitment {
            None => (Root::Val(Some((*proof.proof.root()).into())), true),
            Some(commitment) => (Root::Val(Some(commitment.into())), false),
        };

        ensure!(
            private == public_params.private,
            "Inputs must be consistent with public params"
        );

        Ok(PoRCircuit::<Tree> {
            value: Root::Val(Some(proof.data.into())),
            auth_path: proof.proof.as_options(),
            root,
            private,
            _tree: PhantomData,
        })
    }

    fn blank_circuit(
        public_params: &<PoR<Tree> as ProofScheme<'a>>::PublicParams,
    ) -> PoRCircuit<Tree> {
        PoRCircuit::<Tree> {
            value: Root::Val(None),
            auth_path: vec![
                (vec![None; Tree::Arity::to_usize() - 1], None);
                graph_height::<Tree::Arity>(public_params.leaves) - 1
            ],
            root: Root::Val(None),
            private: public_params.private,
            _tree: PhantomData,
        }
    }

    fn generate_public_inputs(
        pub_inputs: &<PoR<Tree> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<PoR<Tree> as ProofScheme<'a>>::PublicParams,
        _k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let auth_path_bits =
            challenge_into_auth_path_bits::<Tree::Arity>(pub_inputs.challenge, pub_params.leaves);
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

impl<'a, Tree: MerkleTreeTrait> Circuit<Bls12> for PoRCircuit<Tree> {
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
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let value = self.value;
        let auth_path = self.auth_path;
        let root = self.root;

        let base_arity = Tree::Arity::to_usize();
        let sub_arity = Tree::SubTreeArity::to_usize();
        let top_arity = Tree::TopTreeArity::to_usize();

        // All arities must be powers of two or circuits cannot be generated.
        assert_eq!(
            1,
            base_arity.count_ones(),
            "base arity must be power of two"
        );
        assert_eq!(
            1,
            sub_arity.count_ones(),
            "subtree arity must be power of two"
        );
        assert_eq!(
            1,
            top_arity.count_ones(),
            "top tree arity must be power of two"
        );

        let log_base_arity = base_arity.trailing_zeros() as usize;
        let log_sub_arity = sub_arity.trailing_zeros() as usize;
        let log_top_arity = top_arity.trailing_zeros() as usize;

        {
            let value_num = value.allocated(cs.namespace(|| "value"))?;

            let mut cur = value_num;

            let mut auth_path_bits = Vec::with_capacity(auth_path.len());

            // Ascend the merkle tree authentication path
            for (i, (elements, indexes)) in auth_path.into_iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

                let index_bit_count = match elements.len() {
                    base_arity => log_base_arity,
                    sub_arity => log_sub_arity,
                    top_arity => log_top_arity,
                    _ => panic!("wrong number of elements in inclusion proof path step"),
                };

                let mut index_bits = Vec::with_capacity(index_bit_count);
                for i in 0..index_bit_count {
                    let bit = AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                        indexes.map(|index| ((index >> i) & 1) == 1)
                    })?;

                    index_bits.push(Boolean::from(bit));
                }

                auth_path_bits.extend_from_slice(&index_bits);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_elements = elements
                    .iter()
                    .enumerate()
                    .map(|(i, elt)| {
                        num::AllocatedNum::alloc(
                            cs.namespace(|| format!("path element {}", i)),
                            || elt.ok_or_else(|| SynthesisError::AssignmentMissing),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let inserted = insert(cs, &cur, &index_bits, &path_elements)?;

                // Compute the new subtree value
                cur = <Tree::Hasher as Hasher>::Function::hash_multi_leaf_circuit::<Tree::Arity, _>(
                    cs.namespace(|| "computation of commitment hash"),
                    &inserted,
                    i,
                )?;
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

impl<'a, Tree: MerkleTreeTrait> PoRCircuit<Tree> {
    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS>(
        mut cs: CS,
        value: Root<Bls12>,
        auth_path: Vec<(Vec<Option<Fr>>, Option<usize>)>,
        root: Root<Bls12>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        let por = Self {
            value,
            auth_path,
            root,
            private,
            _tree: PhantomData,
        };

        por.synthesize(&mut cs)
    }
}

// #[cfg(test)]
mod tests {
    use super::*;

    use crate::proof::NoRequirements;
    use bellperson::gadgets::multipack;
    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use merkletree::merkle::{is_merkle_tree_size_valid, FromIndexedParallelIterator, MerkleTree};
    use merkletree::store::VecStore;

    use crate::compound_proof;
    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::gadgets::{MetricCS, TestConstraintSystem};
    use crate::hasher::{
        Blake2sHasher, Domain, Hasher, PedersenHasher, PoseidonDomain, PoseidonHasher, Sha256Hasher,
    };
    use crate::merkle::{BinaryTree, MerkleProofTrait, MerkleTreeWrapper};
    use crate::por;
    use crate::proof::ProofScheme;
    use crate::util::data_at_node;

    type TestTree<H, A> =
        MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, typenum::U0, typenum::U0>;

    #[allow(clippy::type_complexity)]
    fn generate_tree<R: Rng, BaseTreeArity: typenum::Unsigned>(
        rng: &mut R,
        size: usize,
    ) -> (
        Vec<u8>,
        MerkleTree<
            <PoseidonHasher as Hasher>::Domain,
            <PoseidonHasher as Hasher>::Function,
            VecStore<<PoseidonHasher as Hasher>::Domain>,
            BaseTreeArity,
        >,
    ) {
        let el = <PoseidonHasher as Hasher>::Domain::random(rng);
        let elements = (0..size).map(|_| el).collect::<Vec<_>>();
        let data = Vec::new();
        elements
            .iter()
            .for_each(|elt| data.extend(elt.into_bytes()));
        (data, MerkleTree::from_data(elements).unwrap())
    }

    #[allow(clippy::type_complexity)]
    fn generate_sub_tree<
        R: Rng,
        BaseTreeArity: typenum::Unsigned,
        SubTreeArity: typenum::Unsigned,
    >(
        rng: &mut R,
        size: usize,
    ) -> (
        Vec<u8>,
        MerkleTree<
            <PoseidonHasher as Hasher>::Domain,
            <PoseidonHasher as Hasher>::Function,
            VecStore<<PoseidonHasher as Hasher>::Domain>,
            BaseTreeArity,
            SubTreeArity,
        >,
    ) {
        let base_tree_count = BaseTreeArity::to_usize();
        let mut trees = Vec::with_capacity(base_tree_count);
        let mut data = Vec::new();
        for _ in 0..base_tree_count {
            let (data, tree) = generate_tree::<R, BaseTreeArity>(rng, size / base_tree_count);
            trees.push(tree);
            data.extend(data);
        }
        (data, MerkleTree::from_trees(trees).unwrap())
    }

    fn generate_top_tree<
        Tree: MerkleTreeTrait<Hasher = PoseidonHasher>,
        R: Rng,
        BaseTreeArity: typenum::Unsigned,
        SubTreeArity: typenum::Unsigned,
        TopTreeArity: typenum::Unsigned,
    >(
        rng: &mut R,
        nodes: usize,
    ) -> (Vec<u8>, Tree)
    where
        <Tree as MerkleTreeTrait>::Store: merkletree::store::Store<PoseidonDomain>,
    {
        let base_tree_count = BaseTreeArity::to_usize();
        let sub_tree_count = SubTreeArity::to_usize();
        let top_tree_count = TopTreeArity::to_usize();

        let mut sub_trees = Vec::with_capacity(sub_tree_count);
        let mut data = Vec::new();
        for i in 0..top_tree_count {
            let (data, tree) =
                generate_sub_tree::<R, BaseTreeArity, SubTreeArity>(rng, nodes / top_tree_count);
            sub_trees.push(tree);
            data.extend(data);
        }

        let tree: MerkleTree<_, _, _, BaseTreeArity, SubTreeArity, TopTreeArity> =
            MerkleTree::from_sub_trees(sub_trees).unwrap();

        (data, Tree::from_merkle(tree))
    }

    #[test]
    fn por_test_shapes() {}

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn por_test_compound() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let leaves = 64; // good for 2, 4 and 8

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let graph = BucketGraph::<PedersenHasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph
            .merkle_tree::<BinaryTree<PedersenHasher>>(None, data.as_slice())
            .unwrap();

        let public_inputs = por::PublicInputs {
            challenge: 2,
            commitment: Some(tree.root()),
        };

        let setup_params = compound_proof::SetupParams {
            vanilla_params: por::SetupParams {
                leaves,
                private: false,
            },
            partitions: None,
            priority: false,
        };
        let public_params =
            PoRCompound::<BinaryTree<PedersenHasher>>::setup(&setup_params).expect("setup failed");

        let private_inputs = por::PrivateInputs::<BinaryTree<PedersenHasher>>::new(
            bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge).unwrap())
                .expect("failed to create Fr from node data")
                .into(),
            &tree,
        );

        let gparams = PoRCompound::<BinaryTree<PedersenHasher>>::groth_params(
            Some(rng),
            &public_params.vanilla_params,
        )
        .expect("failed to generate groth params");

        let proof = PoRCompound::<BinaryTree<PedersenHasher>>::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &gparams,
        )
        .expect("failed while proving");

        let verified = PoRCompound::<BinaryTree<PedersenHasher>>::verify(
            &public_params,
            &public_inputs,
            &proof,
            &NoRequirements,
        )
        .expect("failed while verifying");
        assert!(verified);

        let (circuit, inputs) = PoRCompound::<BinaryTree<PedersenHasher>>::circuit_for_test(
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

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_binary() {
        test_por_input_circuit_with_bls12_381::<TestTree<PedersenHasher, typenum::U2>>(8_247);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_binary() {
        test_por_input_circuit_with_bls12_381::<TestTree<Blake2sHasher, typenum::U2>>(129_135);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_binary() {
        test_por_input_circuit_with_bls12_381::<TestTree<Sha256Hasher, typenum::U2>>(272_295);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_binary() {
        test_por_input_circuit_with_bls12_381::<TestTree<PoseidonHasher, typenum::U2>>(1_905);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_quad() {
        test_por_input_circuit_with_bls12_381::<TestTree<PedersenHasher, typenum::U4>>(12_411);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_quad() {
        test_por_input_circuit_with_bls12_381::<TestTree<Blake2sHasher, typenum::U4>>(130_308);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_quad() {
        test_por_input_circuit_with_bls12_381::<TestTree<Sha256Hasher, typenum::U4>>(216_270);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_quad() {
        test_por_input_circuit_with_bls12_381::<TestTree<PoseidonHasher, typenum::U4>>(1_185);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_pedersen_oct() {
        test_por_input_circuit_with_bls12_381::<TestTree<PedersenHasher, typenum::U8>>(19_357);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_blake2s_oct() {
        test_por_input_circuit_with_bls12_381::<TestTree<Blake2sHasher, typenum::U8>>(174_571);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_sha256_oct() {
        test_por_input_circuit_with_bls12_381::<TestTree<Sha256Hasher, typenum::U8>>(251_055);
    }

    #[test]
    fn test_por_input_circuit_with_bls12_381_poseidon_oct() {
        test_por_input_circuit_with_bls12_381::<TestTree<PoseidonHasher, typenum::U8>>(1_137);
    }

    fn test_por_input_circuit_with_bls12_381<Tree: MerkleTreeTrait<Hasher = PoseidonHasher>>(
        num_constraints: usize,
    ) where
        <Tree as MerkleTreeTrait>::Store: merkletree::store::Store<PoseidonDomain>,
    {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let arity = Tree::Arity::to_usize();
        assert_eq!(1, arity.count_ones());

        // Ensure arity will evenly fill tree.
        let leaves = 64; // good for 2, 4 and 8

        for i in 0..leaves {
            // -- Basic Setup

            // let data: Vec<u8> = (0..leaves)
            //     .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            //     .collect();

            // let graph =
            //     BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
            // let tree = graph.merkle_tree::<Tree>(None, data.as_slice()).unwrap();

            let (data, tree) =
                generate_top_tree::<Tree, _, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>(
                    rng, leaves,
                );
            // -- PoR

            let pub_params = por::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = por::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
                challenge: i,
                commitment: Some(tree.root()),
            };

            let priv_inputs = por::PrivateInputs::<Tree>::new(
                <Tree::Hasher as Hasher>::Domain::try_from_bytes(
                    data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
                )
                .unwrap(),
                &tree,
            );

            // create a non circuit proof
            let proof = por::PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
                .expect("proving failed");

            // make sure it verifies
            let is_valid = por::PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof)
                .expect("verification failed");
            assert!(is_valid, "failed to verify por proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let por = PoRCircuit::<Tree> {
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(pub_inputs.commitment.unwrap().into())),
                private: false,
                _tree: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 3, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );

            let auth_path_bits = challenge_into_auth_path_bits::<Tree::Arity>(
                pub_inputs.challenge,
                pub_params.leaves,
            );
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
        private_por_test_compound::<TestTree<PedersenHasher, typenum::U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_binary() {
        private_por_test_compound::<TestTree<PoseidonHasher, typenum::U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_pedersen_quad() {
        private_por_test_compound::<TestTree<PedersenHasher, typenum::U4>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_quad() {
        private_por_test_compound::<TestTree<PoseidonHasher, typenum::U4>>();
    }

    fn private_por_test_compound<Tree: MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let leaves = 64; // good for 2, 4 and 8

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let graph = BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree::<Tree>(None, data.as_slice()).unwrap();

        for i in 0..3 {
            let public_inputs = por::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let setup_params = compound_proof::SetupParams {
                vanilla_params: por::SetupParams {
                    leaves,
                    private: true,
                },
                partitions: None,
                priority: false,
            };
            let public_params = PoRCompound::<Tree>::setup(&setup_params).expect("setup failed");

            let private_inputs = por::PrivateInputs::<Tree>::new(
                bytes_into_fr(data_at_node(data.as_slice(), public_inputs.challenge).unwrap())
                    .expect("failed to create Fr from node data")
                    .into(),
                &tree,
            );

            {
                let (circuit, inputs) =
                    PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                        .unwrap();

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
            {
                let (circuit1, _inputs) =
                    PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                        .unwrap();
                let blank_circuit =
                    PoRCompound::<Tree>::blank_circuit(&public_params.vanilla_params);

                let mut cs_blank = MetricCS::new();
                blank_circuit
                    .synthesize(&mut cs_blank)
                    .expect("failed to synthesize");

                let a = cs_blank.pretty_print_list();

                let mut cs1 = TestConstraintSystem::new();
                circuit1.synthesize(&mut cs1).expect("failed to synthesize");
                let b = cs1.pretty_print_list();

                for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                    assert_eq!(a, b, "failed at chunk {}", i);
                }
            }

            let blank_groth_params =
                PoRCompound::<Tree>::groth_params(Some(rng), &public_params.vanilla_params)
                    .expect("failed to generate groth params");

            let proof = PoRCompound::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &blank_groth_params,
            )
            .expect("failed while proving");

            let verified =
                PoRCompound::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                    .expect("failed while verifying");

            assert!(verified);
        }
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381_pedersen_binary() {
        test_private_por_input_circuit_with_bls12_381::<TestTree<PedersenHasher, typenum::U2>>(
            8_246,
        );
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381_poseidon_binary() {
        test_private_por_input_circuit_with_bls12_381::<TestTree<PoseidonHasher, typenum::U2>>(
            1_904,
        );
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381_pedersen_quad() {
        test_private_por_input_circuit_with_bls12_381::<TestTree<PedersenHasher, typenum::U4>>(
            12_410,
        );
    }

    #[test]
    fn test_private_por_input_circuit_with_bls12_381_poseidon_quad() {
        test_private_por_input_circuit_with_bls12_381::<TestTree<PoseidonHasher, typenum::U4>>(
            1_184,
        );
    }

    fn test_private_por_input_circuit_with_bls12_381<Tree: MerkleTreeTrait>(
        num_constraints: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64; // good for 2, 4 and 8

        for i in 0..leaves {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
                .collect();

            let graph =
                BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree::<Tree>(None, data.as_slice()).unwrap();

            // -- PoR

            let pub_params = por::PublicParams {
                leaves,
                private: true,
            };
            let pub_inputs = por::PublicInputs {
                challenge: i,
                commitment: None,
            };

            let priv_inputs = por::PrivateInputs::<Tree>::new(
                bytes_into_fr(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap())
                    .unwrap()
                    .into(),
                &tree,
            );

            // create a non circuit proof
            let proof = por::PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
                .expect("proving failed");

            // make sure it verifies
            let is_valid = por::PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof)
                .expect("verification failed");
            assert!(is_valid, "failed to verify por proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<Tree> {
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options(),
                root: Root::Val(Some(tree.root().into())),
                private: true,
                _tree: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );

            let auth_path_bits = challenge_into_auth_path_bits::<Tree::Arity>(
                pub_inputs.challenge,
                pub_params.leaves,
            );
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
