use std::convert::TryFrom;
use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::{
    bls::{Bls12, Fr, FrRepr},
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use filecoin_hashers::{HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::Unsigned;

use crate::{
    compound_proof::{CircuitComponent, CompoundProof},
    error::Result,
    gadgets::{constraint, insertion::insert, variables::Root},
    merkle::{base_path_length, MerkleProofTrait, MerkleTreeTrait},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por::PoR,
    proof::ProofScheme,
};

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
    auth_path: AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    root: Root<Bls12>,
    private: bool,
    _tree: PhantomData<Tree>,
}

#[derive(Debug, Clone)]
pub struct AuthPath<
    H: Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
> {
    base: SubPath<H, U>,
    sub: SubPath<H, V>,
    top: SubPath<H, W>,
}

impl<
        H: Hasher,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
    > From<Vec<(Vec<Option<Fr>>, Option<usize>)>> for AuthPath<H, U, V, W>
{
    fn from(mut base_opts: Vec<(Vec<Option<Fr>>, Option<usize>)>) -> Self {
        let has_top = W::to_usize() > 0;
        let has_sub = V::to_usize() > 0;
        let len = base_opts.len();

        let x = if has_top {
            2
        } else if has_sub {
            1
        } else {
            0
        };
        let mut opts = base_opts.split_off(len - x);

        let base = base_opts
            .into_iter()
            .map(|(hashes, index)| PathElement {
                hashes,
                index,
                _a: Default::default(),
                _h: Default::default(),
            })
            .collect();

        let top = if has_top {
            let (hashes, index) = opts.pop().expect("pop failure");
            vec![PathElement {
                hashes,
                index,
                _a: Default::default(),
                _h: Default::default(),
            }]
        } else {
            Vec::new()
        };

        let sub = if has_sub {
            let (hashes, index) = opts.pop().expect("pop failure");
            vec![PathElement {
                hashes,
                index,
                _a: Default::default(),
                _h: Default::default(),
            }]
        } else {
            Vec::new()
        };

        assert!(opts.is_empty());

        AuthPath {
            base: SubPath { path: base },
            sub: SubPath { path: sub },
            top: SubPath { path: top },
        }
    }
}

#[derive(Debug, Clone)]
struct SubPath<H: Hasher, Arity: 'static + PoseidonArity> {
    path: Vec<PathElement<H, Arity>>,
}

#[derive(Debug, Clone)]
struct PathElement<H: Hasher, Arity: 'static + PoseidonArity> {
    hashes: Vec<Option<Fr>>,
    index: Option<usize>,
    _a: PhantomData<Arity>,
    _h: PhantomData<H>,
}

impl<H: Hasher, Arity: 'static + PoseidonArity> SubPath<H, Arity> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        mut cur: AllocatedNum<Bls12>,
    ) -> Result<(AllocatedNum<Bls12>, Vec<Boolean>), SynthesisError> {
        let arity = Arity::to_usize();

        if arity == 0 {
            // Nothing to do here.
            assert!(self.path.is_empty());
            return Ok((cur, vec![]));
        }

        assert_eq!(1, arity.count_ones(), "arity must be a power of two");
        let index_bit_count = arity.trailing_zeros() as usize;

        let mut auth_path_bits = Vec::with_capacity(self.path.len());

        for (i, path_element) in self.path.into_iter().enumerate() {
            let path_hashes = path_element.hashes;
            let optional_index = path_element.index; // Optional because of Bellman blank-circuit construction mechanics.

            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            let mut index_bits = Vec::with_capacity(index_bit_count);

            for i in 0..index_bit_count {
                let bit = AllocatedBit::alloc(cs.namespace(|| format!("index bit {}", i)), {
                    optional_index.map(|index| ((index >> i) & 1) == 1)
                })?;

                index_bits.push(Boolean::from(bit));
            }

            auth_path_bits.extend_from_slice(&index_bits);

            // Witness the authentication path elements adjacent at this depth.
            let path_hash_nums = path_hashes
                .iter()
                .enumerate()
                .map(|(i, elt)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("path element {}", i)), || {
                        elt.ok_or_else(|| SynthesisError::AssignmentMissing)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let inserted = insert(cs, &cur, &index_bits, &path_hash_nums)?;

            // Compute the new subtree value
            cur = H::Function::hash_multi_leaf_circuit::<Arity, _>(
                cs.namespace(|| "computation of commitment hash"),
                &inserted,
                i,
            )?;
        }

        Ok((cur, auth_path_bits))
    }
}

impl<H: Hasher, U: PoseidonArity, V: PoseidonArity, W: PoseidonArity> AuthPath<H, U, V, W> {
    pub fn blank(leaves: usize) -> Self {
        let has_sub = V::to_usize() > 0;
        let has_top = W::to_usize() > 0;
        let base_elements = base_path_length::<U, V, W>(leaves);

        let base = vec![
            PathElement::<H, U> {
                hashes: vec![None; U::to_usize() - 1],
                index: None,
                _a: Default::default(),
                _h: Default::default(),
            };
            base_elements
        ];

        let sub = if has_sub {
            vec![PathElement::<H, V> {
                hashes: vec![None; V::to_usize() - 1],
                index: None,
                _a: Default::default(),
                _h: Default::default(),
            }]
        } else {
            Vec::new()
        };

        let top = if has_top {
            vec![PathElement::<H, W> {
                hashes: vec![None; W::to_usize() - 1],
                index: None,
                _a: Default::default(),
                _h: Default::default(),
            }]
        } else {
            Vec::new()
        };

        AuthPath {
            base: SubPath { path: base },
            sub: SubPath { path: sub },
            top: SubPath { path: top },
        }
    }
}

impl<Tree: MerkleTreeTrait> CircuitComponent for PoRCircuit<Tree> {
    type ComponentPrivateInputs = Option<Root<Bls12>>;
}

pub struct PoRCompound<Tree: MerkleTreeTrait> {
    _tree: PhantomData<Tree>,
}

fn to_bits(bit_count: u32, n: usize) -> Vec<bool> {
    (0..bit_count).map(|i| (n >> i) & 1 == 1).collect()
}

pub fn challenge_into_auth_path_bits(challenge: usize, leaves: usize) -> Vec<bool> {
    assert_eq!(1, leaves.count_ones());

    to_bits(leaves.trailing_zeros(), challenge)
}

impl<C: Circuit<Bls12>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
    for PoRCompound<Tree>
{
    fn cache_prefix() -> String {
        format!("proof-of-retrievability-{}", Tree::display())
    }
}

// can only implment for Bls12 because por is not generic over the engine.
impl<'a, Tree: 'static + MerkleTreeTrait> CompoundProof<'a, PoR<Tree>, PoRCircuit<Tree>>
    for PoRCompound<Tree>
{
    fn circuit<'b>(
        public_inputs: &<PoR<Tree> as ProofScheme<'a>>::PublicInputs,
        _component_private_inputs: <PoRCircuit<Tree> as CircuitComponent>::ComponentPrivateInputs,
        proof: &'b <PoR<Tree> as ProofScheme<'a>>::Proof,
        public_params: &'b <PoR<Tree> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<PoRCircuit<Tree>> {
        let (root, private) = match (*public_inputs).commitment {
            None => (Root::Val(Some(proof.proof.root().into())), true),
            Some(commitment) => (Root::Val(Some(commitment.into())), false),
        };

        ensure!(
            private == public_params.private,
            "Inputs must be consistent with public params"
        );

        Ok(PoRCircuit::<Tree> {
            value: Root::Val(Some(proof.data.into())),
            auth_path: proof.proof.as_options().into(),
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
            auth_path: AuthPath::blank(public_params.leaves),
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
        ensure!(
            pub_inputs.challenge < pub_params.leaves,
            "Challenge out of range"
        );
        let mut inputs = Vec::new();

        // Inputs are (currently, inefficiently) packed with one `Fr` per challenge.
        // Boolean/bit auth paths trivially correspond to the challenged node's index within a sector.
        // Defensively convert the challenge with `try_from` as a reminder that we must not truncate.
        let input_fr = Fr::from_repr(FrRepr::from(
            u64::try_from(pub_inputs.challenge).expect("challenge type too wide"),
        ))?;
        inputs.push(input_fr);

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
        if sub_arity > 0 {
            assert_eq!(
                1,
                sub_arity.count_ones(),
                "subtree arity must be power of two"
            );
        }
        if top_arity > 0 {
            assert_eq!(
                1,
                top_arity.count_ones(),
                "top tree arity must be power of two"
            );
        }

        {
            let value_num = value.allocated(cs.namespace(|| "value"))?;
            let cur = value_num;

            // Ascend the merkle tree authentication path

            // base tree
            let (cur, base_auth_path_bits) =
                auth_path.base.synthesize(cs.namespace(|| "base"), cur)?;

            // sub
            let (cur, sub_auth_path_bits) =
                auth_path.sub.synthesize(cs.namespace(|| "sub"), cur)?;

            // top
            let (computed_root, top_auth_path_bits) =
                auth_path.top.synthesize(cs.namespace(|| "top"), cur)?;

            let mut auth_path_bits = Vec::new();
            auth_path_bits.extend(base_auth_path_bits);
            auth_path_bits.extend(sub_auth_path_bits);
            auth_path_bits.extend(top_auth_path_bits);

            multipack::pack_into_inputs(cs.namespace(|| "path"), &auth_path_bits)?;
            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                let rt = root.allocated(cs.namespace(|| "root_value"))?;
                constraint::equal(cs, || "enforce root is correct", &computed_root, &rt);

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
    pub fn new(proof: Tree::Proof, private: bool) -> Self {
        PoRCircuit::<Tree> {
            value: Root::Val(Some(proof.leaf().into())),
            auth_path: proof.as_options().into(),
            root: Root::Val(Some(proof.root().into())),
            private,
            _tree: PhantomData,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn synthesize<CS>(
        mut cs: CS,
        value: Root<Bls12>,
        auth_path: AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
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

/// Synthesizes a non-compound arity PoR without adding a public input for the challenge (whereas
/// `PoRCircuit` adds one public input for the challenge). This PoR gadget allows the caller to pack
/// mulitple PoR challenges into a single public input when the challenge bit length is less than
/// `Fr::Capacity`.
pub fn por_no_challenge_input<Tree, CS>(
    cs: &mut CS,
    // Least significant bit first, most significant bit last.
    challenge_bits: Vec<AllocatedBit>,
    leaf: AllocatedNum<Bls12>,
    path_values: Vec<Vec<AllocatedNum<Bls12>>>,
    root: AllocatedNum<Bls12>,
) -> Result<(), SynthesisError>
where
    Tree: MerkleTreeTrait,
    CS: ConstraintSystem<Bls12>,
{
    let arity = Tree::Arity::to_usize();
    let arity_bit_len = arity.trailing_zeros() as usize;
    let challenge_bit_len = challenge_bits.len();
    let height = path_values.len();

    // Check that all path elements are consistent with the arity.
    assert!(path_values
        .iter()
        .all(|siblings| siblings.len() == arity - 1));

    // Check that the challenge bit length is consistent with the height and arity.
    assert_eq!(challenge_bit_len, arity_bit_len * height);

    let challenge_bits: Vec<Boolean> = challenge_bits.into_iter().map(Boolean::from).collect();

    // Compute a root from the provided path and check equality with the provided root.
    let mut cur = leaf;
    for (height, (siblings, insert_index)) in path_values
        .iter()
        .zip(challenge_bits.chunks(arity_bit_len))
        .enumerate()
    {
        let inputs = insert(
            &mut cs.namespace(|| format!("merkle insert, height {}", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::Arity, _>(
            cs.namespace(|| format!("merkle hash, height {}", height)),
            &inputs,
            height,
        )?;
    }
    let computed_root = cur;
    constraint::equal(cs, || "merkle root equality", &computed_root, &root);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem};
    use ff::Field;
    use filecoin_hashers::{
        blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain,
    };
    use fr32::{bytes_into_fr, fr_into_bytes};
    use generic_array::typenum::{U0, U2, U4, U8};
    use merkletree::store::VecStore;
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::{
        compound_proof,
        merkle::{
            create_base_merkle_tree, generate_tree, get_base_tree_count, MerkleTreeWrapper, ResTree,
        },
        por,
        proof::NoRequirements,
        util::data_at_node,
        TEST_SEED,
    };

    type TestTree<H, A> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, U0, U0>;

    type TestTree2<H, A, B> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, U0>;

    type TestTree3<H, A, B, C> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, C>;

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn por_test_compound_poseidon_base_8() {
        por_compound::<TestTree<PoseidonHasher, U8>>();
    }

    fn por_compound<Tree: 'static + MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice())
            .expect("create_base_merkle_tree failure");

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
        let public_params = PoRCompound::<Tree>::setup(&setup_params).expect("setup failed");

        let private_inputs = por::PrivateInputs::<Tree>::new(
            bytes_into_fr(
                data_at_node(data.as_slice(), public_inputs.challenge)
                    .expect("bytes_into_fr failure"),
            )
            .expect("failed to create Fr from node data")
            .into(),
            &tree,
        );

        let gparams = PoRCompound::<Tree>::groth_params(Some(rng), &public_params.vanilla_params)
            .expect("failed to generate groth params");

        let proof =
            PoRCompound::<Tree>::prove(&public_params, &public_inputs, &private_inputs, &gparams)
                .expect("failed while proving");

        let verified =
            PoRCompound::<Tree>::verify(&public_params, &public_inputs, &proof, &NoRequirements)
                .expect("failed while verifying");
        assert!(verified);

        let (circuit, inputs) =
            PoRCompound::<Tree>::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                .expect("circuit_for_test failure");

        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));
    }

    #[test]
    fn test_por_circuit_blake2s_base_2() {
        test_por_circuit::<TestTree<Blake2sHasher, U2>>(3, 129_135);
    }

    #[test]
    fn test_por_circuit_sha256_base_2() {
        test_por_circuit::<TestTree<Sha256Hasher, U2>>(3, 272_295);
    }

    #[test]
    fn test_por_circuit_poseidon_base_2() {
        test_por_circuit::<TestTree<PoseidonHasher, U2>>(3, 1_887);
    }

    #[test]
    fn test_por_circuit_blake2s_base_4() {
        test_por_circuit::<TestTree<Blake2sHasher, U4>>(3, 130_296);
    }

    #[test]
    fn test_por_circuit_sha256_base_4() {
        test_por_circuit::<TestTree<Sha256Hasher, U4>>(3, 216_258);
    }

    #[test]
    fn test_por_circuit_poseidon_base_4() {
        test_por_circuit::<TestTree<PoseidonHasher, U4>>(3, 1_164);
    }

    #[test]
    fn test_por_circuit_blake2s_base_8() {
        test_por_circuit::<TestTree<Blake2sHasher, U8>>(3, 174_503);
    }

    #[test]
    fn test_por_circuit_sha256_base_8() {
        test_por_circuit::<TestTree<Sha256Hasher, U8>>(3, 250_987);
    }

    #[test]
    fn test_por_circuit_poseidon_base_8() {
        test_por_circuit::<TestTree<PoseidonHasher, U8>>(3, 1_063);
    }

    #[test]
    fn test_por_circuit_poseidon_sub_8_2() {
        test_por_circuit::<TestTree2<PoseidonHasher, U8, U2>>(3, 1_377);
    }

    #[test]
    fn test_por_circuit_poseidon_top_8_4_2() {
        test_por_circuit::<TestTree3<PoseidonHasher, U8, U4, U2>>(3, 1_764);
    }

    #[test]
    fn test_por_circuit_poseidon_top_8_8() {
        // This is the shape we want for 32GiB sectors.
        test_por_circuit::<TestTree2<PoseidonHasher, U8, U8>>(3, 1_593);
    }
    #[test]
    fn test_por_circuit_poseidon_top_8_8_2() {
        // This is the shape we want for 64GiB secotrs.
        test_por_circuit::<TestTree3<PoseidonHasher, U8, U8, U2>>(3, 1_907);
    }

    #[test]
    fn test_por_circuit_poseidon_top_8_2_4() {
        // We can handle top-heavy trees with a non-zero subtree arity.
        // These should never be produced, though.
        test_por_circuit::<TestTree3<PoseidonHasher, U8, U2, U4>>(3, 1_764);
    }

    fn test_por_circuit<Tree: 'static + MerkleTreeTrait>(
        num_inputs: usize,
        num_constraints: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        // Ensure arity will evenly fill tree.
        let leaves = 64 * get_base_tree_count::<Tree>();

        // -- Basic Setup
        let (data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

        for i in 0..leaves {
            //println!("challenge: {}, ({})", i, leaves);

            // -- PoR
            let pub_params = por::PublicParams {
                leaves,
                private: false,
            };
            let pub_inputs = por::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
                challenge: i,
                commitment: Some(tree.root()),
            };
            let leaf =
                data_at_node(data.as_slice(), pub_inputs.challenge).expect("data_at_node failure");
            let leaf_element = <Tree::Hasher as Hasher>::Domain::try_from_bytes(leaf)
                .expect("try_from_bytes failure");
            let priv_inputs = por::PrivateInputs::<ResTree<Tree>>::new(leaf_element, &tree);
            let p = tree.gen_proof(i).expect("gen_proof failure");
            assert!(p.verify());

            // create a non circuit proof
            let proof = PoR::<ResTree<Tree>>::prove(&pub_params, &pub_inputs, &priv_inputs)
                .expect("proving failed");

            // make sure it verifies
            let is_valid = PoR::<ResTree<Tree>>::verify(&pub_params, &pub_inputs, &proof)
                .expect("verification failed");
            assert!(is_valid, "failed to verify por proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let por = PoRCircuit::<ResTree<Tree>> {
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options().into(),
                root: Root::Val(Some(
                    pub_inputs
                        .commitment
                        .expect("pub_inputs.commitment failure")
                        .into(),
                )),
                private: false,
                _tree: PhantomData,
            };

            por.synthesize(&mut cs).expect("circuit synthesis failed");
            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), num_inputs, "wrong number of inputs");
            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );

            let generated_inputs = PoRCompound::<ResTree<Tree>>::generate_public_inputs(
                &pub_inputs,
                &pub_params,
                None,
            )
            .expect("generate_public_inputs failure");

            let expected_inputs = cs.get_inputs();

            for ((input, label), generated_input) in
                expected_inputs.iter().skip(1).zip(generated_inputs.iter())
            {
                assert_eq!(input, generated_input, "{}", label);
            }

            assert_eq!(
                generated_inputs.len(),
                expected_inputs.len() - 1,
                "inputs are not the same length"
            );

            assert!(cs.verify(&generated_inputs), "failed to verify inputs");
        }
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_base_2() {
        private_por_test_compound::<TestTree<PoseidonHasher, U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_base_4() {
        private_por_test_compound::<TestTree<PoseidonHasher, U4>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_sub_8_2() {
        private_por_test_compound::<TestTree2<PoseidonHasher, U8, U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_top_8_4_2() {
        private_por_test_compound::<TestTree3<PoseidonHasher, U8, U4, U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_top_8_8() {
        private_por_test_compound::<TestTree2<PoseidonHasher, U8, U8>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_top_8_8_2() {
        private_por_test_compound::<TestTree3<PoseidonHasher, U8, U8, U2>>();
    }

    #[ignore] // Slow test – run only when compiled for release.
    #[test]
    fn test_private_por_compound_poseidon_top_8_2_4() {
        private_por_test_compound::<TestTree3<PoseidonHasher, U8, U2, U4>>();
    }

    fn private_por_test_compound<Tree: 'static + MerkleTreeTrait>() {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        // Ensure arity will evenly fill tree.
        let leaves = 64 * get_base_tree_count::<Tree>();

        // -- Basic Setup
        let (data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

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
            let public_params =
                PoRCompound::<ResTree<Tree>>::setup(&setup_params).expect("setup failed");

            let private_inputs = por::PrivateInputs::<ResTree<Tree>>::new(
                bytes_into_fr(
                    data_at_node(data.as_slice(), public_inputs.challenge)
                        .expect("data_at_node failure"),
                )
                .expect("failed to create Fr from node data")
                .into(),
                &tree,
            );

            {
                let (circuit, inputs) =
                    PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                        .expect("circuit_for_test");

                let mut cs = TestConstraintSystem::new();

                circuit.synthesize(&mut cs).expect("failed to synthesize");

                if !cs.is_satisfied() {
                    panic!(
                        "failed to satisfy: {:?}",
                        cs.which_is_unsatisfied().expect("cs is_satisfied failure")
                    );
                }
                assert!(
                    cs.verify(&inputs),
                    "verification failed with TestContraintSystem and generated inputs"
                );
            }
            // NOTE: This diagnostic code currently fails, even though the proof generated from the blank circuit verifies.
            // Use this to debug differences between blank and regular circuit generation.
            {
                let (circuit1, _inputs) =
                    PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                        .expect("circuit_for_test failure");
                let blank_circuit =
                    PoRCompound::<ResTree<Tree>>::blank_circuit(&public_params.vanilla_params);

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

            let blank_groth_params = PoRCompound::<ResTree<Tree>>::groth_params(
                Some(rng),
                &public_params.vanilla_params,
            )
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
    fn test_private_por_input_circuit_poseidon_binary() {
        test_private_por_input_circuit::<TestTree<PoseidonHasher, U2>>(1_886);
    }

    #[test]
    fn test_private_por_input_circuit_poseidon_quad() {
        test_private_por_input_circuit::<TestTree<PoseidonHasher, U4>>(1_163);
    }

    #[test]
    fn test_private_por_input_circuit_poseidon_oct() {
        test_private_por_input_circuit::<TestTree<PoseidonHasher, U8>>(1_062);
    }

    fn test_private_por_input_circuit<Tree: MerkleTreeTrait>(num_constraints: usize) {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        let leaves = 64 * get_base_tree_count::<Tree>();
        for i in 0..leaves {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
                .collect();

            let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice())
                .expect("create_base_merkle_tree failure");

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
                bytes_into_fr(
                    data_at_node(data.as_slice(), pub_inputs.challenge)
                        .expect("data_at_node failure"),
                )
                .expect("bytes_into_fr failure")
                .into(),
                &tree,
            );

            // create a non circuit proof
            let proof =
                PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

            // make sure it verifies
            let is_valid =
                PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
            assert!(is_valid, "failed to verify por proof");

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let por = PoRCircuit::<Tree> {
                value: Root::Val(Some(proof.data.into())),
                auth_path: proof.proof.as_options().into(),
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

            let auth_path_bits =
                challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
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
