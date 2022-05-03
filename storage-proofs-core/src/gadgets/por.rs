use std::convert::TryFrom;
use std::marker::PhantomData;

use anyhow::ensure;
use bellperson::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        num::AllocatedNum,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
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
    value: Root<Fr>,
    auth_path: AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    root: Root<Fr>,
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
    fn synthesize<CS: ConstraintSystem<Fr>>(
        self,
        mut cs: CS,
        mut cur: AllocatedNum<Fr>,
    ) -> Result<(AllocatedNum<Fr>, Vec<Boolean>), SynthesisError> {
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
    type ComponentPrivateInputs = Option<Root<Fr>>;
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

impl<C: Circuit<Fr>, P: ParameterSetMetadata, Tree: MerkleTreeTrait> CacheableParameters<C, P>
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
        let input_fr =
            Fr::from(u64::try_from(pub_inputs.challenge).expect("challenge type too wide"));
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

impl<'a, Tree: MerkleTreeTrait> Circuit<Fr> for PoRCircuit<Tree> {
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
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
        value: Root<Fr>,
        auth_path: AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        root: Root<Fr>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Fr>,
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

/// Synthesizes a PoR proof without adding a public input for the challenge (whereas `PoRCircuit`
/// adds a public input for the packed challenge bits).
pub fn por_no_challenge_input<Tree, CS>(
    mut cs: CS,
    // little-endian
    challenge_bits: Vec<AllocatedBit>,
    leaf: AllocatedNum<Fr>,
    path_values: Vec<Vec<AllocatedNum<Fr>>>,
    root: AllocatedNum<Fr>,
) -> Result<(), SynthesisError>
where
    Tree: MerkleTreeTrait,
    CS: ConstraintSystem<Fr>,
{
    let base_arity = Tree::Arity::to_usize();
    let sub_arity = Tree::SubTreeArity::to_usize();
    let top_arity = Tree::TopTreeArity::to_usize();

    // Validate `Tree`'s shape. This gadget requires that all non-zero arities are a power of two.
    assert!(base_arity.is_power_of_two());
    assert!(sub_arity.is_power_of_two() || sub_arity == 0);
    assert!(top_arity.is_power_of_two() || top_arity == 0);
    if top_arity > 0 {
        assert!(sub_arity > 0);
    }

    // All non-zero `Tree` arities are guaranteed to be a power of two, thus the number of low zeros
    // gives the number of bits required to represent an integer in `0..arity` (a Merkle proof
    // insertion index). `challenge_bits` is the concatentation of the Merkle proof's insertion
    // indexes which is equal to the challenge's (an integer in `0..leafs`) binary representation.
    let base_arity_bit_len = base_arity.trailing_zeros();
    let sub_arity_bit_len = sub_arity.trailing_zeros();
    let top_arity_bit_len = top_arity.trailing_zeros();

    let base_path_len = if top_arity > 0 {
        path_values.len() - 2
    } else if sub_arity > 0 {
        path_values.len() - 1
    } else {
        path_values.len()
    };

    let mut cur = leaf;
    let mut height = 0;
    let mut path_values = path_values.into_iter();
    let mut challenge_bits = challenge_bits.into_iter().map(Boolean::from);

    // Hash base-tree Merkle proof elements.
    for _ in 0..base_path_len {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            base_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..base_arity_bit_len)
            .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::Arity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
        height += 1;
    }

    // If one exists, hash the sub-tree Merkle proof element.
    if sub_arity > 0 {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            sub_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..sub_arity_bit_len)
            .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::SubTreeArity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
        height += 1;
    }

    // If one exists, hash the top-tree Merkle proof element.
    if top_arity > 0 {
        let siblings = path_values.next().expect("no path elements remaining");
        assert_eq!(
            siblings.len(),
            top_arity - 1,
            "path element has incorrect number of siblings"
        );
        let insert_index: Vec<Boolean> = (0..top_arity_bit_len)
            .map(|_| challenge_bits.next().expect("no challenge bits remaining"))
            .collect();
        let preimg = insert(
            &mut cs.namespace(|| format!("merkle proof insert (height={})", height)),
            &cur,
            &insert_index,
            &siblings,
        )?;
        cur = <<Tree::Hasher as Hasher>::Function as HashFunction<
            <Tree::Hasher as Hasher>::Domain,
        >>::hash_multi_leaf_circuit::<Tree::TopTreeArity, _>(
            cs.namespace(|| format!("merkle proof hash (height={})", height)),
            &preimg,
            height,
        )?;
    }

    // Check that no additional challenge bits were provided.
    assert!(
        challenge_bits.next().is_none(),
        "challenge bit-length and tree arity do not agree"
    );

    // Assert equality between the computed root and the provided root.
    let computed_root = cur;

    cs.enforce(
        || "calculated root == provided root",
        |lc| lc + computed_root.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + root.get_variable(),
    );

    Ok(())
}
