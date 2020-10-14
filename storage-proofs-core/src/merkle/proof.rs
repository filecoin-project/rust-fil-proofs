#![allow(clippy::len_without_is_empty)]

use std::marker::PhantomData;

use anyhow::{ensure, Result};
use generic_array::typenum::{Unsigned, U0};
use merkletree::hash::Algorithm;
use merkletree::proof;
use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};

use crate::drgraph::graph_height;
use crate::hasher::{Hasher, PoseidonArity};

/// Trait to abstract over the concept of Merkle Proof.
pub trait MerkleProofTrait:
    Clone + Serialize + serde::de::DeserializeOwned + std::fmt::Debug + Sync + Send
{
    type Hasher: Hasher;
    type Arity: 'static + PoseidonArity;
    type SubTreeArity: 'static + PoseidonArity;
    type TopTreeArity: 'static + PoseidonArity;

    /// Try to convert a merkletree proof into this structure.
    fn try_from_proof(
        p: proof::Proof<<Self::Hasher as Hasher>::Domain, Self::Arity>,
    ) -> Result<Self>;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
        self.path()
            .iter()
            .map(|v| {
                (
                    v.0.iter().copied().map(Into::into).map(Some).collect(),
                    Some(v.1),
                )
            })
            .collect::<Vec<_>>()
    }

    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
        let leaf = self.leaf();
        let path = self.path();
        (
            Some(leaf.into()),
            path.into_iter()
                .map(|(a, b)| {
                    (
                        a.iter().copied().map(Into::into).map(Some).collect(),
                        Some(b),
                    )
                })
                .collect::<Vec<_>>(),
        )
    }
    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        self.path()
            .iter()
            .map(|v| (v.0.iter().copied().map(Into::into).collect(), v.1))
            .collect::<Vec<_>>()
    }
    fn verify(&self) -> bool;

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    ///
    /// TODO: audit performance and usage in case verification is
    /// unnecessary based on how it's used.
    fn validate(&self, node: usize) -> bool {
        if !self.verify() {
            return false;
        }

        node == self.path_index()
    }

    fn validate_data(&self, data: <Self::Hasher as Hasher>::Domain) -> bool {
        if !self.verify() {
            return false;
        }

        self.leaf() == data
    }

    fn leaf(&self) -> <Self::Hasher as Hasher>::Domain;
    fn root(&self) -> <Self::Hasher as Hasher>::Domain;
    fn len(&self) -> usize;
    fn path(&self) -> Vec<(Vec<<Self::Hasher as Hasher>::Domain>, usize)>;

    fn path_index(&self) -> usize {
        self.path()
            .iter()
            .rev()
            .fold(0, |acc, (_, index)| (acc * Self::Arity::to_usize()) + index)
    }

    fn proves_challenge(&self, challenge: usize) -> bool {
        self.path_index() == challenge
    }

    /// Calcluates the exected length of the full path, given the number of leaves in the base layer.
    fn expected_len(&self, leaves: usize) -> usize {
        compound_path_length::<Self::Arity, Self::SubTreeArity, Self::TopTreeArity>(leaves)
    }

    /// Test only method to break a valid proof.
    #[cfg(test)]
    fn break_me(&mut self, leaf: <Self::Hasher as Hasher>::Domain);
}

pub fn base_path_length<A: Unsigned, B: Unsigned, C: Unsigned>(leaves: usize) -> usize {
    let leaves = if C::to_usize() > 0 {
        leaves / C::to_usize() / B::to_usize()
    } else if B::to_usize() > 0 {
        leaves / B::to_usize()
    } else {
        leaves
    };

    graph_height::<A>(leaves) - 1
}

pub fn compound_path_length<A: Unsigned, B: Unsigned, C: Unsigned>(leaves: usize) -> usize {
    let mut len = base_path_length::<A, B, C>(leaves);
    if B::to_usize() > 0 {
        len += 1;
    }

    if C::to_usize() > 0 {
        len += 1;
    }

    len
}
pub fn compound_tree_height<A: Unsigned, B: Unsigned, C: Unsigned>(leaves: usize) -> usize {
    // base layer
    let a = graph_height::<A>(leaves) - 1;

    // sub tree layer
    let b = if B::to_usize() > 0 {
        B::to_usize() - 1
    } else {
        0
    };

    // top tree layer
    let c = if C::to_usize() > 0 {
        C::to_usize() - 1
    } else {
        0
    };

    a + b + c
}

macro_rules! forward_method {
    ($caller:expr, $name:ident) => {
        match $caller {
            ProofData::Single(ref proof) => proof.$name(),
            ProofData::Sub(ref proof) => proof.$name(),
            ProofData::Top(ref proof) => proof.$name(),
        }
    };
    ($caller:expr, $name:ident, $( $args:expr ),+) => {
        match $caller {
            ProofData::Single(ref proof) => proof.$name($($args),+),
            ProofData::Sub(ref proof) => proof.$name($($args),+),
            ProofData::Top(ref proof) => proof.$name($($args),+),
        }
    };
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InclusionPath<H: Hasher, Arity: PoseidonArity> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    path: Vec<PathElement<H, Arity>>,
}

impl<H: Hasher, Arity: PoseidonArity> From<Vec<PathElement<H, Arity>>> for InclusionPath<H, Arity> {
    fn from(path: Vec<PathElement<H, Arity>>) -> Self {
        Self { path }
    }
}

impl<H: Hasher, Arity: PoseidonArity> InclusionPath<H, Arity> {
    /// Calculate the root of this path, given the leaf as input.
    pub fn root(&self, leaf: H::Domain) -> H::Domain {
        let mut a = H::Function::default();
        (0..self.path.len()).fold(leaf, |h, height| {
            a.reset();

            let index = self.path[height].index;
            let mut nodes = self.path[height].hashes.clone();
            nodes.insert(index, h);

            a.multi_node(&nodes, height)
        })
    }

    pub fn len(&self) -> usize {
        self.path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<PathElement<H, Arity>> {
        self.path.iter()
    }

    pub fn path_index(&self) -> usize {
        self.path
            .iter()
            .rev()
            .fold(0, |acc, p| (acc * Arity::to_usize()) + p.index)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PathElement<H: Hasher, Arity: PoseidonArity> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    hashes: Vec<H::Domain>,
    index: usize,
    #[serde(skip)]
    _arity: PhantomData<Arity>,
}

/// Representation of a merkle proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof<
    H: Hasher,
    BaseArity: PoseidonArity,
    SubTreeArity: PoseidonArity = U0,
    TopTreeArity: PoseidonArity = U0,
> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    data: ProofData<H, BaseArity, SubTreeArity, TopTreeArity>,
}

impl<
        H: Hasher,
        Arity: 'static + PoseidonArity,
        SubTreeArity: 'static + PoseidonArity,
        TopTreeArity: 'static + PoseidonArity,
    > MerkleProofTrait for MerkleProof<H, Arity, SubTreeArity, TopTreeArity>
{
    type Hasher = H;
    type Arity = Arity;
    type SubTreeArity = SubTreeArity;
    type TopTreeArity = TopTreeArity;

    fn try_from_proof(
        p: proof::Proof<<Self::Hasher as Hasher>::Domain, Self::Arity>,
    ) -> Result<Self> {
        if p.top_layer_nodes() > 0 {
            Ok(MerkleProof {
                data: ProofData::Top(TopProof::try_from_proof(p)?),
            })
        } else if p.sub_layer_nodes() > 0 {
            Ok(MerkleProof {
                data: ProofData::Sub(SubProof::try_from_proof(p)?),
            })
        } else {
            Ok(MerkleProof {
                data: ProofData::Single(SingleProof::try_from_proof(p)?),
            })
        }
    }

    fn verify(&self) -> bool {
        forward_method!(self.data, verify)
    }

    fn leaf(&self) -> H::Domain {
        forward_method!(self.data, leaf)
    }

    fn root(&self) -> H::Domain {
        forward_method!(self.data, root)
    }

    fn len(&self) -> usize {
        forward_method!(self.data, len)
    }

    fn path(&self) -> Vec<(Vec<H::Domain>, usize)> {
        forward_method!(self.data, path)
    }
    fn path_index(&self) -> usize {
        forward_method!(self.data, path_index)
    }

    /// Test only method to break a valid proof.
    #[cfg(test)]
    fn break_me(&mut self, leaf: H::Domain) {
        match self.data {
            ProofData::Single(ref mut proof) => {
                proof.leaf = leaf;
            }
            ProofData::Sub(ref mut proof) => {
                proof.leaf = leaf;
            }
            ProofData::Top(ref mut proof) => {
                proof.leaf = leaf;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProofData<
    H: Hasher,
    BaseArity: PoseidonArity,
    SubTreeArity: PoseidonArity,
    TopTreeArity: PoseidonArity,
> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    Single(SingleProof<H, BaseArity>),
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    Sub(SubProof<H, BaseArity, SubTreeArity>),
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    Top(TopProof<H, BaseArity, SubTreeArity, TopTreeArity>),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SingleProof<H: Hasher, Arity: PoseidonArity> {
    /// Root of the merkle tree.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    root: H::Domain,
    /// The original leaf data for this prof.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    leaf: H::Domain,
    /// The path from leaf to root.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    path: InclusionPath<H, Arity>,
}

impl<H: Hasher, Arity: PoseidonArity> SingleProof<H, Arity> {
    pub fn new(path: InclusionPath<H, Arity>, root: H::Domain, leaf: H::Domain) -> Self {
        SingleProof { root, leaf, path }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SubProof<H: Hasher, BaseArity: PoseidonArity, SubTreeArity: PoseidonArity> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    base_proof: InclusionPath<H, BaseArity>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    sub_proof: InclusionPath<H, SubTreeArity>,
    /// Root of the merkle tree.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    root: H::Domain,
    /// The original leaf data for this prof.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    leaf: H::Domain,
}

impl<H: Hasher, BaseArity: PoseidonArity, SubTreeArity: PoseidonArity>
    SubProof<H, BaseArity, SubTreeArity>
{
    pub fn new(
        base_proof: InclusionPath<H, BaseArity>,
        sub_proof: InclusionPath<H, SubTreeArity>,
        root: H::Domain,
        leaf: H::Domain,
    ) -> Self {
        Self {
            base_proof,
            sub_proof,
            root,
            leaf,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct TopProof<
    H: Hasher,
    BaseArity: PoseidonArity,
    SubTreeArity: PoseidonArity,
    TopTreeArity: PoseidonArity,
> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    base_proof: InclusionPath<H, BaseArity>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    sub_proof: InclusionPath<H, SubTreeArity>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    top_proof: InclusionPath<H, TopTreeArity>,
    /// Root of the merkle tree.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    root: H::Domain,
    /// The original leaf data for this prof.
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    leaf: H::Domain,
}

impl<
        H: Hasher,
        BaseArity: PoseidonArity,
        SubTreeArity: PoseidonArity,
        TopTreeArity: PoseidonArity,
    > TopProof<H, BaseArity, SubTreeArity, TopTreeArity>
{
    pub fn new(
        base_proof: InclusionPath<H, BaseArity>,
        sub_proof: InclusionPath<H, SubTreeArity>,
        top_proof: InclusionPath<H, TopTreeArity>,
        root: H::Domain,
        leaf: H::Domain,
    ) -> Self {
        Self {
            base_proof,
            sub_proof,
            top_proof,
            root,
            leaf,
        }
    }
}

impl<
        H: Hasher,
        BaseArity: PoseidonArity,
        SubTreeArity: PoseidonArity,
        TopTreeArity: PoseidonArity,
    > MerkleProof<H, BaseArity, SubTreeArity, TopTreeArity>
{
    pub fn new(n: usize) -> Self {
        let root = Default::default();
        let leaf = Default::default();
        let path_elem = PathElement {
            hashes: vec![Default::default(); BaseArity::to_usize()],
            index: 0,
            _arity: Default::default(),
        };
        let path = vec![path_elem; n];
        MerkleProof {
            data: ProofData::Single(SingleProof::new(path.into(), root, leaf)),
        }
    }
}

/// Converts a merkle_light proof to a SingleProof
fn proof_to_single<H: Hasher, Arity: PoseidonArity, TargetArity: PoseidonArity>(
    proof: &proof::Proof<H::Domain, Arity>,
    lemma_start_index: usize,
    sub_root: Option<H::Domain>,
) -> SingleProof<H, TargetArity> {
    let root = proof.root();
    let leaf = if let Some(sub_root) = sub_root {
        sub_root
    } else {
        proof.item()
    };
    let path = extract_path::<H, TargetArity>(proof.lemma(), proof.path(), lemma_start_index);

    SingleProof::new(path, root, leaf)
}

/// 'lemma_start_index' is required because sub/top proofs start at
/// index 0 and base proofs start at index 1 (skipping the leaf at the
/// front)
fn extract_path<H: Hasher, Arity: PoseidonArity>(
    lemma: &[H::Domain],
    path: &[usize],
    lemma_start_index: usize,
) -> InclusionPath<H, Arity> {
    let path = lemma[lemma_start_index..lemma.len() - 1]
        .chunks(Arity::to_usize() - 1)
        .zip(path.iter())
        .map(|(hashes, index)| PathElement {
            hashes: hashes.to_vec(),
            index: *index,
            _arity: Default::default(),
        })
        .collect::<Vec<_>>();

    path.into()
}

impl<H: Hasher, Arity: 'static + PoseidonArity> SingleProof<H, Arity> {
    fn try_from_proof(p: proof::Proof<<H as Hasher>::Domain, Arity>) -> Result<Self> {
        Ok(proof_to_single(&p, 1, None))
    }

    fn verify(&self) -> bool {
        let calculated_root = self.path.root(self.leaf);
        self.root == calculated_root
    }

    fn leaf(&self) -> H::Domain {
        self.leaf
    }

    fn root(&self) -> H::Domain {
        self.root
    }

    fn len(&self) -> usize {
        self.path.len() * (Arity::to_usize() - 1) + 2
    }

    fn path(&self) -> Vec<(Vec<H::Domain>, usize)> {
        self.path
            .iter()
            .map(|x| (x.hashes.clone(), x.index))
            .collect::<Vec<_>>()
    }

    fn path_index(&self) -> usize {
        self.path.path_index()
    }
}

impl<H: Hasher, Arity: 'static + PoseidonArity, SubTreeArity: 'static + PoseidonArity>
    SubProof<H, Arity, SubTreeArity>
{
    fn try_from_proof(p: proof::Proof<<H as Hasher>::Domain, Arity>) -> Result<Self> {
        ensure!(
            p.sub_layer_nodes() == SubTreeArity::to_usize(),
            "sub arity mismatch"
        );
        ensure!(
            p.sub_tree_proof.is_some(),
            "Cannot generate sub proof without a base-proof"
        );
        let base_p = p.sub_tree_proof.as_ref().expect("proof as_ref failure");

        // Generate SubProof
        let root = p.root();
        let leaf = base_p.item();
        let base_proof = extract_path::<H, Arity>(base_p.lemma(), base_p.path(), 1);
        let sub_proof = extract_path::<H, SubTreeArity>(p.lemma(), p.path(), 0);

        Ok(SubProof::new(base_proof, sub_proof, root, leaf))
    }

    fn verify(&self) -> bool {
        let sub_leaf = self.base_proof.root(self.leaf);
        let calculated_root = self.sub_proof.root(sub_leaf);

        self.root == calculated_root
    }

    fn leaf(&self) -> H::Domain {
        self.leaf
    }

    fn root(&self) -> H::Domain {
        self.root
    }

    fn len(&self) -> usize {
        SubTreeArity::to_usize()
    }

    fn path(&self) -> Vec<(Vec<H::Domain>, usize)> {
        self.base_proof
            .iter()
            .map(|x| (x.hashes.clone(), x.index))
            .chain(self.sub_proof.iter().map(|x| (x.hashes.clone(), x.index)))
            .collect()
    }

    fn path_index(&self) -> usize {
        let mut base_proof_leaves = 1;
        for _i in 0..self.base_proof.len() {
            base_proof_leaves *= Arity::to_usize()
        }

        let sub_proof_index = self.sub_proof.path_index();

        (sub_proof_index * base_proof_leaves) + self.base_proof.path_index()
    }
}

impl<
        H: Hasher,
        Arity: 'static + PoseidonArity,
        SubTreeArity: 'static + PoseidonArity,
        TopTreeArity: 'static + PoseidonArity,
    > TopProof<H, Arity, SubTreeArity, TopTreeArity>
{
    fn try_from_proof(p: proof::Proof<<H as Hasher>::Domain, Arity>) -> Result<Self> {
        ensure!(
            p.top_layer_nodes() == TopTreeArity::to_usize(),
            "top arity mismatch"
        );
        ensure!(
            p.sub_layer_nodes() == SubTreeArity::to_usize(),
            "sub arity mismatch"
        );

        ensure!(
            p.sub_tree_proof.is_some(),
            "Cannot generate top proof without a sub-proof"
        );
        let sub_p = p.sub_tree_proof.as_ref().expect("proofs as ref failure");

        ensure!(
            sub_p.sub_tree_proof.is_some(),
            "Cannot generate top proof without a base-proof"
        );
        let base_p = sub_p
            .sub_tree_proof
            .as_ref()
            .expect("proofs as ref failure");

        let root = p.root();
        let leaf = base_p.item();

        let base_proof = extract_path::<H, Arity>(base_p.lemma(), base_p.path(), 1);
        let sub_proof = extract_path::<H, SubTreeArity>(sub_p.lemma(), sub_p.path(), 0);
        let top_proof = extract_path::<H, TopTreeArity>(p.lemma(), p.path(), 0);

        Ok(TopProof::new(base_proof, sub_proof, top_proof, root, leaf))
    }

    fn verify(&self) -> bool {
        let sub_leaf = self.base_proof.root(self.leaf);
        let top_leaf = self.sub_proof.root(sub_leaf);
        let calculated_root = self.top_proof.root(top_leaf);

        self.root == calculated_root
    }

    fn leaf(&self) -> H::Domain {
        self.leaf
    }

    fn root(&self) -> H::Domain {
        self.root
    }

    fn len(&self) -> usize {
        TopTreeArity::to_usize()
    }

    fn path(&self) -> Vec<(Vec<H::Domain>, usize)> {
        self.base_proof
            .iter()
            .map(|x| (x.hashes.clone(), x.index))
            .chain(self.sub_proof.iter().map(|x| (x.hashes.clone(), x.index)))
            .chain(self.top_proof.iter().map(|x| (x.hashes.clone(), x.index)))
            .collect()
    }

    fn path_index(&self) -> usize {
        let mut base_proof_leaves = 1;
        for _i in 0..self.base_proof.len() {
            base_proof_leaves *= Arity::to_usize()
        }

        let sub_proof_leaves = base_proof_leaves * SubTreeArity::to_usize();

        let sub_proof_index = self.sub_proof.path_index();
        let top_proof_index = self.top_proof.path_index();

        (sub_proof_index * base_proof_leaves)
            + (top_proof_index * sub_proof_leaves)
            + self.base_proof.path_index()
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    use generic_array::typenum;

    use crate::hasher::{Blake2sHasher, Domain, PedersenHasher, PoseidonHasher, Sha256Hasher};
    use crate::merkle::{generate_tree, MerkleProofTrait};

    fn merklepath<Tree: 'static + MerkleTreeTrait>() {
        let node_size = 32;
        let nodes = 64 * get_base_tree_count::<Tree>();

        let mut rng = rand::thread_rng();
        let (data, tree) = generate_tree::<Tree, _>(&mut rng, nodes, None);

        for i in 0..nodes {
            let proof = tree.gen_proof(i).expect("gen_proof failure");

            assert!(proof.verify(), "failed to validate");

            assert!(proof.validate(i), "failed to validate valid merkle path");
            let data_slice = &data[i * node_size..(i + 1) * node_size].to_vec();
            assert!(
                proof.validate_data(
                    <Tree::Hasher as Hasher>::Domain::try_from_bytes(data_slice)
                        .expect("try from bytes failure")
                ),
                "failed to validate valid data"
            );
        }
    }

    #[test]
    fn merklepath_pedersen_2() {
        merklepath::<
            MerkleTreeWrapper<
                PedersenHasher,
                DiskStore<<PedersenHasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_pedersen_4() {
        merklepath::<
            MerkleTreeWrapper<
                PedersenHasher,
                DiskStore<<PedersenHasher as Hasher>::Domain>,
                typenum::U4,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_pedersen_8() {
        merklepath::<
            MerkleTreeWrapper<
                PedersenHasher,
                DiskStore<<PedersenHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_pedersen_2_2() {
        merklepath::<
            MerkleTreeWrapper<
                PedersenHasher,
                DiskStore<<PedersenHasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U2,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_pedersen_2_2_2() {
        merklepath::<
            MerkleTreeWrapper<
                PedersenHasher,
                DiskStore<<PedersenHasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U2,
                typenum::U2,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_2() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_4() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U4,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_8() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_8_2() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U2,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_8_4() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U4,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_poseidon_8_4_2() {
        merklepath::<
            MerkleTreeWrapper<
                PoseidonHasher,
                DiskStore<<PoseidonHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U4,
                typenum::U2,
            >,
        >();
    }

    #[test]
    fn merklepath_sha256_2() {
        merklepath::<
            MerkleTreeWrapper<
                Sha256Hasher,
                DiskStore<<Sha256Hasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_sha256_4() {
        merklepath::<
            MerkleTreeWrapper<
                Sha256Hasher,
                DiskStore<<Sha256Hasher as Hasher>::Domain>,
                typenum::U4,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_sha256_2_4() {
        merklepath::<
            MerkleTreeWrapper<
                Sha256Hasher,
                DiskStore<<Sha256Hasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U4,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_sha256_top_2_4_2() {
        merklepath::<
            MerkleTreeWrapper<
                Sha256Hasher,
                DiskStore<<Sha256Hasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U4,
                typenum::U2,
            >,
        >();
    }

    #[test]
    fn merklepath_blake2s_2() {
        merklepath::<
            MerkleTreeWrapper<
                Blake2sHasher,
                DiskStore<<Blake2sHasher as Hasher>::Domain>,
                typenum::U2,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_blake2s_4() {
        merklepath::<
            MerkleTreeWrapper<
                Blake2sHasher,
                DiskStore<<Blake2sHasher as Hasher>::Domain>,
                typenum::U4,
                typenum::U0,
                typenum::U0,
            >,
        >();
    }

    #[test]
    fn merklepath_blake2s_8_4_2() {
        merklepath::<
            MerkleTreeWrapper<
                Blake2sHasher,
                DiskStore<<Blake2sHasher as Hasher>::Domain>,
                typenum::U8,
                typenum::U4,
                typenum::U2,
            >,
        >();
    }
}
