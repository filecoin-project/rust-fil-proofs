use std::marker::PhantomData;

use generic_array::typenum::{U0, U2};
use paired::bls12_381::Fr;
use storage_proofs_core::{
    gadgets::por::{AuthPath, PoRCircuit},
    hasher::Hasher,
    merkle::{DiskStore, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
};

use super::super::vanilla::{LayerProof as VanillaLayerProof, Proof as VanillaProof};

pub struct LayerProof<Tree: MerkleTreeTrait, G: Hasher> {
    pub first_layer_proof: Proof<Tree, G>,
    pub expander_layer_proofs: Vec<Proof<Tree, G>>,
    pub butterfly_layer_proofs: Vec<Proof<Tree, G>>,
    pub last_layer_proof: Proof<Tree, G>,
}

type TreeAuthPath<T> = AuthPath<
    <T as MerkleTreeTrait>::Hasher,
    <T as MerkleTreeTrait>::Arity,
    <T as MerkleTreeTrait>::SubTreeArity,
    <T as MerkleTreeTrait>::TopTreeArity,
>;

pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    /// Inclusion path for the challenged data node in tree D.
    pub data_path: AuthPath<G, U2, U0, U0>,
    /// The value of the challenged data node.
    pub data_leaf: Option<Fr>,
    /// The index of the challenged node.
    pub challenge: Option<u64>,
    /// Inclusion path of the challenged node in challenged layer.
    pub layer_path: TreeAuthPath<Tree>,
    /// Proofs for the parents.
    pub parents_paths: Vec<TreeAuthPath<Tree>>,
    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> From<VanillaLayerProof<Tree, G>> for LayerProof<Tree, G> {
    fn from(vanilla_proof: VanillaLayerProof<Tree, G>) -> Self {
        let VanillaLayerProof {
            first_layer_proof,
            butterfly_layer_proofs,
            expander_layer_proofs,
            last_layer_proof,
        } = vanilla_proof;

        LayerProof {
            first_layer_proof: first_layer_proof.into(),
            butterfly_layer_proofs: butterfly_layer_proofs.into_iter().map(Into::into).collect(),
            expander_layer_proofs: expander_layer_proofs.into_iter().map(Into::into).collect(),
            last_layer_proof: last_layer_proof.into(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> From<VanillaProof<Tree, G>> for Proof<Tree, G> {
    fn from(vanilla_proof: VanillaProof<Tree, G>) -> Self {
        let VanillaProof {
            data_proof,
            layer_proof,
            parents_proofs,
            ..
        } = vanilla_proof;

        let data_leaf = Some(data_proof.leaf().into());

        Proof {
            data_path: data_proof.as_options().into(),
            data_leaf,
            challenge: Some(layer_proof.path_index() as u64),
            layer_path: layer_proof.as_options().into(),
            parents_paths: parents_proofs
                .into_iter()
                .map(|p| p.as_options().into())
                .collect(),
            _t: PhantomData,
        }
    }
}
