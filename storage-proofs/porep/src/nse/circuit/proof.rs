use std::marker::PhantomData;

use bellperson::{
    bls::{Bls12, Fr},
    gadgets::num,
    ConstraintSystem, SynthesisError,
};
use generic_array::typenum::{U0, U2};
use storage_proofs_core::{
    gadgets::por::AuthPath,
    hasher::Hasher,
    merkle::{MerkleProofTrait, MerkleTreeTrait},
};

use super::super::vanilla::{
    Config, LayerProof as VanillaLayerProof, NodeProof as VanillaNodeProof,
};

pub struct LayerProof<Tree: MerkleTreeTrait, G: Hasher> {
    pub first_layer_proof: NodeProof<Tree, G>,
    pub expander_layer_proofs: Vec<NodeProof<Tree, G>>,
    pub butterfly_layer_proofs: Vec<NodeProof<Tree, G>>,
    pub last_layer_proof: NodeProof<Tree, G>,
}

type TreeAuthPath<T> = AuthPath<
    <T as MerkleTreeTrait>::Hasher,
    <T as MerkleTreeTrait>::Arity,
    <T as MerkleTreeTrait>::SubTreeArity,
    <T as MerkleTreeTrait>::TopTreeArity,
>;

pub struct NodeProof<Tree: MerkleTreeTrait, G: Hasher> {
    /// Inclusion path for the challenged data node in tree D.
    pub data_path: AuthPath<G, U2, U0, U0>,
    /// The value of the challenged data node.
    pub data_leaf: Option<Fr>,
    /// The index of the challenged node.
    pub challenge: Option<u64>,
    /// Inclusion path of the challenged node in challenged layer.
    pub layer_path: TreeAuthPath<Tree>,
    /// Proofs for the parents, first the path and then the leaf node.
    pub parents: Vec<(TreeAuthPath<Tree>, Option<<Tree::Hasher as Hasher>::Domain>)>,
    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> LayerProof<Tree, G> {
    pub fn blank(config: &Config) -> Self {
        LayerProof {
            first_layer_proof: NodeProof::blank(config, 0),
            expander_layer_proofs: (0..config.num_expander_layers - 1)
                .map(|_| NodeProof::blank(config, config.degree_expander_expanded()))
                .collect(),
            butterfly_layer_proofs: (0..config.num_butterfly_layers - 1)
                .map(|_| NodeProof::blank(config, config.degree_butterfly))
                .collect(),
            last_layer_proof: NodeProof::blank(config, config.degree_butterfly),
        }
    }
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

impl<Tree: MerkleTreeTrait, G: Hasher> NodeProof<Tree, G> {
    pub fn blank(config: &Config, num_parents: usize) -> Self {
        NodeProof {
            data_path: AuthPath::blank(config.num_nodes_sector()),
            data_leaf: None,
            challenge: None,
            layer_path: TreeAuthPath::<Tree>::blank(config.num_nodes_sector()),
            parents: (0..num_parents)
                .map(|_| (TreeAuthPath::<Tree>::blank(config.num_nodes_sector()), None))
                .collect(),
            _t: PhantomData,
        }
    }

    ///  Allocate the `data_leaf` of this proof.
    pub fn alloc_data_leaf<CS: ConstraintSystem<Bls12>>(
        &self,
        cs: CS,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        num::AllocatedNum::alloc(cs, || {
            self.data_leaf
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })
    }

    /// Allocate the leafs of the parents of this proof.
    pub fn alloc_parents_leafs<CS: ConstraintSystem<Bls12>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<num::AllocatedNum<Bls12>>, SynthesisError> {
        self.parents
            .iter()
            .enumerate()
            .map(|(j, (_, leaf))| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("leaf_{}", j)), || {
                    leaf.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })
            })
            .collect()
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> From<VanillaNodeProof<Tree, G>> for NodeProof<Tree, G> {
    fn from(vanilla_proof: VanillaNodeProof<Tree, G>) -> Self {
        let VanillaNodeProof {
            data_proof,
            layer_proof,
            parents_proofs,
            ..
        } = vanilla_proof;

        let data_leaf = Some(data_proof.leaf().into());

        NodeProof {
            data_path: data_proof.as_options().into(),
            data_leaf,
            challenge: Some(layer_proof.path_index() as u64),
            layer_path: layer_proof.as_options().into(),
            parents: parents_proofs
                .into_iter()
                .map(|p| (p.as_options().into(), Some(p.leaf())))
                .collect(),
            _t: PhantomData,
        }
    }
}
