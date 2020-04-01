use std::marker::PhantomData;

use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};

use super::{
    column_proof::ColumnProof, encoding_proof::EncodingProof, labeling_proof::LabelingProof,
};
use crate::drgraph::Graph;
use crate::gadgets::por::{AuthPath, PoRCircuit};
use crate::gadgets::variables::Root;
use crate::hasher::{Hasher, PoseidonArity};
use crate::merkle::{DiskStore, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper, Store};
use crate::porep::stacked::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

#[derive(Debug, Clone)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    pub comm_d_proof: InclusionPath<G, typenum::U2, typenum::U0, typenum::U0>,
    pub comm_r_last_proof:
        InclusionPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    pub replica_column_proof:
        ReplicaColumnProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    pub labeling_proofs: Vec<(usize, LabelingProof)>,
    pub encoding_proof: EncodingProof,
    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> Proof<Tree, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<Tree>) -> Self {
        let layers = params.layer_challenges.layers();

        let mut labeling_proofs = Vec::with_capacity(layers);
        for layer in 1..=layers {
            labeling_proofs.push((layer, LabelingProof::empty(params, layer)));
        }

        Proof {
            comm_d_proof: InclusionPath::empty(&params.graph),
            comm_r_last_proof: InclusionPath::empty(&params.graph),
            replica_column_proof: ReplicaColumnProof::empty(params),
            labeling_proofs,
            encoding_proof: EncodingProof::empty(params),
            _t: PhantomData,
        }
    }

    /// Circuit synthesis.
    #[allow(clippy::too_many_arguments)]
    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        layers: usize,
        comm_d: &num::AllocatedNum<Bls12>,
        comm_c: &num::AllocatedNum<Bls12>,
        comm_r_last: &num::AllocatedNum<Bls12>,
        replica_id: &[Boolean],
    ) -> Result<(), SynthesisError> {
        let Proof {
            comm_d_proof,
            comm_r_last_proof,
            replica_column_proof,
            labeling_proofs,
            encoding_proof,
            ..
        } = self;

        // verify initial data layer
        let comm_d_leaf = comm_d_proof.alloc_value(cs.namespace(|| "comm_d_leaf"))?;
        comm_d_proof.synthesize(
            cs.namespace(|| "comm_d_inclusion"),
            comm_d.clone(),
            comm_d_leaf.clone(),
        )?;

        let comm_r_last_data_leaf =
            comm_r_last_proof.alloc_value(cs.namespace(|| "comm_r_last_data_leaf"))?;

        // verify encodings
        for (layer, proof) in labeling_proofs.into_iter() {
            let raw = replica_column_proof.c_x.get_node_at_layer(layer);
            let labeled_node =
                num::AllocatedNum::alloc(cs.namespace(|| format!("label_node_{}", layer)), || {
                    raw.map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

            proof.synthesize(
                cs.namespace(|| format!("labeling_proof_{}", layer)),
                replica_id,
                &labeled_node,
            )?;
        }

        encoding_proof.synthesize(
            cs.namespace(|| format!("encoding_proof_{}", layers)),
            replica_id,
            &comm_r_last_data_leaf,
            &comm_d_leaf,
        )?;

        // verify replica column openings
        replica_column_proof.synthesize(cs.namespace(|| "replica_column_proof"), comm_c)?;

        // verify final replica layer
        comm_r_last_proof.synthesize(
            cs.namespace(|| "comm_r_last_data_inclusion"),
            comm_r_last.clone(),
            comm_r_last_data_leaf,
        )?;

        Ok(())
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> From<VanillaProof<Tree, G>> for Proof<Tree, G>
where
    Tree::Hasher: 'static,
{
    fn from(vanilla_proof: VanillaProof<Tree, G>) -> Self {
        let VanillaProof {
            comm_d_proofs,
            comm_r_last_proof,
            replica_column_proofs,
            labeling_proofs,
            encoding_proof,
        } = vanilla_proof;

        let mut labeling_proofs: Vec<_> = labeling_proofs
            .into_iter()
            .map(|(layer, p)| (layer, p.into()))
            .collect();

        labeling_proofs.sort_by_cached_key(|(k, _)| *k);

        Proof {
            comm_d_proof: comm_d_proofs.into(),
            comm_r_last_proof: comm_r_last_proof.into(),
            replica_column_proof: replica_column_proofs.into(),
            labeling_proofs,
            encoding_proof: encoding_proof.into(),
            _t: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InclusionPath<H: Hasher, U, V, W>
where
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    value: Option<Fr>,
    auth_path: AuthPath<H, U, V, W>,
}

impl<H: Hasher, U, V, W> InclusionPath<H, U, V, W>
where
    H: 'static,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<G: Hasher>(graph: &impl Graph<G>) -> Self {
        InclusionPath {
            value: None,
            auth_path: AuthPath::blank(graph.size()),
        }
    }

    pub fn alloc_value<CS: ConstraintSystem<Bls12>>(
        &self,
        cs: CS,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        num::AllocatedNum::alloc(cs, || {
            self.value
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        cs: CS,
        root: num::AllocatedNum<Bls12>,
        leaf: num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let InclusionPath { auth_path, .. } = self;

        let root = Root::from_allocated::<CS>(root);
        let value = Root::from_allocated::<CS>(leaf);
        PoRCircuit::<MerkleTreeWrapper<H, DiskStore<H::Domain>, U, V, W>>::synthesize(
            cs, value, auth_path, root, true,
        )
    }
}

impl<
        H: Hasher,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
        X: MerkleProofTrait<Hasher = H, Arity = U, SubTreeArity = V, TopTreeArity = W>,
    > From<X> for InclusionPath<H, U, V, W>
{
    fn from(other: X) -> Self {
        let (value, auth_path) = other.into_options_with_leaf();

        InclusionPath {
            value,
            auth_path: auth_path.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplicaColumnProof<
    H: Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
> {
    c_x: ColumnProof<H, U, V, W>,
    drg_parents: Vec<ColumnProof<H, U, V, W>>,
    exp_parents: Vec<ColumnProof<H, U, V, W>>,
}

impl<
        H: 'static + Hasher,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
    > ReplicaColumnProof<H, U, V, W>
{
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<S, Tree>(params: &PublicParams<Tree>) -> Self
    where
        S: Store<H::Domain>,
        Tree: MerkleTreeTrait<Hasher = H, Store = S, Arity = U, SubTreeArity = V, TopTreeArity = W>,
    {
        ReplicaColumnProof {
            c_x: ColumnProof::empty(params),
            drg_parents: vec![ColumnProof::empty(params); params.graph.base_graph().degree()],
            exp_parents: vec![ColumnProof::empty(params); params.graph.expansion_degree()],
        }
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let ReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        } = self;

        // c_x
        c_x.synthesize(cs.namespace(|| "c_x"), comm_c)?;

        // drg parents
        for (i, parent) in drg_parents.into_iter().enumerate() {
            parent.synthesize(cs.namespace(|| format!("drg_parent_{}", i)), comm_c)?;
        }

        // exp parents
        for (i, parent) in exp_parents.into_iter().enumerate() {
            parent.synthesize(cs.namespace(|| format!("exp_parent_{}", i)), comm_c)?;
        }

        Ok(())
    }
}

impl<
        H: 'static + Hasher,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
        X: MerkleProofTrait<Hasher = H, Arity = U, SubTreeArity = V, TopTreeArity = W>,
    > From<VanillaReplicaColumnProof<X>> for ReplicaColumnProof<H, U, V, W>
{
    fn from(vanilla_proof: VanillaReplicaColumnProof<X>) -> Self {
        let VanillaReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        } = vanilla_proof;

        ReplicaColumnProof {
            c_x: c_x.into(),
            drg_parents: drg_parents.into_iter().map(|p| p.into()).collect(),
            exp_parents: exp_parents.into_iter().map(|p| p.into()).collect(),
        }
    }
}
