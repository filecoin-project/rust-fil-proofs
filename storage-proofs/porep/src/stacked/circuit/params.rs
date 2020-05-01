use std::marker::PhantomData;

use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use generic_array::typenum::{U0, U2};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    drgraph::Graph,
    gadgets::por::{AuthPath, PoRCircuit},
    gadgets::{encode::encode, uint64, variables::Root},
    hasher::{Hasher, PoseidonArity},
    merkle::{DiskStore, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper, Store},
    util::fixup_bits,
};

use super::{
    column::AllocatedColumn, column_proof::ColumnProof, create_label_circuit as create_label,
    hash::hash_single_column,
};
use crate::stacked::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

/// Proof for a single challenge.
#[derive(Debug)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    /// Inclusion path for the data_leaf in tree D.
    pub comm_d_path: AuthPath<G, U2, U0, U0>,
    /// The original value of the challenged node.
    pub data_leaf: Option<Fr>,
    /// Inclusion path of the replica node in tree R.
    pub comm_r_last_path:
        AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    pub replica_column_proof:
        ReplicaColumnProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    /// Labeling proofs consist of `(layer_index, node_index)`
    pub labeling_proofs: Vec<(usize, Option<u64>)>,
    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> Proof<Tree, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<Tree>) -> Self {
        let layers = params.layer_challenges.layers();

        let mut labeling_proofs = Vec::with_capacity(layers);
        for layer in 1..=layers {
            labeling_proofs.push((layer, None));
        }

        Proof {
            comm_d_path: AuthPath::blank(params.graph.size()),
            data_leaf: None,
            comm_r_last_path: AuthPath::blank(params.graph.size()),
            replica_column_proof: ReplicaColumnProof::empty(params),
            labeling_proofs,
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
            comm_d_path,
            data_leaf,
            comm_r_last_path,
            replica_column_proof,
            labeling_proofs,
            ..
        } = self;

        assert_eq!(
            layers,
            labeling_proofs.len(),
            "invalid number of labeling proofs"
        );

        // -- verify initial data layer

        // PrivateInput: data_leaf
        let data_leaf_num = num::AllocatedNum::alloc(cs.namespace(|| "data_leaf"), || {
            data_leaf.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        // enforce inclusion of the data leaf in the tree D
        enforce_inclusion(
            cs.namespace(|| "comm_d_inclusion"),
            comm_d_path,
            comm_d,
            &data_leaf_num,
        )?;

        // -- verify replica column openings

        // allocate the private inputs in the replica column proof
        let replica_column_proof =
            replica_column_proof.alloc(cs.namespace(|| "replica_column_proof"))?;

        // enforce the replica column proof
        replica_column_proof.enforce(cs.namespace(|| "replica_column_proof_constraint"), comm_c)?;

        // -- Verify labeling and encoding

        // stores the labels of the challenged column
        let mut column_labels = Vec::new();

        for (layer, node_index) in labeling_proofs.into_iter() {
            let mut cs = cs.namespace(|| format!("labeling_proof_{}", layer));

            // Collect the parents
            let mut parents = Vec::new();
            for (parent, _) in &replica_column_proof.drg_parents {
                let val_num = parent.get_value(layer);
                let val_bits = fixup_bits(val_num.to_bits_le(
                    cs.namespace(|| format!("drg_parent_value_num_{}", parents.len())),
                )?);
                parents.push(val_bits);
            }

            let expanded_parents = if layer > 1 {
                for (parent, _) in &replica_column_proof.exp_parents {
                    // subtract 1 from the layer index, as the exp parents, are shifted by one, as they
                    // do not store a value for the first layer
                    let val_num = parent.get_value(layer - 1);
                    let val_bits = fixup_bits(val_num.to_bits_le(
                        cs.namespace(|| format!("exp_parent_value_num_{}", parents.len())),
                    )?);
                    parents.push(val_bits);
                }

                // duplicate parents, according to the hashing algorithm
                // TODO: verify this is okay
                let mut expanded_parents = parents.clone(); // 14
                expanded_parents.extend_from_slice(&parents); // 28
                expanded_parents.extend_from_slice(&parents[..9]); // 37
                expanded_parents
            } else {
                // layer 1 only has drg parents
                let mut expanded_parents = parents.clone(); // 6
                expanded_parents.extend_from_slice(&parents); // 12
                expanded_parents.extend_from_slice(&parents); // 18
                expanded_parents.extend_from_slice(&parents); // 24
                expanded_parents.extend_from_slice(&parents); // 30
                expanded_parents.extend_from_slice(&parents); // 36
                expanded_parents.push(parents[0].clone()); // 37
                expanded_parents
            };

            let node_num = uint64::UInt64::alloc(cs.namespace(|| "node"), node_index)?;

            // reconstruct the label
            let label = create_label(
                cs.namespace(|| "create_label"),
                replica_id,
                expanded_parents,
                node_num,
            )?;

            if layer == layers {
                // -- encoding layer

                // encode the node
                let encoded_node = encode(cs.namespace(|| "encode_node"), &label, &data_leaf_num)?;

                // verify inclusion of the encoded node
                enforce_inclusion(
                    cs.namespace(|| "comm_r_last_data_inclusion"),
                    comm_r_last_path.clone(),
                    comm_r_last,
                    &encoded_node,
                )?;
            }

            column_labels.push(label);
        }

        // -- ensure the column hash of the labels is included

        // calculate column_hash
        let column_hash = hash_single_column(cs.namespace(|| "c_x_column_hash"), &column_labels)?;

        // enforce inclusion of the column hash in the tree C
        enforce_inclusion(
            cs.namespace(|| "c_x_inclusion"),
            replica_column_proof.c_x_path,
            comm_c,
            &column_hash,
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
            ..
        } = vanilla_proof;

        let mut labeling_proofs: Vec<_> = labeling_proofs
            .into_iter()
            .map(|(layer, p)| (layer, Some(p.node)))
            .collect();

        labeling_proofs.sort_by_cached_key(|(k, _)| *k);
        let data_leaf = Some(comm_d_proofs.leaf().into());

        Proof {
            comm_d_path: comm_d_proofs.as_options().into(),
            data_leaf,
            comm_r_last_path: comm_r_last_proof.as_options().into(),
            replica_column_proof: replica_column_proofs.into(),
            labeling_proofs,
            _t: PhantomData,
        }
    }
}

/// Enforce the inclusion of the given path, to the given leaf and the root.
fn enforce_inclusion<H, U, V, W, CS: ConstraintSystem<Bls12>>(
    cs: CS,
    path: AuthPath<H, U, V, W>,
    root: &num::AllocatedNum<Bls12>,
    leaf: &num::AllocatedNum<Bls12>,
) -> Result<(), SynthesisError>
where
    H: 'static + Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    let root = Root::from_allocated::<CS>(root.clone());
    let leaf = Root::from_allocated::<CS>(leaf.clone());

    PoRCircuit::<MerkleTreeWrapper<H, DiskStore<H::Domain>, U, V, W>>::synthesize(
        cs, leaf, path, root, true,
    )?;

    Ok(())
}

#[derive(Debug)]
pub struct ReplicaColumnProof<
    H: Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
> {
    c_x_path: AuthPath<H, U, V, W>,
    drg_parents: Vec<ColumnProof<H, U, V, W>>,
    exp_parents: Vec<ColumnProof<H, U, V, W>>,
}

pub struct AllocatedReplicaColumnProof<H, U, V, W>
where
    H: Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    c_x_path: AuthPath<H, U, V, W>,
    drg_parents: Vec<(AllocatedColumn, AuthPath<H, U, V, W>)>,
    exp_parents: Vec<(AllocatedColumn, AuthPath<H, U, V, W>)>,
}

impl<H, U, V, W> AllocatedReplicaColumnProof<H, U, V, W>
where
    H: 'static + Hasher,
    U: 'static + PoseidonArity,
    V: 'static + PoseidonArity,
    W: 'static + PoseidonArity,
{
    /// Enforces constraints on the parts.
    pub fn enforce<CS: ConstraintSystem<Bls12>>(
        &self,
        mut cs: CS,
        comm_c: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        for (i, (parent, inclusion_path)) in self.drg_parents.iter().enumerate() {
            // calculate column hash
            let val = parent.hash(cs.namespace(|| format!("drg_parent_{}_constraint", i)))?;

            // enforce inclusion of the column hash in the tree C
            enforce_inclusion(
                cs.namespace(|| format!("drg_parent_{}_inclusion", i)),
                inclusion_path.clone(),
                comm_c,
                &val,
            )?;
        }

        for (i, (parent, inclusion_path)) in self.exp_parents.iter().enumerate() {
            // calculate column hash
            let val = parent.hash(cs.namespace(|| format!("exp_parent_{}_constraint", i)))?;

            // enforce inclusion of the column hash in the tree C
            enforce_inclusion(
                cs.namespace(|| format!("exp_parent_{}_inclusion", i)),
                inclusion_path.clone(),
                comm_c,
                &val,
            )?;
        }

        Ok(())
    }
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
            c_x_path: AuthPath::blank(params.graph.size()),
            drg_parents: vec![ColumnProof::empty(params); params.graph.base_graph().degree()],
            exp_parents: vec![ColumnProof::empty(params); params.graph.expansion_degree()],
        }
    }

    /// Allocates all the private inputs of the ReplicaColumnProof.
    pub fn alloc<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
    ) -> Result<AllocatedReplicaColumnProof<H, U, V, W>, SynthesisError> {
        let Self {
            c_x_path,
            drg_parents,
            exp_parents,
        } = self;

        // Private Inputs for the DRG parent nodes.
        let drg_parents = drg_parents
            .into_iter()
            .enumerate()
            .map(|(i, parent)| parent.alloc(cs.namespace(|| format!("drg_parents_{}", i))))
            .collect::<Result<_, _>>()?;

        // Private Inputs for the Expander Parent nodes.
        let exp_parents = exp_parents
            .into_iter()
            .enumerate()
            .map(|(i, parent)| parent.alloc(cs.namespace(|| format!("exp_parents_{}", i))))
            .collect::<Result<_, _>>()?;

        Ok(AllocatedReplicaColumnProof {
            c_x_path,
            drg_parents,
            exp_parents,
        })
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
            c_x_path: c_x.inclusion_proof.as_options().into(),
            drg_parents: drg_parents.into_iter().map(|p| p.into()).collect(),
            exp_parents: exp_parents.into_iter().map(|p| p.into()).collect(),
        }
    }
}
