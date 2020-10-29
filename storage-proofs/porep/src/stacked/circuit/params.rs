use std::marker::PhantomData;

use bellperson::bls::{Bls12, Fr};
use bellperson::gadgets::{boolean::Boolean, num, uint32};
use bellperson::{ConstraintSystem, SynthesisError};
use generic_array::typenum::{U0, U2};
use storage_proofs_core::{
    drgraph::Graph,
    gadgets::por::{AuthPath, PoRCircuit},
    gadgets::{encode::encode, uint64, variables::Root},
    hasher::{Hasher, PoseidonArity},
    merkle::{DiskStore, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    util::reverse_bit_numbering,
};

use super::{
    column_proof::ColumnProof, create_label_circuit as create_label, hash::hash_single_column,
};
use crate::stacked::{
    Proof as VanillaProof, PublicParams, ReplicaColumnProof as VanillaReplicaColumnProof,
};

type TreeAuthPath<T> = AuthPath<
    <T as MerkleTreeTrait>::Hasher,
    <T as MerkleTreeTrait>::Arity,
    <T as MerkleTreeTrait>::SubTreeArity,
    <T as MerkleTreeTrait>::TopTreeArity,
>;

type TreeColumnProof<T> = ColumnProof<
    <T as MerkleTreeTrait>::Hasher,
    <T as MerkleTreeTrait>::Arity,
    <T as MerkleTreeTrait>::SubTreeArity,
    <T as MerkleTreeTrait>::TopTreeArity,
>;

/// Proof for a single challenge.
#[derive(Debug)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    /// Inclusion path for the challenged data node in tree D.
    pub comm_d_path: AuthPath<G, U2, U0, U0>,
    /// The value of the challenged data node.
    pub data_leaf: Option<Fr>,
    /// The index of the challenged node.
    pub challenge: Option<u64>,
    /// Inclusion path of the challenged replica node in tree R.
    pub comm_r_last_path: TreeAuthPath<Tree>,
    /// Inclusion path of the column hash of the challenged node  in tree C.
    pub comm_c_path: TreeAuthPath<Tree>,
    /// Column proofs for the drg parents.
    pub drg_parents_proofs: Vec<TreeColumnProof<Tree>>,
    /// Column proofs for the expander parents.
    pub exp_parents_proofs: Vec<TreeColumnProof<Tree>>,
    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> Proof<Tree, G> {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty(params: &PublicParams<Tree>) -> Self {
        Proof {
            comm_d_path: AuthPath::blank(params.graph.size()),
            data_leaf: None,
            challenge: None,
            comm_r_last_path: AuthPath::blank(params.graph.size()),
            comm_c_path: AuthPath::blank(params.graph.size()),
            drg_parents_proofs: vec![
                ColumnProof::empty(params);
                params.graph.base_graph().degree()
            ],
            exp_parents_proofs: vec![ColumnProof::empty(params); params.graph.expansion_degree()],
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
            challenge,
            comm_r_last_path,
            comm_c_path,
            drg_parents_proofs,
            exp_parents_proofs,
            ..
        } = self;

        assert!(!drg_parents_proofs.is_empty());
        assert!(!exp_parents_proofs.is_empty());

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

        // Private Inputs for the DRG parent nodes.
        let mut drg_parents = Vec::with_capacity(layers);

        for (i, parent) in drg_parents_proofs.into_iter().enumerate() {
            let (parent_col, inclusion_path) =
                parent.alloc(cs.namespace(|| format!("drg_parent_{}_num", i)))?;
            assert_eq!(layers, parent_col.len());

            // calculate column hash
            let val = parent_col.hash(cs.namespace(|| format!("drg_parent_{}_constraint", i)))?;
            // enforce inclusion of the column hash in the tree C
            enforce_inclusion(
                cs.namespace(|| format!("drg_parent_{}_inclusion", i)),
                inclusion_path,
                comm_c,
                &val,
            )?;
            drg_parents.push(parent_col);
        }

        // Private Inputs for the Expander parent nodes.
        let mut exp_parents = Vec::new();

        for (i, parent) in exp_parents_proofs.into_iter().enumerate() {
            let (parent_col, inclusion_path) =
                parent.alloc(cs.namespace(|| format!("exp_parent_{}_num", i)))?;
            assert_eq!(layers, parent_col.len());

            // calculate column hash
            let val = parent_col.hash(cs.namespace(|| format!("exp_parent_{}_constraint", i)))?;
            // enforce inclusion of the column hash in the tree C
            enforce_inclusion(
                cs.namespace(|| format!("exp_parent_{}_inclusion", i)),
                inclusion_path,
                comm_c,
                &val,
            )?;
            exp_parents.push(parent_col);
        }

        // -- Verify labeling and encoding

        // stores the labels of the challenged column
        let mut column_labels = Vec::new();

        // PublicInput: challenge index
        let challenge_num = uint64::UInt64::alloc(cs.namespace(|| "challenge"), challenge)?;
        challenge_num.pack_into_input(cs.namespace(|| "challenge input"))?;

        for layer in 1..=layers {
            let layer_num = uint32::UInt32::constant(layer as u32);

            let mut cs = cs.namespace(|| format!("labeling_{}", layer));

            // Collect the parents
            let mut parents = Vec::new();

            // all layers have drg parents
            for parent_col in &drg_parents {
                let parent_val_num = parent_col.get_value(layer);
                let parent_val_bits =
                    reverse_bit_numbering(parent_val_num.to_bits_le(
                        cs.namespace(|| format!("drg_parent_{}_bits", parents.len())),
                    )?);
                parents.push(parent_val_bits);
            }

            // the first layer does not contain expander parents
            if layer > 1 {
                for parent_col in &exp_parents {
                    // subtract 1 from the layer index, as the exp parents, are shifted by one, as they
                    // do not store a value for the first layer
                    let parent_val_num = parent_col.get_value(layer - 1);
                    let parent_val_bits = reverse_bit_numbering(parent_val_num.to_bits_le(
                        cs.namespace(|| format!("exp_parent_{}_bits", parents.len())),
                    )?);
                    parents.push(parent_val_bits);
                }
            }

            // Duplicate parents, according to the hashing algorithm.
            let mut expanded_parents = parents.clone();
            if layer > 1 {
                expanded_parents.extend_from_slice(&parents); // 28
                expanded_parents.extend_from_slice(&parents[..9]); // 37
            } else {
                // layer 1 only has drg parents
                expanded_parents.extend_from_slice(&parents); // 12
                expanded_parents.extend_from_slice(&parents); // 18
                expanded_parents.extend_from_slice(&parents); // 24
                expanded_parents.extend_from_slice(&parents); // 30
                expanded_parents.extend_from_slice(&parents); // 36
                expanded_parents.push(parents[0].clone()); // 37
            };

            // Reconstruct the label
            let label = create_label(
                cs.namespace(|| "create_label"),
                replica_id,
                expanded_parents,
                layer_num,
                challenge_num.clone(),
            )?;
            column_labels.push(label);
        }

        // -- encoding node
        {
            // encode the node

            // key is the last label
            let key = &column_labels[column_labels.len() - 1];
            let encoded_node = encode(cs.namespace(|| "encode_node"), key, &data_leaf_num)?;

            // verify inclusion of the encoded node
            enforce_inclusion(
                cs.namespace(|| "comm_r_last_data_inclusion"),
                comm_r_last_path,
                comm_r_last,
                &encoded_node,
            )?;
        }

        // -- ensure the column hash of the labels is included
        {
            // calculate column_hash
            let column_hash =
                hash_single_column(cs.namespace(|| "c_x_column_hash"), &column_labels)?;

            // enforce inclusion of the column hash in the tree C
            enforce_inclusion(
                cs.namespace(|| "c_x_inclusion"),
                comm_c_path,
                comm_c,
                &column_hash,
            )?;
        }

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
        let VanillaReplicaColumnProof {
            c_x,
            drg_parents,
            exp_parents,
        } = replica_column_proofs;

        let data_leaf = Some(comm_d_proofs.leaf().into());

        Proof {
            comm_d_path: comm_d_proofs.as_options().into(),
            data_leaf,
            challenge: Some(labeling_proofs[0].node),
            comm_r_last_path: comm_r_last_proof.as_options().into(),
            comm_c_path: c_x.inclusion_proof.as_options().into(),
            drg_parents_proofs: drg_parents.into_iter().map(|p| p.into()).collect(),
            exp_parents_proofs: exp_parents.into_iter().map(|p| p.into()).collect(),
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
