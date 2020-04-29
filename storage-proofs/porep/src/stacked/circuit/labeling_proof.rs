use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    gadgets::{constraint, uint64},
    hasher::Hasher,
    merkle::{MerkleTreeTrait, Store},
    util::fixup_bits,
};

use super::create_label_circuit;
use crate::stacked::{LabelingProof as VanillaLabelingProof, PublicParams, TOTAL_PARENTS};

#[derive(Debug, Clone)]
pub struct LabelingProof {
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl LabelingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<S: Store<H::Domain>, Tree, H: 'static + Hasher>(
        _params: &PublicParams<Tree>,
        _layer: usize,
    ) -> Self
    where
        Tree: MerkleTreeTrait<Hasher = H, Store = S>,
    {
        LabelingProof {
            node: None,
            parents: vec![None; TOTAL_PARENTS],
        }
    }

    fn create_label<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        replica_id: &[Boolean],
        node: Option<u64>,
        parents: Vec<Option<Fr>>,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        // get the parents into bits
        let parents_bits: Vec<Vec<Boolean>> = parents
            .into_iter()
            .enumerate()
            .map(|(i, val)| {
                let num = num::AllocatedNum::alloc(
                    cs.namespace(|| format!("parents_{}_num", i)),
                    || {
                        val.map(Into::into)
                            .ok_or_else(|| SynthesisError::AssignmentMissing)
                    },
                )?;

                Ok(fixup_bits(num.to_bits_le(
                    cs.namespace(|| format!("parents_{}_bits", i)),
                )?))
            })
            .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

        let node_num = uint64::UInt64::alloc(cs.namespace(|| "node"), node)?;

        create_label_circuit(
            cs.namespace(|| "create_label"),
            replica_id,
            parents_bits,
            node_num,
        )
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        replica_id: &[Boolean],
        exp_encoded_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let LabelingProof { node, parents } = self;

        let key = Self::create_label(cs.namespace(|| "create_label"), replica_id, node, parents)?;

        // enforce equality
        constraint::equal(&mut cs, || "equality_key", &exp_encoded_node, &key);

        Ok(())
    }
}

impl<H: Hasher> From<VanillaLabelingProof<H>> for LabelingProof {
    fn from(vanilla_proof: VanillaLabelingProof<H>) -> Self {
        let VanillaLabelingProof { parents, node, .. } = vanilla_proof;

        LabelingProof {
            node: Some(node),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
