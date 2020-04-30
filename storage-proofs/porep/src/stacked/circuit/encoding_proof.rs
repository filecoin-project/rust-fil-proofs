use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use paired::bls12_381::{Bls12, Fr};
use storage_proofs_core::{
    gadgets::{constraint, encode::encode, uint64},
    hasher::Hasher,
    merkle::MerkleTreeTrait,
    util::fixup_bits,
};

use super::create_label_circuit;
use crate::stacked::{EncodingProof as VanillaEncodingProof, PublicParams, TOTAL_PARENTS};

#[derive(Debug, Clone)]
pub struct EncodingProof {
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<Tree: MerkleTreeTrait>(_params: &PublicParams<Tree>) -> Self {
        EncodingProof {
            node: None,
            parents: vec![None; TOTAL_PARENTS],
        }
    }

    fn create_key<CS: ConstraintSystem<Bls12>>(
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
        decoded_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let EncodingProof { node, parents } = self;

        let key = Self::create_key(cs.namespace(|| "create_key"), replica_id, node, parents)?;

        let encoded_node = encode(cs.namespace(|| "encode"), &key, decoded_node)?;

        // enforce equality
        constraint::equal(
            &mut cs,
            || "equality_encoded_node",
            &exp_encoded_node,
            &encoded_node,
        );

        Ok(())
    }
}

impl<H: Hasher> From<VanillaEncodingProof<H>> for EncodingProof {
    fn from(vanilla_proof: VanillaEncodingProof<H>) -> Self {
        let VanillaEncodingProof { parents, node, .. } = vanilla_proof;

        EncodingProof {
            node: Some(node),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
