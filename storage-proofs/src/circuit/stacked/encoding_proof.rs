use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean::Boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{constraint, encode::encode, kdf::kdf, uint64};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::stacked::{EncodingProof as VanillaEncodingProof, PublicParams};

#[derive(Debug, Clone)]
pub struct EncodingProof {
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>, layer: usize) -> Self {
        let degree = if layer == 1 {
            params.graph.base_graph().degree()
        } else {
            params.graph.degree()
        };
        EncodingProof {
            node: None,
            parents: vec![None; degree],
        }
    }

    fn create_key<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        node: Option<u64>,
        parents: Vec<Option<Fr>>,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        let parents_num = parents
            .into_iter()
            .enumerate()
            .map(|(i, parent)| {
                num::AllocatedNum::alloc(cs.namespace(|| format!("parent_{}_num", i)), || {
                    parent
                        .map(Into::into)
                        .ok_or_else(|| SynthesisError::AssignmentMissing)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let parents_bits = parents_num
            .into_iter()
            .enumerate()
            .map(|(i, parent)| {
                let mut bits =
                    parent.into_bits_le(cs.namespace(|| format!("parent_{}_bits", i)))?;
                while bits.len() % 8 > 0 {
                    bits.push(Boolean::Constant(false));
                }
                Ok(bits)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let node_num = uint64::UInt64::alloc(cs.namespace(|| "node"), node)?;

        kdf(
            cs.namespace(|| "create_key"),
            replica_id,
            parents_bits,
            Some(node_num),
        )
    }

    pub fn synthesize_key<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        exp_encoded_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let EncodingProof { node, parents } = self;

        let key = Self::create_key(
            cs.namespace(|| "create_key"),
            params,
            replica_id,
            node,
            parents,
        )?;

        // enforce equality
        constraint::equal(&mut cs, || "equality_key", &exp_encoded_node, &key);

        Ok(())
    }

    pub fn synthesize_decoded<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        exp_encoded_node: &num::AllocatedNum<Bls12>,
        decoded_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let EncodingProof { node, parents } = self;

        let key = Self::create_key(
            cs.namespace(|| "create_key"),
            params,
            replica_id,
            node,
            parents,
        )?;

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
