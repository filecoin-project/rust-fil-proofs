use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean::Boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{constraint, kdf::kdf, stacked::encode::encode, uint64};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::stacked::{EncodingProof as VanillaEncodingProof, PublicParams};

#[derive(Debug, Clone)]
pub struct EncodingProof {
    node: Option<u64>,
    encoded_node: Option<Fr>,
    // The inner `Option` is for the circuit, the outer to determine if
    // if we need to encode sth.
    #[allow(clippy::option_option)]
    decoded_node: Option<Option<Fr>>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        EncodingProof {
            node: None,
            encoded_node: None,
            decoded_node: None,
            parents: vec![None; params.graph.degree()],
        }
    }

    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty_base<H: Hasher>(params: &PublicParams<H>) -> Self {
        EncodingProof {
            node: None,
            encoded_node: None,
            decoded_node: None,
            parents: vec![None; params.graph.base_graph().degree()],
        }
    }

    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty_with_decoded<H: Hasher>(params: &PublicParams<H>) -> Self {
        EncodingProof {
            node: None,
            encoded_node: None,
            decoded_node: Some(None),
            parents: vec![None; params.graph.degree()],
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

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
    ) -> Result<(), SynthesisError> {
        let EncodingProof {
            node,
            parents,
            encoded_node,
            decoded_node,
        } = self;

        let key = Self::create_key(
            cs.namespace(|| "create_key"),
            params,
            replica_id,
            node,
            parents,
        )?;

        let encoded_node = num::AllocatedNum::alloc(cs.namespace(|| "encoded_num"), || {
            encoded_node
                .map(Into::into)
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let encoded_node_new = if let Some(decoded_node) = decoded_node {
            let decoded_num = num::AllocatedNum::alloc(cs.namespace(|| "decoded_num"), || {
                decoded_node
                    .map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;
            encode(cs.namespace(|| "encode"), &key, &decoded_num)?
        } else {
            key
        };

        // enforce equality
        constraint::equal(&mut cs, || "equality", &encoded_node_new, &encoded_node);

        Ok(())
    }
}

impl<H: Hasher> From<VanillaEncodingProof<H>> for EncodingProof {
    fn from(vanilla_proof: VanillaEncodingProof<H>) -> Self {
        let VanillaEncodingProof {
            parents,
            decoded_node,
            encoded_node,
            node,
            ..
        } = vanilla_proof;

        EncodingProof {
            node: Some(node),
            encoded_node: Some(encoded_node.into_fr()),
            decoded_node: decoded_node.map(|n| Some(n.into_fr())),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
