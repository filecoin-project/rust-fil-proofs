use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::{boolean::Boolean, num};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{constraint, kdf::kdf, sloth};
use crate::drgraph::Graph;
use crate::hasher::Hasher;
use crate::zigzag::{EncodingProof as VanillaEncodingProof, PublicParams};

#[derive(Debug, Clone)]
pub struct EncodingProof {
    encoded_node: Option<Fr>,
    decoded_node: Option<Fr>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        EncodingProof {
            encoded_node: None,
            decoded_node: None,
            parents: vec![None; params.graph.degree()],
        }
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
        degree: usize,
        replica_id: &[Boolean],
        expected_encoded_node: &num::AllocatedNum<Bls12>,
        expected_decoded_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let EncodingProof {
            parents,
            encoded_node,
            decoded_node,
        } = self;

        // Consistency check, not needed in the circuit.
        if expected_encoded_node.get_value().is_some() {
            assert_eq!(
                encoded_node,
                expected_encoded_node.get_value(),
                "invalid encoded node"
            );
            assert_eq!(
                decoded_node,
                expected_decoded_node.get_value(),
                "invalid decoded node"
            );
        }

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

        let key = kdf(
            cs.namespace(|| "create_key"),
            replica_id,
            parents_bits,
            degree,
        )?;

        // decode
        let decoded =
            sloth::decode_no_alloc(cs.namespace(|| "decode"), &key, expected_encoded_node)?;

        // enforce equality
        constraint::equal(&mut cs, || "equality", &expected_decoded_node, &decoded);

        Ok(())
    }
}

impl<H: Hasher> From<VanillaEncodingProof<H>> for EncodingProof {
    fn from(vanilla_proof: VanillaEncodingProof<H>) -> Self {
        let VanillaEncodingProof {
            parents,
            decoded_node,
            encoded_node,
            ..
        } = vanilla_proof;

        EncodingProof {
            encoded_node: Some(encoded_node.into_fr()),
            decoded_node: Some(decoded_node.into_fr()),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
