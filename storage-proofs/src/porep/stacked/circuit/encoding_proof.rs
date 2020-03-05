use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::fr32::fr_into_bytes;
use crate::gadgets::{constraint, encode::encode, uint64};
use crate::hasher::Hasher;
use crate::porep::stacked::{EncodingProof as VanillaEncodingProof, PublicParams, TOTAL_PARENTS};
use crate::util::bytes_into_boolean_vec_be;

use super::create_label_circuit;

#[derive(Debug, Clone)]
pub struct EncodingProof {
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(_params: &PublicParams<H>) -> Self {
        EncodingProof {
            node: None,
            parents: vec![None; TOTAL_PARENTS],
        }
    }

    fn create_key<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        node: Option<u64>,
        parents: Vec<Option<Fr>>,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        // get the parents into bits
        let parents_bits: Vec<Vec<Boolean>> = parents
            .into_iter()
            .enumerate()
            .map(|(i, val)| match val {
                Some(val) => {
                    let bytes = fr_into_bytes::<Bls12>(&val);
                    bytes_into_boolean_vec_be(
                        cs.namespace(|| format!("parents_{}_bits", i)),
                        Some(&bytes),
                        256,
                    )
                }
                None => bytes_into_boolean_vec_be(
                    cs.namespace(|| format!("parents_{}_bits", i)),
                    None,
                    256,
                ),
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
