use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{constraint, create_label::create_label as kdf, encode::encode, uint64};
use crate::drgraph::Graph;
use crate::fr32::fr_into_bytes;
use crate::hasher::Hasher;
use crate::stacked::{EncodingProof as VanillaEncodingProof, PublicParams};
use crate::util::bytes_into_boolean_vec_be;

#[derive(Debug, Clone)]
pub struct EncodingProof {
    window_index: Option<u64>,
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl EncodingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>) -> Self {
        EncodingProof {
            window_index: None,
            node: None,
            parents: vec![None; params.window_graph.degree()],
        }
    }

    fn create_key<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        window_index: Option<u64>,
        node: Option<u64>,
        parents: Vec<Option<Fr>>,
    ) -> Result<num::AllocatedNum<Bls12>, SynthesisError> {
        // get the parents into bits
        let parents_bits: Vec<Vec<Boolean>> = parents
            .iter()
            .enumerate()
            .map(|(i, val)| match val {
                Some(val) => {
                    let bytes = fr_into_bytes::<Bls12>(val);
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

        let window_index_num =
            uint64::UInt64::alloc(cs.namespace(|| "window_index"), window_index)?;
        let node_num = uint64::UInt64::alloc(cs.namespace(|| "node"), node)?;

        kdf(
            cs.namespace(|| "create_key"),
            replica_id,
            parents_bits,
            Some(window_index_num),
            Some(node_num),
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
        let EncodingProof {
            window_index,
            node,
            parents,
        } = self;

        let key = Self::create_key(
            cs.namespace(|| "create_key"),
            params,
            replica_id,
            window_index,
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
        let VanillaEncodingProof {
            parents,
            window_index,
            node,
            ..
        } = vanilla_proof;

        EncodingProof {
            window_index: Some(window_index),
            node: Some(node),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
