use bellperson::gadgets::{boolean::Boolean, num};
use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::{constraint, create_label::create_label, uint64};
use crate::drgraph::Graph;
use crate::fr32::fr_into_bytes;
use crate::hasher::Hasher;
use crate::stacked::{LabelingProof as VanillaLabelingProof, PublicParams};
use crate::util::bytes_into_boolean_vec_be;

#[derive(Debug, Clone)]
pub struct LabelingProof {
    // outer option is if a window index is used, inner is for the circuit
    #[allow(clippy::option_option)]
    window_index: Option<Option<u64>>,
    node: Option<u64>,
    parents: Vec<Option<Fr>>,
}

impl LabelingProof {
    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty<H: Hasher>(params: &PublicParams<H>, layer: usize) -> Self {
        let degree = if layer == 1 {
            params.window_graph.base_graph().degree()
        } else {
            params.window_graph.degree()
        };
        LabelingProof {
            window_index: Some(None),
            node: None,
            parents: vec![None; degree],
        }
    }

    /// Create an empty proof, used in `blank_circuit`s.
    pub fn empty_expansion<H: Hasher>(params: &PublicParams<H>) -> Self {
        let degree = params.wrapper_graph.expansion_degree();
        LabelingProof {
            window_index: None,
            node: None,
            parents: vec![None; degree],
        }
    }

    #[allow(clippy::option_option)]
    fn create_label<CS: ConstraintSystem<Bls12>>(
        mut cs: CS,
        _params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        window_index: Option<Option<u64>>,
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

        let window_index_num = match window_index {
            Some(w) => Some(uint64::UInt64::alloc(cs.namespace(|| "window_index"), w)?),
            None => None,
        };
        let node_num = uint64::UInt64::alloc(cs.namespace(|| "node"), node)?;

        create_label(
            cs.namespace(|| "create_label"),
            replica_id,
            parents_bits,
            window_index_num,
            Some(node_num),
        )
    }

    pub fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        mut cs: CS,
        params: &<Bls12 as JubjubEngine>::Params,
        replica_id: &[Boolean],
        exp_labeled_node: &num::AllocatedNum<Bls12>,
    ) -> Result<(), SynthesisError> {
        let LabelingProof {
            window_index,
            node,
            parents,
        } = self;

        let key = Self::create_label(
            cs.namespace(|| "create_label"),
            params,
            replica_id,
            window_index,
            node,
            parents,
        )?;

        // enforce equality
        constraint::equal(&mut cs, || "equality_label", &exp_labeled_node, &key);

        Ok(())
    }
}

impl<H: Hasher> From<VanillaLabelingProof<H>> for LabelingProof {
    fn from(vanilla_proof: VanillaLabelingProof<H>) -> Self {
        let VanillaLabelingProof {
            parents,
            window_index,
            node,
            ..
        } = vanilla_proof;

        LabelingProof {
            window_index: window_index.map(Some),
            node: Some(node),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
