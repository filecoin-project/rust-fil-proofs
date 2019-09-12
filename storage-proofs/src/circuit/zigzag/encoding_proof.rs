use paired::bls12_381::Fr;

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
}

impl<H: Hasher> From<VanillaEncodingProof<H>> for EncodingProof {
    fn from(vanilla_proof: VanillaEncodingProof<H>) -> Self {
        let VanillaEncodingProof {
            encoded_node,
            decoded_node,
            parents,
            ..
        } = vanilla_proof;

        EncodingProof {
            encoded_node: Some(encoded_node.into_fr()),
            decoded_node: Some(decoded_node.into_fr()),
            parents: parents.into_iter().map(|p| Some(p.into())).collect(),
        }
    }
}
