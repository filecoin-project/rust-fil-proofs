//! ZigZagDrgPorep is a layered PoRep which replicates layer by layer.
//! Between layers, the graph is 'reversed' in such a way that the dependencies expand with each iteration.
//! This reversal is not a straightforward inversion -- so we coin the term 'zigzag' to describe the transformation.
//! Each graph can be divided into base and expansion components.
//! The 'base' component is an ordinary DRG. The expansion component attempts to add a target (expansion_degree) number of connections
//! between nodes in a reversible way. Expansion connections are therefore simply inverted at each layer.
//! Because of how DRG-sampled parents are calculated on demand, the base components are not. Instead, a same-degree
//! DRG with connections in the opposite direction (and using the same random seed) is used when calculating parents on demand.
//! For the algorithm to have the desired properties, it is important that the expansion components are directly inverted at each layer.
//! However, it is fortunately not necessary that the base DRG components also have this property.

#[macro_use]
mod macros;

mod challenges;
mod column;
mod column_proof;
mod encoding_proof;
mod graph;
mod hash;
mod params;
mod porep;
mod proof;
mod proof_scheme;

pub use self::challenges::{ChallengeRequirements, LayerChallenges};
pub use self::column::{Column, RawColumn};
pub use self::column_proof::ColumnProof;
pub use self::encoding_proof::EncodingProof;
pub use self::graph::{ZigZagBucketGraph, ZigZagGraph, EXP_DEGREE};
pub use self::params::{
    PersistentAux, PrivateInputs, Proof, PublicInputs, PublicParams, ReplicaColumnProof,
    SetupParams, Tau, TemporaryAux,
};
pub use self::proof::ZigZagDrgPoRep;
