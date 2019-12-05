#[macro_use]
mod macros;

mod challenges;
mod column;
mod column_proof;
mod encoding_proof;
mod graph;
pub(crate) mod hash;
mod labeling_proof;
mod params;
mod porep;
mod proof;
mod proof_scheme;

pub const OPENINGS_PER_WINDOW: usize = 1;

pub use self::challenges::{ChallengeRequirements, LayerChallenges};
pub use self::column::Column;
pub use self::column_proof::ColumnProof;
pub use self::encoding_proof::EncodingProof;
pub use self::graph::{StackedBucketGraph, StackedGraph, EXP_DEGREE};
pub use self::params::{
    generate_replica_id, CacheKey, PersistentAux, PrivateInputs, Proof, PublicInputs, PublicParams,
    ReplicaColumnProof, SetupParams, Tau, TemporaryAux, TemporaryAuxCache, WindowProof,
    WrapperProof,
};
pub use self::proof::{StackedConfig, StackedDrg};
pub use labeling_proof::LabelingProof;
