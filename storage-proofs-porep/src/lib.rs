#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![warn(clippy::unwrap_used)]
#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![warn(clippy::unnecessary_wraps)]

use std::path::PathBuf;

use filecoin_hashers::Hasher;
use merkletree::store::StoreConfig;
use storage_proofs_core::{error::Result, merkle::BinaryMerkleTree, proof::ProofScheme, Data};

pub mod drg;
pub mod stacked;

mod encode;

pub const MAX_LEGACY_POREP_REGISTERED_PROOF_ID: u64 = 4;

pub trait PoRep<'a, H: Hasher, G: Hasher>: ProofScheme<'a> {
    type Tau;
    type ProverAux;

    fn replicate(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(Self::Tau, Self::ProverAux)>;

    fn extract_all(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        config: Option<StoreConfig>,
    ) -> Result<()>;

    fn extract(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        node: usize,
        config: Option<StoreConfig>,
    ) -> Result<()>;
}
