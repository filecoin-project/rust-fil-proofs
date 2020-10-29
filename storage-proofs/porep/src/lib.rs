//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]

pub mod drg;
pub mod stacked;

mod encode;

use std::path::PathBuf;

use merkletree::store::StoreConfig;
use storage_proofs_core::{
    error::Result, hasher::Hasher, merkle::BinaryMerkleTree, proof::ProofScheme, Data,
};

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
        replica: &[u8],
        config: Option<StoreConfig>,
    ) -> Result<Vec<u8>>;

    fn extract(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        replica: &[u8],
        node: usize,
        config: Option<StoreConfig>,
    ) -> Result<Vec<u8>>;
}

pub const MAX_LEGACY_POREP_REGISTERED_PROOF_ID: u64 = 4;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
