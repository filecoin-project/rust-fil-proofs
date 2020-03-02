use std::path::PathBuf;

use merkletree::store::StoreConfig;

use crate::error::Result;
use crate::hasher::Hasher;
use crate::merkle::BinaryMerkleTree;
use crate::proof::ProofScheme;
use crate::Data;

pub mod drg;
pub mod stacked;

pub trait PoRep<'a, H: Hasher, G: Hasher>: ProofScheme<'a> {
    type Tau;
    type ProverAux;

    fn replicate(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<G::Domain, G::Function>>,
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
