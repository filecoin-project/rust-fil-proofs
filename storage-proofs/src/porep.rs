use crate::error::Result;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::MerkleTree;
use crate::proof::ProofScheme;

use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct PublicParams {
    pub time: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Tau<T> {
    pub comm_r: T,
    pub comm_d: T,
}

impl<T: Domain> Tau<T> {
    pub fn new(comm_d: T, comm_r: T) -> Self {
        Tau { comm_d, comm_r }
    }
}

#[derive(Debug)]
pub struct PublicInputs<'a, T: Domain> {
    pub id: &'a [u8],
    pub r: usize,
    pub tau: Tau<T>,
}

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ProverAux<H: Hasher> {
    pub tree_d: MerkleTree<H::Domain, H::Function>,
    pub tree_r: MerkleTree<H::Domain, H::Function>,
}

impl<H: Hasher> ProverAux<H> {
    pub fn new(
        tree_d: MerkleTree<H::Domain, H::Function>,
        tree_r: MerkleTree<H::Domain, H::Function>,
    ) -> Self {
        ProverAux { tree_d, tree_r }
    }
}

pub trait PoRep<'a, H: Hasher, G: Hasher>: ProofScheme<'a> {
    type Tau;
    type ProverAux;

    fn replicate(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        data_tree: Option<MerkleTree<G::Domain, G::Function>>,
        config: Option<StoreConfig>,
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

pub fn replica_id<H: Hasher>(prover_id: [u8; 32], sector_id: [u8; 32]) -> H::Domain {
    let mut to_hash = [0; 64];
    to_hash[..32].copy_from_slice(&prover_id);
    to_hash[32..].copy_from_slice(&sector_id);

    H::Function::hash_leaf(&to_hash)
}
