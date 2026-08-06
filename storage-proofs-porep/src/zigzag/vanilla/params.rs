use filecoin_hashers::{Domain, HashFunction, Hasher};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    api_version::ApiVersion,
    error::Result,
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    parameter_cache::ParameterSetMetadata,
    PoRepID,
};

use crate::zigzag::vanilla::{
    challenges::{derive_challenges, LayerChallenges},
    graph::ZigZagBucketGraph,
};

/// Parameters for setting up a ZigZag layered PoRep.
#[derive(Debug, Clone)]
pub struct SetupParams {
    pub nodes: usize,
    pub degree: usize,
    pub expansion_degree: usize,
    pub porep_id: PoRepID,
    pub api_version: ApiVersion,
    pub layer_challenges: LayerChallenges,
}

/// Public parameters for a ZigZag layered PoRep.
///
/// `Tree` is the Poseidon replica-tree shape; `G` is the piece/data hasher (Sha256) used for
/// `comm_d` so it matches Filecoin's standard piece-aggregated CommD.
pub struct PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    pub graph: ZigZagBucketGraph<Tree::Hasher>,
    pub layer_challenges: LayerChallenges,
}

impl<Tree: MerkleTreeTrait> std::fmt::Debug for PublicParams<Tree> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicParams")
            .field("graph", &self.graph)
            .field("layer_challenges", &self.layer_challenges)
            .finish()
    }
}

impl<Tree: MerkleTreeTrait> Clone for PublicParams<Tree> {
    fn clone(&self) -> Self {
        PublicParams {
            graph: self.graph.clone(),
            layer_challenges: self.layer_challenges.clone(),
        }
    }
}

impl<Tree> PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    pub fn new(graph: ZigZagBucketGraph<Tree::Hasher>, layer_challenges: LayerChallenges) -> Self {
        PublicParams {
            graph,
            layer_challenges,
        }
    }
}

impl<Tree> ParameterSetMetadata for PublicParams<Tree>
where
    Tree: MerkleTreeTrait,
{
    fn identifier(&self) -> String {
        format!(
            "zigzag::PublicParams{{ graph: {}, challenges: {:?}, tree: {} }}",
            self.graph.identifier(),
            self.layer_challenges,
            Tree::display(),
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

/// Public commitments: Sha256 `comm_d` (piece/data tree) and Poseidon `comm_r` (final replica).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerTau<R: Domain, D: Domain> {
    #[serde(bound = "")]
    pub comm_d: D,
    #[serde(bound = "")]
    pub comm_r: R,
}

impl<R: Domain, D: Domain> LayerTau<R, D> {
    pub fn new(comm_d: D, comm_r: R) -> Self {
        LayerTau { comm_d, comm_r }
    }
}

/// Commitments produced during replication.
///
/// `comm_d` is the Sha256 root of the original (fr32-padded) data. `layer_comm_rs` holds the
/// Poseidon root of each layer's replica tree. `comm_r_star` folds `replica_id` with every
/// per-layer replica root.
#[derive(Debug, Clone)]
pub struct Tau<R: Domain, D: Domain> {
    pub comm_d: D,
    pub layer_comm_rs: Vec<R>,
    pub comm_r_star: R,
}

impl<R: Domain, D: Domain> Tau<R, D> {
    /// Collapse into the public `(comm_d, comm_r)` pair used as circuit inputs.
    pub fn simplify(&self) -> LayerTau<R, D> {
        LayerTau {
            comm_d: self.comm_d,
            comm_r: self.layer_comm_rs[self.layer_comm_rs.len() - 1],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs<R: Domain, D: Domain> {
    #[serde(bound = "")]
    pub replica_id: R,
    /// Chain-provided challenge seed (ticket). When `None`, challenges derive from `comm_r_star`
    /// (non-interactive / legacy behaviour).
    #[serde(bound = "")]
    pub seed: Option<R>,
    #[serde(bound = "")]
    pub tau: Option<LayerTau<R, D>>,
    #[serde(bound = "")]
    pub comm_r_star: R,
    pub k: Option<usize>,
}

impl<R: Domain, D: Domain> PublicInputs<R, D> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        layer: u8,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let commitment = self.seed.as_ref().unwrap_or(&self.comm_r_star);
        derive_challenges::<R>(
            layer_challenges,
            layer,
            leaves,
            &self.replica_id,
            commitment,
            partition_k.unwrap_or(0) as u8,
        )
    }
}

/// Private inputs for proving.
///
/// `tree_d` is the Sha256 binary Merkle tree over the original data (`comm_d`). `aux` holds one
/// Poseidon replica tree per layer.
pub struct PrivateInputs<Tree, G>
where
    Tree: MerkleTreeTrait,
    G: 'static + Hasher,
{
    pub tree_d: BinaryMerkleTree<G>,
    pub aux: Vec<Tree>,
    pub layer_comm_rs: Vec<<Tree::Hasher as Hasher>::Domain>,
    pub comm_d: G::Domain,
}

/// The ZigZag challenge requirement: at least `minimum_challenges` across all partitions.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

/// Computes the aggregate `comm_r_star` as a commitment over `replica_id` and every per-layer
/// replica root.
///
/// The 2019 ZigZag used Pedersen, which hashes arbitrary-length input. Poseidon only supports fixed
/// arities, so we instead fold `[replica_id, comm_r_0, comm_r_1, ...]` with a binary
/// Merkle-Damgard construction (`hash_md`, i.e. repeated `hash2`), which preserves the "vector
/// commitment over all layer roots" property.
pub fn comm_r_star<H: Hasher>(
    replica_id: &H::Domain,
    comm_rs: &[H::Domain],
) -> Result<H::Domain> {
    let input: Vec<H::Domain> = std::iter::once(*replica_id)
        .chain(comm_rs.iter().copied())
        .collect();

    Ok(H::Function::hash_md(&input))
}
