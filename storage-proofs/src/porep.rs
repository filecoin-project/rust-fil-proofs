use drgraph::{MerkleTree, TreeHash};
use error::Result;
use proof::ProofScheme;

#[derive(Debug)]
pub struct PublicParams {
    pub lambda: usize,
    pub time: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Tau {
    pub comm_r: TreeHash,
    pub comm_d: TreeHash,
}
impl Tau {
    pub fn new(comm_d: TreeHash, comm_r: TreeHash) -> Tau {
        Tau { comm_d, comm_r }
    }
}

#[derive(Debug)]
pub struct PublicInputs<'a> {
    pub id: &'a [u8],
    pub r: usize,
    pub tau: Tau,
}

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ProverAux {
    pub tree_d: MerkleTree,
    pub tree_r: MerkleTree,
}

impl ProverAux {
    pub fn new(tree_d: MerkleTree, tree_r: MerkleTree) -> ProverAux {
        ProverAux { tree_d, tree_r }
    }
}

pub trait PoRep<'a>: ProofScheme<'a> {
    type Tau;
    type ProverAux;

    fn replicate(
        pub_params: &'a Self::PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Self::Tau, Self::ProverAux)>; // Tau, ProverAux
    fn extract_all(
        pub_params: &'a Self::PublicParams,
        prover_id: &[u8],
        replica: &[u8],
    ) -> Result<Vec<u8>>;
    fn extract(
        pub_params: &'a Self::PublicParams,
        prover_id: &[u8],
        replica: &[u8],
        node: usize,
    ) -> Result<Vec<u8>>;
}
