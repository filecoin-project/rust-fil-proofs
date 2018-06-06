use drgraph::MerkleTree;
use error::Result;
use proof::ProofScheme;

#[derive(Debug)]
pub struct PublicParams {
    pub lambda: usize,
    pub time: usize,
}

#[derive(Debug)]
pub struct Tau {
    pub comm_r: Vec<u8>,
    pub comm_d: Vec<u8>,
}
impl Tau {
    pub fn new(comm_d: Vec<u8>, comm_r: Vec<u8>) -> Tau {
        Tau {
            comm_d: comm_d,
            comm_r: comm_r,
        }
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

#[derive(Debug)]
pub struct ProverAux {
    pub tree_d: MerkleTree,
    pub tree_r: MerkleTree,
}

impl ProverAux {
    pub fn new(tree_d: MerkleTree, tree_r: MerkleTree) -> ProverAux {
        ProverAux {
            tree_d: tree_d,
            tree_r: tree_r,
        }
    }
}

pub trait PoRep<'a>: ProofScheme<'a> {
    fn replicate(&'a Self::PublicParams, &[u8], &mut [u8]) -> Result<(Tau, ProverAux)>;
    fn extract_all(&'a Self::PublicParams, &[u8], &[u8]) -> Result<Vec<u8>>;
    fn extract(&'a Self::PublicParams, &[u8], &[u8], usize) -> Result<Vec<u8>>;
}
