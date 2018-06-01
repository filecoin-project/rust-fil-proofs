use drgraph::MerkleTree;

pub struct PublicParams {
    pub lambda: usize,
    pub time: usize,
}

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


pub struct PublicInputs<'a> {
    pub id: &'a [u8],
    pub r: usize,
    pub tau: Tau,
}

pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
}

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

pub trait PoRep<T> {
    fn replicate<'a>(&'a self, &'a T, &'a [u8], &'a mut [u8]) -> (Tau, ProverAux);
    fn extract_all<'a>(&'a self, &'a T, &'a [u8], &'a [u8]) -> Vec<u8>;
    fn extract<'a>(&'a self, &'a T, &'a [u8], &'a [u8], usize) -> Vec<u8>;
}
