use anyhow::{ensure, Context};
use log::info;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::MerkleTree;
use crate::proof::ProofScheme;

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

use std::path::PathBuf;

#[derive(Debug)]
pub struct Data<'a> {
    raw: Option<RawData<'a>>,
    path: Option<PathBuf>,
    len: usize,
}

#[derive(Debug)]
enum RawData<'a> {
    Slice(&'a mut [u8]),
    Mmap(memmap::MmapMut),
}

use std::ops::{Deref, DerefMut};

impl<'a> Deref for RawData<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            RawData::Slice(ref raw) => raw,
            RawData::Mmap(ref raw) => raw,
        }
    }
}

impl<'a> DerefMut for RawData<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            RawData::Slice(ref mut raw) => raw,
            RawData::Mmap(ref mut raw) => raw,
        }
    }
}

impl<'a> From<&'a mut [u8]> for Data<'a> {
    fn from(raw: &'a mut [u8]) -> Self {
        let len = raw.len();
        Data {
            raw: Some(RawData::Slice(raw)),
            path: None,
            len,
        }
    }
}

impl<'a> From<(memmap::MmapMut, PathBuf)> for Data<'a> {
    fn from(raw: (memmap::MmapMut, PathBuf)) -> Self {
        let len = raw.0.len();
        Data {
            raw: Some(RawData::Mmap(raw.0)),
            path: Some(raw.1),
            len,
        }
    }
}

impl<'a> AsRef<[u8]> for Data<'a> {
    fn as_ref(&self) -> &[u8] {
        match self.raw {
            Some(ref raw) => raw,
            None => panic!("figure it out"),
        }
    }
}

impl<'a> AsMut<[u8]> for Data<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self.raw {
            Some(ref mut raw) => raw,
            None => panic!("figure it out"),
        }
    }
}

impl<'a> Data<'a> {
    pub fn from_path(path: PathBuf) -> Self {
        Data {
            raw: None,
            path: Some(path),
            len: 0,
        }
    }

    pub fn new(raw: &'a mut [u8], path: PathBuf) -> Self {
        let len = raw.len();

        Data {
            raw: Some(RawData::Slice(raw)),
            path: Some(path),
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Recover the data.
    pub fn ensure_data(&mut self) -> Result<()> {
        match self.raw {
            Some(..) => {}
            None => {
                ensure!(self.path.is_some(), "Missing path");
                let path = self.path.as_ref().unwrap();

                info!("restoring {}", path.display());

                let f_data = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .with_context(|| format!("could not open path={:?}", path))?;
                let data = unsafe {
                    memmap::MmapOptions::new()
                        .map_mut(&f_data)
                        .with_context(|| format!("could not mmap path={:?}", path))?
                };

                self.len = data.len();
                self.raw = Some(RawData::Mmap(data));
            }
        }

        Ok(())
    }

    /// Drops the actual data, if we can recover it.
    pub fn drop_data(&mut self) {
        if let Some(ref p) = self.path {
            info!("dropping data {}", p.display());
            self.raw.take();
        }
    }
}

pub trait PoRep<'a, H: Hasher, G: Hasher>: ProofScheme<'a> {
    type Tau;
    type ProverAux;

    fn replicate(
        pub_params: &'a Self::PublicParams,
        replica_id: &H::Domain,
        data: Data<'a>,
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
