use std::fs::OpenOptions;
use std::marker::PhantomData;
use std::path::PathBuf;

use anyhow::{ensure, Context};
use byteorder::{LittleEndian, WriteBytesExt};
use generic_array::typenum;
use merkletree::store::StoreConfig;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::drgraph::Graph;
use crate::encode;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::{BinaryLCMerkleTree, BinaryMerkleTree, LCMerkleTree, MerkleProof};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::PoRep;
use crate::proof::{NoRequirements, ProofScheme};
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};
use crate::Data;

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
pub struct ProverAux<H: Hasher> {
    pub tree_d: BinaryMerkleTree<H::Domain, H::Function>,
    pub tree_r: BinaryLCMerkleTree<H::Domain, H::Function>,
}

impl<H: Hasher> ProverAux<H> {
    pub fn new(
        tree_d: BinaryMerkleTree<H::Domain, H::Function>,
        tree_r: BinaryLCMerkleTree<H::Domain, H::Function>,
    ) -> Self {
        ProverAux { tree_d, tree_r }
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: Option<T>,
    pub challenges: Vec<usize>,
    pub tau: Option<Tau<T>>,
}

#[derive(Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub tree_d: &'a BinaryMerkleTree<H::Domain, H::Function>,
    pub tree_r: &'a BinaryLCMerkleTree<H::Domain, H::Function>,
    pub tree_r_config_levels: usize,
}

#[derive(Clone, Debug)]
pub struct SetupParams {
    pub drg: DrgParams,
    pub private: bool,
    pub challenges_count: usize,
}

#[derive(Debug, Clone)]
pub struct DrgParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    // Random seed
    pub seed: [u8; 28],
}

#[derive(Debug, Clone)]
pub struct PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    pub graph: G,
    pub private: bool,
    pub challenges_count: usize,

    _h: PhantomData<H>,
}

impl<H, G> PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    pub fn new(graph: G, private: bool, challenges_count: usize) -> Self {
        PublicParams {
            graph,
            private,
            challenges_count,
            _h: PhantomData,
        }
    }
}

impl<H, G> ParameterSetMetadata for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        format!(
            "drgporep::PublicParams{{graph: {}}}",
            self.graph.identifier(),
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof<H: Hasher, U: typenum::Unsigned> {
    #[serde(bound(
        serialize = "MerkleProof<H, U>: Serialize",
        deserialize = "MerkleProof<H, U>: Deserialize<'de>"
    ))]
    pub proof: MerkleProof<H, U>,
    pub data: H::Domain,
}

impl<H: Hasher, U: typenum::Unsigned> DataProof<H, U> {
    pub fn new(n: usize) -> Self {
        DataProof {
            proof: MerkleProof::new(n),
            data: Default::default(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.proof.serialize();
        let len = out.len();
        out.resize(len + 32, 0u8);
        // Unwrapping here is safe, all hash domain elements are 32 bytes long.
        self.data.write_bytes(&mut out[len..]).unwrap();

        out
    }

    /// proves_challenge returns true if this self.proof corresponds to challenge.
    /// This is useful for verifying that a supplied proof is actually relevant to a given challenge.
    pub fn proves_challenge(&self, challenge: usize) -> bool {
        self.proof.proves_challenge(challenge)
    }
}

pub type ReplicaParents<H> = Vec<(u32, DataProof<H, typenum::U2>)>;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub data_root: H::Domain,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub replica_root: H::Domain,
    #[serde(bound(
        serialize = "DataProof<H, typenum::U2>: Serialize",
        deserialize = "DataProof<H, typenum::U2>: Deserialize<'de>"
    ))]
    pub replica_nodes: Vec<DataProof<H, typenum::U2>>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub replica_parents: Vec<ReplicaParents<H>>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub nodes: Vec<DataProof<H, typenum::U2>>,
}

impl<H: Hasher> Proof<H> {
    pub fn new_empty(height: usize, degree: usize, challenges: usize) -> Proof<H> {
        Proof {
            data_root: Default::default(),
            replica_root: Default::default(),
            replica_nodes: vec![DataProof::new(height); challenges],
            replica_parents: vec![vec![(0, DataProof::new(height)); degree]; challenges],
            nodes: vec![DataProof::new(height); challenges],
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let res: Vec<_> = (0..self.nodes.len())
            .map(|i| {
                vec![
                    self.replica_nodes[i].serialize(),
                    self.replica_parents[i]
                        .iter()
                        .fold(Vec::new(), |mut acc, (s, p)| {
                            let mut v = vec![0u8; 4];
                            v.write_u32::<LittleEndian>(*s as u32).unwrap();
                            acc.extend(v);
                            acc.extend(p.serialize());
                            acc
                        }),
                    self.nodes[i].serialize(),
                ]
                .concat()
            })
            .collect::<Vec<Vec<u8>>>()
            .concat();

        res
    }

    pub fn new(
        replica_nodes: Vec<DataProof<H, typenum::U2>>,
        replica_parents: Vec<ReplicaParents<H>>,
        nodes: Vec<DataProof<H, typenum::U2>>,
    ) -> Proof<H> {
        Proof {
            data_root: *nodes[0].proof.root(),
            replica_root: *replica_nodes[0].proof.root(),
            replica_nodes,
            replica_parents,
            nodes,
        }
    }
}

impl<'a, H: Hasher> From<&'a Proof<H>> for Proof<H> {
    fn from(p: &Proof<H>) -> Proof<H> {
        Proof {
            data_root: *p.nodes[0].proof.root(),
            replica_root: *p.replica_nodes[0].proof.root(),
            replica_nodes: p.replica_nodes.clone(),
            replica_parents: p.replica_parents.clone(),
            nodes: p.nodes.clone(),
        }
    }
}

#[derive(Default)]
pub struct DrgPoRep<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H>,
{
    _h: PhantomData<&'a H>,
    _g: PhantomData<G>,
}

impl<'a, H, G> ProofScheme<'a> for DrgPoRep<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetMetadata,
{
    type PublicParams = PublicParams<H, G>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = G::new(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            sp.drg.seed,
        )?;

        Ok(PublicParams::new(graph, sp.private, sp.challenges_count))
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let len = pub_inputs.challenges.len();
        ensure!(
            len <= pub_params.challenges_count,
            "too many challenges {} > {}",
            len,
            pub_params.challenges_count
        );

        let mut replica_nodes = Vec::with_capacity(len);
        let mut replica_parents = Vec::with_capacity(len);
        let mut data_nodes: Vec<DataProof<H, typenum::U2>> = Vec::with_capacity(len);

        for i in 0..len {
            let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
            ensure!(challenge != 0, "cannot prove the first node");

            let tree_d = &priv_inputs.tree_d;
            let tree_r = &priv_inputs.tree_r;
            let tree_r_config_levels = priv_inputs.tree_r_config_levels;

            let data = tree_r.read_at(challenge)?;

            let tree_proof = {
                if tree_r_config_levels == 0 {
                    tree_r.gen_proof(challenge)?
                } else {
                    let (tree_proof, _) =
                        tree_r.gen_proof_and_partial_tree(challenge, tree_r_config_levels)?;

                    tree_proof
                }
            };
            replica_nodes.push(DataProof {
                proof: MerkleProof::new_from_proof(&tree_proof),
                data,
            });

            let mut parents = vec![0; pub_params.graph.degree()];
            pub_params.graph.parents(challenge, &mut parents)?;
            let mut replica_parentsi = Vec::with_capacity(parents.len());

            for p in &parents {
                replica_parentsi.push((*p, {
                    let proof = {
                        if tree_r_config_levels == 0 {
                            tree_r.gen_proof(*p as usize)?
                        } else {
                            let (proof, _) = tree_r
                                .gen_proof_and_partial_tree(*p as usize, tree_r_config_levels)?;

                            proof
                        }
                    };
                    DataProof {
                        proof: MerkleProof::new_from_proof(&proof),
                        data: tree_r.read_at(*p as usize)?,
                    }
                }));
            }

            replica_parents.push(replica_parentsi);

            let node_proof = tree_d.gen_proof(challenge)?;

            {
                // TODO: use this again, I can't make lifetimes work though atm and I do not know why
                // let extracted = Self::extract(
                //     pub_params,
                //     &pub_inputs.replica_id.into_bytes(),
                //     &replica,
                //     challenge,
                // )?;

                let extracted = decode_domain_block::<H>(
                    &pub_inputs.replica_id.context("missing replica_id")?,
                    tree_r,
                    challenge,
                    tree_r.read_at(challenge)?,
                    &parents,
                )?;
                data_nodes.push(DataProof {
                    data: extracted,
                    proof: MerkleProof::new_from_proof(&node_proof),
                });
            }
        }

        let proof = Proof::new(replica_nodes, replica_parents, data_nodes);

        Ok(proof)
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let mut hasher = Sha256::new();

        for i in 0..pub_inputs.challenges.len() {
            {
                // This was verify_proof_meta.
                if pub_inputs.challenges[i] >= pub_params.graph.size() {
                    return Ok(false);
                }

                if !(proof.nodes[i].proves_challenge(pub_inputs.challenges[i])) {
                    return Ok(false);
                }

                if !(proof.replica_nodes[i].proves_challenge(pub_inputs.challenges[i])) {
                    return Ok(false);
                }

                let mut expected_parents = vec![0; pub_params.graph.degree()];
                pub_params
                    .graph
                    .parents(pub_inputs.challenges[i], &mut expected_parents)?;
                if proof.replica_parents[i].len() != expected_parents.len() {
                    println!(
                        "proof parents were not the same length as in public parameters: {} != {}",
                        proof.replica_parents[i].len(),
                        expected_parents.len()
                    );
                    return Ok(false);
                }

                let parents_as_expected = proof.replica_parents[i]
                    .iter()
                    .zip(&expected_parents)
                    .all(|(actual, expected)| actual.0 == *expected);

                if !parents_as_expected {
                    println!("proof parents were not those provided in public parameters");
                    return Ok(false);
                }
            }

            let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
            ensure!(challenge != 0, "cannot prove the first node");

            if !proof.replica_nodes[i].proof.validate(challenge) {
                return Ok(false);
            }

            for (parent_node, p) in &proof.replica_parents[i] {
                if !p.proof.validate(*parent_node as usize) {
                    return Ok(false);
                }
            }

            let key = {
                let prover_bytes = pub_inputs.replica_id.context("missing replica_id")?;
                hasher.input(AsRef::<[u8]>::as_ref(&prover_bytes));

                for p in proof.replica_parents[i].iter() {
                    hasher.input(AsRef::<[u8]>::as_ref(&p.1.data));
                }

                let hash = hasher.result_reset();
                bytes_into_fr_repr_safe(hash.as_ref()).into()
            };

            let unsealed = encode::decode(key, proof.replica_nodes[i].data);

            if unsealed != proof.nodes[i].data {
                return Ok(false);
            }

            if !proof.nodes[i].proof.validate_data(unsealed) {
                println!("invalid data for merkle path {:?}", unsealed);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl<'a, H, G> PoRep<'a, H, H> for DrgPoRep<'a, H, G>
where
    H: 'a + Hasher,
    G::Key: AsRef<H::Domain>,
    G: 'a + Graph<H> + ParameterSetMetadata + Sync + Send,
{
    type Tau = Tau<H::Domain>;
    type ProverAux = ProverAux<H>;

    fn replicate(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
        mut data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<H::Domain, H::Function>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(Tau<H::Domain>, ProverAux<H>)> {
        use crate::cache_key::CacheKey;

        use std::io::prelude::*;

        let tree_d = match data_tree {
            Some(tree) => tree,
            None => pp.graph.merkle_tree(Some(config.clone()), data.as_ref())?,
        };

        let graph = &pp.graph;
        // encode(&pp.graph, replica_id, data, None)?;
        // Because a node always follows all of its parents in the data,
        // the nodes are by definition already topologically sorted.
        // Therefore, if we simply traverse the data in order, encoding each node in place,
        // we can always get each parent's encodings with a simple lookup --
        // since we will already have encoded the parent earlier in the traversal.

        let mut parents = vec![0; graph.degree()];
        for node in 0..graph.size() {
            graph.parents(node, &mut parents)?;
            let key = graph.create_key(replica_id, node, &parents, data.as_ref(), None)?;
            let start = data_at_node_offset(node);
            let end = start + NODE_SIZE;

            let node_data = H::Domain::try_from_bytes(&data.as_ref()[start..end])?;
            let encoded = H::sloth_encode(key.as_ref(), &node_data)?;

            encoded.write_bytes(&mut data.as_mut()[start..end])?;
        }

        // Write out the encoded data here.
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&replica_path)?;
        f.write_all(&data.as_ref())?;

        let tree_r_last_config =
            StoreConfig::from_config(&config, CacheKey::CommRLastTree.to_string(), None);
        let tree_r: BinaryLCMerkleTree<_, _> =
            pp.graph
                .lcmerkle_tree(tree_r_last_config, &data.as_ref(), &replica_path)?;

        let comm_d = tree_d.root();
        let comm_r = tree_r.root();

        Ok((Tau::new(comm_d, comm_r), ProverAux::new(tree_d, tree_r)))
    }

    fn extract_all<'b>(
        pp: &'b Self::PublicParams,
        replica_id: &'b H::Domain,
        data: &'b [u8],
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        decode(&pp.graph, replica_id, data, None)
    }

    fn extract(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
        data: &[u8],
        node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<Vec<u8>> {
        Ok(decode_block(&pp.graph, replica_id, data, None, node)?.into_bytes())
    }
}

pub fn decode<'a, H, G>(
    graph: &'a G,
    replica_id: &'a H::Domain,
    data: &'a [u8],
    exp_parents_data: Option<&'a [u8]>,
) -> Result<Vec<u8>>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H> + Sync,
{
    // TODO: proper error handling
    let result = (0..graph.size())
        .into_par_iter()
        .flat_map(|i| {
            decode_block(graph, replica_id, data, exp_parents_data, i)
                .unwrap()
                .into_bytes()
        })
        .collect();

    Ok(result)
}

pub fn decode_block<'a, H, G>(
    graph: &'a G,
    replica_id: &'a H::Domain,
    data: &'a [u8],
    exp_parents_data: Option<&'a [u8]>,
    v: usize,
) -> Result<H::Domain>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H>,
{
    let mut parents = vec![0; graph.degree()];
    graph.parents(v, &mut parents)?;
    let key = graph.create_key(replica_id, v, &parents, &data, exp_parents_data)?;
    let node_data = H::Domain::try_from_bytes(&data_at_node(data, v)?)?;

    Ok(encode::decode(*key.as_ref(), node_data))
}

pub fn decode_domain_block<H>(
    replica_id: &H::Domain,
    tree: &BinaryLCMerkleTree<H::Domain, H::Function>,
    node: usize,
    node_data: <H as Hasher>::Domain,
    parents: &[u32],
) -> Result<H::Domain>
where
    H: Hasher,
{
    let key = create_key_from_tree::<H, _>(replica_id, node, parents, tree)?;

    Ok(encode::decode(key, node_data))
}

/// Creates the encoding key from a `MerkleTree`.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key_from_tree<H: Hasher, U: typenum::Unsigned>(
    id: &H::Domain,
    node: usize,
    parents: &[u32],
    tree: &LCMerkleTree<H::Domain, H::Function, U>,
) -> Result<H::Domain> {
    let mut hasher = Sha256::new();
    hasher.input(AsRef::<[u8]>::as_ref(&id));

    // The hash is about the parents, hence skip if a node doesn't have any parents
    if node != parents[0] as usize {
        let mut scratch: [u8; NODE_SIZE] = [0; NODE_SIZE];
        for parent in parents.iter() {
            tree.read_into(*parent as usize, &mut scratch)?;
            hasher.input(&scratch);
        }
    }

    let hash = hasher.result();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}

pub fn replica_id<H: Hasher>(prover_id: [u8; 32], sector_id: [u8; 32]) -> H::Domain {
    let mut to_hash = [0; 64];
    to_hash[..32].copy_from_slice(&prover_id);
    to_hash[32..].copy_from_slice(&sector_id);

    H::Function::hash_leaf(&to_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use memmap::MmapMut;
    use memmap::MmapOptions;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::fs::File;
    use std::io::Write;
    use tempfile;

    use crate::cache_key::CacheKey;
    use crate::drgraph::{new_seed, BucketGraph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::porep::stacked::BINARY_ARITY;
    use crate::util::data_at_node;

    pub fn file_backed_mmap_from(data: &[u8]) -> MmapMut {
        let mut tmpfile: File = tempfile::tempfile().expect("Failed to create tempfile");
        tmpfile
            .write_all(data)
            .expect("Failed to write data to tempfile");

        unsafe {
            MmapOptions::new()
                .map_mut(&tmpfile)
                .expect("Failed to back memory map with tempfile")
        }
    }

    fn test_extract_all<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: H::Domain = H::Domain::random(rng);
        let data = vec![2u8; 32 * 4];

        // create a copy, so we can compare roundtrips
        let mut mmapped_data_copy = file_backed_mmap_from(&data);

        let sp = SetupParams {
            drg: DrgParams {
                nodes: data.len() / 32,
                degree: BASE_DEGREE,
                expansion_degree: 0,
                seed: new_seed(),
            },
            private: false,
            challenges_count: 1,
        };

        let pp = DrgPoRep::<H, BucketGraph<H>>::setup(&sp).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(data.len() / 32, BINARY_ARITY),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("test-extract-all").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        DrgPoRep::replicate(
            &pp,
            &replica_id,
            (mmapped_data_copy.as_mut()).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        let decoded_data = DrgPoRep::extract_all(
            &pp,
            &replica_id,
            &mut mmapped_data_copy,
            Some(config.clone()),
        )
        .unwrap_or_else(|e| {
            panic!("Failed to extract data from `DrgPoRep`: {}", e);
        });

        assert_eq!(data, decoded_data.as_slice(), "failed to extract data");
    }

    #[test]
    fn extract_all_pedersen() {
        test_extract_all::<PedersenHasher>();
    }

    #[test]
    fn extract_all_sha256() {
        test_extract_all::<Sha256Hasher>();
    }

    #[test]
    fn extract_all_blake2s() {
        test_extract_all::<Blake2sHasher>();
    }

    fn test_extract<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let replica_id: H::Domain = H::Domain::random(rng);
        let nodes = 4;
        let data = vec![2u8; 32 * nodes];

        // create a copy, so we can compare roundtrips
        let mut mmapped_data_copy = file_backed_mmap_from(&data);

        let sp = SetupParams {
            drg: DrgParams {
                nodes: data.len() / 32,
                degree: BASE_DEGREE,
                expansion_degree: 0,
                seed: new_seed(),
            },
            private: false,
            challenges_count: 1,
        };

        let pp = DrgPoRep::<H, BucketGraph<H>>::setup(&sp).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempfile::tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            StoreConfig::default_cached_above_base_layer(data.len() / 32, BINARY_ARITY),
        );

        // Generate a replica path.
        let temp_dir = tempdir::TempDir::new("test-extract").unwrap();
        let temp_path = temp_dir.path();
        let replica_path = temp_path.join("replica-path");

        DrgPoRep::replicate(
            &pp,
            &replica_id,
            (mmapped_data_copy.as_mut()).into(),
            None,
            config.clone(),
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        for i in 0..nodes {
            let decoded_data = DrgPoRep::extract(
                &pp,
                &replica_id,
                &mmapped_data_copy,
                i,
                Some(config.clone()),
            )
            .expect("failed to extract node data from PoRep");

            let original_data = data_at_node(&data, i).unwrap();

            assert_eq!(
                original_data,
                decoded_data.as_slice(),
                "failed to extract data"
            );
        }
    }

    #[test]
    fn extract_pedersen() {
        test_extract::<PedersenHasher>();
    }

    #[test]
    fn extract_sha256() {
        test_extract::<Sha256Hasher>();
    }

    #[test]
    fn extract_blake2s() {
        test_extract::<Blake2sHasher>();
    }

    fn prove_verify_aux<H: Hasher>(
        nodes: usize,
        i: usize,
        use_wrong_challenge: bool,
        use_wrong_parents: bool,
    ) {
        assert!(i < nodes);

        // The loop is here in case we need to retry because of an edge case in the test design.
        loop {
            let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
            let degree = BASE_DEGREE;
            let expansion_degree = 0;
            let seed = new_seed();

            let replica_id: H::Domain = H::Domain::random(rng);
            let data: Vec<u8> = (0..nodes)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            // create a copy, so we can comare roundtrips
            let mut mmapped_data_copy = file_backed_mmap_from(&data);

            let challenge = i;

            let sp = SetupParams {
                drg: DrgParams {
                    nodes,
                    degree,
                    expansion_degree,
                    seed,
                },
                private: false,
                challenges_count: 2,
            };

            let pp = DrgPoRep::<H, BucketGraph<_>>::setup(&sp).expect("setup failed");

            // MT for original data is always named tree-d, and it will be
            // referenced later in the process as such.
            let cache_dir = tempfile::tempdir().unwrap();
            let config = StoreConfig::new(
                cache_dir.path(),
                CacheKey::CommDTree.to_string(),
                StoreConfig::default_cached_above_base_layer(nodes, BINARY_ARITY),
            );

            // Generate a replica path.
            let temp_dir = tempdir::TempDir::new("prove-verify-aux").unwrap();
            let temp_path = temp_dir.path();
            let replica_path = temp_path.join("replica-path");

            let (tau, aux) = DrgPoRep::<H, _>::replicate(
                &pp,
                &replica_id,
                (mmapped_data_copy.as_mut()).into(),
                None,
                config,
                replica_path.clone(),
            )
            .expect("replication failed");

            let mut copied = vec![0; data.len()];
            copied.copy_from_slice(&mmapped_data_copy);

            assert_ne!(data, copied, "replication did not change data");

            let pub_inputs = PublicInputs::<H::Domain> {
                replica_id: Some(replica_id),
                challenges: vec![challenge, challenge],
                tau: Some(tau.clone().into()),
            };

            let priv_inputs = PrivateInputs::<H> {
                tree_d: &aux.tree_d,
                tree_r: &aux.tree_r,
                tree_r_config_levels: StoreConfig::default_cached_above_base_layer(
                    nodes,
                    BINARY_ARITY,
                ),
            };

            let real_proof =
                DrgPoRep::<H, _>::prove(&pp, &pub_inputs, &priv_inputs).expect("proving failed");

            if use_wrong_parents {
                // Only one 'wrong' option will be tested at a time.
                assert!(!use_wrong_challenge);
                let real_parents = real_proof.replica_parents;

                // Parent vector claiming the wrong parents.
                let fake_parents = vec![real_parents[0]
                    .iter()
                    // Incrementing each parent node will give us a different parent set.
                    // It's fine to be out of range, since this only needs to fail.
                    .map(|(i, data_proof)| (i + 1, data_proof.clone()))
                    .collect::<Vec<_>>()];

                let proof = Proof::new(
                    real_proof.replica_nodes.clone(),
                    fake_parents,
                    real_proof.nodes.clone().into(),
                );

                let is_valid =
                    DrgPoRep::verify(&pp, &pub_inputs, &proof).expect("verification failed");

                assert!(!is_valid, "verified in error -- with wrong parents");

                let mut all_same = true;
                for (p, _) in &real_parents[0] {
                    if *p != real_parents[0][0].0 {
                        all_same = false;
                    }
                }

                if all_same {
                    println!("invalid test data can't scramble proofs with all same parents.");

                    // If for some reason, we hit this condition because of the data passeed in,
                    // try again.
                    continue;
                }

                // Parent vector claiming the right parents but providing valid proofs for different
                // parents.
                let fake_proof_parents = vec![real_parents[0]
                    .iter()
                    .enumerate()
                    .map(|(i, (p, _))| {
                        // Rotate the real parent proofs.
                        let x = (i + 1) % real_parents[0].len();
                        let j = real_parents[0][x].0;
                        (*p, real_parents[0][j as usize].1.clone())
                    })
                    .collect::<Vec<_>>()];

                let proof2 = Proof::new(
                    real_proof.replica_nodes,
                    fake_proof_parents,
                    real_proof.nodes.into(),
                );

                assert!(
                    !DrgPoRep::<H, _>::verify(&pp, &pub_inputs, &proof2).unwrap_or_else(|e| {
                        panic!("Verification failed: {}", e);
                    }),
                    "verified in error -- with wrong parent proofs"
                );

                return ();
            }

            let proof = real_proof;

            if use_wrong_challenge {
                let pub_inputs_with_wrong_challenge_for_proof = PublicInputs::<H::Domain> {
                    replica_id: Some(replica_id),
                    challenges: vec![if challenge == 1 { 2 } else { 1 }],
                    tau: Some(tau.into()),
                };
                let verified = DrgPoRep::<H, _>::verify(
                    &pp,
                    &pub_inputs_with_wrong_challenge_for_proof,
                    &proof,
                )
                .expect("Verification failed");
                assert!(
                    !verified,
                    "wrongly verified proof which does not match challenge in public input"
                );
            } else {
                assert!(
                    DrgPoRep::<H, _>::verify(&pp, &pub_inputs, &proof)
                        .expect("verification failed"),
                    "failed to verify"
                );
            }

            // Normally, just run once.
            break;
        }
    }

    fn prove_verify(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher>(n, i, false, false);
        prove_verify_aux::<Sha256Hasher>(n, i, false, false);
        prove_verify_aux::<Blake2sHasher>(n, i, false, false);
    }

    fn prove_verify_wrong_challenge(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher>(n, i, true, false);
        prove_verify_aux::<Sha256Hasher>(n, i, true, false);
        prove_verify_aux::<Blake2sHasher>(n, i, true, false);
    }

    fn prove_verify_wrong_parents(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher>(n, i, false, true);
        prove_verify_aux::<Sha256Hasher>(n, i, false, true);
        prove_verify_aux::<Blake2sHasher>(n, i, false, true);
    }

    table_tests! {
        prove_verify {
            prove_verify_32_16_1(16, 1);

            prove_verify_32_64_1(64, 1);
            prove_verify_32_64_2(64, 2);

            prove_verify_32_256_1(256, 1);
            prove_verify_32_256_2(256, 2);
            prove_verify_32_256_3(256, 3);
            prove_verify_32_256_4(256, 4);
            prove_verify_32_256_5(256, 5);
        }
    }

    #[test]
    fn test_drgporep_verifies_using_challenge() {
        prove_verify_wrong_challenge(8, 1);
    }

    #[test]
    fn test_drgporep_verifies_parents() {
        // Challenge a node (3) that doesn't have all the same parents.
        prove_verify_wrong_parents(8, 5);
    }
}
