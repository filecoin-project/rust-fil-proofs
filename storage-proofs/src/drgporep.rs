use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use byteorder::{LittleEndian, WriteBytesExt};
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::{HybridMerkleProof, HybridMerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::{self, PoRep};
use crate::proof::{NoRequirements, ProofScheme};
use crate::vde::{self, decode_block, decode_domain_block};

// The type parameters `A` and `B` are abbreviations for "Alpha Hasher Domain" and "Beta Hasher
// Domain" respectively. Hybrid Merkle Tree commitments/roots/taus are from the alpha domain,
// replica-ids are from the beta hasher's domain.
#[derive(Debug, Clone)]
pub struct PublicInputs<A, B>
where
    A: Domain,
    B: Domain,
{
    pub replica_id: Option<B>,
    pub challenges: Vec<usize>,
    pub tau: Option<porep::Tau<A>>,
}

#[derive(Debug)]
pub struct PrivateInputs<'a, AH, BH>
where
    AH: 'a + Hasher,
    BH: 'a + Hasher,
{
    pub tree_d: &'a HybridMerkleTree<AH, BH>,
    pub tree_r: &'a HybridMerkleTree<AH, BH>,
}

#[derive(Debug)]
pub struct SetupParams {
    pub drg: DrgParams,
    pub sloth_iter: usize,
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
    pub seed: [u32; 7],
}

#[derive(Debug, Clone)]
pub struct PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    pub graph: G,
    pub sloth_iter: usize,
    pub private: bool,
    pub challenges_count: usize,
    _bh: PhantomData<BH>,
    _ah: PhantomData<AH>,
}

impl<AH, BH, G> PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    pub fn new(graph: G, sloth_iter: usize, private: bool, challenges_count: usize) -> Self {
        PublicParams {
            graph,
            sloth_iter,
            private,
            challenges_count,
            _bh: PhantomData,
            _ah: PhantomData,
        }
    }
}

impl<AH, BH, G> ParameterSetMetadata for PublicParams<AH, BH, G>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        format!(
            "drgporep::PublicParams{{graph: {}; sloth_iter: {}}}",
            self.graph.identifier(),
            self.sloth_iter
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    // (jake) TODO: as these serde bounds correct?
    #[serde(bound(
        serialize = "HybridMerkleProof<AH, BH>: Serialize",
        deserialize = "HybridMerkleProof<AH, BH>: Deserialize<'de>"
    ))]
    pub proof: HybridMerkleProof<AH, BH>,
    pub data: BH::Domain,
}

impl<AH, BH> DataProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new_empty(tree_height: usize) -> Self {
        DataProof {
            proof: HybridMerkleProof::new_empty(tree_height),
            data: BH::Domain::default(),
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

    /// Returns `true` if this proof corresponds to `challenge` by checking the challenge against
    /// its "is_right" bits (`self.proof.path`). This is useful for verifying that a supplied proof
    /// is actually relevant to a given challenge.
    ///
    /// Note that for a given node in a Merkle Tree that has a layer index of `x` ("layer index"
    /// refers to the number of nodes to the right a given node is in its Merkle Tree layer, which
    /// differs from a node's index in the entire Merkle Tree), that the node's child's layer index
    /// (i.e. the number of nodes to the right that the child is in the above Merkle Tree layer) can
    /// be calculated by right shifting `x` by 1.
    pub fn proves_challenge(&self, challenge: usize) -> bool {
        let mut index_in_layer = challenge;

        for (_, is_right_proof) in self.proof.beta_path() {
            let is_right_calculated = (index_in_layer & 1) == 1;
            let bits_are_different = is_right_calculated ^ is_right_proof;
            if bits_are_different {
                return false;
            };
            index_in_layer >>= 1;
        }

        for (_, is_right_proof) in self.proof.alpha_path() {
            let is_right_calculated = (index_in_layer & 1) == 1;
            let bits_are_different = is_right_calculated ^ is_right_proof;
            if bits_are_different {
                return false;
            };
            index_in_layer >>= 1;
        }

        true
    }
}

pub type ReplicaParents<AH, BH> = Vec<(usize, DataProof<AH, BH>)>;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Proof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    #[serde(bound(
        serialize = "AH::Domain: Serialize",
        deserialize = "AH::Domain: Deserialize<'de>"
    ))]
    pub data_root: AH::Domain,

    #[serde(bound(
        serialize = "AH::Domain: Serialize",
        deserialize = "AH::Domain: Deserialize<'de>"
    ))]
    pub replica_root: AH::Domain,

    #[serde(bound(
        serialize = "DataProof<AH, BH>: Serialize",
        deserialize = "DataProof<AH, BH>: Deserialize<'de>"
    ))]
    pub replica_nodes: Vec<DataProof<AH, BH>>,

    // (jake) TODO: are these serde bounds right?
    #[serde(bound(
        serialize = "ReplicaParents<AH, BH>: Serialize",
        deserialize = "ReplicaParents<AH, BH>: Deserialize<'de>"
    ))]
    pub replica_parents: Vec<ReplicaParents<AH, BH>>,

    #[serde(bound(
        serialize = "DataProof<AH, BH>: Serialize",
        deserialize = "DataProof<AH, BH>: Deserialize<'de>"
    ))]
    pub nodes: Vec<DataProof<AH, BH>>,
}

impl<AH, BH> Proof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new_empty(height: usize, degree: usize, n_challenges: usize) -> Self {
        let replica_nodes = vec![DataProof::new_empty(height); n_challenges];
        let replica_parents = vec![vec![(0, DataProof::new_empty(height)); degree]; n_challenges];
        let nodes = vec![DataProof::new_empty(height); n_challenges];

        Proof {
            replica_nodes,
            replica_parents,
            nodes,
            ..Default::default()
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
        replica_nodes: Vec<DataProof<AH, BH>>,
        replica_parents: Vec<ReplicaParents<AH, BH>>,
        nodes: Vec<DataProof<AH, BH>>,
    ) -> Self {
        Proof {
            data_root: *nodes[0].proof.root(),
            replica_root: *replica_nodes[0].proof.root(),
            replica_nodes,
            replica_parents,
            nodes,
        }
    }
}

#[derive(Default)]
pub struct DrgPoRep<'a, AH, BH, G>
where
    AH: 'a + Hasher,
    BH: 'a + Hasher,
    G: 'a + Graph<AH, BH>,
{
    _ah: PhantomData<&'a AH>,
    _bh: PhantomData<&'a BH>,
    _g: PhantomData<G>,
}

impl<'a, AH, BH, G> ProofScheme<'a> for DrgPoRep<'a, AH, BH, G>
where
    AH: 'a + Hasher,
    BH: 'a + Hasher,
    G: 'a + Graph<AH, BH> + ParameterSetMetadata,
{
    type PublicParams = PublicParams<AH, BH, G>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<AH::Domain, BH::Domain>;
    type PrivateInputs = PrivateInputs<'a, AH, BH>;
    type Proof = Proof<AH, BH>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = G::new(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            sp.drg.seed,
        );

        Ok(PublicParams::new(
            graph,
            sp.sloth_iter,
            sp.private,
            sp.challenges_count,
        ))
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let len = pub_inputs.challenges.len();
        assert!(
            len <= pub_params.challenges_count,
            "too many challenges {} > {}",
            len,
            pub_params.challenges_count
        );

        let mut replica_nodes = Vec::with_capacity(len);
        let mut replica_parents = Vec::with_capacity(len);
        let mut data_nodes: Vec<DataProof<AH, BH>> = Vec::with_capacity(len);

        for i in 0..len {
            let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
            assert_ne!(challenge, 0, "cannot prove the first node");

            let tree_d = &priv_inputs.tree_d;
            let tree_r = &priv_inputs.tree_r;

            let data = tree_r
                .read_at(challenge)
                .beta
                .expect("hybrid merkle tree does not contain challenge leaf");

            replica_nodes.push(DataProof {
                data,
                proof: tree_r.gen_proof(challenge),
            });

            let mut parents = vec![0; pub_params.graph.degree()];
            pub_params.graph.parents(challenge, &mut parents);
            let mut replica_parentsi = Vec::with_capacity(parents.len());

            for p in &parents {
                let data = tree_r
                    .read_at(*p)
                    .beta
                    .expect("parent node does not exist in the hybrid merkle tree's leaf tree");

                let proof = tree_r.gen_proof(*p);

                replica_parentsi.push((*p, DataProof { data, proof }));
            }

            replica_parents.push(replica_parentsi);

            let node_proof = tree_d.gen_proof(challenge);

            // TODO: use this again, I can't make lifetimes work though atm and I do not know why
            // let extracted = Self::extract(
            //     pub_params,
            //     &pub_inputs.replica_id.into_bytes(),
            //     &replica,
            //     challenge,
            // )?;

            let extracted = decode_domain_block::<AH, BH>(
                pub_params.sloth_iter,
                &pub_inputs.replica_id.expect("missing replica_id"),
                tree_r,
                challenge,
                data,
                &parents,
            )?;

            data_nodes.push(DataProof {
                data: extracted,
                proof: node_proof,
            });
        }

        Ok(Proof::new(replica_nodes, replica_parents, data_nodes))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
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
                    .parents(pub_inputs.challenges[i], &mut expected_parents);
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
            assert_ne!(challenge, 0, "cannot prove the first node");

            if !proof.replica_nodes[i].proof.validate(challenge) {
                return Ok(false);
            }

            for (parent_node, p) in &proof.replica_parents[i] {
                if !p.proof.validate(*parent_node) {
                    return Ok(false);
                }
            }

            let key = {
                let mut hasher = Blake2s::new().hash_length(32).to_state();
                let prover_bytes = pub_inputs.replica_id.expect("missing replica_id");
                hasher.update(prover_bytes.as_ref());

                for p in proof.replica_parents[i].iter() {
                    hasher.update(p.1.data.as_ref());
                }

                let hash = hasher.finalize();
                bytes_into_fr_repr_safe(hash.as_ref()).into()
            };

            let unsealed =
                BH::sloth_decode(&key, &proof.replica_nodes[i].data, pub_params.sloth_iter);

            if unsealed != proof.nodes[i].data {
                return Ok(false);
            }

            if !proof.nodes[i]
                .proof
                .validate_challenge_value_as_bytes(&unsealed.into_bytes())
            {
                println!("invalid data for merkle path {:?}", unsealed);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl<'a, AH, BH, G> PoRep<'a, AH, BH> for DrgPoRep<'a, AH, BH, G>
where
    AH: 'a + Hasher,
    BH: 'a + Hasher,
    G: 'a + Graph<AH, BH> + ParameterSetMetadata + Sync + Send,
{
    type Tau = porep::Tau<AH::Domain>;
    type ProverAux = porep::ProverAux<AH, BH>;

    #[allow(clippy::type_complexity)]
    fn replicate(
        pp: &Self::PublicParams,
        replica_id: &BH::Domain,
        data: &mut [u8],
        data_tree: Option<HybridMerkleTree<AH, BH>>,
    ) -> Result<(porep::Tau<AH::Domain>, porep::ProverAux<AH, BH>)> {
        let tree_d = match data_tree {
            Some(tree) => tree,
            None => pp
                .graph
                .hybrid_merkle_tree(data)
                .expect("failed to create hybrid merkle tree from data"),
        };
        let comm_d = tree_d.root();
        vde::encode(&pp.graph, pp.sloth_iter, replica_id, data).expect("vde failed");
        let tree_r = pp
            .graph
            .hybrid_merkle_tree(data)
            .expect("failed to create hybrid merkle tree from replicated data");
        let comm_r = tree_r.root();
        Ok((
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        ))
    }

    fn extract_all<'b>(
        pp: &'b Self::PublicParams,
        replica_id: &'b BH::Domain,
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        vde::decode(&pp.graph, pp.sloth_iter, replica_id, data)
    }

    fn extract(
        pp: &Self::PublicParams,
        replica_id: &BH::Domain,
        data: &[u8],
        node: usize,
    ) -> Result<Vec<u8>> {
        Ok(decode_block(&pp.graph, pp.sloth_iter, replica_id, data, node)?.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::fs::File;
    use std::io::Write;
    use tempfile;

    use crate::drgraph::{new_seed, BucketGraph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::hybrid_merkle::MIN_N_LEAVES;
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

    fn test_extract_all<AH, BH>()
    where
        AH: Hasher,
        BH: Hasher,
    {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sloth_iter = 1;
        let replica_id: BH::Domain = rng.gen();
        let data = vec![2u8; 32 * MIN_N_LEAVES];
        // create a copy, so we can compare roundtrips
        let mut mmapped_data_copy = file_backed_mmap_from(&data);

        let sp = SetupParams {
            drg: DrgParams {
                nodes: data.len() / 32,
                degree: 5,
                expansion_degree: 0,
                seed: new_seed(),
            },
            sloth_iter,
            private: false,
            challenges_count: 1,
        };

        let pp = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::setup(&sp).expect("setup failed");

        DrgPoRep::replicate(&pp, &replica_id, &mut mmapped_data_copy, None)
            .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        let decoded_data = DrgPoRep::extract_all(&pp, &replica_id, &mut mmapped_data_copy)
            .unwrap_or_else(|e| {
                panic!("Failed to extract data from `DrgPoRep`: {}", e);
            });

        assert_eq!(data, decoded_data.as_slice(), "failed to extract data");
    }

    #[test]
    fn extract_all_pedersen() {
        test_extract_all::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn extract_all_sha256() {
        test_extract_all::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn extract_all_blake2s() {
        test_extract_all::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn extract_all_pedersen_blake2s() {
        test_extract_all::<PedersenHasher, Blake2sHasher>();
    }

    fn test_extract<AH, BH>()
    where
        AH: Hasher,
        BH: Hasher,
    {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sloth_iter = 1;
        let replica_id: BH::Domain = rng.gen();
        let nodes = MIN_N_LEAVES;
        let data = vec![2u8; 32 * nodes];

        // create a copy, so we can compare roundtrips
        let mut mmapped_data_copy = file_backed_mmap_from(&data);

        let sp = SetupParams {
            drg: DrgParams {
                nodes: data.len() / 32,
                degree: 5,
                expansion_degree: 0,
                seed: new_seed(),
            },
            sloth_iter,
            private: false,
            challenges_count: 1,
        };

        let pp = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::setup(&sp).expect("setup failed");

        DrgPoRep::replicate(&pp, &replica_id, &mut mmapped_data_copy, None)
            .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        for i in 0..nodes {
            let decoded_data = DrgPoRep::extract(&pp, &replica_id, &mmapped_data_copy, i)
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
        test_extract::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn extract_sha256() {
        test_extract::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn extract_blake2s() {
        test_extract::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn extract_pedersen_blake2s() {
        test_extract::<PedersenHasher, Blake2sHasher>();
    }

    fn prove_verify_aux<AH, BH>(
        nodes: usize,
        i: usize,
        use_wrong_challenge: bool,
        use_wrong_parents: bool,
    ) where
        AH: Hasher,
        BH: Hasher,
    {
        assert!(i < nodes);

        // The loop is here in case we need to retry because of an edge case in the test design.
        loop {
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let sloth_iter = 1;
            let degree = 10;
            let expansion_degree = 0;
            let seed = new_seed();

            let replica_id: BH::Domain = rng.gen();
            let data: Vec<u8> = (0..nodes)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
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
                sloth_iter,
                private: false,
                challenges_count: 2,
            };

            let pp = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::setup(&sp).expect("setup failed");

            let (tau, aux) = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::replicate(
                &pp,
                &replica_id,
                &mut mmapped_data_copy,
                None,
            )
            .expect("replication failed");

            let mut copied = vec![0; data.len()];
            copied.copy_from_slice(&mmapped_data_copy);

            assert_ne!(data, copied, "replication did not change data");

            let pub_inputs = PublicInputs::<AH::Domain, BH::Domain> {
                replica_id: Some(replica_id),
                challenges: vec![challenge, challenge],
                tau: Some(tau.clone().into()),
            };

            let priv_inputs = PrivateInputs::<AH, BH> {
                tree_d: &aux.tree_d,
                tree_r: &aux.tree_r,
            };

            let real_proof =
                DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::prove(&pp, &pub_inputs, &priv_inputs)
                    .expect("proving failed");

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
                        (*p, real_parents[0][j].1.clone())
                    })
                    .collect::<Vec<_>>()];

                let proof2 = Proof::new(
                    real_proof.replica_nodes,
                    fake_proof_parents,
                    real_proof.nodes.into(),
                );

                let is_valid =
                    DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::verify(&pp, &pub_inputs, &proof2)
                        .unwrap_or_else(|e| panic!("Verification failed: {}", e));

                assert!(!is_valid, "verified in error -- with wrong parent proofs");

                return ();
            }

            let proof = real_proof;

            if use_wrong_challenge {
                let pub_inputs_with_wrong_challenge_for_proof =
                    PublicInputs::<AH::Domain, BH::Domain> {
                        replica_id: Some(replica_id),
                        challenges: vec![if challenge == 1 { 2 } else { 1 }],
                        tau: Some(tau.into()),
                    };
                let verified = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::verify(
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
                    DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::verify(&pp, &pub_inputs, &proof)
                        .expect("verification failed"),
                    "failed to verify"
                );
            }

            // Normally, just run once.
            break;
        }
    }

    fn prove_verify(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher, PedersenHasher>(n, i, false, false);
        prove_verify_aux::<Sha256Hasher, Sha256Hasher>(n, i, false, false);
        prove_verify_aux::<Blake2sHasher, Blake2sHasher>(n, i, false, false);
        prove_verify_aux::<PedersenHasher, Blake2sHasher>(n, i, false, false);
    }

    fn prove_verify_wrong_challenge(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher, PedersenHasher>(n, i, true, false);
        prove_verify_aux::<Sha256Hasher, Sha256Hasher>(n, i, true, false);
        prove_verify_aux::<Blake2sHasher, Blake2sHasher>(n, i, true, false);
        prove_verify_aux::<PedersenHasher, Blake2sHasher>(n, i, true, false);
    }

    fn prove_verify_wrong_parents(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher, PedersenHasher>(n, i, false, true);
        prove_verify_aux::<Sha256Hasher, Sha256Hasher>(n, i, false, true);
        prove_verify_aux::<Blake2sHasher, Blake2sHasher>(n, i, false, true);
        prove_verify_aux::<PedersenHasher, Blake2sHasher>(n, i, false, true);
    }

    table_tests! {
        prove_verify {
            prove_verify_32_16_1(16, 1);
            prove_verify_32_16_2(16, 2);
            prove_verify_32_16_3(16, 3);
            prove_verify_32_16_4(16, 4);
            prove_verify_32_16_5(16, 5);
        }
    }

    #[test]
    fn test_drgporep_verifies_using_challenge() {
        prove_verify_wrong_challenge(MIN_N_LEAVES, 1);
    }

    #[test]
    fn test_drgporep_verifies_parents() {
        // Challenge a node that doesn't have all the same parents.
        prove_verify_wrong_parents(MIN_N_LEAVES, 4);
    }
}
