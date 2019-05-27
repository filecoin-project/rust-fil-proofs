use std::marker::PhantomData;

use blake2s_simd::Params as Blake2s;
use byteorder::{LittleEndian, WriteBytesExt};
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetIdentifier;
use crate::porep::{self, PoRep};
use crate::proof::{NoRequirements, ProofScheme};
use crate::vde::{self, decode_block, decode_domain_block};

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: Option<T>,
    pub challenges: Vec<usize>,
    pub tau: Option<porep::Tau<T>>,
}

#[derive(Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub tree_d: &'a MerkleTree<H::Domain, H::Function>,
    pub tree_r: &'a MerkleTree<H::Domain, H::Function>,
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
pub struct PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    pub graph: G,
    pub sloth_iter: usize,
    pub private: bool,
    pub challenges_count: usize,

    _h: PhantomData<H>,
}

impl<H, G> PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    pub fn new(graph: G, sloth_iter: usize, private: bool, challenges_count: usize) -> Self {
        PublicParams {
            graph,
            sloth_iter,
            private,
            challenges_count,
            _h: PhantomData,
        }
    }
}

impl<H, G> ParameterSetIdentifier for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    fn parameter_set_identifier(&self) -> String {
        format!(
            "drgporep::PublicParams{{graph: {}; sloth_iter: {}}}",
            self.graph.parameter_set_identifier(),
            self.sloth_iter
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    pub proof: MerkleProof<H>,
    pub data: H::Domain,
}

impl<H: Hasher> DataProof<H> {
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
        self.data.write_bytes(&mut out[len..]).unwrap();

        out
    }

    /// proves_challenge returns true if this self.proof corresponds to challenge.
    /// This is useful for verifying that a supplied proof is actually relevant to a given challenge.
    pub fn proves_challenge(&self, challenge: usize) -> bool {
        let mut c = challenge;
        for (_, is_right) in self.proof.path().iter() {
            if ((c & 1) == 1) ^ is_right {
                return false;
            };
            c >>= 1;
        }
        true
    }
}

pub type ReplicaParents<H> = Vec<(usize, DataProof<H>)>;

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
        serialize = "DataProof<H>: Serialize",
        deserialize = "DataProof<H>: Deserialize<'de>"
    ))]
    pub replica_nodes: Vec<DataProof<H>>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub replica_parents: Vec<ReplicaParents<H>>,
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub nodes: Vec<DataProof<H>>,
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
        replica_nodes: Vec<DataProof<H>>,
        replica_parents: Vec<ReplicaParents<H>>,
        nodes: Vec<DataProof<H>>,
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
    G: 'a + Graph<H> + ParameterSetIdentifier,
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
        let mut data_nodes: Vec<DataProof<H>> = Vec::with_capacity(len);

        for i in 0..len {
            let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
            assert_ne!(challenge, 0, "cannot prove the first node");

            let tree_d = &priv_inputs.tree_d;
            let tree_r = &priv_inputs.tree_r;

            let data = tree_r.read_at(challenge);

            replica_nodes.push(DataProof {
                proof: MerkleProof::new_from_proof(&tree_r.gen_proof(challenge)),
                data,
            });

            let mut parents = vec![0; pub_params.graph.degree()];
            pub_params.graph.parents(challenge, &mut parents);
            let mut replica_parentsi = Vec::with_capacity(parents.len());

            for p in &parents {
                replica_parentsi.push((*p, {
                    let proof = tree_r.gen_proof(*p);
                    DataProof {
                        proof: MerkleProof::new_from_proof(&proof),
                        data: tree_r.read_at(*p),
                    }
                }));
            }

            replica_parents.push(replica_parentsi);

            let node_proof = tree_d.gen_proof(challenge);

            {
                // TODO: use this again, I can't make lifetimes work though atm and I do not know why
                // let extracted = Self::extract(
                //     pub_params,
                //     &pub_inputs.replica_id.into_bytes(),
                //     &replica,
                //     challenge,
                // )?;

                let extracted = decode_domain_block::<H>(
                    pub_params.sloth_iter,
                    &pub_inputs.replica_id.expect("missing replica_id"),
                    tree_r,
                    challenge,
                    tree_r.read_at(challenge),
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
                H::sloth_decode(&key, &proof.replica_nodes[i].data, pub_params.sloth_iter);

            if unsealed != proof.nodes[i].data {
                return Ok(false);
            }

            if !proof.nodes[i].proof.validate_data(&unsealed.into_bytes()) {
                println!("invalid data for merkle path {:?}", unsealed);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl<'a, H, G> PoRep<'a, H> for DrgPoRep<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetIdentifier + Sync + Send,
{
    type Tau = porep::Tau<H::Domain>;
    type ProverAux = porep::ProverAux<H>;

    fn replicate(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        data_tree: Option<MerkleTree<H::Domain, H::Function>>,
    ) -> Result<(porep::Tau<H::Domain>, porep::ProverAux<H>)> {
        let tree_d = match data_tree {
            Some(tree) => tree,
            None => pp.graph.merkle_tree(data)?,
        };

        vde::encode(&pp.graph, pp.sloth_iter, replica_id, data)?;

        let comm_d = tree_d.root();
        let tree_r = pp.graph.merkle_tree(data)?;
        let comm_r = tree_r.root();

        Ok((
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        ))
    }

    fn extract_all<'b>(
        pp: &'b Self::PublicParams,
        replica_id: &'b H::Domain,
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        vde::decode(&pp.graph, pp.sloth_iter, replica_id, data)
    }

    fn extract(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
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
    use crate::util::data_at_node;

    pub fn file_backed_mmap_from(data: &[u8]) -> MmapMut {
        let mut tmpfile: File = tempfile::tempfile().unwrap();
        tmpfile.write_all(data).unwrap();

        unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
    }

    fn test_extract_all<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sloth_iter = 1;
        let replica_id: H::Domain = rng.gen();
        let data = vec![2u8; 32 * 3];
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

        let pp = DrgPoRep::<H, BucketGraph<H>>::setup(&sp).unwrap();

        DrgPoRep::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        let decoded_data = DrgPoRep::extract_all(&pp, &replica_id, &mut mmapped_data_copy).unwrap();

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
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sloth_iter = 1;
        let replica_id: H::Domain = rng.gen();
        let nodes = 3;
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

        let pp = DrgPoRep::<H, BucketGraph<H>>::setup(&sp).unwrap();

        DrgPoRep::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        for i in 0..nodes {
            let decoded_data = DrgPoRep::extract(&pp, &replica_id, &mmapped_data_copy, i).unwrap();

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
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let sloth_iter = 1;
            let degree = 10;
            let expansion_degree = 0;
            let seed = new_seed();

            let replica_id: H::Domain = rng.gen();
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

            let pp = DrgPoRep::<H, BucketGraph<_>>::setup(&sp).unwrap();

            let (tau, aux) =
                DrgPoRep::<H, _>::replicate(&pp, &replica_id, &mut mmapped_data_copy, None)
                    .unwrap();

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
            };

            let real_proof = DrgPoRep::<H, _>::prove(&pp, &pub_inputs, &priv_inputs).unwrap();

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

                assert!(
                    !DrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap(),
                    "verified in error -- with wrong parents"
                );

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

                assert!(
                    !DrgPoRep::<H, _>::verify(&pp, &pub_inputs, &proof2).unwrap(),
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
                .unwrap();
                assert!(
                    !verified,
                    "wrongly verified proof which does not match challenge in public input"
                );
            } else {
                assert!(
                    DrgPoRep::<H, _>::verify(&pp, &pub_inputs, &proof).unwrap(),
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
            prove_verify_32_2_1(2, 1);

            prove_verify_32_3_1(3, 1);
            prove_verify_32_3_2(3, 2);

            prove_verify_32_10_1(10, 1);
            prove_verify_32_10_2(10, 2);
            prove_verify_32_10_3(10, 3);
            prove_verify_32_10_4(10, 4);
            prove_verify_32_10_5(10, 5);
        }
    }

    #[test]
    fn test_drgporep_verifies_using_challenge() {
        prove_verify_wrong_challenge(5, 1);
    }

    #[test]
    fn test_drgporep_verifies_parents() {
        // Challenge a node (3) that doesn't have all the same parents.
        prove_verify_wrong_parents(7, 4);
    }
}
