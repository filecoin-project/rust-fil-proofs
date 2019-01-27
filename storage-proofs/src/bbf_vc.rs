use std::marker::PhantomData;

use accumulators::accumulator::Accumulator;
use accumulators::group::RSAGroup;
use accumulators::traits::*;
use accumulators::vc::*;
use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::porep::PoRep;
use crate::proof::ProofScheme;
use crate::util::{data_at_node, data_at_node_offset};
use crate::vde::{self, decode_block};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tau {
    // TODO: ensure the serialization only contains the state it has to transmit, to be able to reconstruct itself.
    pub comm: VectorCommitment<Accumulator>,
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: T,
    pub challenges: Vec<usize>,
    pub tau: Tau,
}

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
}

#[derive(Debug)]
pub struct SetupParams {
    pub drg: DrgParams,
    pub sloth_iter: usize,
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

    _h: PhantomData<H>,
}

impl<H, G> PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    pub fn new(graph: G, sloth_iter: usize) -> Self {
        PublicParams {
            graph,
            sloth_iter,
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
            "bbf_vc::PublicParams{{graph: {}; sloth_iter: {}}}",
            self.graph.parameter_set_identifier(),
            self.sloth_iter
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub proof: <VectorCommitment<Accumulator> as StaticVectorCommitment>::BatchCommitment,
    // TODO: derive indices, instead of adding them to the proof
    pub nodes: Vec<(Vec<u8>, usize)>,
}

impl Proof {
    pub fn serialize(&self) -> Vec<u8> {
        // TODO: implement using serde
        vec![]
    }

    pub fn new(
        proof: <VectorCommitment<Accumulator> as StaticVectorCommitment>::BatchCommitment,
        nodes: Vec<(Vec<u8>, usize)>,
    ) -> Self {
        Proof { proof, nodes }
    }
}

#[derive(Default)]
pub struct BbfVc<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H>,
{
    _h: PhantomData<&'a H>,
    _g: PhantomData<G>,
}

impl<'a, H, G> ProofScheme<'a> for BbfVc<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetIdentifier,
{
    type PublicParams = PublicParams<H, G>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = G::new(
            sp.drg.nodes,
            sp.drg.degree,
            sp.drg.expansion_degree,
            sp.drg.seed,
        );

        Ok(PublicParams::new(graph, sp.sloth_iter))
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let len = pub_inputs.challenges.len();
        let replica = priv_inputs.replica;
        let vc = &pub_inputs.tau.comm;

        // can only open values once
        // TODO: verify this is okay, security wise

        use std::collections::BTreeMap;
        let mut indices = BTreeMap::new();

        // accumulate
        // - replicated node
        // - original node
        // - parent nodes
        for challenge in &pub_inputs.challenges {
            let node_index = challenge % pub_params.graph.size();
            assert_ne!(node_index, 0, "cannot prove the first node");

            if !indices.contains_key(&node_index) {
                let replica_node = data_at_node(replica, node_index)?;
                let original_node = decode_block(
                    &pub_params.graph,
                    pub_params.sloth_iter,
                    &pub_inputs.replica_id,
                    replica,
                    node_index,
                )?
                .into_bytes();

                indices.insert(node_index, original_node.to_vec());
                indices.insert(len + node_index, replica_node.to_vec());
            }

            // TODO: ask research
            // - if we need to do inclusion proofs for parents?
            // - do we need to reveal the q-bits for the replica bits?
            let parents = pub_params.graph.parents(node_index);
            for p in &parents {
                if !indices.contains_key(p) {
                    let data = data_at_node(replica, *p).expect("bad index logic");
                    indices.insert(len + p, data.to_vec());
                }
            }
        }

        let nodes = indices.into_iter().map(|(k, v)| (v, k)).collect::<Vec<_>>();
        let comm = vc.batch_open(nodes.clone());

        Ok(Proof::new(comm, nodes))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let vc = &pub_inputs.tau.comm;
        Ok(vc.batch_verify(proof.nodes.clone(), &proof.proof))
    }
}

impl<'a, H, G> PoRep<'a, H> for BbfVc<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetIdentifier + Sync + Send,
{
    type Tau = Tau;
    type ProverAux = ();

    fn replicate(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        _data_tree: Option<MerkleTree<H::Domain, H::Function>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        // TODO: right parameters
        let n = 1024;
        let lambda = 256;
        let mut vc = create_vector_commitment::<Accumulator, RSAGroup>(lambda, n);

        let nodes = pp.graph.size();
        // TODO: is this the right size, with accumulators?
        let node_size = 32;

        encode(&pp.graph, pp.sloth_iter, replica_id, data, &mut vc)?;

        Ok((Tau { comm: vc }, ()))
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

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, H, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a mut [u8],
    vc: &mut VectorCommitment<Accumulator>,
) -> Result<()>
where
    H: Hasher,
    G: Graph<H>,
{
    let degree = graph.degree();

    // Because a node always follows all of its parents in the data,
    // the nodes are by definition already topologically sorted.
    // Therefore, if we simply traverse the data in order, encoding each node in place,
    // we can always get each parent's encodings with a simple lookup --
    // since we will already have encoded the parent earlier in the traversal.
    // The only subtlety is that a ZigZag graph may be reversed, so the direction
    // of the traversal must also be.

    for n in 0..graph.size() {
        let node = if graph.forward() {
            n
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - n) - 1
        };

        let parents = graph.parents(node);
        assert_eq!(parents.len(), graph.degree(), "wrong number of parents");

        let key = vde::create_key::<H>(replica_id, node, &parents, data, degree)?;
        let start = data_at_node_offset(node);
        let end = start + 32;

        // commit original data
        let original_data = vec![data[start..end].to_vec()];
        vc.commit(original_data);

        // encode data
        let node_data = H::Domain::try_from_bytes(&data[start..end])?;
        let encoded = H::sloth_encode(&key, &node_data, sloth_iter);
        encoded.write_bytes(&mut data[start..end])?;

        // commit encoded data
        vc.commit(vec![data[start..end].to_vec()]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use memmap::MmapMut;
    use memmap::MmapOptions;
    use pairing::bls12_381::Bls12;
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
        };

        let pp = BbfVc::<H, BucketGraph<H>>::setup(&sp).unwrap();

        BbfVc::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        let decoded_data = BbfVc::extract_all(&pp, &replica_id, &mut mmapped_data_copy).unwrap();

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
        };

        let pp = BbfVc::<H, BucketGraph<H>>::setup(&sp).unwrap();

        BbfVc::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);
        assert_ne!(data, copied, "replication did not change data");

        for i in 0..nodes {
            let decoded_data = BbfVc::extract(&pp, &replica_id, &mmapped_data_copy, i).unwrap();

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

    fn prove_verify_aux<H: Hasher>(nodes: usize, i: usize) {
        assert!(i < nodes);

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
        };

        let pp = BbfVc::<H, BucketGraph<_>>::setup(&sp).unwrap();

        let (tau, _aux) =
            BbfVc::<H, _>::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data_copy);

        assert_ne!(data, copied, "replication did not change data");

        let pub_inputs = PublicInputs::<H::Domain> {
            replica_id,
            challenges: vec![challenge, challenge],
            tau: tau.clone().into(),
        };

        let priv_inputs = PrivateInputs {
            replica: &mmapped_data_copy,
        };

        let proof = BbfVc::<H, _>::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
        assert!(
            BbfVc::<H, _>::verify(&pp, &pub_inputs, &proof).unwrap(),
            "failed to verify"
        );
    }

    fn prove_verify(n: usize, i: usize) {
        prove_verify_aux::<PedersenHasher>(n, i);
        prove_verify_aux::<Sha256Hasher>(n, i);
        prove_verify_aux::<Blake2sHasher>(n, i);
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
}
