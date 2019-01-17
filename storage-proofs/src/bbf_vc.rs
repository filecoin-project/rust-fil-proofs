use std::marker::PhantomData;

use accumulators::accumulator::Accumulator;
use accumulators::group::RSAGroup;
use accumulators::traits::*;
use accumulators::vc::*;
use num_bigint::BigUint;
use num_traits::Zero;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetIdentifier;
use crate::porep::PoRep;
use crate::proof::ProofScheme;
use crate::util::data_at_node;
use crate::vde::{self, decode_block, decode_domain_block};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tau {
    // pub comm: <VectorCommitment<Accumulator> as StaticVectorCommitment>::Commitment,
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: T,
    pub challenges: Vec<usize>,
    pub tau: Option<Tau>,
}

pub type ProverAux = VectorCommitment<Accumulator>;

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub aux: ProverAux,
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
}

impl Proof {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!()
    }

    pub fn new(
        proof: <VectorCommitment<Accumulator> as StaticVectorCommitment>::BatchCommitment,
    ) -> Self {
        Proof { proof }
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
        let vc = &priv_inputs.aux;

        let mut nodes = Vec::with_capacity(len);
        let mut indices = Vec::with_capacity(len);
        println!("replica: {:?}", replica);
        // accumulate
        // - replicated node
        // - original node
        // - parent nodes
        for challenge in &pub_inputs.challenges {
            let node_index = challenge % pub_params.graph.size();
            println!(
                "{}, {}, {}, {}",
                len,
                pub_params.graph.size(),
                challenge,
                node_index
            );

            assert_ne!(node_index, 0, "cannot prove the first node");

            let replica_node = data_at_node(replica, node_index)?;
            let original_node = decode_block(
                &pub_params.graph,
                pub_params.sloth_iter,
                &pub_inputs.replica_id,
                replica,
                node_index,
            )?
            .into_bytes();

            nodes.push(BigUint::from_bytes_be(&replica_node));
            indices.push(len + node_index);

            nodes.push(BigUint::from_bytes_be(&original_node));
            indices.push(node_index);

            let parents = pub_params.graph.parents(node_index);
            for p in &parents {
                let parent = data_at_node(replica, *p)?;
                nodes.push(BigUint::from_bytes_be(&parent));
                indices.push(len + p);
            }
        }
        println!("open: {:?}", &nodes);
        let comm = vc.batch_open(&nodes[..], &indices[..]);
        Ok(Proof::new(comm))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        // TODO: verify

        Ok(true)
    }
}

impl<'a, H, G> PoRep<'a, H> for BbfVc<'a, H, G>
where
    H: 'a + Hasher,
    G: 'a + Graph<H> + ParameterSetIdentifier + Sync + Send,
{
    type Tau = Tau;
    type ProverAux = ProverAux;

    fn replicate(
        pp: &Self::PublicParams,
        replica_id: &H::Domain,
        data: &mut [u8],
        _data_tree: Option<MerkleTree<H::Domain, H::Function>>,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        // TODO: right parameters
        let n = 1024;
        let lambda = 128;
        let mut vc = create_vector_commitment::<Accumulator, RSAGroup>(lambda, n);

        let nodes = pp.graph.size();
        // TODO: is this the right size, with accumulators?
        let node_size = 32;

        // TODO: use iterator & allow passing raw bytes
        let big_data: Vec<BigUint> = (0..nodes)
            .map(|i| {
                let el = data_at_node(&data, i).expect("data_at_node math failed");
                BigUint::from_bytes_be(el)
            })
            .collect();

        println!("data: {:?}", &big_data);
        vc.commit(&big_data[..]);

        vde::encode(&pp.graph, pp.sloth_iter, replica_id, data)?;

        // TODO: use iterator & allow passing raw bytes
        let big_data_enc: Vec<BigUint> = (0..nodes)
            .map(|i| {
                let el = data_at_node(&data, i).expect("data_at_node math failed");
                BigUint::from_bytes_be(el)
            })
            .collect();

        println!("enc: {:?}", &big_data);
        vc.commit(&big_data_enc[..]);

        Ok((Tau {}, vc))
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
            };

            let pp = BbfVc::<H, BucketGraph<_>>::setup(&sp).unwrap();

            let (tau, aux) =
                BbfVc::<H, _>::replicate(&pp, &replica_id, &mut mmapped_data_copy, None).unwrap();

            let mut copied = vec![0; data.len()];
            copied.copy_from_slice(&mmapped_data_copy);

            assert_ne!(data, copied, "replication did not change data");

            let pub_inputs = PublicInputs::<H::Domain> {
                replica_id,
                challenges: vec![challenge, challenge],
                tau: Some(tau.clone().into()),
            };

            let priv_inputs = PrivateInputs {
                aux,
                replica: &mmapped_data_copy,
            };

            let proof = BbfVc::<H, _>::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
            assert!(
                BbfVc::<H, _>::verify(&pp, &pub_inputs, &proof).unwrap(),
                "failed to verify"
            );

            // Normally, just run once.
            break;
        }
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
