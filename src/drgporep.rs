use crypto::{decode, kdf};
use drgraph::{Graph, MerklePath, Sampling};
use porep::{self, PoRep};
use util::data_at_node;
use vde::{self, decode_block};

use error::Result;
use proof::ProofScheme;

#[derive(Debug)]
pub struct PublicInputs<'a> {
    pub prover_id: &'a [u8],
    pub challenge: usize,
    pub tau: &'a porep::Tau,
}

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
    pub aux: &'a porep::ProverAux,
}

#[derive(Debug)]
pub struct SetupParams {
    pub lambda: usize,
    pub drg: DrgParams,
}

#[derive(Debug)]
pub struct DrgParams {
    pub n: usize,
    pub m: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    pub lambda: usize,
    pub graph: Graph,
}

#[derive(Debug)]
pub struct DataProof<'a> {
    pub proof: MerklePath,
    pub data: &'a [u8],
}

pub type ReplicaParents<'a> = Vec<(usize, DataProof<'a>)>;

#[derive(Debug)]
pub struct Proof<'a> {
    pub replica_node: DataProof<'a>,
    pub replica_parents: ReplicaParents<'a>,
    pub node: MerklePath,
}

impl<'a> Proof<'a> {
    pub fn new(
        replica_node: DataProof<'a>,
        replica_parents: ReplicaParents<'a>,
        node: MerklePath,
    ) -> Proof<'a> {
        Proof {
            replica_node,
            replica_parents,
            node,
        }
    }
}

#[derive(Default)]
pub struct DrgPoRep {}

impl<'a> ProofScheme<'a> for DrgPoRep {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof<'a>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = Graph::new(sp.drg.n, Some(Sampling::Bucket(sp.drg.m)));

        Ok(PublicParams {
            lambda: sp.lambda,
            graph,
        })
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let challenge = pub_inputs.challenge % pub_params.graph.size();

        let tree_d = &priv_inputs.aux.tree_d;
        let tree_r = &priv_inputs.aux.tree_r;
        let replica = priv_inputs.replica;

        let d = data_at_node(replica, challenge + 1, pub_params.lambda)?;
        let replica_node = DataProof {
            proof: tree_r.gen_proof(challenge).into(),
            data: d,
        };

        let parents = pub_params.graph.parents(challenge + 1);
        let mut replica_parents = Vec::with_capacity(parents.len());

        for p in parents {
            replica_parents.push((
                p,
                DataProof {
                    proof: tree_r.gen_proof(p - 1).into(),
                    data: data_at_node(replica, p, pub_params.lambda)?,
                },
            ));
        }

        let node_proof = tree_d.gen_proof(challenge);
        let proof = Proof::new(replica_node, replica_parents, node_proof.into());
        Ok(proof)
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        // We should return false, not Err here -- though having the failure information is
        // useful when debugging. What to do…

        if !proof.replica_node.proof.validate() {
            return Ok(false);
        }

        for (_, p) in &proof.replica_parents {
            if !p.proof.validate() {
                return Ok(false);
            }
        }

        let ciphertexts = proof.replica_parents.iter().fold(
            pub_inputs.prover_id.to_vec(),
            |mut acc, (_, p)| {
                acc.extend(p.data);
                acc
            },
        );
        let key = kdf::kdf(ciphertexts.as_slice());
        let unsealed = decode(&key, proof.replica_node.data)?;

        Ok(proof.node.validate_data(&unsealed))
    }
}

impl<'a> PoRep<'a> for DrgPoRep {
    type Tau = porep::Tau;
    type ProverAux = porep::ProverAux;

    fn replicate(
        pp: &PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(porep::Tau, porep::ProverAux)> {
        let tree_d = pp.graph.merkle_tree(data, pp.lambda)?;
        let comm_d = pp.graph.commit(data, pp.lambda)?;

        vde::encode(&pp.graph, pp.lambda, prover_id, data)?;

        let tree_r = pp.graph.merkle_tree(data, pp.lambda)?;
        let comm_r = pp.graph.commit(data, pp.lambda)?;
        Ok((
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        ))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        vde::decode(&pp.graph, pp.lambda, prover_id, data)
    }

    fn extract(pp: &PublicParams, prover_id: &[u8], data: &[u8], node: usize) -> Result<Vec<u8>> {
        decode_block(&pp.graph, pp.lambda, prover_id, data, node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_extract_all() {
        let lambda = 16;
        let prover_id = vec![1u8; 16];
        let data = vec![2u8; 16 * 3];
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            lambda: lambda,
            drg: DrgParams {
                n: data.len() / lambda,
                m: 10,
            },
        };

        let pp = DrgPoRep::setup(&sp).unwrap();

        DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_ne!(data, data_copy);

        let decoded_data =
            DrgPoRep::extract_all(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_eq!(data, decoded_data);
    }

    fn prove_verify(lambda: usize, n: usize) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 1..10 {
            let m = i * 10;
            let lambda = lambda;
            let prover_id = vec![rng.gen(); lambda];
            let data = vec![rng.gen(); lambda * n];
            // create a copy, so we can comare roundtrips
            let mut data_copy = data.clone();
            let challenge = 1;

            let sp = SetupParams {
                lambda: lambda,
                drg: DrgParams { n: n, m: m },
            };

            let pp = DrgPoRep::setup(&sp).unwrap();

            let (tau, aux) =
                DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

            assert_ne!(data, data_copy);

            let pub_inputs = PublicInputs {
                prover_id: prover_id.as_slice(),
                challenge: challenge,
                tau: &tau,
            };

            let priv_inputs = PrivateInputs {
                replica: data_copy.as_slice(),
                aux: &aux,
            };

            let proof = DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();
            assert!(DrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap());
        }
    }

    #[test]
    fn test_prove_verify_16_2() {
        prove_verify(16, 2);
    }

    #[test]
    fn test_prove_verify_16_3() {
        prove_verify(16, 3);
    }

    #[test]
    fn test_prove_verify_16_10() {
        prove_verify(16, 10);
    }

    #[test]
    fn test_prove_verify_32_2() {
        prove_verify(32, 2);
    }

    #[test]
    fn test_prove_verify_32_3() {
        prove_verify(32, 3);
    }

    #[test]
    fn test_prove_verify_32_10() {
        prove_verify(32, 10);
    }
}
