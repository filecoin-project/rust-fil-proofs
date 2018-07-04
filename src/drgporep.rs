use crypto::{kdf, sloth};
use drgraph::{BucketGraph, Graph, MerkleProof};
use fr32::{bytes_into_fr, fr_into_bytes};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{PrimeField, PrimeFieldRepr};
use porep::{self, PoRep};
use util::data_at_node;
use vde::{self, decode_block};

use error::Result;
use proof::ProofScheme;

#[derive(Debug)]
pub struct PublicInputs<'a> {
    pub prover_id: &'a Fr,
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

#[derive(Debug, Clone)]
pub struct DrgParams {
    pub n: usize,
    pub m: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams<G: Graph> {
    pub lambda: usize,
    pub graph: G,
}

#[derive(Debug, Clone)]
pub struct DataProof {
    pub proof: MerkleProof,
    pub data: Fr,
}

impl DataProof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.proof.serialize();
        self.data.into_repr().write_le(&mut out).unwrap();

        out
    }
}

pub type ReplicaParents = Vec<(usize, DataProof)>;

#[derive(Debug, Clone)]
pub struct Proof {
    pub replica_node: DataProof,
    pub replica_parents: ReplicaParents,
    pub node: MerkleProof,
}

impl Proof {
    pub fn new(
        replica_node: DataProof,
        replica_parents: ReplicaParents,
        node: MerkleProof,
    ) -> Proof {
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
    type PublicParams = PublicParams<BucketGraph>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = BucketGraph::new(sp.drg.n, sp.drg.m);

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
        assert_ne!(challenge, 0, "can not prove the first node");

        let tree_d = &priv_inputs.aux.tree_d;
        let tree_r = &priv_inputs.aux.tree_r;
        let replica = priv_inputs.replica;

        let data = bytes_into_fr::<Bls12>(data_at_node(replica, challenge, pub_params.lambda)?)?;

        let replica_node = DataProof {
            proof: tree_r.gen_proof(challenge).into(),
            data,
        };

        let parents = pub_params.graph.parents(challenge);
        let mut replica_parents = Vec::with_capacity(parents.len());

        for p in parents {
            replica_parents.push((
                p,
                DataProof {
                    proof: tree_r.gen_proof(p).into(),
                    data: bytes_into_fr::<Bls12>(data_at_node(replica, p, pub_params.lambda)?)?,
                },
            ));
        }

        let node_proof = tree_d.gen_proof(challenge);
        let proof = Proof::new(replica_node, replica_parents, node_proof.into());
        Ok(proof)
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let challenge = pub_inputs.challenge % pub_params.graph.size();
        assert_ne!(challenge, 0, "can not prove the first node");

        if !proof.replica_node.proof.validate(challenge) {
            println!("invalid replica node");
            return Ok(false);
        }

        for (parent_node, p) in &proof.replica_parents {
            if !p.proof.validate(*parent_node) {
                println!("invalid replica parent: {:?}", p);
                return Ok(false);
            }
        }

        let key_input = proof.replica_parents.iter().fold(
            fr_into_bytes::<Bls12>(pub_inputs.prover_id),
            |mut acc, (_, p)| {
                acc.extend(fr_into_bytes::<Bls12>(&p.data));
                acc
            },
        );
        let key = kdf::kdf::<Bls12>(key_input.as_slice(), pub_params.graph.degree());
        let unsealed: Fr =
            sloth::decode::<Bls12>(&key, &proof.replica_node.data, sloth::DEFAULT_ROUNDS);

        if !proof.node.validate_data(&unsealed) {
            println!("invalid data {:?}", unsealed);
            return Ok(false);
        }

        Ok(true)
    }
}

impl<'a> PoRep<'a> for DrgPoRep {
    type Tau = porep::Tau;
    type ProverAux = porep::ProverAux;

    fn replicate(
        pp: &PublicParams<BucketGraph>,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(porep::Tau, porep::ProverAux)> {
        let tree_d = pp.graph.merkle_tree(data, pp.lambda)?;
        let comm_d = pp.graph.commit(data, pp.lambda)?;

        vde::encode(
            &pp.graph,
            pp.lambda,
            &bytes_into_fr::<Bls12>(prover_id)?,
            data,
        )?;

        let tree_r = pp.graph.merkle_tree(data, pp.lambda)?;
        let comm_r = pp.graph.commit(data, pp.lambda)?;

        Ok((
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        ))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<BucketGraph>,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        vde::decode(
            &pp.graph,
            pp.lambda,
            &bytes_into_fr::<Bls12>(prover_id)?,
            data,
        )
    }

    fn extract(
        pp: &PublicParams<BucketGraph>,
        prover_id: &[u8],
        data: &[u8],
        node: usize,
    ) -> Result<Vec<u8>> {
        Ok(fr_into_bytes::<Bls12>(&decode_block(
            &pp.graph,
            pp.lambda,
            &bytes_into_fr::<Bls12>(prover_id)?,
            data,
            node,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn extract_all() {
        let lambda = 32;
        let prover_id = vec![1u8; 32];
        let data = vec![2u8; 32 * 3];
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

        assert_ne!(data, data_copy, "replication did not change data");

        let decoded_data =
            DrgPoRep::extract_all(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_eq!(data, decoded_data, "failed to extract data");
    }

    #[test]
    fn extract() {
        let lambda = 32;
        let prover_id = vec![1u8; 32];
        let nodes = 3;
        let data = vec![2u8; 32 * nodes];

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

        assert_ne!(data, data_copy, "replication did not change data");

        for i in 0..nodes {
            let decoded_data =
                DrgPoRep::extract(&pp, prover_id.as_slice(), data_copy.as_mut_slice(), i).unwrap();

            let original_data = data_at_node(&data, i, lambda).unwrap();

            assert_eq!(
                original_data,
                decoded_data.as_slice(),
                "failed to extract data"
            );
        }
    }

    fn prove_verify_aux(
        lambda: usize,
        n: usize,
        i: usize,
        use_wrong_challenge: bool,
        use_wrong_parents: bool,
    ) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let m = i * 10;
        let lambda = lambda;

        let prover_id = fr_into_bytes::<Bls12>(&rng.gen());
        let data: Vec<u8> = (0..n)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        // create a copy, so we can comare roundtrips
        let mut data_copy = data.clone();
        let challenge = i;

        let sp = SetupParams {
            lambda,
            drg: DrgParams { n, m },
        };

        let pp = DrgPoRep::setup(&sp).unwrap();

        let (tau, aux) =
            DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_ne!(data, data_copy, "replication did not change data");

        let pub_inputs = PublicInputs {
            prover_id: &bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
            challenge,
            tau: &tau,
        };

        let priv_inputs = PrivateInputs {
            replica: data_copy.as_slice(),
            aux: &aux,
        };

        let real_proof = DrgPoRep::prove(&pp, &pub_inputs, &priv_inputs).unwrap();

        if use_wrong_parents {
            // Only one 'wrong' option will be tested at a time.
            assert!(!use_wrong_challenge);
            let real_parents = real_proof.replica_parents;
            // A real node will never have all parents equal to 1.
            let fake_parents = real_parents
                .iter()
                .map(|(p, data_proof)| (1, data_proof.clone()))
                .collect::<Vec<_>>();

            let proof = Proof::new(
                real_proof.replica_node,
                fake_parents,
                real_proof.node.into(),
            );

            assert!(
                !DrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap(),
                "verified in error -- with wrong parents"
            );
            return;
        }

        let proof = real_proof;

        if use_wrong_challenge {
            let pub_inputs_with_wrong_challenge_for_proof = PublicInputs {
                prover_id: &bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
                challenge: if challenge == 1 { 2 } else { 1 },
                tau: &tau,
            };
            let verified =
                DrgPoRep::verify(&pp, &pub_inputs_with_wrong_challenge_for_proof, &proof).unwrap();
            assert!(
                !verified,
                "wrongly verified proof which does not match challenge in public input"
            );
        } else {
            assert!(
                DrgPoRep::verify(&pp, &pub_inputs, &proof).unwrap(),
                "failed to verify"
            );
        }
    }

    fn prove_verify(lambda: usize, n: usize, i: usize) {
        prove_verify_aux(lambda, n, i, false, false)
    }

    fn prove_verify_wrong_challenge(lambda: usize, n: usize, i: usize) {
        prove_verify_aux(lambda, n, i, true, false)
    }

    fn prove_verify_wrong_parents(lambda: usize, n: usize, i: usize) {
        prove_verify_aux(lambda, n, i, false, true)
    }

    table_tests!{
        prove_verify {
            prove_verify_32_2_1(32, 2, 1);
            #[ignore] prove_verify_32_2_2(32, 2, 2);
            prove_verify_32_2_3(32, 2, 3);
            #[ignore] prove_verify_32_2_4(32, 2, 4);
            prove_verify_32_2_5(32, 2, 5);

            prove_verify_32_3_1(32, 3, 1);
            prove_verify_32_3_2(32, 3, 2);
            #[ignore] prove_verify_32_3_3(32, 3, 3);
            prove_verify_32_3_4(32, 3, 4);
            prove_verify_32_3_5(32, 3, 5);

            prove_verify_32_10_1(32, 10, 1);
            prove_verify_32_10_2(32, 10, 2);
            prove_verify_32_10_3(32, 10, 3);
            prove_verify_32_10_4(32, 10, 4);
            prove_verify_32_10_5(32, 10, 5);
        }
    }

    #[test]
    fn test_drgporep_verifies_using_challenge() {
        prove_verify_wrong_challenge(32, 5, 1);
    }

    #[test]
    fn test_drgporep_verifies_parents() {
        prove_verify_wrong_parents(32, 5, 1);
    }

}
