use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{kdf, sloth};
use drgraph::{Graph, MerkleProof};

use fr32::{bytes_into_fr, fr_into_bytes};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{PrimeField, PrimeFieldRepr};
use porep::{self, PoRep};
use std::marker::PhantomData;
use util::data_at_node;
use vde::{self, decode_block};

use error::Result;
use proof::ProofScheme;

#[derive(Debug)]
pub struct PublicInputs<'a> {
    pub prover_id: Fr,
    pub challenges: Vec<usize>,
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
    pub sloth_iter: usize,
}

#[derive(Debug, Clone)]
pub struct DrgParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    // Random seed
    pub seed: [u32; 7],
}

#[derive(Debug, Clone)]
pub struct PublicParams<G: Graph> {
    pub lambda: usize,
    pub graph: G,
    pub sloth_iter: usize,
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

pub type ReplicaParents = Vec<(usize, DataProof)>;

#[derive(Debug, Clone)]
pub struct Proof {
    pub replica_nodes: Vec<DataProof>,
    pub replica_parents: Vec<ReplicaParents>,
    pub nodes: Vec<DataProof>,
}

impl Proof {
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
                ].concat()
            }).collect::<Vec<Vec<u8>>>()
            .concat();

        res
    }
}

impl Proof {
    pub fn new(
        replica_nodes: Vec<DataProof>,
        replica_parents: Vec<ReplicaParents>,
        nodes: Vec<DataProof>,
    ) -> Proof {
        Proof {
            replica_nodes,
            replica_parents,
            nodes,
        }
    }
}

#[derive(Default)]
pub struct DrgPoRep<G: Graph> {
    phantom: PhantomData<G>,
}

impl<'a, G: Graph> ProofScheme<'a> for DrgPoRep<G> {
    type PublicParams = PublicParams<G>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = G::new(sp.drg.nodes, sp.drg.degree, sp.drg.seed);

        Ok(PublicParams {
            lambda: sp.lambda,
            graph,
            sloth_iter: sp.sloth_iter,
        })
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let len = pub_inputs.challenges.len();

        let mut replica_nodes = Vec::with_capacity(len);
        let mut replica_parents = Vec::with_capacity(len);
        let mut data_nodes = Vec::with_capacity(len);

        for i in 0..len {
            let challenge = pub_inputs.challenges[i] % pub_params.graph.size();
            assert_ne!(challenge, 0, "can not prove the first node");

            let tree_d = &priv_inputs.aux.tree_d;
            let tree_r = &priv_inputs.aux.tree_r;
            let replica = priv_inputs.replica;

            let data =
                bytes_into_fr::<Bls12>(data_at_node(replica, challenge, pub_params.lambda)?)?;

            replica_nodes.push(DataProof {
                proof: tree_r.gen_proof(challenge).into(),
                data,
            });

            let parents = pub_params.graph.parents(challenge);
            let mut replica_parentsi = Vec::with_capacity(parents.len());

            for p in parents {
                replica_parentsi.push((p, {
                    let proof = tree_r.gen_proof(p);
                    DataProof {
                        proof: proof.into(),
                        data: bytes_into_fr::<Bls12>(data_at_node(replica, p, pub_params.lambda)?)?,
                    }
                }));
            }

            replica_parents.push(replica_parentsi);

            let node_proof = tree_d.gen_proof(challenge);

            let extracted = Self::extract(
                pub_params,
                &fr_into_bytes::<Bls12>(&pub_inputs.prover_id),
                &replica,
                challenge,
            )?;

            data_nodes.push(DataProof {
                data: bytes_into_fr::<Bls12>(&extracted)?,
                proof: node_proof.into(),
            });
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

                let expected_parents = pub_params.graph.parents(pub_inputs.challenges[i]);
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
            assert_ne!(challenge, 0, "can not prove the first node");

            if !proof.replica_nodes[i].proof.validate(challenge) {
                println!("invalid replica node");
                return Ok(false);
            }

            for (parent_node, p) in &proof.replica_parents[i] {
                if !p.proof.validate(*parent_node) {
                    println!("invalid replica parent: {:?}", p);
                    return Ok(false);
                }
            }

            let prover_bytes = fr_into_bytes::<Bls12>(&pub_inputs.prover_id);

            let key_input =
                proof.replica_parents[i]
                    .iter()
                    .fold(prover_bytes, |mut acc, (_, p)| {
                        acc.extend(fr_into_bytes::<Bls12>(&p.data));
                        acc
                    });

            let key = kdf::kdf::<Bls12>(key_input.as_slice(), pub_params.graph.degree());
            let unsealed: Fr =
                sloth::decode::<Bls12>(&key, &proof.replica_nodes[i].data, pub_params.sloth_iter);

            if unsealed != proof.nodes[i].data {
                return Ok(false);
            }

            if !proof.nodes[i].proof.validate_data(&unsealed) {
                println!("invalid data {:?}", unsealed);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl<'a, G: Graph> PoRep<'a> for DrgPoRep<G> {
    type Tau = porep::Tau;
    type ProverAux = porep::ProverAux;

    fn replicate(
        pp: &Self::PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(porep::Tau, porep::ProverAux)> {
        let tree_d = pp.graph.merkle_tree(data, pp.lambda)?;
        let comm_d = pp.graph.commit(data, pp.lambda)?;

        vde::encode(
            &pp.graph,
            pp.lambda,
            pp.sloth_iter,
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
        pp: &'b Self::PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        vde::decode(
            &pp.graph,
            pp.lambda,
            pp.sloth_iter,
            &bytes_into_fr::<Bls12>(prover_id)?,
            data,
        )
    }

    fn extract(
        pp: &Self::PublicParams,
        prover_id: &[u8],
        data: &[u8],
        node: usize,
    ) -> Result<Vec<u8>> {
        Ok(fr_into_bytes::<Bls12>(&decode_block(
            &pp.graph,
            pp.lambda,
            pp.sloth_iter,
            &bytes_into_fr::<Bls12>(prover_id)?,
            data,
            node,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::{new_seed, BucketGraph};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn extract_all() {
        let lambda = 32;
        let sloth_iter = 1;
        let prover_id = vec![1u8; 32];
        let data = vec![2u8; 32 * 3];
        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            lambda: lambda,
            drg: DrgParams {
                nodes: data.len() / lambda,
                degree: 10,
                seed: new_seed(),
            },
            sloth_iter,
        };

        let pp = DrgPoRep::<BucketGraph>::setup(&sp).unwrap();

        DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_ne!(data, data_copy, "replication did not change data");

        let decoded_data =
            DrgPoRep::extract_all(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

        assert_eq!(data, decoded_data, "failed to extract data");
    }

    #[test]
    fn extract() {
        let lambda = 32;
        let sloth_iter = 1;
        let prover_id = vec![1u8; 32];
        let nodes = 3;
        let data = vec![2u8; 32 * nodes];

        // create a copy, so we can compare roundtrips
        let mut data_copy = data.clone();

        let sp = SetupParams {
            lambda: lambda,
            drg: DrgParams {
                nodes: data.len() / lambda,
                degree: 10,
                seed: new_seed(),
            },
            sloth_iter,
        };

        let pp = DrgPoRep::<BucketGraph>::setup(&sp).unwrap();

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
        nodes: usize,
        i: usize,
        use_wrong_challenge: bool,
        use_wrong_parents: bool,
    ) {
        assert!(i < nodes);

        let mut repeat = true;
        while repeat {
            repeat = false;

            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let sloth_iter = 1;
            let degree = 5;
            let seed = new_seed();

            let prover_id = fr_into_bytes::<Bls12>(&rng.gen());
            let data: Vec<u8> = (0..nodes)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            // create a copy, so we can comare roundtrips
            let mut data_copy = data.clone();
            let challenge = i;

            let sp = SetupParams {
                lambda,
                drg: DrgParams {
                    nodes,
                    degree,
                    seed,
                },
                sloth_iter,
            };

            let pp = DrgPoRep::<BucketGraph>::setup(&sp).unwrap();

            let (tau, aux) =
                DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice()).unwrap();

            assert_ne!(data, data_copy, "replication did not change data");

            let pub_inputs = PublicInputs {
                prover_id: bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
                challenges: vec![challenge, challenge],
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

                // Parent vector claiming the wrong parents.
                let fake_parents = vec![
                    real_parents[0]
                    .iter()
                    // Incrementing each parent node will give us a different parent set.
                    // It's fine to be out of range, since this only needs to fail.
                    .map(|(i, data_proof)| (i + 1, data_proof.clone()))
                    .collect::<Vec<_>>(),
                ];

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
                    repeat = true;
                    continue;
                }

                // Parent vector claiming the right parents but providing valid proofs for different
                // parents.
                let fake_proof_parents = vec![
                    real_parents[0]
                        .iter()
                        .enumerate()
                        .map(|(i, (p, _))| {
                            // Rotate the real parent proofs.
                            let x = (i + 1) % real_parents[0].len();
                            let j = real_parents[0][x].0;
                            (*p, real_parents[0][j].1.clone())
                        }).collect::<Vec<_>>(),
                ];

                let proof2 = Proof::new(
                    real_proof.replica_nodes,
                    fake_proof_parents,
                    real_proof.nodes.into(),
                );

                assert!(
                    !DrgPoRep::verify(&pp, &pub_inputs, &proof2).unwrap(),
                    "verified in error -- with wrong parent proofs"
                );

                return ();
            }

            let proof = real_proof;

            if use_wrong_challenge {
                let pub_inputs_with_wrong_challenge_for_proof = PublicInputs {
                    prover_id: bytes_into_fr::<Bls12>(prover_id.as_slice()).unwrap(),
                    challenges: vec![if challenge == 1 { 2 } else { 1 }],
                    tau: &tau,
                };
                let verified =
                    DrgPoRep::verify(&pp, &pub_inputs_with_wrong_challenge_for_proof, &proof)
                        .unwrap();
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

            prove_verify_32_3_1(32, 3, 1);
            prove_verify_32_3_2(32, 3, 2);

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
        // Challenge a node (3) that doesn't have all the same parents.
        prove_verify_wrong_parents(32, 7, 4);
    }

}
