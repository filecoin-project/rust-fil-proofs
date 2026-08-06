use std::marker::PhantomData;

use bellperson::{
    gadgets::{boolean::Boolean, num::AllocatedNum},
    Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::Scalar as Fr;
use filecoin_hashers::{HashFunction, Hasher};
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    drgraph::Graph,
    gadgets::{constraint, encode as encode_gadget, por::AuthPath, por::PoRCircuit, variables::Root},
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    util::reverse_bit_numbering,
};

use crate::zigzag::{
    circuit::kdf::kdf,
    vanilla::{Proof, PublicParams},
};

/// The ZigZag layered PoRep circuit.
///
/// `Tree` is the Poseidon replica-tree shape; `G` is the Sha256 piece/data hasher used for
/// layer-0 `comm_d` openings (Filecoin CommD).
///
/// Public inputs (in synthesis order): `replica_id`, `comm_d`, `comm_r`, then for each layer and
/// each challenge the packed Merkle-path positions of (data node, replica node, each parent), and
/// finally `comm_r_star`.
pub struct ZigZagCircuit<Tree: MerkleTreeTrait, G: 'static + Hasher> {
    pub public_params: PublicParams<Tree>,
    pub replica_id: Option<<Tree::Hasher as Hasher>::Domain>,
    pub comm_d: Option<G::Domain>,
    pub comm_r: Option<<Tree::Hasher as Hasher>::Domain>,
    pub comm_r_star: Option<<Tree::Hasher as Hasher>::Domain>,
    pub proof: Option<Proof<Tree, G>>,
    pub _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> Clone for ZigZagCircuit<Tree, G> {
    fn clone(&self) -> Self {
        ZigZagCircuit {
            public_params: self.public_params.clone(),
            replica_id: self.replica_id,
            comm_d: self.comm_d,
            comm_r: self.comm_r,
            comm_r_star: self.comm_r_star,
            proof: self.proof.clone(),
            _g: PhantomData,
        }
    }
}

impl<Tree: MerkleTreeTrait, G: 'static + Hasher> CircuitComponent for ZigZagCircuit<Tree, G> {
    type ComponentPrivateInputs = ();
}

/// Converts an allocated field element into the 256 big-endian-per-byte bits that the SHA256 KDF
/// consumes (matching the vanilla KDF's 32-byte little-endian serialization).
fn num_into_kdf_bits<CS: ConstraintSystem<Fr>>(
    cs: CS,
    num: &AllocatedNum<Fr>,
) -> Result<Vec<Boolean>, SynthesisError> {
    Ok(reverse_bit_numbering(num.to_bits_le(cs)?))
}

impl<Tree, G> Circuit<Fr> for ZigZagCircuit<Tree, G>
where
    Tree: 'static + MerkleTreeTrait,
    G: 'static + Hasher,
{
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let layers = self.public_params.layer_challenges.layers();
        let leaves = self.public_params.graph.size();
        let degree = self.public_params.graph.degree();

        let replica_id_num = AllocatedNum::alloc(cs.namespace(|| "replica_id"), || {
            self.replica_id
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        replica_id_num.inputize(cs.namespace(|| "replica_id_input"))?;
        let replica_id_bits =
            num_into_kdf_bits(cs.namespace(|| "replica_id_bits"), &replica_id_num)?;

        // Public: Sha256 comm_d (Filecoin CommD).
        let comm_d_num = AllocatedNum::alloc(cs.namespace(|| "comm_d"), || {
            self.comm_d
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_d_num.inputize(cs.namespace(|| "comm_d_input"))?;

        // Public: Poseidon comm_r (final replica root).
        let comm_r_num = AllocatedNum::alloc(cs.namespace(|| "comm_r"), || {
            self.comm_r
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        comm_r_num.inputize(cs.namespace(|| "comm_r_input"))?;

        let mut layer_comm_rs: Vec<AllocatedNum<Fr>> = Vec::with_capacity(layers);

        for layer in 0..layers {
            let is_last_layer = layer == layers - 1;
            let challenge_count = self
                .public_params
                .layer_challenges
                .challenges_for_layer(layer);

            // Layer 0 data root is Sha256 comm_d; later layers use the previous Poseidon replica root.
            let comm_d_layer = if layer == 0 {
                comm_d_num.clone()
            } else {
                layer_comm_rs[layer - 1].clone()
            };

            let comm_r_layer = if is_last_layer {
                comm_r_num.clone()
            } else {
                AllocatedNum::alloc(cs.namespace(|| format!("comm_r_layer_{}", layer)), || {
                    self.proof
                        .as_ref()
                        .map(|p| p.layer_comm_rs[layer].into())
                        .ok_or(SynthesisError::AssignmentMissing)
                })?
            };
            layer_comm_rs.push(comm_r_layer.clone());

            for c in 0..challenge_count {
                let mut cs = cs.namespace(|| format!("layer_{}_challenge_{}", layer, c));

                let layer_proof = self.proof.as_ref().map(|p| &p.encoding_proofs[layer]);

                let replica_value = AllocatedNum::alloc(cs.namespace(|| "replica_value"), || {
                    layer_proof
                        .map(|lp| lp.replica_nodes[c].data.into())
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;

                let data_value = AllocatedNum::alloc(cs.namespace(|| "data_value"), || {
                    if layer == 0 {
                        self.proof
                            .as_ref()
                            .map(|p| p.layer0_data_nodes[c].data.into())
                            .ok_or(SynthesisError::AssignmentMissing)
                    } else {
                        layer_proof
                            .map(|lp| lp.nodes[c].data.into())
                            .ok_or(SynthesisError::AssignmentMissing)
                    }
                })?;

                let mut parent_values = Vec::with_capacity(degree);
                let mut parent_kdf_bits = Vec::with_capacity(degree);
                for p in 0..degree {
                    let parent_num =
                        AllocatedNum::alloc(cs.namespace(|| format!("parent_{}", p)), || {
                            layer_proof
                                .map(|lp| lp.replica_parents[c][p].1.data.into())
                                .ok_or(SynthesisError::AssignmentMissing)
                        })?;
                    let bits = num_into_kdf_bits(
                        cs.namespace(|| format!("parent_{}_bits", p)),
                        &parent_num,
                    )?;
                    parent_kdf_bits.push(bits);
                    parent_values.push(parent_num);
                }

                let key = kdf(cs.namespace(|| "kdf"), &replica_id_bits, parent_kdf_bits)?;

                let decoded =
                    encode_gadget::decode(cs.namespace(|| "decode"), &key, &replica_value)?;
                constraint::equal(&mut cs, || "enforce encoding", &decoded, &data_value);

                // Data-node inclusion: Sha256 binary tree for layer 0, Poseidon Tree otherwise.
                if layer == 0 {
                    let data_auth_path = auth_path_for_piece::<G>(
                        self.proof.as_ref().map(|p| &p.layer0_data_nodes[c]),
                        leaves,
                    );
                    PoRCircuit::<BinaryMerkleTree<G>>::synthesize(
                        cs.namespace(|| "data_inclusion"),
                        Root::Var(data_value.clone()),
                        data_auth_path,
                        Root::Var(comm_d_layer.clone()),
                        true,
                    )?;
                } else {
                    let data_auth_path =
                        auth_path_for::<Tree>(layer_proof.map(|lp| &lp.nodes[c]), leaves);
                    PoRCircuit::<Tree>::synthesize(
                        cs.namespace(|| "data_inclusion"),
                        Root::Var(data_value.clone()),
                        data_auth_path,
                        Root::Var(comm_d_layer.clone()),
                        true,
                    )?;
                }

                let replica_auth_path =
                    auth_path_for::<Tree>(layer_proof.map(|lp| &lp.replica_nodes[c]), leaves);
                PoRCircuit::<Tree>::synthesize(
                    cs.namespace(|| "replica_inclusion"),
                    Root::Var(replica_value.clone()),
                    replica_auth_path,
                    Root::Var(comm_r_layer.clone()),
                    true,
                )?;

                for (p, parent_value) in parent_values.into_iter().enumerate() {
                    let parent_auth_path = auth_path_for::<Tree>(
                        layer_proof.map(|lp| &lp.replica_parents[c][p].1),
                        leaves,
                    );
                    PoRCircuit::<Tree>::synthesize(
                        cs.namespace(|| format!("parent_inclusion_{}", p)),
                        Root::Var(parent_value),
                        parent_auth_path,
                        Root::Var(comm_r_layer.clone()),
                        true,
                    )?;
                }
            }
        }

        let mut md_elements = Vec::with_capacity(layers + 1);
        md_elements.push(replica_id_num);
        md_elements.extend(layer_comm_rs.iter().cloned());
        let computed_comm_r_star = <Tree::Hasher as Hasher>::Function::hash_md_circuit(
            &mut cs.namespace(|| "comm_r_star_md"),
            &md_elements,
        )?;

        let comm_r_star_num = AllocatedNum::alloc(cs.namespace(|| "comm_r_star"), || {
            self.comm_r_star
                .map(Into::into)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        constraint::equal(
            cs,
            || "enforce comm_r_star",
            &computed_comm_r_star,
            &comm_r_star_num,
        );
        comm_r_star_num.inputize(cs.namespace(|| "comm_r_star_input"))?;

        Ok(())
    }
}

fn auth_path_for<Tree: MerkleTreeTrait>(
    data_proof: Option<&storage_proofs_core::por::DataProof<Tree::Proof>>,
    leaves: usize,
) -> AuthPath<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity> {
    use storage_proofs_core::merkle::MerkleProofTrait;

    match data_proof {
        Some(dp) => dp.proof.as_options().into(),
        None => AuthPath::blank(leaves),
    }
}

fn auth_path_for_piece<G: 'static + Hasher>(
    data_proof: Option<
        &storage_proofs_core::por::DataProof<<BinaryMerkleTree<G> as MerkleTreeTrait>::Proof>,
    >,
    leaves: usize,
) -> AuthPath<G, generic_array::typenum::U2, generic_array::typenum::U0, generic_array::typenum::U0>
{
    use storage_proofs_core::merkle::MerkleProofTrait;

    match data_proof {
        Some(dp) => dp.proof.as_options().into(),
        None => AuthPath::blank(leaves),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use filecoin_hashers::{
        poseidon::{PoseidonDomain, PoseidonHasher},
        sha256::Sha256Hasher,
    };
    use generic_array::typenum::{U0, U2};
    use storage_proofs_core::{
        api_version::ApiVersion,
        drgraph::BASE_DEGREE,
        merkle::{DiskStore, MerkleTreeWrapper},
        proof::ProofScheme,
        util::NODE_SIZE,
    };

    use crate::zigzag::vanilla::{
        LayerChallenges, PrivateInputs, PublicInputs, SetupParams, ZigZagDrgPoRep, EXP_DEGREE,
    };

    type ZZTree = MerkleTreeWrapper<PoseidonHasher, DiskStore<PoseidonDomain>, U2, U0, U0>;
    type Piece = Sha256Hasher;

    fn synthesize_satisfied(layers: usize, challenge_count: usize) {
        let nodes = 128;
        let porep_id = [21u8; 32];

        let sp = SetupParams {
            nodes,
            degree: BASE_DEGREE,
            expansion_degree: EXP_DEGREE,
            porep_id,
            api_version: ApiVersion::V1_2_0,
            layer_challenges: LayerChallenges::new_fixed(layers, challenge_count),
        };

        let pp = ZigZagDrgPoRep::<ZZTree, Piece>::setup(&sp).expect("setup failed");

        let replica_id = PoseidonDomain::from([19u8; 32]);
        let mut data = vec![0u8; nodes * NODE_SIZE];

        let (tau, tree_d, replica_trees) =
            ZigZagDrgPoRep::<ZZTree, Piece>::transform_and_replicate_layers(
                &pp.graph,
                &pp.layer_challenges,
                &replica_id,
                &mut data,
                None,
            )
            .expect("replication failed");

        let simplified = tau.simplify();

        let pub_inputs = PublicInputs {
            replica_id,
            seed: None,
            tau: Some(simplified),
            comm_r_star: tau.comm_r_star,
            k: None,
        };

        let priv_inputs = PrivateInputs::<ZZTree, Piece> {
            tree_d,
            aux: replica_trees,
            layer_comm_rs: tau.layer_comm_rs.clone(),
            comm_d: tau.comm_d,
        };

        let vanilla_proof =
            ZigZagDrgPoRep::<ZZTree, Piece>::prove(&pp, &pub_inputs, &priv_inputs)
                .expect("vanilla prove failed");

        assert!(
            ZigZagDrgPoRep::<ZZTree, Piece>::verify(&pp, &pub_inputs, &vanilla_proof)
                .expect("vanilla verify errored"),
            "vanilla proof must verify before circuit synthesis"
        );

        let circuit = ZigZagCircuit::<ZZTree, Piece> {
            public_params: pp,
            replica_id: Some(replica_id),
            comm_d: Some(simplified.comm_d),
            comm_r: Some(simplified.comm_r),
            comm_r_star: Some(tau.comm_r_star),
            proof: Some(vanilla_proof),
            _g: PhantomData,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        circuit.synthesize(&mut cs).expect("synthesis failed");
        if !cs.is_satisfied() {
            panic!("unsatisfied: {:?}", cs.which_is_unsatisfied());
        }
        assert!(cs.is_satisfied(), "constraints not satisfied");
        println!(
            "zigzag circuit ({} layers, {} challenges/layer): {} constraints, {} inputs",
            layers,
            challenge_count,
            cs.num_constraints(),
            cs.num_inputs()
        );
    }

    #[test]
    fn zigzag_circuit_satisfied_single_layer() {
        synthesize_satisfied(1, 1);
    }

    #[test]
    fn zigzag_circuit_satisfied_multi_layer() {
        synthesize_satisfied(2, 1);
    }
}
