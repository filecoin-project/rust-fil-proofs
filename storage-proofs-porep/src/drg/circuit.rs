use std::marker::PhantomData;

use bellperson::{
    bls::{Bls12, Engine, Fr},
    gadgets::{boolean::Boolean, multipack, num::AllocatedNum, sha256::sha256 as sha256_circuit},
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use filecoin_hashers::Hasher;
use storage_proofs_core::{
    compound_proof::CircuitComponent,
    error::Result,
    gadgets::{constraint, encode, por::PoRCircuit, uint64::UInt64, variables::Root},
    merkle::BinaryMerkleTree,
    util::reverse_bit_numbering,
};

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
/// ----> Private `replica_node` - The replica node being proven.
///
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
///
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
///
/// ----> Private `data_node` - The data node being proven.
///
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `replica_id` - The id of the replica.
///

pub struct DrgPoRepCircuit<'a, H: Hasher> {
    pub replica_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub replica_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub replica_root: Root<Bls12>,
    pub replica_parents: Vec<Vec<Option<Fr>>>,
    #[allow(clippy::type_complexity)]
    pub replica_parents_paths: Vec<Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>>,
    pub data_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    pub data_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
    pub data_root: Root<Bls12>,
    pub replica_id: Option<Fr>,
    pub private: bool,
    pub _h: PhantomData<&'a H>,
}

impl<'a, H: 'static + Hasher> DrgPoRepCircuit<'a, H> {
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        replica_nodes: Vec<Option<Fr>>,
        replica_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
        replica_root: Root<Bls12>,
        replica_parents: Vec<Vec<Option<Fr>>>,
        replica_parents_paths: Vec<Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>>,
        data_nodes: Vec<Option<Fr>>,
        data_nodes_paths: Vec<Vec<(Vec<Option<Fr>>, Option<usize>)>>,
        data_root: Root<Bls12>,
        replica_id: Option<Fr>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        DrgPoRepCircuit::<H> {
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id,
            private,
            _h: Default::default(),
        }
        .synthesize(&mut cs)
    }
}

#[derive(Default, Clone)]
pub struct ComponentPrivateInputs {
    pub comm_r: Option<Root<Bls12>>,
    pub comm_d: Option<Root<Bls12>>,
}

impl<'a, H: Hasher> CircuitComponent for DrgPoRepCircuit<'a, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

///
/// # Public Inputs
///
/// * [0] replica_id/0
/// * [1] replica_id/1
/// * [2] replica auth_path_bits
/// * [3] replica commitment (root hash)
/// * for i in 0..replica_parents.len()
///   * [ ] replica parent auth_path_bits
///   * [ ] replica parent commitment (root hash) // Same for all.
/// * [r + 1] data auth_path_bits
/// * [r + 2] data commitment (root hash)
///
///  Total = 6 + (2 * replica_parents.len())
/// # Private Inputs
///
/// * [ ] replica value/0
/// * for i in 0..replica_parents.len()
///  * [ ] replica parent value/0
/// * [ ] data value/
///
/// Total = 2 + replica_parents.len()
///
impl<'a, H: 'static + Hasher> Circuit<Bls12> for DrgPoRepCircuit<'a, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let replica_id = self.replica_id;
        let replica_root = self.replica_root;
        let data_root = self.data_root;

        let nodes = self.data_nodes.len();

        assert_eq!(self.replica_nodes.len(), nodes);
        assert_eq!(self.replica_nodes_paths.len(), nodes);
        assert_eq!(self.replica_parents.len(), nodes);
        assert_eq!(self.replica_parents_paths.len(), nodes);
        assert_eq!(self.data_nodes_paths.len(), nodes);

        let replica_node_num = AllocatedNum::alloc(cs.namespace(|| "replica_id_num"), || {
            replica_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        replica_node_num.inputize(cs.namespace(|| "replica_id"))?;

        // get the replica_id in bits
        let replica_id_bits =
            reverse_bit_numbering(replica_node_num.to_bits_le(cs.namespace(|| "replica_id_bits"))?);

        let replica_root_var = Root::Var(replica_root.allocated(cs.namespace(|| "replica_root"))?);
        let data_root_var = Root::Var(data_root.allocated(cs.namespace(|| "data_root"))?);

        for i in 0..self.data_nodes.len() {
            let mut cs = cs.namespace(|| format!("challenge_{}", i));
            // ensure that all inputs are well formed
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents_paths = &self.replica_parents_paths[i];
            let data_node_path = &self.data_nodes_paths[i];

            let replica_node = &self.replica_nodes[i];
            let replica_parents = &self.replica_parents[i];
            let data_node = &self.data_nodes[i];

            assert_eq!(replica_parents.len(), replica_parents_paths.len());
            assert_eq!(data_node_path.len(), replica_node_path.len());
            assert_eq!(replica_node.is_some(), data_node.is_some());

            // Inclusion checks
            {
                let mut cs = cs.namespace(|| "inclusion_checks");
                PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                    cs.namespace(|| "replica_inclusion"),
                    Root::Val(*replica_node),
                    replica_node_path.clone().into(),
                    replica_root_var.clone(),
                    self.private,
                )?;

                // validate each replica_parents merkle proof
                for j in 0..replica_parents.len() {
                    PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                        cs.namespace(|| format!("parents_inclusion_{}", j)),
                        Root::Val(replica_parents[j]),
                        replica_parents_paths[j].clone().into(),
                        replica_root_var.clone(),
                        self.private,
                    )?;
                }

                // validate data node commitment
                PoRCircuit::<BinaryMerkleTree<H>>::synthesize(
                    cs.namespace(|| "data_inclusion"),
                    Root::Val(*data_node),
                    data_node_path.clone().into(),
                    data_root_var.clone(),
                    self.private,
                )?;
            }

            // Encoding checks
            {
                let mut cs = cs.namespace(|| "encoding_checks");
                // get the parents into bits
                let parents_bits: Vec<Vec<Boolean>> = replica_parents
                    .iter()
                    .enumerate()
                    .map(|(i, val)| {
                        let num = AllocatedNum::alloc(
                            cs.namespace(|| format!("parents_{}_num", i)),
                            || val.map(Into::into).ok_or(SynthesisError::AssignmentMissing),
                        )?;
                        Ok(reverse_bit_numbering(num.to_bits_le(
                            cs.namespace(|| format!("parents_{}_bits", i)),
                        )?))
                    })
                    .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

                // generate the encryption key
                let key = kdf(
                    cs.namespace(|| "kdf"),
                    &replica_id_bits,
                    parents_bits,
                    None,
                    None,
                )?;

                let replica_node_num =
                    AllocatedNum::alloc(cs.namespace(|| "replica_node"), || {
                        (*replica_node).ok_or(SynthesisError::AssignmentMissing)
                    })?;

                let decoded = encode::decode(cs.namespace(|| "decode"), &key, &replica_node_num)?;

                // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                // TODO also note that we need to change/makesurethat the leaves are the data, instead of hashes of the data
                let expected = AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                    data_node.ok_or(SynthesisError::AssignmentMissing)
                })?;

                // ensure the encrypted data and data_node match
                constraint::equal(&mut cs, || "equality", &expected, &decoded);
            }
        }
        // profit!
        Ok(())
    }
}

/// Key derivation function.
fn kdf<E, CS>(
    mut cs: CS,
    id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    window_index: Option<UInt64>,
    node: Option<UInt64>,
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    // ciphertexts will become a buffer of the layout
    // id | node | encodedParentNode1 | encodedParentNode1 | ...

    let mut ciphertexts = id.to_vec();

    if let Some(window_index) = window_index {
        ciphertexts.extend_from_slice(&window_index.to_bits_be());
    }

    if let Some(node) = node {
        ciphertexts.extend_from_slice(&node.to_bits_be());
    }

    for parent in parents.into_iter() {
        ciphertexts.extend_from_slice(&parent);
    }

    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;
    let fr = if alloc_bits[0].get_value().is_some() {
        let be_bits = alloc_bits
            .iter()
            .map(|v| v.get_value().ok_or(SynthesisError::AssignmentMissing))
            .collect::<Result<Vec<bool>, SynthesisError>>()?;

        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .copied()
            .take(E::Fr::CAPACITY as usize)
            .collect::<Vec<bool>>();

        Ok(multipack::compute_multipacking::<E>(&le_bits)[0])
    } else {
        Err(SynthesisError::AssignmentMissing)
    };

    AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || fr)
}
