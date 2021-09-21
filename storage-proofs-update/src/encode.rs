use blstrs::Scalar as Fr;
use filecoin_hashers::{Hasher, HashFunction};
use storage_proofs_core::merkle::MerkleTreeTrait;

use crate::constants::TreeD;

pub fn encode_new_replica<H: Hasher>(
    labels_r_old: &[H::Domain],
    labels_d_new: &[<<TreeD as MerkleTreeTrait>::Hasher as Hasher>::Domain],
    phi: &H::Domain,
    h: usize,
) -> Vec<H::Domain> {
    let sector_nodes = labels_r_old.len();
    assert_eq!(sector_nodes, labels_d_new.len());

    let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
    let get_high_bits_shr = node_index_bit_len - h;

    (0..sector_nodes)
        .map(|node_index| {
            // Get `h` high bits of `node_index`.
            let high: H::Domain = {
                let high = node_index >> get_high_bits_shr;
                Fr::from(high as u64).into()
            };

            // `rho = H(phi || node_index >> (log2(sector_nodes) - h))`
            let rho: Fr = H::Function::hash2(phi, &high).into();

            // `label_r_new = label_r_old + label_d_new * rho`
            let label_r_old: Fr = labels_r_old[node_index].into();
            let label_d_new: Fr = labels_d_new[node_index].into();
            (label_r_old + label_d_new * rho).into()
        })
        .collect()
}
