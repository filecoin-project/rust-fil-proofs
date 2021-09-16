use std::ops::{AddAssign, MulAssign};

use blstrs::{Bls12, Scalar as Fr};
use ff::Field;
use filecoin_hashers::{HashFunction, Hasher};
use storage_proofs_core::merkle::MerkleTreeTrait;

use crate::TreeD;

pub fn encode_new_replica<H: Hasher>(
    labels_r_old: &[H::Domain],
    labels_d_new: &[<<TreeD as MerkleTreeTrait>::Hasher as Hasher>::Domain],
    phi: &H::Domain,
    h: usize,
) -> Vec<H::Domain> {
    let sector_nodes = labels_r_old.len();
    assert_eq!(sector_nodes, labels_d_new.len());

    let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
    let shr = node_index_bit_len - h;

    (0..sector_nodes)
        .map(|node_index| {
            // Get `h` high bits of `node_index`.
            let shifted = node_index >> shr;
            let shifted: H::Domain = Fr::from(shifted as u64).into();

            // rho = H(phi || node_index >> (log2(sector_nodes) - h))
            let rho: Fr = H::Function::hash2(phi, &shifted).into();

            // label_r_new = label_r_old + label_d_new * rho
            let label_r_old: Fr = labels_r_old[node_index].into();
            let label_d_new: Fr = labels_d_new[node_index].into();

            let label_r_new = {
                let mut label = label_d_new;
                label.mul_assign(&rho);
                label.add_assign(&label_r_old);
                label
            };

            label_r_new.into()
        })
        .collect()
}
