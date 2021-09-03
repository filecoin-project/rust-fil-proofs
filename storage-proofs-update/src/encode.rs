use blstrs::Scalar as Fr;
use filecoin_hashers::{Hasher, HashFunction};

use crate::constants::{partition_count, TreeDDomain, TreeRDomain, TreeRHasher};

pub fn encode_new_replica(
    labels_r_old: &[TreeRDomain],
    labels_d_new: &[TreeDDomain],
    phi: &TreeRDomain,
    h: usize,
) -> Vec<TreeRDomain> {
    let sector_nodes = labels_r_old.len();
    assert_eq!(sector_nodes, labels_d_new.len());

    let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
    let partition_count = partition_count(sector_nodes);
    let partition_bit_len = partition_count.trailing_zeros() as usize;

    // The bit-length of a node-index after the partition bits have been stripped.
    let node_index_sans_partition_bit_len = node_index_bit_len - partition_bit_len;
    // Bitwise AND-mask which removes the partition bits from each node-index.
    let remove_partition_mask = (1 << node_index_sans_partition_bit_len) - 1;
    let get_high_bits_shr = node_index_sans_partition_bit_len - h;

    (0..sector_nodes)
        .map(|node| {
            // Remove the partition-index from the node-index then take the `h` high bits.
            let high: TreeRDomain = {
                let node_sans_partition = node & remove_partition_mask;
                let high = node_sans_partition >> get_high_bits_shr;
                Fr::from(high as u64).into()
            };

            // `rho = H(phi || high)`
            let rho: Fr = <TreeRHasher as Hasher>::Function::hash2(phi, &high).into();

            // `label_r_new = label_r_old + label_d_new * rho`
            let label_r_old: Fr = labels_r_old[node].into();
            let label_d_new: Fr = labels_d_new[node].into();
            (label_r_old + label_d_new * rho).into()
        })
        .collect()
}
