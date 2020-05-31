#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use sha2raw::Sha256;
use storage_proofs_core::{
    error::Result,
    hasher::Hasher,
    util::{data_at_node_offset, NODE_SIZE},
};

use super::graph::{PartialParentCache, StackedBucketGraph};

pub fn create_label_mixed<H: Hasher>(
    parents: &mut PartialParentCache,
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    layer_labels: &mut [u8],
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..8].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data_mixed(parents, node as u32, &*layer_labels, hasher)?
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub fn create_label_exp_mixed<H: Hasher>(
    parents: &mut PartialParentCache,
    graph: &StackedBucketGraph<H>,
    replica_id: &H::Domain,
    exp_parents_data: &[u8],
    layer_labels: &mut [u8],
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..8].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[AsRef::<[u8]>::as_ref(replica_id), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        unsafe {
            _mm_prefetch(prev.as_ptr() as *const i8, _MM_HINT_T0);
        }

        graph.copy_parents_data_exp_mixed(
            parents,
            node as u32,
            &*layer_labels,
            exp_parents_data,
            hasher,
        )?
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub struct MixedLayer<'a> {
    ondisk: &'a mut [u8],
    ondisk_nodes: usize,
    ondisk_bytes: usize,

    inmem: &'a mut [u8],
    inmem_nodes: usize,
    inmem_bytes: usize,

    nodes: usize,
}

impl<'a> MixedLayer<'a> {
    pub fn push(&mut self, hash: &[u8]) {
        let start = self.nodes * NODE_SIZE;
        let end = start + NODE_SIZE;

        if end <= self.inmem_bytes {
            self.inmem[start..end].copy_from_slice(hash);
            if end == self.ondisk_bytes {
                self.ondisk
                    .copy_from_slice(&self.inmem[..self.ondisk_bytes]);
            }
        } else {
            self.inmem[start - self.inmem_bytes..end - self.inmem_bytes].copy_from_slice(hash);
        }

        self.nodes += 1;
    }

    // [ 0,  1,  2,  3 ][ 0,  1,  2,  3,  4,  5,  6,  7 ]
    //                  [ 8,  9, 10, 11 ]
    pub fn read(&self, node: usize) -> &[u8] {
        let mut start = node * NODE_SIZE;
        // we'll never read a node larger than the latest generated one
        if self.nodes <= self.inmem_nodes {
            return &self.inmem[start..start + NODE_SIZE];
        }

        let lowest = self.nodes - self.inmem_nodes;
        // lower nodes can only be read from ondisk part
        if node < lowest {
            return &self.ondisk[start..start + NODE_SIZE];
        }

        if node >= self.inmem_nodes {
            start = (node - self.inmem_nodes) * NODE_SIZE;
        }

        &self.inmem[start..start + NODE_SIZE]
    }
}
