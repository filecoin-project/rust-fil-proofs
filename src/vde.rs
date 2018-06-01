
use drgraph;
use util::{data_at_node_offset, data_at_node};
use crypto;

/// encodes the data and overwrites the original data slice.
pub fn encode<'a>(
    graph: &'a drgraph::Graph,
    lambda: usize,
    prover_id: &'a [u8],
    data: &'a mut [u8],
) {
    // cache to keep track of which parts have been encrypted yet
    let mut cache = vec![false; graph.size()];

    (0..graph.size()).rev().for_each(|i| {
        recursive_encode(graph, lambda, prover_id, &mut cache, data, i + 1)
    });
}

fn recursive_encode(
    graph: &drgraph::Graph,
    lambda: usize,
    prover_id: &[u8],
    cache: &mut Vec<bool>,
    data: &mut [u8],
    node: usize,
) {
    if !cache[node - 1] {
        if let Some(parents) = graph.parents(node) {
            // -- seal all parents of this node

            parents.iter().for_each(|parent| {
                recursive_encode(graph, lambda, prover_id, cache, data, *parent)
            });

            // -- create sealing key for this ndoe

            let key = create_key(prover_id, parents, data, lambda);

            // -- seal this node
            let start = data_at_node_offset(node, lambda);
            let end = start + lambda;
            let mut out = vec![0u8; lambda];

            crypto::encode(key.as_slice(), &data[start..end], out.as_mut_slice());
            data[start..end].clone_from_slice(out.as_slice());
            cache[node - 1] = true;
        }
    }
}

fn create_key(id: &[u8], parents: &Vec<usize>, data: &[u8], node_size: usize) -> Vec<u8> {
    // ciphertexts will become a buffer of the layout
    // encodedParentNode1 | encodedParentNode1 | ...
    let ciphertexts = parents.iter().fold(Vec::new(), |mut acc, parent| {
        let offset = data_at_node_offset(*parent, node_size);
        acc.extend(data[offset..offset + node_size].to_vec());
        acc
    });

    crypto::kdf(ciphertexts.as_slice())
}
