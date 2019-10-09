use blake2s_simd::Params as Blake2s;
use rayon::prelude::*;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, H, G>(
    graph: &'a G,
    replica_id: &'a H::Domain,
    data: &'a mut [u8],
    exp_parents_data: Option<&'a [u8]>,
) -> Result<()>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H>,
{
    // Because a node always follows all of its parents in the data,
    // the nodes are by definition already topologically sorted.
    // Therefore, if we simply traverse the data in order, encoding each node in place,
    // we can always get each parent's encodings with a simple lookup --
    // since we will already have encoded the parent earlier in the traversal.

    let mut parents = vec![0; graph.degree()];
    for node in 0..graph.size() {
        graph.parents(node, &mut parents);
        let key = graph.create_key(replica_id, node, &parents, data, exp_parents_data)?;
        let start = data_at_node_offset(node);
        let end = start + NODE_SIZE;

        let node_data = H::Domain::try_from_bytes(&data[start..end])?;
        let encoded = H::sloth_encode(key.as_ref(), &node_data);

        encoded.write_bytes(&mut data[start..end])?;
    }

    Ok(())
}

pub fn decode<'a, H, G>(
    graph: &'a G,
    replica_id: &'a H::Domain,
    data: &'a [u8],
    exp_parents_data: Option<&'a [u8]>,
) -> Result<Vec<u8>>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H> + Sync,
{
    // TODO: proper error handling
    let result = (0..graph.size())
        .into_par_iter()
        .flat_map(|i| {
            decode_block(graph, replica_id, data, exp_parents_data, i)
                .unwrap()
                .into_bytes()
        })
        .collect();

    Ok(result)
}

pub fn decode_block<'a, H, G>(
    graph: &'a G,
    replica_id: &'a H::Domain,
    data: &'a [u8],
    exp_parents_data: Option<&'a [u8]>,
    v: usize,
) -> Result<H::Domain>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H>,
{
    let mut parents = vec![0; graph.degree()];
    graph.parents(v, &mut parents);
    let key = graph.create_key(replica_id, v, &parents, &data, exp_parents_data)?;
    let node_data = H::Domain::try_from_bytes(&data_at_node(data, v)?)?;

    Ok(H::sloth_decode(key.as_ref(), &node_data))
}

pub fn decode_domain_block<H>(
    replica_id: &H::Domain,
    tree: &MerkleTree<H::Domain, H::Function>,
    node: usize,
    node_data: <H as Hasher>::Domain,
    parents: &[usize],
) -> Result<H::Domain>
where
    H: Hasher,
{
    let key = create_key_from_tree::<H>(replica_id, node, parents, tree)?;

    Ok(H::sloth_decode(&key, &node_data))
}

/// Creates the encoding key from a `MerkleTree`.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key_from_tree<H: Hasher>(
    id: &H::Domain,
    node: usize,
    parents: &[usize],
    tree: &MerkleTree<H::Domain, H::Function>,
) -> Result<H::Domain> {
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(AsRef::<[u8]>::as_ref(&id));

    // The hash is about the parents, hence skip if a node doesn't have any parents
    if node != parents[0] {
        let mut scratch: [u8; NODE_SIZE] = [0; NODE_SIZE];
        for parent in parents.iter() {
            tree.read_into(*parent, &mut scratch);
            hasher.update(&scratch);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}
