use blake2s_simd::Params as Blake2s;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::HybridMerkleTree;
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, AH, BH, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a BH::Domain,
    data: &'a mut [u8],
) -> Result<()>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    // Because a node always follows all of its parents in the data,
    // the nodes are by definition already topologically sorted.
    // Therefore, if we simply traverse the data in order, encoding each node in place,
    // we can always get each parent's encodings with a simple lookup --
    // since we will already have encoded the parent earlier in the traversal.
    // The only subtlety is that a ZigZag graph may be reversed, so the direction
    // of the traversal must also be.

    let mut parents = vec![0usize; graph.degree()];
    for n in 0..graph.size() {
        let node = if graph.forward() {
            n
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - n) - 1
        };

        graph.parents(node, &mut parents);

        let key = create_key::<BH>(replica_id, node, &parents, data)?;
        let start = data_at_node_offset(node);
        let end = start + NODE_SIZE;
        let node_data = BH::Domain::try_from_bytes(&data[start..end])?;
        let encoded = BH::sloth_encode(&key, &node_data, sloth_iter);
        encoded.write_bytes(&mut data[start..end])?;
    }

    Ok(())
}

pub fn decode<'a, AH, BH, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a BH::Domain,
    data: &'a [u8],
) -> Result<Vec<u8>>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    // TODO: parallelize
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(decode_block(graph, sloth_iter, replica_id, data, i)?.into_bytes());
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, AH, BH, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a BH::Domain,
    data: &'a [u8],
    v: usize,
) -> Result<BH::Domain>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    let mut parents = vec![0usize; graph.degree()];
    graph.parents(v, &mut parents);
    let key = create_key::<BH>(replica_id, v, &parents, &data)?;
    let node_data = BH::Domain::try_from_bytes(&data_at_node(data, v)?)?;
    Ok(BH::sloth_decode(&key, &node_data, sloth_iter))
}

pub fn decode_domain_block<AH, BH>(
    sloth_iter: usize,
    replica_id: &BH::Domain,
    tree: &HybridMerkleTree<AH, BH>,
    node: usize,
    node_data: BH::Domain,
    parents: &[usize],
) -> Result<BH::Domain>
where
    AH: Hasher,
    BH: Hasher,
{
    let key = create_key_from_tree::<AH, BH>(replica_id, node, parents, tree)?;
    Ok(BH::sloth_decode(&key, &node_data, sloth_iter))
}

/// Creates the encoding key.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key<H: Hasher>(
    replica_id: &H::Domain,
    node: usize,
    parents: &[usize],
    data: &[u8],
) -> Result<H::Domain> {
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(replica_id.as_ref());

    // The hash is about the parents, hence skip if a node doesn't have any parents
    if node != parents[0] {
        for parent in parents.iter() {
            let offset = data_at_node_offset(*parent);
            hasher.update(&data[offset..offset + NODE_SIZE]);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}

/// Creates the encoding key from a `HybridMerkleTree`.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key_from_tree<AH, BH>(
    replica_id: &BH::Domain,
    node: usize,
    parents: &[usize],
    tree: &HybridMerkleTree<AH, BH>,
) -> Result<BH::Domain>
where
    AH: Hasher,
    BH: Hasher,
{
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(replica_id.as_ref());

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
