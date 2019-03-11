use blake2s_simd::Params as Blake2s;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::util::{data_at_node, data_at_node_offset};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, H, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a mut [u8],
) -> Result<()>
where
    H: Hasher,
    G: Graph<H>,
{
    let degree = graph.degree();

    // Because a node always follows all of its parents in the data,
    // the nodes are by definition already topologically sorted.
    // Therefore, if we simply traverse the data in order, encoding each node in place,
    // we can always get each parent's encodings with a simple lookup --
    // since we will already have encoded the parent earlier in the traversal.
    // The only subtlety is that a ZigZag graph may be reversed, so the direction
    // of the traversal must also be.

    for n in 0..graph.size() {
        let node = if graph.forward() {
            n
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - n) - 1
        };

        let parents = graph.parents(node);
        assert_eq!(parents.len(), graph.degree(), "wrong number of parents");

        let key = create_key::<H>(replica_id, node, &parents, data, degree)?;
        let start = data_at_node_offset(node);
        let end = start + 32;

        let node_data = H::Domain::try_from_bytes(&data[start..end])?;
        let encoded = H::sloth_encode(&key, &node_data, sloth_iter);

        encoded.write_bytes(&mut data[start..end])?;
    }

    Ok(())
}

pub fn decode<'a, H, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a [u8],
) -> Result<Vec<u8>>
where
    H: Hasher,
    G: Graph<H>,
{
    // TODO: parallelize
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(decode_block(graph, sloth_iter, replica_id, data, i)?.into_bytes());
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, H, G>(
    graph: &'a G,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a [u8],
    v: usize,
) -> Result<H::Domain>
where
    H: Hasher,
    G: Graph<H>,
{
    let parents = graph.parents(v);
    let key = create_key::<H>(replica_id, v, &parents, &data, graph.degree())?;
    let node_data = H::Domain::try_from_bytes(&data_at_node(data, v)?)?;

    Ok(H::sloth_decode(&key, &node_data, sloth_iter))
}

pub fn decode_domain_block<H>(
    sloth_iter: usize,
    replica_id: &H::Domain,
    data: &[H::Domain],
    node: usize,
    parents: &[usize],
) -> Result<H::Domain>
where
    H: Hasher,
{
    let key = create_domain_key::<H>(replica_id, node, parents, data)?;

    Ok(H::sloth_decode(&key, &data[node], sloth_iter))
}

/// Creates the encoding key, using domain encoded data.
fn create_domain_key<H: Hasher>(
    id: &H::Domain,
    node: usize,
    parents: &[usize],
    data: &[H::Domain],
) -> Result<H::Domain> {
    let mut hasher = Blake2s::new().hash_length(32).to_state();
    hasher.update(id.as_ref());

    for parent in parents.iter() {
        // special super shitty case
        // TODO: unsuck
        if node == parents[0] {
            // skip, as we would only write 0s
        } else {
            hasher.update(data[*parent].as_ref());
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}

/// Creates the encoding key.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
fn create_key<H: Hasher>(
    id: &H::Domain,
    node: usize,
    parents: &[usize],
    data: &[u8],
    _m: usize,
) -> Result<H::Domain> {
    let mut hasher = Blake2s::new().hash_length(32).to_state();
    hasher.update(id.as_ref());

    for parent in parents.iter() {
        // special super shitty case
        // TODO: unsuck
        if node == parents[0] {
            // skip, as we would only write 0s
        } else {
            let offset = data_at_node_offset(*parent);
            hasher.update(&data[offset..offset + 32]);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}
