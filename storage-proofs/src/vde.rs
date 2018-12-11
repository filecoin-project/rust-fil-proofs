use crate::crypto::kdf;
use crate::drgraph::Graph;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::util::{data_at_node, data_at_node_offset};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, H, G>(
    graph: &'a G,
    lambda: usize,
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

    let mut ciphertexts = vec![0u8; 32 + lambda * graph.degree()];
    replica_id
        .write_bytes(&mut ciphertexts[0..32])
        .expect("preallocated dest");

    for n in 0..graph.size() {
        let node = if graph.forward() {
            n
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - n) - 1
        };

        let parents = graph.parents(node);
        assert_eq!(parents.len(), graph.degree(), "wrong number of parents");

        let key = create_key::<H>(&mut ciphertexts, node, &parents, data, lambda, degree);
        let start = data_at_node_offset(node, lambda);
        let end = start + lambda;

        let node_data = H::Domain::try_from_bytes(&data[start..end])?;
        let encoded = H::sloth_encode(&key, &node_data, sloth_iter);

        encoded.write_bytes(&mut data[start..end])?;
    }

    Ok(())
}

pub fn decode<'a, H, G>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a [u8],
) -> Result<Vec<u8>>
where
    H: Hasher,
    G: Graph<H>,
{
    // TODO: parallelize
    let mut ciphertexts = vec![0u8; 32 + lambda * graph.degree()];
    replica_id
        .write_bytes(&mut ciphertexts[0..32])
        .expect("preallocated dest");

    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(
                decode_block(graph, lambda, sloth_iter, data, i, &mut ciphertexts)?.into_bytes(),
            );
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, H, G>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    data: &'a [u8],
    v: usize,
    ciphertexts: &mut [u8],
) -> Result<H::Domain>
where
    H: Hasher,
    G: Graph<H>,
{
    let parents = graph.parents(v);
    let key = create_key::<H>(ciphertexts, v, &parents, &data, lambda, graph.degree());
    let node_data = H::Domain::try_from_bytes(&data_at_node(data, v, lambda)?)?;

    // TODO: round constant
    Ok(H::sloth_decode(&key, &node_data, sloth_iter))
}

pub fn decode_domain_block<'a, H, G>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    replica_id: &'a H::Domain,
    data: &'a [H::Domain],
    v: usize,
) -> Result<H::Domain>
where
    H: Hasher,
    G: Graph<H>,
{
    let parents = graph.parents(v);

    let byte_data = data
        .iter()
        .flat_map(H::Domain::into_bytes)
        .collect::<Vec<u8>>();

    let mut ciphertexts = vec![0u8; 32 + lambda * graph.degree()];
    replica_id
        .write_bytes(&mut ciphertexts[0..32])
        .expect("preallocated dest");

    let key = create_key::<H>(
        &mut ciphertexts,
        v,
        &parents,
        &byte_data,
        lambda,
        graph.degree(),
    );
    let node_data = data[v];

    // TODO: round constant
    Ok(H::sloth_decode(&key, &node_data, sloth_iter))
}

pub fn create_key<H: Hasher>(
    ciphertexts: &mut [u8],
    node: usize,
    parents: &[usize],
    data: &[u8],
    node_size: usize,
    m: usize,
) -> H::Domain {
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...

    // special super shitty case
    // TODO: unsuck
    // skip, as we would only write 0s, but the vector is prefilled with 0.
    if node != parents[0] {
        for (i, parent) in parents.iter().enumerate() {
            let start = 32 + i * node_size;
            let end = 32 + (i + 1) * node_size;
            ciphertexts[start..end].copy_from_slice(
                data_at_node(data, *parent, node_size).expect("failed to calc offsets"),
            );
        }
    }

    kdf::kdf(ciphertexts, m).into()
}
