use crypto;
use drgraph;
use error::Result;
use fr32::{bytes_into_fr, fr_into_bytes};
use pairing::bls12_381::{Bls12, Fr};
use pairing::{Field, PrimeField, PrimeFieldRepr};
use util::{data_at_node, data_at_node_offset};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, G: drgraph::Graph>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    prover_id: &'a Fr,
    data: &'a mut [u8],
) -> Result<()> {
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

        let key = create_key(prover_id, node, &parents, data, lambda, degree)?;
        let start = data_at_node_offset(node, lambda);
        let end = start + lambda;
        let fr = bytes_into_fr::<Bls12>(&data[start..end])?;

        let encoded =
            fr_into_bytes::<Bls12>(&crypto::sloth::encode::<Bls12>(&key, &fr, sloth_iter));

        data[start..end].copy_from_slice(&encoded);
    }

    Ok(())
}

pub fn decode<'a, G: drgraph::Graph>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    prover_id: &'a Fr,
    data: &'a [u8],
) -> Result<Vec<u8>> {
    // TODO: parallelize
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(fr_into_bytes::<Bls12>(&decode_block(
                graph, lambda, sloth_iter, prover_id, data, i,
            )?));
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, G: drgraph::Graph>(
    graph: &'a G,
    lambda: usize,
    sloth_iter: usize,
    prover_id: &'a Fr,
    data: &'a [u8],
    v: usize,
) -> Result<Fr> {
    let parents = graph.parents(v);
    let key = create_key(prover_id, v, &parents, data, lambda, graph.degree())?;
    let fr = bytes_into_fr::<Bls12>(&data_at_node(data, v, lambda)?)?;

    // TODO: round constant
    Ok(crypto::sloth::decode::<Bls12>(&key, &fr, sloth_iter))
}

fn create_key(
    id: &Fr,
    node: usize,
    parents: &[usize],
    data: &[u8],
    node_size: usize,
    m: usize,
) -> Result<Fr> {
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...

    let ciphertexts = parents.iter().fold(
        Ok(fr_into_bytes::<Bls12>(id)),
        |acc: Result<Vec<u8>>, parent: &usize| {
            acc.and_then(|mut acc| {
                // special super shitty case
                // TODO: unsuck
                if node == parents[0] {
                    Fr::zero().into_repr().write_le(&mut acc)?;
                } else {
                    acc.extend(data_at_node(data, *parent, node_size)?.to_vec());
                }
                Ok(acc)
            })
        },
    )?;

    Ok(crypto::kdf::kdf::<Bls12>(ciphertexts.as_slice(), m))
}
