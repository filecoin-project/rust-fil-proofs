use crypto;
use drgraph;
use error::Result;
use util::{data_at_node, data_at_node_offset};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a>(
    graph: &'a drgraph::Graph,
    lambda: usize,
    prover_id: &'a [u8],
    data: &'a mut [u8],
) -> Result<()> {
    // cache to keep track of which parts have been encrypted yet
    let mut cache = vec![false; graph.size()];

    (0..graph.size())
        .rev()
        .map(|i| recursive_encode(graph, lambda, prover_id, &mut cache, data, i + 1))
        .collect()
}

fn recursive_encode(
    graph: &drgraph::Graph,
    lambda: usize,
    prover_id: &[u8],
    cache: &mut Vec<bool>,
    data: &mut [u8],
    node: usize,
) -> Result<()> {
    if cache[node - 1] {
        return Ok(());
    }

    // -- seal all parents of this node

    let parents = graph.parents(node);

    // TODO: unsuck
    if node != parents[0] {
        parents
            .iter()
            .map(|parent| recursive_encode(graph, lambda, prover_id, cache, data, *parent))
            .collect::<Result<()>>()?;
    }

    // -- create sealing key for this ndoe

    println!("parents: {}", parents.len());
    println!("prover_id: {}", prover_id.len());
    println!("node: {}", node);

    let key = create_key(prover_id, node, &parents, data, lambda, graph.degree())?;

    // -- seal this node
    let start = data_at_node_offset(node, lambda);
    let end = start + lambda;

    let encoded = crypto::xor::encode(key.as_slice(), &data[start..end])?;

    data[start..end].clone_from_slice(encoded.as_slice());
    cache[node - 1] = true;

    Ok(())
}

pub fn decode<'a>(
    graph: &'a drgraph::Graph,
    lambda: usize,
    prover_id: &'a [u8],
    data: &'a [u8],
) -> Result<Vec<u8>> {
    // TODO: parallelize
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(decode_block(graph, lambda, prover_id, data, i + 1)?);
            Ok(acc)
        })
    })
}

pub fn decode_block<'a>(
    graph: &'a drgraph::Graph,
    lambda: usize,
    prover_id: &'a [u8],
    data: &'a [u8],
    v: usize,
) -> Result<Vec<u8>> {
    let parents = graph.parents(v);
    let key = create_key(prover_id, v, &parents, data, lambda, graph.degree())?;
    let node_data = data_at_node(data, v, lambda)?;

    crypto::xor::decode(key.as_slice(), node_data)
}

fn create_key(
    id: &[u8],
    node: usize,
    parents: &[usize],
    data: &[u8],
    node_size: usize,
    m: usize,
) -> Result<Vec<u8>> {
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...
    let ciphertexts = parents.iter().fold(
        Ok(id.to_vec()),
        |acc: Result<Vec<u8>>, parent: &usize| {
            acc.and_then(|mut acc| {
                // special super shitty case
                // TODO: unsuck
                if node == parents[0] {
                    acc.extend(vec![0u8; node_size]);
                } else {
                    acc.extend(data_at_node(data, *parent, node_size)?.to_vec());
                }
                Ok(acc)
            })
        },
    )?;

    Ok(crypto::kdf::kdf(ciphertexts.as_slice(), m))
}
