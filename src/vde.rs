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
    prover_id: &'a Fr,
    data: &'a mut [u8],
) -> Result<()> {
    // cache to keep track of which parts have been encrypted yet
    let mut cache = vec![false; graph.size()];

    (0..graph.size())
        .rev()
        .map(|i| recursive_encode(graph, lambda, prover_id, &mut cache, data, i))
        .collect()
}

fn recursive_encode<G: drgraph::Graph>(
    graph: &G,
    lambda: usize,
    prover_id: &Fr,
    cache: &mut [bool],
    data: &mut [u8],
    node: usize,
) -> Result<()> {
    if cache[node] {
        return Ok(());
    }

    // -- seal all parents of this node

    let parents = graph.parents(node);

    assert_eq!(parents.len(), graph.degree(), "wrong number of parents");

    // TODO: unsuck
    if node != parents[0] {
        parents
            .iter()
            .map(|parent| recursive_encode(graph, lambda, prover_id, cache, data, *parent))
            .collect::<Result<()>>()?;
    }

    // -- create sealing key for this ndoe

    let key = create_key(prover_id, node, &parents, data, lambda, graph.degree())?;

    // -- seal this node

    let start = data_at_node_offset(node, lambda);
    let end = start + lambda;
    let fr = bytes_into_fr::<Bls12>(&data[start..end])?;

    let encoded = fr_into_bytes::<Bls12>(&crypto::sloth::encode::<Bls12>(
        &key,
        &fr,
        crypto::sloth::DEFAULT_ROUNDS,
    ));
    data[start..end].clone_from_slice(encoded.as_slice());
    cache[node] = true;

    Ok(())
}

pub fn decode<'a, G: drgraph::Graph>(
    graph: &'a G,
    lambda: usize,
    prover_id: &'a Fr,
    data: &'a [u8],
) -> Result<Vec<u8>> {
    // TODO: parallelize
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(fr_into_bytes::<Bls12>(&decode_block(
                graph, lambda, prover_id, data, i,
            )?));
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, G: drgraph::Graph>(
    graph: &'a G,
    lambda: usize,
    prover_id: &'a Fr,
    data: &'a [u8],
    v: usize,
) -> Result<Fr> {
    let parents = graph.parents(v);
    let key = create_key(prover_id, v, &parents, data, lambda, graph.degree())?;
    let fr = bytes_into_fr::<Bls12>(&data_at_node(data, v, lambda)?)?;

    // TODO: round constant
    Ok(crypto::sloth::decode::<Bls12>(
        &key,
        &fr,
        crypto::sloth::DEFAULT_ROUNDS,
    ))
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
