use drgraph::{bucket_parents, Graph};
use error::Result;
use hasher::{Domain, Hasher};
use itertools::*;
use rayon::prelude::*;
use util::data_at_node;

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
    // Because a node always follows all of its parents in the data,
    // the nodes are by definition already topologically sorted.
    // Therefore, if we simply traverse the data in order, encoding each node in place,
    // we can always get each parent's encodings with a simple lookup --
    // since we will already have encoded the parent earlier in the traversal.
    // The only subtlety is that a ZigZag graph may be reversed, so the direction
    // of the traversal must also be.

    // Trading memory for speed here
    let graph_size = graph.size();
    let degree = graph.degree();
    let seed = graph.seed();

    // TODO: handle reverse graph

    // this code relies heavily on the fact that parents are sorted!

    let parents = (0..graph_size).into_iter().map(|n| {
        // TODO: make graph thread safe
        bucket_parents(&seed, degree, n)
    });

    let buckets_iter = parents
        .into_iter()
        .group_by(|p| (p.iter().max().unwrap()).clone());
    let mut buckets = buckets_iter
        .into_iter()
        .map(|(k, v)| (k, v.collect::<Vec<_>>()))
        .collect::<Vec<_>>();

    buckets.sort_by_key(|(k, _)| *k);

    for (done, cur_parents) in &buckets {
        // println!("bucket {} {:?}", done, cur_parents);
        let split_point = if done == &0 { 0 } else { (done + 1) * 32 };

        let (read_data, write_data) = data.split_at_mut(split_point);

        cur_parents
            .par_iter()
            .enumerate()
            .zip(write_data.par_chunks_mut(32)) // verify this does the right thing
            .try_for_each(|((n, p), raw_node)| -> Result<()> {
                // WARNING: inlined from create_key, due to borrowing issues

                // ciphertexts will become a buffer of the layout
                // id | encodedParentNode1 | encodedParentNode1 | ...

                let mut ciphertexts = vec![0u8; 32 + lambda * p.len()];
                replica_id.write_bytes(&mut ciphertexts[0..32])?;

                for (i, parent) in p.iter().enumerate() {
                    // special super shitty case
                    // TODO: unsuck
                    // println!("{} {}", n, p[0]);
                    if n == 1 || n == 0 {
                        // skip, as we would only write 0s, but the vector is prefilled with 0.
                    } else {
                        let start = 32 + i * lambda;
                        let end = 32 + (i + 1) * lambda;
                        ciphertexts[start..end]
                            .copy_from_slice(data_at_node(read_data, *parent, lambda)?);
                    }
                }

                let key = H::kdf(ciphertexts.as_slice(), degree);

                let node_data = H::Domain::try_from_bytes(raw_node)?;
                let encoded = H::sloth_encode(&key, &node_data, sloth_iter);

                encoded.write_bytes(raw_node)?;

                Ok(())
            })?;
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
    (0..graph.size()).fold(Ok(Vec::with_capacity(data.len())), |acc, i| {
        acc.and_then(|mut acc| {
            acc.extend(&decode_block(graph, lambda, sloth_iter, replica_id, data, i)?.into_bytes());
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, H, G>(
    graph: &'a G,
    lambda: usize,
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

    let key = create_key::<H>(replica_id, v, &parents, data, lambda, graph.degree())?;
    let node_data = H::Domain::try_from_bytes(&data_at_node(data, v, lambda)?)?;

    // TODO: round constant
    Ok(H::sloth_decode(&key, &node_data, sloth_iter))
}

fn create_key<H: Hasher>(
    id: &H::Domain,
    node: usize,
    parents: &[usize],
    data: &[u8],
    node_size: usize,
    m: usize,
) -> Result<H::Domain> {
    // ciphertexts will become a buffer of the layout
    // id | encodedParentNode1 | encodedParentNode1 | ...

    let mut ciphertexts = vec![0u8; 32 + node_size * parents.len()];
    id.write_bytes(&mut ciphertexts[0..32])?;

    for (i, parent) in parents.iter().enumerate() {
        // special super shitty case
        // TODO: unsuck
        if node == parents[0] {
            // skip, as we would only write 0s, but the vector is prefilled with 0.
        } else {
            let start = 32 + i * node_size;
            let end = 32 + (i + 1) * node_size;
            ciphertexts[start..end].copy_from_slice(data_at_node(data, *parent, node_size)?);
        }
    }

    Ok(H::kdf(ciphertexts.as_slice(), m))
}
