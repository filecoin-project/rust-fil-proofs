use blake2s_simd::Params as Blake2s;
use paired::bls12_381::FrRepr;

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::hybrid::HybridDomain;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::HybridMerkleTree;
use crate::util::{data_at_node, data_at_node_offset, NODE_SIZE};

/// encodes the data and overwrites the original data slice.
pub fn encode<'a, AH, BH, G>(
    graph: &'a G,
    replica_id: &'a HybridDomain<AH::Domain, BH::Domain>,
    data: &'a mut [u8],
) -> Result<()>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    // Because a node always follows all of its parents in the data, the nodes are by definition
    // already topologically sorted.  Therefore, if we simply traverse the data in order, encoding
    // each node in place, we can always get each parent's encodings with a simple lookup -- since
    // we will already have encoded the parent earlier in the traversal.  The only subtlety is that
    // a ZigZag graph may be reversed, so the direction of the traversal must also be.

    let mut parents = vec![0; graph.degree()];

    for node_index in 0..graph.size() {
        let node_index = if graph.forward() {
            node_index
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - node_index) - 1
        };

        graph.parents(node_index, &mut parents);

        let key_fr = create_key(replica_id.as_ref(), node_index, &parents, data)?;
        let start = data_at_node_offset(node_index);
        let stop = start + NODE_SIZE;

        // Nodes and encoding keys are always the same variant of `HybridDomain` as the replica-id.
        if replica_id.is_alpha() {
            let key: AH::Domain = key_fr.into();
            let node_alpha = AH::Domain::try_from_bytes(&data[start..stop])?;
            let encoded = AH::sloth_encode(&key, &node_alpha);
            encoded.write_bytes(&mut data[start..stop])?;
        } else {
            let key: BH::Domain = key_fr.into();
            let node_beta = BH::Domain::try_from_bytes(&data[start..stop])?;
            let encoded = BH::sloth_encode(&key, &node_beta);
            encoded.write_bytes(&mut data[start..stop])?;
        };
    }

    Ok(())
}

pub fn decode<'a, AH, BH, G>(
    graph: &'a G,
    replica_id: &'a HybridDomain<AH::Domain, BH::Domain>,
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
            acc.extend(decode_block(graph, replica_id, data, i)?.into_bytes());
            Ok(acc)
        })
    })
}

pub fn decode_block<'a, AH, BH, G>(
    graph: &'a G,
    replica_id: &'a HybridDomain<AH::Domain, BH::Domain>,
    data: &'a [u8],
    v: usize,
) -> Result<HybridDomain<AH::Domain, BH::Domain>>
where
    AH: Hasher,
    BH: Hasher,
    G: Graph<AH, BH>,
{
    let mut parents = vec![0; graph.degree()];
    graph.parents(v, &mut parents);

    let key_fr = create_key(replica_id.as_ref(), v, &parents, &data)?;
    let node_data = data_at_node(data, v)?;

    // Nodes and encoding keys have the same variant of `HybridDomain` as the replica-id.
    let decoded = if replica_id.is_alpha() {
        let key: AH::Domain = key_fr.into();
        let node_alpha = AH::Domain::try_from_bytes(node_data)?;
        let decoded_alpha = AH::sloth_decode(&key, &node_alpha);
        HybridDomain::Alpha(decoded_alpha)
    } else {
        let key: BH::Domain = key_fr.into();
        let node_beta = BH::Domain::try_from_bytes(node_data)?;
        let decoded_beta = BH::sloth_decode(&key, &node_beta);
        HybridDomain::Beta(decoded_beta)
    };

    Ok(decoded)
}

pub fn decode_domain_block<AH, BH>(
    replica_id: &HybridDomain<AH::Domain, BH::Domain>,
    tree: &HybridMerkleTree<AH, BH>,
    node_index: usize,
    node_data: HybridDomain<AH::Domain, BH::Domain>,
    parents: &[usize],
) -> Result<HybridDomain<AH::Domain, BH::Domain>>
where
    AH: Hasher,
    BH: Hasher,
{
    let key_fr = create_key_from_tree::<AH, BH>(replica_id.as_ref(), node_index, parents, tree)?;

    // Nodes and encoding keys have the same variant of `HybridDomain` as the replica-id.
    let decoded = if replica_id.is_alpha() {
        let key: AH::Domain = key_fr.into();
        let decoded_alpha = AH::sloth_decode(&key, node_data.alpha_value());
        HybridDomain::Alpha(decoded_alpha)
    } else {
        let key: BH::Domain = key_fr.into();
        let decoded_beta = BH::sloth_decode(&key, node_data.beta_value());
        HybridDomain::Beta(decoded_beta)
    };

    Ok(decoded)
}

/// Creates the encoding key.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key(
    replica_id_bytes: &[u8],
    node_index: usize,
    parents: &[usize],
    data: &[u8],
) -> Result<FrRepr> {
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(replica_id_bytes);

    // The hash is about the parents, hence skip if a node_index doesn't have any parents
    if node_index != parents[0] {
        for parent in parents.iter() {
            let offset = data_at_node_offset(*parent);
            hasher.update(&data[offset..offset + NODE_SIZE]);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()))
}

/// Creates the encoding key from a `MerkleTree`.
/// The algorithm for that is `Blake2s(id | encodedParentNode1 | encodedParentNode1 | ...)`.
/// It is only public so that it can be used for benchmarking
pub fn create_key_from_tree<AH, BH>(
    replica_id_bytes: &[u8],
    node: usize,
    parents: &[usize],
    tree: &HybridMerkleTree<AH, BH>,
) -> Result<FrRepr>
where
    AH: Hasher,
    BH: Hasher,
{
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(replica_id_bytes);

    // The hash is about the parents, hence skip if a node doesn't have any parents
    if node != parents[0] {
        let mut scratch: [u8; NODE_SIZE] = [0; NODE_SIZE];
        for parent in parents.iter() {
            tree.read_into(*parent, &mut scratch);
            hasher.update(&scratch);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()))
}
