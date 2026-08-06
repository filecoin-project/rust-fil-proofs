use filecoin_hashers::{Domain, Hasher};
use fr32::bytes_into_fr_repr_safe;
use rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    drgraph::Graph,
    error::Result,
    parameter_cache::ParameterSetMetadata,
    util::{data_at_node, data_at_node_offset, NODE_SIZE},
};

use crate::encode;
use crate::zigzag::vanilla::graph::ZigZagGraph;

/// Encodes `data` in place using the ZigZag `graph`.
///
/// Because a node always follows all of its parents in the data, the nodes are already
/// topologically sorted, so a single in-order traversal can encode each node using its
/// already-encoded parents. The subtlety versus a plain DRG is that a reversed ZigZag layer must be
/// traversed from high to low node index; this is what `graph.forward()` selects.
///
/// **Performance:** encoding is inherently sequential (each node depends on already-encoded
/// parents). Multicore SDR-style strategies from Stacked do not apply directly; any future
/// speedup must exploit graph structure (e.g. independent sub-DAGs) rather than a flat parallel
/// map. Tree building after each layer can use GPU Poseidon builders when enabled.
pub fn encode<H, G>(
    graph: &ZigZagGraph<H, G>,
    replica_id: &H::Domain,
    data: &mut [u8],
) -> Result<()>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    let mut parents = vec![0u32; graph.degree()];
    for n in 0..graph.size() {
        let node = if graph.forward() {
            n
        } else {
            // If the graph is reversed, traverse in reverse order.
            (graph.size() - n) - 1
        };

        graph.parents(node, &mut parents)?;

        let key = create_key::<H>(replica_id, node, &parents, data)?;
        let start = data_at_node_offset(node);
        let end = start + NODE_SIZE;

        let node_data = H::Domain::try_from_bytes(&data[start..end])?;
        let encoded = encode::encode(key, node_data);

        encoded.write_bytes(&mut data[start..end])?;
    }

    Ok(())
}

/// Decodes (extracts) all of `data`, returning the original pre-encoding bytes.
///
/// This is where ZigZag's fast-extraction asymmetry lives. Unlike [`encode`], which is inherently
/// sequential (a node cannot be encoded until its parents have been encoded), every node here is
/// decoded from the *fully-encoded, immutable* replica: [`decode_block`] reads a node's parents from
/// `data` (never from partially-decoded output), so the nodes are mutually independent and can be
/// decoded in any order or fully in parallel. We exploit that here with a parallel iterator.
pub fn decode<H, G>(
    graph: &ZigZagGraph<H, G>,
    replica_id: &H::Domain,
    data: &[u8],
) -> Result<Vec<u8>>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    let mut out = vec![0u8; data.len()];

    out.par_chunks_mut(NODE_SIZE)
        .enumerate()
        .try_for_each(|(node, chunk)| -> Result<()> {
            let decoded = decode_block(graph, replica_id, data, node)?;
            decoded.write_bytes(chunk)?;
            Ok(())
        })?;

    Ok(out)
}

/// Decodes a single node of `data`.
///
/// Depends only on the immutable, fully-encoded `data` (never on other decoded nodes), which is what
/// lets [`decode`] run every node independently/in parallel.
pub fn decode_block<H, G>(
    graph: &ZigZagGraph<H, G>,
    replica_id: &H::Domain,
    data: &[u8],
    v: usize,
) -> Result<H::Domain>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    let mut parents = vec![0u32; graph.degree()];
    graph.parents(v, &mut parents)?;
    let key = create_key::<H>(replica_id, v, &parents, data)?;
    let node_data = H::Domain::try_from_bytes(data_at_node(data, v)?)?;

    Ok(encode::decode(key, node_data))
}

/// Creates the encoding key: `SHA256(replica_id | parent_1 | parent_2 | ...)`, reduced to a field
/// element by clearing the top two bits (the standard LE-254 packing used throughout the codebase).
///
/// The KDF hash is SHA256 (rather than the 2019 original's Blake2s) so it can be reproduced
/// efficiently and reliably in-circuit with `bellperson`'s SHA256 gadget.
pub fn create_key<H: Hasher>(
    id: &H::Domain,
    node: usize,
    parents: &[u32],
    data: &[u8],
) -> Result<H::Domain> {
    let mut hasher = Sha256::new();
    hasher.update(id.into_bytes().as_slice());

    // The hash is about the parents, hence skip if a node doesn't have any parents.
    if node != parents[0] as usize {
        for parent in parents.iter() {
            let offset = data_at_node_offset(*parent as usize);
            hasher.update(&data[offset..offset + NODE_SIZE]);
        }
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}

/// Recreates the encoding key from already-materialized parent domain values (used during
/// verification, where parent bytes come from Merkle-proof leaves rather than the data buffer).
/// This must match `create_key`'s hashing exactly.
pub fn create_key_from_domains<H: Hasher>(
    id: &H::Domain,
    parents_data: &[H::Domain],
) -> Result<H::Domain> {
    let mut hasher = Sha256::new();
    hasher.update(id.into_bytes().as_slice());

    for parent in parents_data.iter() {
        hasher.update(parent.into_bytes().as_slice());
    }

    let hash = hasher.finalize();
    Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use filecoin_hashers::poseidon::{PoseidonDomain, PoseidonHasher};
    use storage_proofs_core::{api_version::ApiVersion, drgraph::BASE_DEGREE, util::NODE_SIZE};

    use crate::zigzag::vanilla::graph::{ZigZagBucketGraph, EXP_DEGREE};

    fn encode_decode_roundtrip(reversed: bool) {
        let nodes = 32;
        let porep_id = [7u8; 32];
        let mut graph: ZigZagBucketGraph<PoseidonHasher> = ZigZagGraph::new_zigzag(
            None,
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_2_0,
        )
        .expect("failed to create graph");
        if reversed {
            graph = graph.zigzag();
        }

        let replica_id = PoseidonDomain::default();

        // All-zero bytes is a valid field-element (Fr) representation for every node.
        let original = vec![0u8; nodes * NODE_SIZE];
        let mut data = original.clone();

        encode::<PoseidonHasher, _>(&graph, &replica_id, &mut data).expect("encode failed");
        assert_ne!(data, original, "encoding did not change data");

        let decoded =
            decode::<PoseidonHasher, _>(&graph, &replica_id, &data).expect("decode failed");
        assert_eq!(decoded, original, "decode did not recover original data");
    }

    #[test]
    fn encode_decode_forward() {
        encode_decode_roundtrip(false);
    }

    #[test]
    fn encode_decode_reversed() {
        encode_decode_roundtrip(true);
    }

    /// ZigZag's defining performance property: extraction is *asymmetric* to replication. Encoding is
    /// inherently sequential (a node depends on its already-encoded parents), but decoding each node
    /// depends only on the immutable, fully-encoded replica. This test locks in that independence:
    /// decoding in forward order, in reverse order, and in parallel must all yield identical results
    /// (and recover the original data). If a future change made `decode_block` read partially-decoded
    /// state, the order variants would diverge and this test would fail.
    #[test]
    fn decode_is_order_independent_and_parallelizable() {
        let nodes = 64;
        let porep_id = [13u8; 32];
        let graph: ZigZagBucketGraph<PoseidonHasher> = ZigZagGraph::new_zigzag(
            None,
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_2_0,
        )
        .expect("failed to create graph");

        let replica_id = PoseidonDomain::from([2u8; 32]);

        // Non-trivial, field-valid data so encoding genuinely depends on parent values.
        let mut original = vec![0u8; nodes * NODE_SIZE];
        for i in 0..nodes {
            original[i * NODE_SIZE] = (i as u8).wrapping_mul(7).wrapping_add(3);
            original[i * NODE_SIZE + 1] = (i as u8).wrapping_mul(31);
        }

        let mut data = original.clone();
        encode::<PoseidonHasher, _>(&graph, &replica_id, &mut data).expect("encode failed");
        assert_ne!(data, original, "encoding did not change data");

        // Decode block-by-block in forward order.
        let mut forward = vec![0u8; data.len()];
        for v in 0..nodes {
            let d = decode_block::<PoseidonHasher, _>(&graph, &replica_id, &data, v)
                .expect("decode_block failed");
            d.write_bytes(&mut forward[v * NODE_SIZE..(v + 1) * NODE_SIZE])
                .expect("write_bytes failed");
        }

        // Decode block-by-block in reverse order, writing each result into its own position. Because
        // blocks are independent, this must produce exactly the same output as forward order.
        let mut reverse = vec![0u8; data.len()];
        for v in (0..nodes).rev() {
            let d = decode_block::<PoseidonHasher, _>(&graph, &replica_id, &data, v)
                .expect("decode_block failed");
            d.write_bytes(&mut reverse[v * NODE_SIZE..(v + 1) * NODE_SIZE])
                .expect("write_bytes failed");
        }

        // The production `decode` path, which decodes all nodes in parallel.
        let parallel =
            decode::<PoseidonHasher, _>(&graph, &replica_id, &data).expect("decode failed");

        assert_eq!(
            forward, original,
            "forward-order extraction did not recover original data"
        );
        assert_eq!(
            reverse, forward,
            "reverse-order extraction differs from forward order: decode blocks are not independent"
        );
        assert_eq!(
            parallel, forward,
            "parallel extraction differs from sequential: decode blocks are not independent"
        );
    }

    /// The other half of the asymmetry: encoding *is* order-dependent. On a forward graph every
    /// node's parents have a lower index, so a correct encoding must proceed low->high (each node
    /// consumes its already-encoded parents). Encoding high->low instead consumes not-yet-encoded
    /// parents and therefore yields different bytes. This guards the sequential nature of encoding,
    /// which is precisely what makes replication slow while extraction stays fast.
    #[test]
    fn encoding_is_order_dependent() {
        let nodes = 64;
        let porep_id = [17u8; 32];
        // Forward (non-reversed) graph: parents(v) are all < v.
        let graph: ZigZagBucketGraph<PoseidonHasher> = ZigZagGraph::new_zigzag(
            None,
            nodes,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_2_0,
        )
        .expect("failed to create graph");

        let replica_id = PoseidonDomain::from([9u8; 32]);

        let mut original = vec![0u8; nodes * NODE_SIZE];
        for i in 0..nodes {
            original[i * NODE_SIZE] = (i as u8).wrapping_mul(5).wrapping_add(1);
        }

        // Correct, sequential low->high encoding.
        let mut correct = original.clone();
        encode::<PoseidonHasher, _>(&graph, &replica_id, &mut correct).expect("encode failed");

        // Deliberately encode high->low; parents are not yet encoded, so keys differ.
        let mut wrong = original.clone();
        let mut parents = vec![0u32; graph.degree()];
        for v in (0..nodes).rev() {
            graph.parents(v, &mut parents).expect("parents failed");
            let key = create_key::<PoseidonHasher>(&replica_id, v, &parents, &wrong)
                .expect("create_key failed");
            let start = data_at_node_offset(v);
            let end = start + NODE_SIZE;
            let node_data =
                PoseidonDomain::try_from_bytes(&wrong[start..end]).expect("try_from_bytes failed");
            let encoded = encode::encode(key, node_data);
            encoded
                .write_bytes(&mut wrong[start..end])
                .expect("write_bytes failed");
        }

        assert_ne!(
            correct, wrong,
            "encoding was order-independent — the sequential dependency (and thus the \
             replication/extraction asymmetry) has been lost"
        );
    }
}
