
pub fn data_at_node_offset(v: usize, node_size: usize) -> usize {
    (v - 1) * node_size
}

/// Returns the byte slice representing one node (of uniform size, node_size) at position v in data.
pub fn data_at_node(data: &[u8], v: usize, node_size: usize) -> &[u8] {
    let offset = data_at_node_offset(v, node_size);

    // TODO: error handling
    if offset + node_size > data.len() {
        panic!("access out of bounds");
    }

    &data[offset..offset + node_size]
}
