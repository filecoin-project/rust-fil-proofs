
use error::Result;

pub fn data_at_node_offset(v: usize, node_size: usize) -> usize {
    (v - 1) * node_size
}

/// Returns the byte slice representing one node (of uniform size, node_size) at position v in data.
pub fn data_at_node(data: &[u8], v: usize, node_size: usize) -> Result<&[u8]> {
    let offset = data_at_node_offset(v, node_size);

    if offset + node_size > data.len() {
        return Err(format_err!(
            "access out of bounds: {} > {}",
            offset + node_size,
            data.len()
        ));
    }

    Ok(&data[offset..offset + node_size])
}
