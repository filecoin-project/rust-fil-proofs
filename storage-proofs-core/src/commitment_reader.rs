use std::io::{self, Read};

use anyhow::{ensure, Result};
use rayon::prelude::*;

use crate::hasher::{HashFunction, Hasher};
use crate::util::NODE_SIZE;

/// Calculates comm-d of the data piped through to it.
/// Data must be bit padded and power of 2 bytes.
pub struct CommitmentReader<R, H: Hasher> {
    source: R,
    buffer: [u8; 64],
    buffer_pos: usize,
    current_tree: Vec<H::Domain>,
}

impl<R: Read, H: Hasher> CommitmentReader<R, H> {
    pub fn new(source: R) -> Self {
        CommitmentReader {
            source,
            buffer: [0u8; 64],
            buffer_pos: 0,
            current_tree: Vec::new(),
        }
    }

    /// Attempt to generate the next hash, but only if the buffers are full.
    fn try_hash(&mut self) {
        if self.buffer_pos < 63 {
            return;
        }

        // WARNING: keep in sync with DefaultPieceHasher and its .node impl
        let hash = <H as Hasher>::Function::hash(&self.buffer);
        self.current_tree.push(hash);
        self.buffer_pos = 0;

        // TODO: reduce hashes when possible, instead of keeping them around.
    }

    pub fn finish(self) -> Result<<H as Hasher>::Domain> {
        ensure!(self.buffer_pos == 0, "not enough inputs provided");

        let CommitmentReader { current_tree, .. } = self;

        let mut current_row = current_tree;

        while current_row.len() > 1 {
            let next_row = current_row
                .par_chunks(2)
                .map(|chunk| {
                    let mut buf = [0u8; NODE_SIZE * 2];
                    buf[..NODE_SIZE].copy_from_slice(AsRef::<[u8]>::as_ref(&chunk[0]));
                    buf[NODE_SIZE..].copy_from_slice(AsRef::<[u8]>::as_ref(&chunk[1]));
                    <H as Hasher>::Function::hash(&buf)
                })
                .collect::<Vec<_>>();

            current_row = next_row;
        }
        debug_assert_eq!(current_row.len(), 1);

        Ok(current_row
            .into_iter()
            .next()
            .expect("should have been caught by debug build: len==1"))
    }
}

impl<R: Read, H: Hasher> Read for CommitmentReader<R, H> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.buffer_pos;
        let left = 64 - self.buffer_pos;
        let end = start + std::cmp::min(left, buf.len());

        // fill the buffer as much as possible
        let r = self.source.read(&mut self.buffer[start..end])?;

        // write the data, we read
        buf[..r].copy_from_slice(&self.buffer[start..start + r]);

        self.buffer_pos += r;

        // try to hash
        self.try_hash();

        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hasher::Sha256Hasher;
    use crate::pieces::generate_piece_commitment_bytes_from_source;

    #[test]
    fn test_commitment_reader() {
        let piece_size = 127 * 8;
        let source = vec![255u8; piece_size];
        let mut fr32_reader = fr32::Fr32Reader::new(io::Cursor::new(&source));

        let commitment1 = generate_piece_commitment_bytes_from_source::<Sha256Hasher>(
            &mut fr32_reader,
            fr32::to_padded_bytes(piece_size),
        )
        .expect("failed to generate piece commitment bytes from source");

        let fr32_reader = fr32::Fr32Reader::new(io::Cursor::new(&source));
        let mut commitment_reader = CommitmentReader::<_, Sha256Hasher>::new(fr32_reader);
        io::copy(&mut commitment_reader, &mut io::sink()).expect("io copy failed");

        let commitment2 = commitment_reader.finish().expect("failed to finish");

        assert_eq!(&commitment1[..], AsRef::<[u8]>::as_ref(&commitment2));
    }
}
