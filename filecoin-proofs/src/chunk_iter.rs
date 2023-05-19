use std::io::{self, Read};

use iowrap::ReadMany;

/// The number of bytes that are read from the reader at once.
const READER_CHUNK_SIZE: usize = 4096;

// Based on
// https://stackoverflow.com/questions/73145503/iterator-for-reading-file-chunks/73145594#73145594
/// Chunks the given reader to the given size.
///
/// If the end is reached and there are a few bytes left, that don't fill a full chunk, those bytes
/// are returned.
pub struct ChunkIterator<R> {
    reader: R,
    chunk_size: usize,
}

impl<R: Read> ChunkIterator<R> {
    /// Return a new iterator with a default chunk size of 4KiB.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            chunk_size: READER_CHUNK_SIZE,
        }
    }

    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

impl<R: Read> Iterator for ChunkIterator<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = vec![0u8; self.chunk_size];
        match self.reader.read_many(&mut buffer) {
            Ok(bytes_read) if bytes_read == self.chunk_size => Some(Ok(buffer)),
            // A position of 0 indicates end of file.
            Ok(bytes_read) if bytes_read == 0 => None,
            Ok(bytes_read) => Some(Ok(buffer[..bytes_read].to_vec())),
            Err(error) => Some(Err(error)),
        }
    }
}
