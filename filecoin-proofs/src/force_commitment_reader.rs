use std::{io, mem, slice};

use crate::{constants::DefaultPieceHasher, PaddedBytesAmount};
use filecoin_hashers::{HashFunction, Hasher};
use rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};

type PieceHashDomain = <DefaultPieceHasher as Hasher>::Domain;

const PIECE_HASH_SIZE: usize = mem::size_of::<PieceHashDomain>() * 2;

const fn align_to(size: usize, align: usize) -> usize {
    (size + (align - 1)) & !(align - 1)
}

const fn align_down_to(size: usize, align: usize) -> usize {
    size & !(align - 1)
}

const fn align_down_to_pow2(x: usize) -> usize {
    (usize::MAX >> (x.leading_zeros() + 1)) + 1
}

struct ChunkTree {
    leaf_nodes: Box<[PieceHashDomain]>,
    leaf_nodes_len: usize,
    par_chunk_size: usize,
    chunk_roots: Vec<PieceHashDomain>,
}

impl ChunkTree {
    fn new(chunk_len: usize) -> Self {
        debug_assert!(chunk_len.is_power_of_two());

        let leaf_nodes = vec![Default::default(); chunk_len];

        Self {
            leaf_nodes: leaf_nodes.into_boxed_slice(),
            leaf_nodes_len: 0,
            par_chunk_size: align_down_to_pow2(2.max(chunk_len / rayon::current_num_threads())),
            chunk_roots: Vec::new(),
        }
    }

    fn hash_one(&mut self, buf: &[u8; PIECE_HASH_SIZE]) {
        let domain = <DefaultPieceHasher as Hasher>::Function::hash(buf);
        self.leaf_nodes[self.leaf_nodes_len] = domain;
        self.leaf_nodes_len += 1;
        self.try_compute_chunk_root();
    }

    #[inline]
    fn try_hash_many(&mut self, buf: &[u8]) {
        if buf.len() < PIECE_HASH_SIZE {
            return;
        }
        self.hash_many(buf);
    }

    fn hash_many(&mut self, buf: &[u8]) {
        let max_len = self.leaf_nodes.len() - self.leaf_nodes_len;
        let len = max_len.min(buf.len() / PIECE_HASH_SIZE);

        let slots = &mut self.leaf_nodes[self.leaf_nodes_len..];
        self.leaf_nodes_len += len;
        buf.par_chunks(PIECE_HASH_SIZE)
            .zip(slots)
            .for_each(|(chunk, slot)| {
                *slot = <DefaultPieceHasher as Hasher>::Function::hash(chunk)
            });

        self.try_compute_chunk_root();

        self.try_hash_many(&buf[PIECE_HASH_SIZE * len..]);
    }

    fn try_compute_chunk_root(&mut self) {
        if self.leaf_nodes_len < self.leaf_nodes.len() {
            return;
        }

        self.chunk_roots
            .push(par_compute_root(self.par_chunk_size, &mut self.leaf_nodes));

        self.leaf_nodes_len = 0;
    }

    fn finish(mut self) -> PieceHashDomain {
        compute_root(&mut self.chunk_roots)
    }
}

fn par_compute_root(par_chunk_size: usize, row: &mut [PieceHashDomain]) -> PieceHashDomain {
    let mut res = row
        .par_chunks_mut(par_chunk_size)
        .map(compute_root)
        .collect::<Vec<_>>();
    compute_root(&mut res)
}

/// Computes slice root hash
/// Note: For the purpose of reusing memory, this function will change the content of the `row`
fn compute_root(mut row: &mut [PieceHashDomain]) -> PieceHashDomain {
    #[inline]
    fn compute_next_row(row: &mut [PieceHashDomain]) -> &mut [PieceHashDomain] {
        debug_assert!(row.len() % 2 == 0);
        unsafe {
            for i in (0..row.len()).step_by(2) {
                let p = row.get_unchecked(i);
                // Safety: continuous memory can be directly hashed without copies
                let buf = slice::from_raw_parts(p as *const _ as *const u8, PIECE_HASH_SIZE);
                *row.get_unchecked_mut(i / 2) = <DefaultPieceHasher as Hasher>::Function::hash(buf);
            }

            row.get_unchecked_mut(..row.len() / 2)
        }
    }

    while row.len() > 1 {
        row = compute_next_row(row);
    }

    debug_assert_eq!(row.len(), 1);

    row.first()
        .cloned()
        .expect("should have been caught by debug build: len==1")
}

/// Calculates comm-d of the data piped through to it.
/// Data must be bit padded and power of 2 bytes.
pub struct CommitmentReader<R> {
    source: R,

    remainder_bytes: [u8; PIECE_HASH_SIZE],
    remainder_bytes_pos: usize,

    chunk_tree: ChunkTree,
}

impl<R: io::Read> CommitmentReader<R> {
    const SIZE_64_MIB: usize = 1 << 26;
    const SIZE_128_MIB: usize = 1 << 27;
    const SIZE_8_GIB: usize = 1 << 33;

    /// Creates a CommitmentReader. `padded_piece_size` must power of 2
    pub fn new(padded_piece_size: PaddedBytesAmount, source: R) -> Self {
        let padded_piece_size: usize = padded_piece_size.into();
        debug_assert!(padded_piece_size.is_power_of_two());

        let chunk_size_in_bytes = match padded_piece_size {
            x if x >= Self::SIZE_8_GIB => Self::SIZE_128_MIB,
            x if x >= Self::SIZE_64_MIB => Self::SIZE_64_MIB,
            x => x,
        };

        CommitmentReader {
            source,
            remainder_bytes: [0; PIECE_HASH_SIZE],
            remainder_bytes_pos: 0,
            chunk_tree: ChunkTree::new(chunk_size_in_bytes / PIECE_HASH_SIZE),
        }
    }

    pub fn finish(self) -> PieceHashDomain {
        self.chunk_tree.finish()
    }

    fn try_append_to_remainder_bytes(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        self.append_to_remainder_bytes(buf);
    }

    fn append_to_remainder_bytes(&mut self, buf: &[u8]) {
        let Self {
            remainder_bytes,
            remainder_bytes_pos,
            chunk_tree,
            ..
        } = self;

        let can_be_copy = remainder_bytes.len() - *remainder_bytes_pos;
        let will_copy = buf.len().min(can_be_copy);

        unsafe {
            remainder_bytes
                .get_unchecked_mut(*remainder_bytes_pos..*remainder_bytes_pos + will_copy)
                .copy_from_slice(buf.get_unchecked(..will_copy))
        }
        *remainder_bytes_pos += will_copy;

        if *remainder_bytes_pos == remainder_bytes.len() {
            *remainder_bytes_pos = 0;
            chunk_tree.hash_one(remainder_bytes);
        }

        self.try_append_to_remainder_bytes(&buf[will_copy..]);
    }
}

impl<R: io::Read> io::Read for CommitmentReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.source.read(buf)?;
        let mut buf = &buf[..r];

        let start = if self.remainder_bytes_pos != 0 {
            PIECE_HASH_SIZE - self.remainder_bytes_pos
        } else {
            0
        };

        // copy head
        let head_len = start.min(buf.len());
        self.try_append_to_remainder_bytes(&buf[..head_len]);
        buf = &buf[head_len..];

        let can_be_hash_len = align_down_to(r.checked_sub(start).unwrap_or(0), PIECE_HASH_SIZE);

        let tail = &buf[can_be_hash_len..];

        // try to hash
        self.chunk_tree.try_hash_many(&buf[..can_be_hash_len]);

        // copy tail
        self.try_append_to_remainder_bytes(tail);
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use crate::types::UnpaddedBytesAmount;
    use anyhow::Result;
    use fr32::Fr32Reader;

    fn origin_compute_comm(src: impl io::Read) -> Result<PieceHashDomain> {
        let mut reader = crate::commitment_reader::CommitmentReader::new(src);
        io::copy(&mut reader, &mut io::sink()).expect("io copy failed");
        reader.finish()
    }

    #[test]
    fn test_commitment_reader() {
        let piece_size = 127 * 8;
        let source = vec![255u8; piece_size];

        let fr32_reader = Fr32Reader::new(Cursor::new(&source));
        let expect = origin_compute_comm(fr32_reader).expect("compute comm failed");

        let fr32_reader = Fr32Reader::new(Cursor::new(&source));
        let mut commitment_reader =
            CommitmentReader::new(UnpaddedBytesAmount(piece_size as u64).into(), fr32_reader);
        io::copy(&mut commitment_reader, &mut io::sink()).expect("io copy failed");

        let commitment2 = commitment_reader.finish();

        assert_eq!(expect, commitment2);
    }

    #[test]
    fn test_align_to() {
        let cases = vec![
            (33, 32, 64),
            (1, 32, 32),
            (32, 32, 32),
            (31, 32, 32),
            (63, 32, 64),
        ];

        for (size, align, expect) in cases {
            assert_eq!(align_to(size, align), expect);
        }
    }

    #[test]
    fn test_align_down_to() {
        let cases = vec![
            (33, 32, 32),
            (1, 32, 0),
            (32, 32, 32),
            (31, 32, 0),
            (63, 32, 32),
        ];

        for (size, align, expect) in cases {
            assert_eq!(align_down_to(size, align), expect);
        }
    }

    #[test]
    fn test_align_down_to_pow2() {
        let cases = vec![
            (1024, 1024),
            (1025, 1024),
            (2047, 1024),
            (2049, 2048),
            (3, 2),
        ];

        for (size, expect) in cases {
            assert_eq!(align_down_to_pow2(size), expect);
        }
    }
}
