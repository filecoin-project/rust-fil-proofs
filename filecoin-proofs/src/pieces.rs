use std::cmp::min;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};
use std::iter::Iterator;
use std::sync::Mutex;

use anyhow::{ensure, Context, Result};
use filecoin_hashers::{HashFunction, Hasher};
use fr32::Fr32Reader;
use lazy_static::lazy_static;
use log::info;
use storage_proofs_core::util::NODE_SIZE;

use crate::{
    commitment_reader::CommitmentReader,
    constants::{
        DefaultPieceHasher,
        MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
    },
    types::{
        Commitment, PaddedBytesAmount, PieceInfo, SectorSize, UnpaddedByteIndex,
        UnpaddedBytesAmount,
    },
};

/// Verify that the provided `piece_infos` and `comm_d` match.
pub fn verify_pieces(
    comm_d: &Commitment,
    piece_infos: &[PieceInfo],
    sector_size: SectorSize,
) -> Result<bool> {
    let comm_d_calculated = compute_comm_d(sector_size, piece_infos)?;

    Ok(&comm_d_calculated == comm_d)
}

lazy_static! {
    static ref COMMITMENTS: Mutex<HashMap<SectorSize, Commitment>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Clone)]
pub struct EmptySource {
    size: usize,
}

impl EmptySource {
    pub fn new(size: usize) -> Self {
        EmptySource { size }
    }
}

impl Read for EmptySource {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        let to_read = min(self.size, target.len());
        self.size -= to_read;
        for val in target {
            *val = 0;
        }

        Ok(to_read)
    }
}

fn empty_comm_d(sector_size: SectorSize) -> Commitment {
    let map = &mut *COMMITMENTS.lock().expect("COMMITMENTS poisoned");

    *map.entry(sector_size).or_insert_with(|| {
        let size: UnpaddedBytesAmount = sector_size.into();
        let fr32_reader = Fr32Reader::new(EmptySource::new(size.into()));
        let mut commitment_reader = CommitmentReader::new(fr32_reader);
        io::copy(&mut commitment_reader, &mut io::sink())
            .expect("failed to copy commitment to sink");

        let mut comm = [0u8; 32];
        comm.copy_from_slice(
            commitment_reader
                .finish()
                .expect("failed to create commitment")
                .as_ref(),
        );
        comm
    })
}

pub fn compute_comm_d(sector_size: SectorSize, piece_infos: &[PieceInfo]) -> Result<Commitment> {
    info!("verifying {} pieces", piece_infos.len());
    if piece_infos.is_empty() {
        return Ok(empty_comm_d(sector_size));
    }

    let unpadded_sector: UnpaddedBytesAmount = sector_size.into();

    ensure!(
        piece_infos.len() as u64 <= u64::from(unpadded_sector) / MINIMUM_PIECE_SIZE,
        "Too many pieces"
    );

    // make sure the piece sizes are at most a sector size large
    let piece_size: u64 = piece_infos
        .iter()
        .map(|info| u64::from(PaddedBytesAmount::from(info.size)))
        .sum();

    ensure!(
        piece_size <= u64::from(sector_size),
        "Piece is larger than sector."
    );

    let mut stack = Stack::new();

    let first = piece_infos
        .first()
        .expect("unreachable: !is_empty()")
        .clone();
    ensure!(
        u64::from(PaddedBytesAmount::from(first.size)).is_power_of_two(),
        "Piece size ({:?}) must be a power of 2.",
        PaddedBytesAmount::from(first.size)
    );
    stack.shift(first);

    for piece_info in piece_infos.iter().skip(1) {
        ensure!(
            u64::from(PaddedBytesAmount::from(piece_info.size)).is_power_of_two(),
            "Piece size ({:?}) must be a power of 2.",
            PaddedBytesAmount::from(piece_info.size)
        );

        while stack.peek().size < piece_info.size {
            stack.shift_reduce(zero_padding(stack.peek().size)?)?
        }

        stack.shift_reduce(piece_info.clone())?;
    }

    while stack.len() > 1 {
        stack.shift_reduce(zero_padding(stack.peek().size)?)?;
    }

    ensure!(stack.len() == 1, "Stack size ({}) must be 1.", stack.len());

    let comm_d_calculated = stack.pop()?.commitment;

    Ok(comm_d_calculated)
}

/// Stack used for piece reduction.
struct Stack(Vec<PieceInfo>);

impl Stack {
    /// Creates a new stack.
    fn new() -> Self {
        Stack(Vec::new())
    }

    /// Pushes a single element onto the stack.
    fn shift(&mut self, el: PieceInfo) {
        self.0.push(el)
    }

    /// Look at the last element of the stack.
    fn peek(&self) -> &PieceInfo {
        &self.0[self.0.len() - 1]
    }

    /// Look at the second to last element of the stack.
    fn peek2(&self) -> &PieceInfo {
        &self.0[self.0.len() - 2]
    }

    /// Pop the last element of the stack.
    fn pop(&mut self) -> Result<PieceInfo> {
        self.0.pop().context("empty stack popped")
    }

    fn reduce1(&mut self) -> Result<bool> {
        if self.len() < 2 {
            return Ok(false);
        }

        if self.peek().size == self.peek2().size {
            let right = self.pop()?;
            let left = self.pop()?;
            let joined = join_piece_infos(left, right)?;
            self.shift(joined);
            return Ok(true);
        }

        Ok(false)
    }

    fn reduce(&mut self) -> Result<()> {
        while self.reduce1()? {}
        Ok(())
    }

    fn shift_reduce(&mut self, piece: PieceInfo) -> Result<()> {
        self.shift(piece);
        self.reduce()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Create a padding `PieceInfo` of size `size`.
pub fn zero_padding(size: UnpaddedBytesAmount) -> Result<PieceInfo> {
    let padded_size: PaddedBytesAmount = size.into();
    let mut commitment = [0u8; 32];

    // TODO: cache common piece hashes
    let mut hashed_size = 64;
    let h1 = piece_hash(&commitment, &commitment);
    commitment.copy_from_slice(h1.as_ref());

    while hashed_size < u64::from(padded_size) {
        let h = piece_hash(&commitment, &commitment);
        commitment.copy_from_slice(h.as_ref());
        hashed_size *= 2;
    }

    ensure!(
        hashed_size == u64::from(padded_size),
        "Hashed size must equal padded size"
    );

    PieceInfo::new(commitment, size)
}

/// Join two equally sized `PieceInfo`s together, by hashing them and adding their sizes.
fn join_piece_infos(mut left: PieceInfo, right: PieceInfo) -> Result<PieceInfo> {
    ensure!(
        left.size == right.size,
        "Piece sizes must be equal (left: {:?}, right: {:?})",
        left.size,
        right.size
    );
    let h = piece_hash(&left.commitment, &right.commitment);

    left.commitment.copy_from_slice(AsRef::<[u8]>::as_ref(&h));
    left.size = left.size + right.size;
    Ok(left)
}

pub fn piece_hash(a: &[u8], b: &[u8]) -> <DefaultPieceHasher as Hasher>::Domain {
    let mut buf = [0u8; NODE_SIZE * 2];
    buf[..NODE_SIZE].copy_from_slice(a);
    buf[NODE_SIZE..].copy_from_slice(b);
    <DefaultPieceHasher as Hasher>::Function::hash(&buf)
}

#[derive(Debug, Clone)]
pub struct PieceAlignment {
    pub left_bytes: UnpaddedBytesAmount,
    pub right_bytes: UnpaddedBytesAmount,
}

impl PieceAlignment {
    pub fn sum(&self, piece_size: UnpaddedBytesAmount) -> UnpaddedBytesAmount {
        self.left_bytes + piece_size + self.right_bytes
    }
}

/// Given a list of pieces, sum the number of bytes taken by those pieces in that order.
pub fn sum_piece_bytes_with_alignment(pieces: &[UnpaddedBytesAmount]) -> UnpaddedBytesAmount {
    pieces
        .iter()
        .fold(UnpaddedBytesAmount(0), |acc, piece_bytes| {
            acc + get_piece_alignment(acc, *piece_bytes).sum(*piece_bytes)
        })
}

/// Given a list of pieces, find the byte where a given piece does or would start.
pub fn get_piece_start_byte(
    pieces: &[UnpaddedBytesAmount],
    piece_bytes: UnpaddedBytesAmount,
) -> UnpaddedByteIndex {
    // sum up all the bytes taken by the ordered pieces
    let last_byte = sum_piece_bytes_with_alignment(&pieces);
    let alignment = get_piece_alignment(last_byte, piece_bytes);

    // add only the left padding of the target piece to give the start of that piece's data
    UnpaddedByteIndex::from(last_byte + alignment.left_bytes)
}

/// Given a number of bytes already written to a staged sector (ignoring bit padding) and a number
/// of bytes (before bit padding) to be added, return the alignment required to create a piece where
/// len(piece) == len(sector size)/(2^n) and sufficient left padding to ensure simple merkle proof
/// construction.
pub fn get_piece_alignment(
    written_bytes: UnpaddedBytesAmount,
    piece_bytes: UnpaddedBytesAmount,
) -> PieceAlignment {
    let mut piece_bytes_needed = MINIMUM_PIECE_SIZE as u64;

    // Calculate the next power of two multiple that will fully contain the piece's data.
    // This is required to ensure a clean piece merkle root, without being affected by
    // preceding or following pieces.
    while piece_bytes_needed < u64::from(piece_bytes) {
        piece_bytes_needed *= 2;
    }

    // Calculate the bytes being affected from the left of the piece by the previous piece.
    let encroaching = u64::from(written_bytes) % piece_bytes_needed;

    // Calculate the bytes to push from the left to ensure a clean piece merkle root.
    let left_bytes = if encroaching > 0 {
        piece_bytes_needed - encroaching
    } else {
        0
    };

    let right_bytes = piece_bytes_needed - u64::from(piece_bytes);

    PieceAlignment {
        left_bytes: UnpaddedBytesAmount(left_bytes),
        right_bytes: UnpaddedBytesAmount(right_bytes),
    }
}

/// Wraps a Readable source with null bytes on either end according to a provided PieceAlignment.
fn with_alignment(source: impl Read, piece_alignment: PieceAlignment) -> impl Read {
    let PieceAlignment {
        left_bytes,
        right_bytes,
    } = piece_alignment;

    let left_padding = Cursor::new(vec![0; left_bytes.into()]);
    let right_padding = Cursor::new(vec![0; right_bytes.into()]);

    left_padding.chain(source).chain(right_padding)
}

/// Given an enumeration of pieces in a staged sector and a piece to be added (represented by a Read
/// and corresponding length, in UnpaddedBytesAmount) to the staged sector, produce a new Read and
/// UnpaddedBytesAmount pair which includes the appropriate amount of alignment bytes for the piece
/// to be written to the target staged sector.
pub fn get_aligned_source<T: Read>(
    source: T,
    pieces: &[UnpaddedBytesAmount],
    piece_bytes: UnpaddedBytesAmount,
) -> (UnpaddedBytesAmount, PieceAlignment, impl Read) {
    let written_bytes = sum_piece_bytes_with_alignment(pieces);
    let piece_alignment = get_piece_alignment(written_bytes, piece_bytes);
    let expected_num_bytes_written =
        piece_alignment.left_bytes + piece_bytes + piece_alignment.right_bytes;

    (
        expected_num_bytes_written,
        piece_alignment.clone(),
        with_alignment(source, piece_alignment),
    )
}
