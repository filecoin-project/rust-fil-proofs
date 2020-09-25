use std::collections::HashMap;
use std::io::Read;
use std::io::{self, Cursor};
use std::iter::Iterator;
use std::sync::Mutex;

use anyhow::{ensure, Context, Result};
use lazy_static::lazy_static;
use log::info;
use storage_proofs::hasher::{HashFunction, Hasher};
use storage_proofs::util::NODE_SIZE;

use crate::constants::{
    DefaultPieceHasher,
    MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR as MINIMUM_PIECE_SIZE,
};
use crate::types::{
    Commitment, PaddedBytesAmount, PieceInfo, SectorSize, UnpaddedByteIndex, UnpaddedBytesAmount,
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
use crate::commitment_reader::CommitmentReader;
use crate::fr32_reader::Fr32Reader;

#[derive(Debug, Clone)]
struct EmptySource {
    size: usize,
}

impl EmptySource {
    pub fn new(size: usize) -> Self {
        EmptySource { size }
    }
}

impl Read for EmptySource {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        let to_read = std::cmp::min(self.size, target.len());
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
fn zero_padding(size: UnpaddedBytesAmount) -> Result<PieceInfo> {
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

pub(crate) fn piece_hash(a: &[u8], b: &[u8]) -> <DefaultPieceHasher as Hasher>::Domain {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::util::commitment_from_fr;
    use crate::constants::{DRG_DEGREE, EXP_DEGREE};
    use crate::types::DataTree;

    use bellperson::bls::Fr;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs::drgraph::Graph;
    use storage_proofs::merkle::create_base_merkle_tree;
    use storage_proofs::porep::stacked::StackedBucketGraph;

    #[test]
    fn test_empty_source() {
        let mut source = EmptySource::new(12);
        let mut target = Vec::new();
        source
            .read_to_end(&mut target)
            .expect("EmptySource read error");
        assert_eq!(target, vec![0u8; 12]);
    }

    #[test]
    fn test_compute_comm_d_empty() {
        let comm_d = compute_comm_d(SectorSize(2048), &[])
            .expect("failed to verify pieces, empty piece infos");
        assert_eq!(
            comm_d,
            [
                252, 126, 146, 130, 150, 229, 22, 250, 173, 233, 134, 178, 143, 146, 212, 74, 79,
                36, 185, 53, 72, 82, 35, 55, 106, 121, 144, 39, 188, 24, 248, 51
            ]
        );

        let comm_d = compute_comm_d(SectorSize(128), &[]).expect("failed to verify pieces");
        assert_eq!(
            hex::encode(&comm_d),
            "3731bb99ac689f66eef5973e4a94da188f4ddcae580724fc6f3fd60dfd488333",
        );
    }

    #[test]
    fn test_get_piece_alignment() {
        let table = vec![
            (0, 0, (0, 127)),
            (0, 127, (0, 0)),
            (0, 254, (0, 0)),
            (0, 508, (0, 0)),
            (0, 1016, (0, 0)),
            (127, 127, (0, 0)),
            (127, 254, (127, 0)),
            (127, 508, (381, 0)),
            (100, 100, (27, 27)),
            (200, 200, (54, 54)),
            (300, 300, (208, 208)),
        ];

        for (bytes_in_sector, bytes_in_piece, (expected_left_align, expected_right_align)) in
            table.clone()
        {
            let PieceAlignment {
                left_bytes: UnpaddedBytesAmount(actual_left_align),
                right_bytes: UnpaddedBytesAmount(actual_right_align),
            } = get_piece_alignment(
                UnpaddedBytesAmount(bytes_in_sector),
                UnpaddedBytesAmount(bytes_in_piece),
            );
            assert_eq!(
                (expected_left_align, expected_right_align),
                (actual_left_align, actual_right_align)
            );
        }
    }

    #[test]
    fn test_get_piece_start_byte() {
        let pieces = [
            UnpaddedBytesAmount(31),
            UnpaddedBytesAmount(32),
            UnpaddedBytesAmount(33),
        ];

        assert_eq!(
            get_piece_start_byte(&pieces[..0], pieces[0]),
            UnpaddedByteIndex(0)
        );
        assert_eq!(
            get_piece_start_byte(&pieces[..1], pieces[1]),
            UnpaddedByteIndex(127)
        );
        assert_eq!(
            get_piece_start_byte(&pieces[..2], pieces[2]),
            UnpaddedByteIndex(254)
        );
    }

    #[test]
    fn test_verify_simple_pieces() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        //     g
        //   /  \
        //  e    f
        // / \  / \
        // a  b c  d

        let (a, b, c, d): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = rng.gen();

        let mut e = [0u8; 32];
        let h = piece_hash(&a, &b);
        e.copy_from_slice(h.as_ref());

        let mut f = [0u8; 32];
        let h = piece_hash(&c, &d);
        f.copy_from_slice(h.as_ref());

        let mut g = [0u8; 32];
        let h = piece_hash(&e, &f);
        g.copy_from_slice(h.as_ref());
        let a = PieceInfo::new(a, UnpaddedBytesAmount(127)).expect("failed to create piece info a");
        let b = PieceInfo::new(b, UnpaddedBytesAmount(127)).expect("failed to create piece info b");
        let c = PieceInfo::new(c, UnpaddedBytesAmount(127)).expect("failed to create piece info c");
        let d = PieceInfo::new(d, UnpaddedBytesAmount(127)).expect("failed to create piece info d");

        let e = PieceInfo::new(e, UnpaddedBytesAmount(254)).expect("failed to create piece info e");
        let f = PieceInfo::new(f, UnpaddedBytesAmount(254)).expect("failed to create piece info f");
        let g = PieceInfo::new(g, UnpaddedBytesAmount(508)).expect("failed to create piece info g");

        let sector_size = SectorSize(4 * 128);
        let comm_d = g.commitment;

        // println!("e: {:?}", e);
        // println!("f: {:?}", f);
        // println!("g: {:?}", g);

        assert!(
            verify_pieces(
                &comm_d,
                &[a.clone(), b.clone(), c.clone(), d.clone()],
                sector_size
            )
            .expect("failed to verify"),
            "[a, b, c, d]"
        );

        assert!(
            verify_pieces(&comm_d, &[e.clone(), c, d], sector_size).expect("failed to verify"),
            "[e, c, d]"
        );

        assert!(
            verify_pieces(&comm_d, &[e, f.clone()], sector_size).expect("failed to verify"),
            "[e, f]"
        );

        assert!(
            verify_pieces(&comm_d, &[a, b, f], sector_size).expect("failed to verify"),
            "[a, b, f]"
        );

        assert!(
            verify_pieces(&comm_d, &[g], sector_size).expect("failed to verify"),
            "[g]"
        );
    }

    #[test]
    #[allow(clippy::identity_op)]
    fn test_verify_padded_pieces() {
        // [
        //   {(A0 00) (BB BB)} -> A(1) P(1) P(1) P(1) B(4)
        //   {(CC 00) (00 00)} -> C(2)      P(1) P(1) P(1) P(1) P(1) P(1)
        // ]
        // [
        //   {(DD DD) (DD DD)} -> D(8)
        //   {(00 00) (00 00)} -> P(1) P(1) P(1) P(1) P(1) P(1) P(1) P(1)
        // ]

        let sector_size = SectorSize(32 * 128);
        let pad = zero_padding(UnpaddedBytesAmount(127)).expect("failed to create pad");

        let pieces = vec![
            PieceInfo::new([1u8; 32], UnpaddedBytesAmount(1 * 127))
                .expect("failed to create piece info 0"),
            PieceInfo::new([2u8; 32], UnpaddedBytesAmount(4 * 127))
                .expect("failed to create piece info 1"),
            PieceInfo::new([3u8; 32], UnpaddedBytesAmount(2 * 127))
                .expect("failed to create piece info 2"),
            PieceInfo::new([4u8; 32], UnpaddedBytesAmount(8 * 127))
                .expect("failed to create piece info 3"),
        ];

        let padded_pieces = vec![
            PieceInfo::new([1u8; 32], UnpaddedBytesAmount(1 * 127))
                .expect("failed to create padded piece info 0"),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            PieceInfo::new([2u8; 32], UnpaddedBytesAmount(4 * 127))
                .expect("failed to create padded piece info 1"),
            PieceInfo::new([3u8; 32], UnpaddedBytesAmount(2 * 127))
                .expect("failed to create padded piece info 2"),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            PieceInfo::new([4u8; 32], UnpaddedBytesAmount(8 * 127))
                .expect("failed to create padded piece info 4"),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad.clone(),
            pad,
        ];

        let hash = |a, b| {
            let hash = piece_hash(a, b);
            let mut res = [0u8; 32];
            res.copy_from_slice(hash.as_ref());
            res
        };

        let layer1: Vec<[u8; 32]> = vec![
            hash(&padded_pieces[0].commitment, &padded_pieces[1].commitment), // 2: H(A(1) | P(1))
            hash(&padded_pieces[2].commitment, &padded_pieces[3].commitment), // 2: H(P(1) | P(1))
            padded_pieces[4].commitment,                                      // 4: B(4)
            padded_pieces[5].commitment,                                      // 2: C(2)
            hash(&padded_pieces[6].commitment, &padded_pieces[7].commitment), // 2: H(P(1) | P(1))
            hash(&padded_pieces[8].commitment, &padded_pieces[9].commitment), // 2: H(P(1) | P(1))
            hash(&padded_pieces[10].commitment, &padded_pieces[11].commitment), // 2: H(P(1) | P(1))
            padded_pieces[12].commitment,                                     // 8: D(8)
            hash(&padded_pieces[13].commitment, &padded_pieces[14].commitment), // 2: H(P(1) | P(1))
            hash(&padded_pieces[15].commitment, &padded_pieces[16].commitment), // 2: H(P(1) | P(1))
            hash(&padded_pieces[17].commitment, &padded_pieces[18].commitment), // 2: H(P(1) | P(1))
            hash(&padded_pieces[19].commitment, &padded_pieces[20].commitment), // 2: H(P(1) | P(1))
        ];

        let layer2: Vec<[u8; 32]> = vec![
            hash(&layer1[0], &layer1[1]),   // 4
            layer1[2],                      // 4
            hash(&layer1[3], &layer1[4]),   // 4
            hash(&layer1[5], &layer1[6]),   // 4
            layer1[7],                      // 8
            hash(&layer1[8], &layer1[9]),   // 4
            hash(&layer1[10], &layer1[11]), // 4
        ];

        let layer3 = vec![
            hash(&layer2[0], &layer2[1]), // 8
            hash(&layer2[2], &layer2[3]), // 8
            layer2[4],                    // 8
            hash(&layer2[5], &layer2[6]), // 8
        ];

        let layer4 = vec![
            hash(&layer3[0], &layer3[1]), // 16
            hash(&layer3[2], &layer3[3]), // 16
        ];

        let comm_d = hash(&layer4[0], &layer4[1]); // 32

        assert!(verify_pieces(&comm_d, &pieces, sector_size).expect("failed to verify pieces"));
    }

    #[ignore] // slow test
    #[test]
    fn test_verify_random_pieces() -> Result<()> {
        use crate::pieces::*;

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for sector_size in &[
            SectorSize(4 * 128),
            SectorSize(32 * 128),
            SectorSize(1024 * 128),
            SectorSize(1024 * 8 * 128),
        ] {
            println!("--- {:?} ---", sector_size);
            for i in 0..100 {
                println!(" - {} -", i);
                let unpadded_sector_size: UnpaddedBytesAmount = sector_size.clone().into();
                let sector_size = *sector_size;
                let padded_sector_size: PaddedBytesAmount = sector_size.into();

                let mut piece_sizes = Vec::new();
                loop {
                    let sum_piece_sizes: PaddedBytesAmount =
                        sum_piece_bytes_with_alignment(&piece_sizes).into();

                    if sum_piece_sizes > padded_sector_size {
                        piece_sizes.pop();
                        break;
                    }
                    if sum_piece_sizes == padded_sector_size {
                        break;
                    }

                    'inner: loop {
                        // pieces must be power of two
                        let left = u64::from(padded_sector_size) - u64::from(sum_piece_sizes);
                        let left_power_of_two = prev_power_of_two(left as u32);
                        let max_exp = (left_power_of_two as f64).log2() as u32;

                        let padded_exp = if max_exp > 7 {
                            rng.gen_range(
                                7, // 2**7 == 128,
                                max_exp,
                            )
                        } else {
                            7
                        };
                        let padded_piece_size = 2u64.pow(padded_exp);
                        let piece_size: UnpaddedBytesAmount =
                            PaddedBytesAmount(padded_piece_size).into();
                        piece_sizes.push(piece_size);
                        let sum: PaddedBytesAmount =
                            sum_piece_bytes_with_alignment(&piece_sizes).into();

                        if sum > padded_sector_size {
                            // pieces might be too large after padding, so remove them and try again.
                            piece_sizes.pop();
                        } else {
                            break 'inner;
                        }
                    }
                }

                // println!(
                //     "  {:?}",
                //     piece_sizes
                //         .iter()
                //         .map(|s| u64::from(*s) / 127)
                //         .collect::<Vec<_>>()
                // );
                assert!(sum_piece_bytes_with_alignment(&piece_sizes) <= unpadded_sector_size);
                assert!(!piece_sizes.is_empty());

                let (comm_d, piece_infos) = build_sector(&piece_sizes, sector_size)?;

                assert!(
                    verify_pieces(&comm_d, &piece_infos, sector_size)?,
                    "invalid pieces"
                );
            }
        }

        Ok(())
    }

    fn build_sector(
        piece_sizes: &[UnpaddedBytesAmount],
        sector_size: SectorSize,
    ) -> Result<([u8; 32], Vec<PieceInfo>)> {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let porep_id = [32; 32];
        let graph = StackedBucketGraph::<DefaultPieceHasher>::new_stacked(
            u64::from(sector_size) as usize / NODE_SIZE,
            DRG_DEGREE,
            EXP_DEGREE,
            porep_id,
        )?;

        let mut staged_sector = Vec::with_capacity(u64::from(sector_size) as usize);
        let mut staged_sector_io = std::io::Cursor::new(&mut staged_sector);
        let mut piece_infos = Vec::with_capacity(piece_sizes.len());

        for (i, piece_size) in piece_sizes.iter().enumerate() {
            let piece_size_u = u64::from(*piece_size) as usize;
            let mut piece_bytes = vec![255u8; piece_size_u];
            rng.fill_bytes(&mut piece_bytes);

            let mut piece_file = std::io::Cursor::new(&mut piece_bytes);

            let (piece_info, _) = crate::api::add_piece(
                &mut piece_file,
                &mut staged_sector_io,
                *piece_size,
                &piece_sizes[..i],
            )?;

            piece_infos.push(piece_info);
        }
        assert_eq!(staged_sector.len(), u64::from(sector_size) as usize);

        let data_tree: DataTree =
            create_base_merkle_tree::<DataTree>(None, graph.size(), &staged_sector)
                .expect("failed to create data tree");
        let comm_d_root: Fr = data_tree.root().into();
        let comm_d = commitment_from_fr(comm_d_root);

        Ok((comm_d, piece_infos))
    }

    fn prev_power_of_two(mut x: u32) -> u32 {
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        x - (x >> 1)
    }
}
