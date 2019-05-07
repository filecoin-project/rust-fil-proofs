use crate::api::sector_builder::metadata::PieceMetadata;
use sector_base::api::bytes_amount::UnpaddedBytesAmount;
use std::cmp::max;

pub type PiecePadding = (UnpaddedBytesAmount, UnpaddedBytesAmount);

pub fn sum_piece_lengths<'a, T: Iterator<Item = &'a PieceMetadata>>(pieces: T) -> UnpaddedBytesAmount {
    pieces.fold(UnpaddedBytesAmount(0), |acc, p| {
        let (l, r) = get_piece_padding(acc, p.num_bytes);
        acc + l + p.num_bytes + r
    })
}

pub fn get_piece_by_key<'a>(
    pieces: &'a [PieceMetadata],
    piece_key: &str,
) -> Option<&'a PieceMetadata> {
    pieces.iter().find(|p| p.piece_key == piece_key)
}

pub fn get_piece_start(pieces: &[PieceMetadata], piece: &PieceMetadata) -> u64 {
    let last_byte = sum_piece_lengths(pieces.iter().take_while(|p| p.piece_key != piece.piece_key));
    let (left_padding, _) = get_piece_padding(last_byte, piece.num_bytes);

    u64::from(last_byte + left_padding)
}

pub fn get_piece_padding(written_bytes: UnpaddedBytesAmount, piece_bytes: UnpaddedBytesAmount) -> PiecePadding {
    let minimum_piece_bytes = (4 * 32) - 1;
    let adjusted_piece_bytes = max(minimum_piece_bytes, u64::from(piece_bytes));

    let mut piece_bytes_needed = minimum_piece_bytes;

    while piece_bytes_needed < adjusted_piece_bytes {
      piece_bytes_needed *= 2;
    }

    let encroaching = u64::from(written_bytes) % piece_bytes_needed;

    let left_bytes = if encroaching > 0 {
        piece_bytes_needed - encroaching
    } else {
        0
    };

    let right_bytes = piece_bytes_needed - u64::from(piece_bytes);

    (UnpaddedBytesAmount(left_bytes), UnpaddedBytesAmount(right_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_foo() {
        let table = vec![
            (  0,    0, (  0, 127)),
            (  0,  127, (  0,   0)),
            (  0,  254, (  0,   0)),
            (  0,  508, (  0,   0)),
            (  0, 1016, (  0,   0)),
            (127,  127, (  0,   0)),
            (127,  254, (127,   0)),
            (127,  508, (381,   0)),

            (100,  100, ( 27,  27)),
            (200,  200, ( 54,  54)),
            (300,  300, (208, 208)),

        ];

        for (x, y, (a, b)) in table.clone() {
            let (UnpaddedBytesAmount(c), UnpaddedBytesAmount(d)) = get_piece_padding(UnpaddedBytesAmount(x), UnpaddedBytesAmount(y));
            println!("f({}, {}) -> ({}, {}) (expected: {}, {})", x, y, c, d, a, b);
            assert_eq!((c, d), (a, b));
        }
    }

    fn leaves(n: u64) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(n * 32)
    }

    #[test]
    fn test_get_piece_info() {
        // minimally sized piece in clean sector
        assert_eq!(
            get_piece_padding(leaves(0), leaves(4)),
            (leaves(0), leaves(0))
        );

        // smaller than minimum piece in clean sector
        assert_eq!(
            get_piece_padding(leaves(0), leaves(3)),
            (leaves(0), leaves(1))
        );

        // slightly bigger piece in clean sector
        assert_eq!(
            get_piece_padding(leaves(0), leaves(5)),
            (leaves(0), leaves(3))
        );

        // minimal piece in populated sector
        assert_eq!(
            get_piece_padding(leaves(4), leaves(4)),
            (leaves(0), leaves(0))
        );

        // big piece in populated sector
        assert_eq!(
            get_piece_padding(leaves(4), leaves(5)),
            (leaves(4), leaves(3))
        );

        // bigger piece in populated sector
        assert_eq!(
            get_piece_padding(leaves(4), leaves(8)),
            (leaves(4), leaves(0))
        );

        // even bigger piece in populated sector
        assert_eq!(
            get_piece_padding(leaves(4), leaves(15)),
            (leaves(12), leaves(1))
        );

        // piece in misaligned sector
        assert_eq!(
            get_piece_padding(leaves(5), leaves(5)),
            (leaves(3), leaves(3))
        );
    }

    #[test]
    fn test_get_piece_start_foo() {
        let mut pieces: Vec<PieceMetadata> = Default::default();

        pieces.push(PieceMetadata {
            piece_key: String::from("x"),
            num_bytes: UnpaddedBytesAmount(31),
            // comm_p: None,
        });

        pieces.push(PieceMetadata {
            piece_key: String::from("y"),
            num_bytes: UnpaddedBytesAmount(32),
            // comm_p: None,
        });

        pieces.push(PieceMetadata {
            piece_key: String::from("z"),
            num_bytes: UnpaddedBytesAmount(33),
            // comm_p: None,
        });

        match get_piece_start(&pieces, "x") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 0),
            None => panic!(),
        }

        match get_piece_start(&pieces, "y") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 128),
            None => panic!(),
        }

        match get_piece_start(&pieces, "z") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 256),
            None => panic!(),
        }
    }

    #[test]
    fn test_get_piece_start() {
        let mut pieces: Vec<PieceMetadata> = Default::default();

        pieces.push(PieceMetadata {
            piece_key: String::from("x"),
            num_bytes: UnpaddedBytesAmount(5),
            // comm_p: None,
        });

        pieces.push(PieceMetadata {
            piece_key: String::from("y"),
            num_bytes: UnpaddedBytesAmount(300),
            // comm_p: None,
        });

        pieces.push(PieceMetadata {
            piece_key: String::from("z"),
            num_bytes: UnpaddedBytesAmount(100),
            // comm_p: None,
        });

        match get_piece_start(&pieces, "x") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 0),
            None => panic!(),
        }

        match get_piece_start(&pieces, "y") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 512),
            None => panic!(),
        }

        match get_piece_start(&pieces, "z") {
            Some(UnpaddedBytesAmount(start)) => assert_eq!(start, 1024),
            None => panic!(),
        }
    }
}
