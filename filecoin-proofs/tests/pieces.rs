use std::io::{Cursor, Read};
use std::iter::Iterator;

use anyhow::Result;
use bellperson::bls::Fr;
use filecoin_proofs::{
    add_piece, commitment_from_fr,
    pieces::{
        compute_comm_d, get_piece_alignment, get_piece_start_byte, piece_hash, verify_pieces,
        zero_padding, EmptySource, PieceAlignment,
    },
    Commitment, DataTree, DefaultPieceHasher, PaddedBytesAmount, PieceInfo, SectorSize,
    UnpaddedByteIndex, UnpaddedBytesAmount, DRG_DEGREE, EXP_DEGREE, TEST_SEED,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion, drgraph::Graph, merkle::create_base_merkle_tree, util::NODE_SIZE,
};
use storage_proofs_porep::stacked::StackedBucketGraph;

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
    let comm_d =
        compute_comm_d(SectorSize(2048), &[]).expect("failed to verify pieces, empty piece infos");
    assert_eq!(
        comm_d,
        [
            252, 126, 146, 130, 150, 229, 22, 250, 173, 233, 134, 178, 143, 146, 212, 74, 79, 36,
            185, 53, 72, 82, 35, 55, 106, 121, 144, 39, 188, 24, 248, 51
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
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    //     g
    //   /  \
    //  e    f
    // / \  / \
    // a  b c  d

    let (val_a, val_b, val_c, val_d): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = rng.gen();

    let mut val_e = [0u8; 32];
    let val_h = piece_hash(&val_a, &val_b);
    val_e.copy_from_slice(val_h.as_ref());

    let mut val_f = [0u8; 32];
    let val_h = piece_hash(&val_c, &val_d);
    val_f.copy_from_slice(val_h.as_ref());

    let mut val_g = [0u8; 32];
    let val_h = piece_hash(&val_e, &val_f);
    val_g.copy_from_slice(val_h.as_ref());

    let val_a =
        PieceInfo::new(val_a, UnpaddedBytesAmount(127)).expect("failed to create piece info a");
    let val_b =
        PieceInfo::new(val_b, UnpaddedBytesAmount(127)).expect("failed to create piece info b");
    let val_c =
        PieceInfo::new(val_c, UnpaddedBytesAmount(127)).expect("failed to create piece info c");
    let val_d =
        PieceInfo::new(val_d, UnpaddedBytesAmount(127)).expect("failed to create piece info d");

    let val_e =
        PieceInfo::new(val_e, UnpaddedBytesAmount(254)).expect("failed to create piece info e");
    let val_f =
        PieceInfo::new(val_f, UnpaddedBytesAmount(254)).expect("failed to create piece info f");
    let val_g =
        PieceInfo::new(val_g, UnpaddedBytesAmount(508)).expect("failed to create piece info g");

    let sector_size = SectorSize(4 * 128);
    let comm_d = val_g.commitment;

    // println!("e: {:?}", e);
    // println!("f: {:?}", f);
    // println!("g: {:?}", g);

    assert!(
        verify_pieces(
            &comm_d,
            &[val_a.clone(), val_b.clone(), val_c.clone(), val_d.clone()],
            sector_size
        )
        .expect("failed to verify"),
        "[val_a, val_b, val_c, val_d]"
    );

    assert!(
        verify_pieces(&comm_d, &[val_e.clone(), val_c, val_d], sector_size)
            .expect("failed to verify"),
        "[val_e, val_c, val_d]"
    );

    assert!(
        verify_pieces(&comm_d, &[val_e, val_f.clone()], sector_size).expect("failed to verify"),
        "[val_e, val_f]"
    );

    assert!(
        verify_pieces(&comm_d, &[val_a, val_b, val_f], sector_size).expect("failed to verify"),
        "[val_a, val_b, val_f]"
    );

    assert!(
        verify_pieces(&comm_d, &[val_g], sector_size).expect("failed to verify"),
        "[val_g]"
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

    let hash = |val_a, val_b| {
        let hash = piece_hash(val_a, val_b);
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

#[test]
#[ignore] // slow test
fn test_verify_random_pieces() -> Result<()> {
    use filecoin_proofs::pieces::sum_piece_bytes_with_alignment;

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

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
) -> Result<(Commitment, Vec<PieceInfo>)> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let porep_id = [32; 32];
    let graph = StackedBucketGraph::<DefaultPieceHasher>::new_stacked(
        u64::from(sector_size) as usize / NODE_SIZE,
        DRG_DEGREE,
        EXP_DEGREE,
        porep_id,
        ApiVersion::V1_1_0,
    )?;

    let mut staged_sector = Vec::with_capacity(u64::from(sector_size) as usize);
    let mut staged_sector_io = Cursor::new(&mut staged_sector);
    let mut piece_infos = Vec::with_capacity(piece_sizes.len());

    for (i, piece_size) in piece_sizes.iter().enumerate() {
        let piece_size_u = u64::from(*piece_size) as usize;
        let mut piece_bytes = vec![255u8; piece_size_u];
        rng.fill_bytes(&mut piece_bytes);

        let mut piece_file = Cursor::new(&mut piece_bytes);

        let (piece_info, _) = add_piece(
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
