#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use bitvec::{order::Lsb0 as LittleEndian, vec::BitVec};

    use itertools::Itertools;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use filecoin_proofs::fr32::{
        extract_bits_and_shift, shift_bits, write_unpadded, BitByte, BitVecLEu8, FR32_PADDING_MAP,
    };

    use filecoin_proofs::constants::TEST_SEED;

    #[test]
    fn test_position() {
        let mut bits = 0;
        for i in 0..10 {
            for j in 0..8 {
                let position = BitByte { bytes: i, bits: j };
                assert_eq!(position.total_bits(), bits);
                bits += 1;
            }
        }
    }

    // Test the `extract_bits_le` function against the `BitVec` functionality
    // (assumed to be correct).
    #[test]
    fn test_random_bit_extraction() {
        // Length of the data vector we'll be extracting from.
        let len = 20;

        let rng = &mut XorShiftRng::from_seed(TEST_SEED);
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();

        // TODO: Evaluate designing a scattered pattered of `pos` and `num_bits`
        // instead of repeating too many iterations with any number.
        for _ in 0..100 {
            let pos = rng.gen_range(0, data.len() / 2);
            let num_bits = rng.gen_range(1, data.len() * 8 - pos);
            let new_offset = rng.gen_range(0, 8);

            let mut bv = BitVecLEu8::new();
            bv.extend(
                BitVecLEu8::from(&data[..])
                    .into_iter()
                    .skip(pos)
                    .take(num_bits),
            );
            let shifted_bv: BitVecLEu8 = bv >> new_offset;

            assert_eq!(
                shifted_bv.as_slice(),
                &extract_bits_and_shift(&data, pos, num_bits, new_offset)[..],
            );
        }
    }

    // Test the `shift_bits` function against the `BitVec<LittleEndian, u8>`
    // implementation of `shr_assign` and `shl_assign`.
    #[test]
    fn test_bit_shifts() {
        let len = 5;
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        for amount in 1..8 {
            for left in [true, false].iter() {
                let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();

                let shifted_bits = shift_bits(&data, amount, *left);

                let mut bv: BitVec<LittleEndian, u8> = data.into();
                if *left {
                    bv >>= amount;
                } else {
                    bv <<= amount;
                }
                // We use the opposite shift notation (see `shift_bits`).

                assert_eq!(bv.as_slice(), shifted_bits.as_slice());
            }
        }
    }

    // Simple (and slow) padder implementation using `BitVec`.
    // It is technically not quite right to use `BitVec` to test
    // `write_padded` since at the moment that function still uses
    // it for some corner cases, but since largely this implementation
    // has been replaced it seems reasonable.
    fn bit_vec_padding(raw_data: Vec<u8>) -> Box<[u8]> {
        let mut padded_data: BitVec<LittleEndian, u8> = BitVec::new();
        let raw_data: BitVec<LittleEndian, u8> = BitVec::from(raw_data);

        for data_unit in raw_data
            .into_iter()
            .chunks(FR32_PADDING_MAP.data_bits)
            .into_iter()
        {
            padded_data.extend(data_unit);

            // To avoid reconverting the iterator, we deduce if we need the padding
            // by the length of `padded_data`: a full data unit would not leave the
            // padded layout aligned (it would leave it unaligned by just `pad_bits()`).
            if padded_data.len() % 8 != 0 {
                for _ in 0..FR32_PADDING_MAP.pad_bits() {
                    padded_data.push(false);
                }
            }
        }

        padded_data.into_boxed_slice()
    }

    // `write_padded` and `write_unpadded` for 1016 bytes of 1s, check the
    // recovered raw data.
    #[test]
    fn test_read_write_padded() {
        let len = 1016; // Use a multiple of 254.
        let data = vec![255u8; len];
        let mut padded = Vec::new();
        let mut reader = filecoin_proofs::fr32_reader::Fr32Reader::new(io::Cursor::new(&data));
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");

        assert_eq!(
            padded.len(),
            FR32_PADDING_MAP.transform_byte_offset(len, true)
        );

        let mut unpadded = Vec::new();
        let unpadded_written =
            write_unpadded(&padded, &mut unpadded, 0, len).expect("un-padded write failed");
        assert_eq!(unpadded_written, len);
        assert_eq!(data, unpadded);
        assert_eq!(padded.into_boxed_slice(), bit_vec_padding(data));
    }

    // `write_padded` and `write_unpadded` for 1016 bytes of random data, recover
    // different lengths of raw data at different offset, check integrity.
    #[test]
    fn test_read_write_padded_offset() {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        let len = 1016;
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();

        let mut padded = Vec::new();
        let mut reader = filecoin_proofs::fr32_reader::Fr32Reader::new(io::Cursor::new(&data));
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");

        {
            let mut unpadded = Vec::new();
            write_unpadded(&padded, &mut unpadded, 0, 1016).expect("un-padded write failed: 1016");
            let expected = &data[0..1016];

            assert_eq!(expected.len(), unpadded.len());
            assert_eq!(expected, &unpadded[..]);
        }

        {
            let mut unpadded = Vec::new();
            write_unpadded(&padded, &mut unpadded, 0, 44).expect("un-padded write failed: 44");
            let expected = &data[0..44];

            assert_eq!(expected.len(), unpadded.len());
            assert_eq!(expected, &unpadded[..]);
        }

        let excessive_len = 35;
        for start in (1016 - excessive_len + 2)..1016 {
            assert!(write_unpadded(&padded, &mut Vec::new(), start, excessive_len).is_err());
        }
    }

    // TODO: Add a test that drops the last part of an element and tries to recover
    // the rest of the data (may already be present in some form in the above tests).
}
