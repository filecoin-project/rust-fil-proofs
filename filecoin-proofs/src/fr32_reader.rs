use byte_slice_cast::*;
use std::io;

pub struct Fr32Reader<R> {
    /// The source being padded.
    source: R,
    /// Currently read block.
    in_buffer: [u8; NUM_U128S_PER_BLOCK * 16],
    /// Currently writing out block.
    out_buffer: [u128; NUM_U128S_PER_BLOCK],
    /// How many blocks are left in the buffers.
    to_process: usize,
    /// How many bytes of the out_buffer are already read out.
    out_offset: usize,
    /// Are we done reading?
    done: bool,
}

const NUM_U128S_PER_BLOCK: usize = 8;
const MASK_SKIP_HIGH_2: u128 = 0b0011_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111;

impl<R: io::Read> Fr32Reader<R> {
    pub fn new(source: R) -> Self {
        Fr32Reader {
            source,
            in_buffer: [0; NUM_U128S_PER_BLOCK * 16],
            out_buffer: [0; NUM_U128S_PER_BLOCK],
            to_process: 0,
            out_offset: 0,
            done: false,
        }
    }

    /// Processes a single block in in_buffer, writing the result to out_buffer.
    fn process_block(&mut self) {
        let in_buffer: &[u128] = self.in_buffer.as_slice_of::<u128>().unwrap();
        let out_buffer = &mut self.out_buffer;

        // 0..254
        {
            out_buffer[0] = in_buffer[0];
            out_buffer[1] = in_buffer[1] & MASK_SKIP_HIGH_2;
        }
        // 254..508
        {
            out_buffer[2] = in_buffer[1] >> 126; // top 2 bits
            out_buffer[2] |= in_buffer[2] << 2; // low 126 bits
            out_buffer[3] = in_buffer[2] >> 126; // top 2 bits
            out_buffer[3] |= in_buffer[3] << 2; // low 124 bits
            out_buffer[3] &= MASK_SKIP_HIGH_2; // zero high 2 bits
        }
        // 508..762
        {
            out_buffer[4] = in_buffer[3] >> 124; // top 4 bits
            out_buffer[4] |= in_buffer[4] << 4; // low 124 bits
            out_buffer[5] = in_buffer[4] >> 124; // top 4 bits
            out_buffer[5] |= in_buffer[5] << 4; // low 122 bits
            out_buffer[5] &= MASK_SKIP_HIGH_2; // zero high 2 bits
        }
        // 762..1016
        {
            out_buffer[6] = in_buffer[5] >> 122; // top 6 bits
            out_buffer[6] |= in_buffer[6] << 6; // low 122 bits
            out_buffer[7] = in_buffer[6] >> 122; // top 6 bits
            out_buffer[7] |= in_buffer[7] << 6; // low 120 bits
            out_buffer[7] &= MASK_SKIP_HIGH_2; // zero high 2 bits
        }
    }

    fn fill_buffer(&mut self) -> io::Result<usize> {
        let mut bytes_read = 0;
        let mut buf = &mut self.in_buffer[..127];

        while !buf.is_empty() {
            match self.source.read(buf) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    bytes_read += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        // clear unfilled memory
        for val in &mut self.in_buffer[bytes_read..127] {
            *val = 0;
        }

        Ok(bytes_read)
    }
}

/// Division of x by y, rounding up.
/// x must be > 0
#[inline]
const fn div_ceil(x: usize, y: usize) -> usize {
    1 + ((x - 1) / y)
}

impl<R: io::Read> io::Read for Fr32Reader<R> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if self.done || target.is_empty() {
            return Ok(0);
        }

        let num_bytes = target.len();

        let mut read = 0;

        while read < num_bytes {
            // load new block
            if self.to_process == 0 {
                let bytes_read = self.fill_buffer()?;

                // read all data, no new data in the buffer
                if bytes_read == 0 {
                    self.done = true;
                    break;
                }

                self.process_block();
                self.to_process += div_ceil(bytes_read * 8, 254);
                self.out_offset = 0;
            }

            // write out result
            let available_bytes = self.to_process * (256 / 8);

            let start = read;
            let end = std::cmp::min(start + available_bytes, num_bytes);
            let len = end - start;

            let out_start = self.out_offset;
            let out_end = out_start + len;

            target[start..end]
                .copy_from_slice(&self.out_buffer.as_byte_slice()[out_start..out_end]);
            read += len;
            self.out_offset += len;
            self.to_process -= div_ceil(len * 8, 256);
        }

        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::io::Read;

    const DATA_BITS: u64 = 254;
    const TARGET_BITS: u64 = 256;

    #[test]
    fn test_simple_short() {
        // Source is shorter than 1 padding cycle.
        let data = vec![3u8; 30];
        let mut reader = Fr32Reader::new(io::Cursor::new(&data));
        let mut padded = Vec::new();
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");
        assert_eq!(padded.len(), 32);
        assert_eq!(&data[..], &padded[..30]);

        assert_eq!(padded.into_boxed_slice(), bit_vec_padding(data));
    }

    #[test]
    fn test_simple_single() {
        let data = vec![255u8; 32];
        let mut padded = Vec::new();
        let mut reader = Fr32Reader::new(io::Cursor::new(&data));
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");

        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b0000_0011);
        assert_eq!(padded.len(), 64);
        let bv = bit_vec_padding(data);
        assert_eq!(bv.len(), 64);
        assert_eq!(padded.into_boxed_slice(), bv);
    }

    #[test]
    fn test_simple_127() {
        let data = vec![255u8; 127];
        let mut padded = Vec::new();
        let mut reader = Fr32Reader::new(io::Cursor::new(&data));
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");

        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);

        assert_eq!(padded.len(), 128);

        assert_eq!(padded.into_boxed_slice(), bit_vec_padding(data));
    }

    #[test]
    fn test_chained_byte_source() {
        let random_bytes: Vec<u8> = (0..127).map(|_| rand::random::<u8>()).collect();

        // read 127 bytes from a non-chained source
        let output_x = {
            let input_x = io::Cursor::new(random_bytes.clone());

            let mut reader = Fr32Reader::new(input_x);
            let mut buf_x = Vec::new();
            reader.read_to_end(&mut buf_x).expect("could not seek");
            buf_x
        };

        for n in 1..127 {
            let random_bytes = random_bytes.clone();

            // read 127 bytes from a n-byte buffer and then the rest
            let output_y = {
                let input_y =
                    io::Cursor::new(random_bytes.iter().take(n).cloned().collect::<Vec<u8>>())
                        .chain(io::Cursor::new(
                            random_bytes.iter().skip(n).cloned().collect::<Vec<u8>>(),
                        ));

                let mut reader = Fr32Reader::new(input_y);
                let mut buf_y = Vec::new();
                reader.read_to_end(&mut buf_y).expect("could not seek");

                buf_y
            };

            assert_eq!(&output_x, &output_y, "should have written same bytes");
            assert_eq!(
                output_x.clone().into_boxed_slice(),
                bit_vec_padding(random_bytes)
            );
        }
    }

    #[test]
    fn test_full() {
        let data = vec![255u8; 127];

        let mut buf = Vec::new();
        let mut reader = Fr32Reader::new(io::Cursor::new(&data));
        reader.read_to_end(&mut buf).expect("in-memory read failed");

        assert_eq!(buf.clone().into_boxed_slice(), bit_vec_padding(data));
        validate_fr32(&buf);
    }

    #[test]
    #[ignore]
    fn test_long() {
        use rand::RngCore;

        let mut rng = rand::thread_rng();
        for i in 1..100 {
            for j in 1..50 {
                let mut data = vec![0u8; i * j];
                rng.fill_bytes(&mut data);

                let mut buf = Vec::new();
                let mut reader = Fr32Reader::new(io::Cursor::new(&data));
                reader.read_to_end(&mut buf).expect("in-memory read failed");

                assert_eq!(
                    buf.into_boxed_slice(),
                    bit_vec_padding(data),
                    "{} - {}",
                    i,
                    j
                );
            }
        }
    }

    fn bit_vec_padding(raw_data: Vec<u8>) -> Box<[u8]> {
        use bitvec::{order::Lsb0 as LittleEndian, vec::BitVec};
        use itertools::Itertools;

        let mut padded_data: BitVec<LittleEndian, u8> = BitVec::new();
        let raw_data: BitVec<LittleEndian, u8> = BitVec::from(raw_data);

        for data_unit in raw_data.into_iter().chunks(DATA_BITS as usize).into_iter() {
            padded_data.extend(data_unit);

            // To avoid reconverting the iterator, we deduce if we need the padding
            // by the length of `padded_data`: a full data unit would not leave the
            // padded layout aligned (it would leave it unaligned by just `pad_bits()`).
            if padded_data.len() % 8 != 0 {
                for _ in 0..(TARGET_BITS - DATA_BITS) {
                    padded_data.push(false);
                }
            }
        }

        while padded_data.len() % (TARGET_BITS as usize) != 0 {
            padded_data.push(false);
        }

        padded_data.into_boxed_slice()
    }

    fn validate_fr32(bytes: &[u8]) {
        let chunks = (bytes.len() as f64 / 32_f64).ceil() as usize;
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let _ = storage_proofs::fr32::bytes_into_fr(chunk).unwrap_or_else(|_| {
                panic!(
                    "chunk {}/{} cannot be converted to valid Fr: {:?}",
                    i + 1,
                    chunks,
                    chunk
                )
            });
        }
    }

    // raw data stream of increasing values and specific
    // outliers (0xFF, 9), check the content of the raw data encoded (with
    // different alignments) in the padded layouts.
    #[test]
    fn test_exotic() {
        let mut source = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff, 9, 9,
        ];
        source.extend(vec![9, 0xff]);

        let mut buf = Vec::new();
        let mut reader = Fr32Reader::new(io::Cursor::new(&source));
        reader.read_to_end(&mut buf).expect("in-memory read failed");

        for (i, &byte) in buf.iter().enumerate().take(31) {
            assert_eq!(byte, i as u8 + 1);
        }
        assert_eq!(buf[31], 63); // Six least significant bits of 0xff
        assert_eq!(buf[32], (1 << 2) | 0b11); // 7
        for (i, &byte) in buf.iter().enumerate().skip(33).take(30) {
            assert_eq!(byte, (i as u8 - 31) << 2);
        }
        assert_eq!(buf[63], (0x0f << 2)); // 4-bits of ones, half of 0xff, shifted by two, followed by two bits of 0-padding.
        assert_eq!(buf[64], 0x0f | 9 << 4); // The last half of 0xff, 'followed' by 9.
        assert_eq!(buf[65], 9 << 4); // A shifted 9.
        assert_eq!(buf[66], 9 << 4); // Another.
        assert_eq!(buf[67], 0xf0); // The final 0xff is split into two bytes. Here is the first half.
        assert_eq!(buf[68], 0x0f); // And here is the second.

        assert_eq!(buf.into_boxed_slice(), bit_vec_padding(source));
    }

    const BLOCK_SIZE: usize = 127 * 8;

    #[test]
    fn test_fast() {
        // unpadded 127 * 8 bits => 4 * 254
        // padded   128 * 8 bits => 4 * 256

        // source: 127bytes
        // [
        //  0:   0..254  (0..31)
        //  1: 254..508  (31..64)
        //       254..318
        //       318..382
        //       382..446
        //
        //  2: 508..762  (64..96)
        //  3: 762..1016 (96..)
        // ]

        // target: 128bytes

        let data = [255u8; 127];
        let mut padded = [0u8; 128];

        let num_bits = data.len() * 8;
        assert_eq!(num_bits % 127, 0);

        let num_blocks = div_ceil(num_bits, BLOCK_SIZE);

        let mut in_buffer_bytes = [0u8; 128];
        let mut out_buffer = [0u128; NUM_U128S_PER_BLOCK];
        for block in 0..num_blocks {
            // load current block
            let block_offset_start = block * 127;
            let block_offset_end = std::cmp::min(block_offset_start + 128, data.len());
            let end = block_offset_end - block_offset_start;
            in_buffer_bytes[..end]
                .copy_from_slice(&data[dbg!(block_offset_start)..dbg!(block_offset_end)]);
            let in_buffer: &[u128] = in_buffer_bytes.as_slice_of::<u128>().unwrap();

            // write out fr chunks

            // 0..254
            {
                out_buffer[0] = in_buffer[0];
                out_buffer[1] = in_buffer[1] & MASK_SKIP_HIGH_2;
            }
            // 254..508
            {
                out_buffer[2] = in_buffer[1] >> 126; // top 2 bits
                out_buffer[2] |= in_buffer[2] << 2; // low 126 bits
                out_buffer[3] = in_buffer[2] >> 126; // top 2 bits
                out_buffer[3] |= in_buffer[3] << 2; // low 124 bits
                out_buffer[3] &= MASK_SKIP_HIGH_2; // zero high 2 bits
            }
            // 508..762
            {
                out_buffer[4] = in_buffer[3] >> 124; // top 4 bits
                out_buffer[4] |= in_buffer[4] << 4; // low 124 bits
                out_buffer[5] = in_buffer[4] >> 124; // top 4 bits
                out_buffer[5] |= in_buffer[5] << 4; // low 122 bits
                out_buffer[5] &= MASK_SKIP_HIGH_2; // zero high 2 bits
            }
            // 762..1016
            {
                out_buffer[6] = in_buffer[5] >> 122; // top 6 bits
                out_buffer[6] |= in_buffer[6] << 6; // low 122 bits
                out_buffer[7] = in_buffer[6] >> 122; // top 6 bits
                out_buffer[7] |= in_buffer[7] << 6; // low 120 bits
                out_buffer[7] &= MASK_SKIP_HIGH_2; // zero high 2 bits
            }
            padded[block * 128..(block + 1) * 128].copy_from_slice(out_buffer.as_byte_slice());
        }

        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);

        assert_eq!(padded.len(), 128);

        assert_eq!(&padded[..], &bit_vec_padding(data.to_vec())[..]);
    }
}
