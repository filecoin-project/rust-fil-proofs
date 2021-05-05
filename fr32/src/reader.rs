use std::cmp::min;
use std::io::{self, Read};
use std::mem::size_of;

#[cfg(not(target_arch = "aarch64"))]
use byte_slice_cast::AsSliceOf;

use byte_slice_cast::AsByteSlice;

/// The number of Frs per Block.
const NUM_FRS_PER_BLOCK: usize = 4;
/// The amount of bits in an Fr when not padded.
const IN_BITS_FR: usize = 254;
/// The amount of bits in an Fr when padded.
const OUT_BITS_FR: usize = 256;

const NUM_BYTES_IN_BLOCK: usize = NUM_FRS_PER_BLOCK * IN_BITS_FR / 8;
const NUM_BYTES_OUT_BLOCK: usize = NUM_FRS_PER_BLOCK * OUT_BITS_FR / 8;

const NUM_U128S_PER_BLOCK: usize = NUM_BYTES_OUT_BLOCK / size_of::<u128>();

const MASK_SKIP_HIGH_2: u128 = 0b0011_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111;

#[repr(align(16))]
struct AlignedBuffer([u8; NUM_BYTES_IN_BLOCK + 1]);

/// An `io::Reader` that converts unpadded input into valid `Fr32` padded output.
pub struct Fr32Reader<R> {
    /// The source being padded.
    source: R,
    /// Currently read block.
    /// This is padded to 128 bytes to allow reading all values as `u128`s, but only the first
    /// 127 bytes are ever valid.
    in_buffer: AlignedBuffer,
    /// Currently writing out block.
    out_buffer: [u128; NUM_U128S_PER_BLOCK],
    /// The current offset into the `out_buffer` in bytes.
    out_offset: usize,
    /// How many `Fr32`s are available in the `out_buffer`.
    available_frs: usize,
    /// Are we done reading?
    done: bool,
}

macro_rules! process_fr {
    (
        $in_buffer:expr,
        $out0:expr,
        $out1:expr,
        $bit_offset:expr
    ) => {{
        $out0 = $in_buffer[0] >> 128 - $bit_offset;
        $out0 |= $in_buffer[1] << $bit_offset;
        $out1 = $in_buffer[1] >> 128 - $bit_offset;
        $out1 |= $in_buffer[2] << $bit_offset;
        $out1 &= MASK_SKIP_HIGH_2; // zero high 2 bits
    }};
}

impl<R: Read> Fr32Reader<R> {
    pub fn new(source: R) -> Self {
        Fr32Reader {
            source,
            in_buffer: AlignedBuffer([0; NUM_BYTES_IN_BLOCK + 1]),
            out_buffer: [0; NUM_U128S_PER_BLOCK],
            out_offset: 0,
            available_frs: 0,
            done: false,
        }
    }

    /// Processes a single block in in_buffer, writing the result to out_buffer.
    fn process_block(&mut self) {
        let in_buffer: &[u128] = {
            #[cfg(target_arch = "aarch64")]
            // Safety: This is safe because the struct/data is aligned on
            // a 16 byte boundary and can therefore be casted from u128
            // to u8 without alignment safety issues.
            unsafe {
                &mut (*(&self.in_buffer.0 as *const [u8] as *mut [u128]))
            }
            #[cfg(not(target_arch = "aarch64"))]
            self.in_buffer.0.as_slice_of::<u128>().unwrap()
        };
        let out = &mut self.out_buffer;

        // 0..254
        {
            out[0] = in_buffer[0];
            out[1] = in_buffer[1] & MASK_SKIP_HIGH_2;
        }
        // 254..508
        process_fr!(&in_buffer[1..], out[2], out[3], 2);
        // 508..762
        process_fr!(&in_buffer[3..], out[4], out[5], 4);
        // 762..1016
        process_fr!(&in_buffer[5..], out[6], out[7], 6);

        // Reset buffer offset.
        self.out_offset = 0;
    }

    fn fill_in_buffer(&mut self) -> io::Result<usize> {
        let mut bytes_read = 0;
        let mut buf = &mut self.in_buffer.0[..NUM_BYTES_IN_BLOCK];

        while !buf.is_empty() {
            match self.source.read(buf) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                    bytes_read += n;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        // Clear unfilled memory.
        for val in &mut self.in_buffer.0[bytes_read..NUM_BYTES_IN_BLOCK] {
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

impl<R: Read> Read for Fr32Reader<R> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if self.done || target.is_empty() {
            return Ok(0);
        }

        // The number of bytes already read and written into `target`.
        let mut bytes_read = 0;
        // The number of bytes to read.
        let bytes_to_read = target.len();

        while bytes_read < bytes_to_read {
            // Load and process the next block, if no Frs are available anymore.
            if self.available_frs == 0 {
                let bytes_read = self.fill_in_buffer()?;

                // All data was read from the source, no new data in the buffer.
                if bytes_read == 0 {
                    self.done = true;
                    break;
                }

                self.process_block();

                // Update state of how many new Frs are now available.
                self.available_frs = div_ceil(bytes_read * 8, IN_BITS_FR);
            }

            // Write out as many Frs as available and requested
            {
                let available_bytes = self.available_frs * (OUT_BITS_FR / 8);

                let target_start = bytes_read;
                let target_end = min(target_start + available_bytes, bytes_to_read);
                let len = target_end - target_start;

                let out_start = self.out_offset;
                let out_end = out_start + len;

                target[target_start..target_end]
                    .copy_from_slice(&self.out_buffer.as_byte_slice()[out_start..out_end]);
                bytes_read += len;
                self.out_offset += len;
                self.available_frs -= div_ceil(len * 8, OUT_BITS_FR);
            }
        }

        Ok(bytes_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use bitvec::{order::Lsb0 as LittleEndian, vec::BitVec};
    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use rand::random;

    use crate::bytes_into_fr;

    const DATA_BITS: u64 = 254;
    const TARGET_BITS: u64 = 256;

    #[test]
    fn test_simple_short() {
        // Source is shorter than 1 padding cycle.
        let data = vec![3u8; 30];
        let mut reader = Fr32Reader::new(Cursor::new(&data));
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
        let mut reader = Fr32Reader::new(Cursor::new(&data));
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
        let mut reader = Fr32Reader::new(Cursor::new(&data));
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
        let random_bytes: Vec<u8> = (0..127).map(|_| random::<u8>()).collect();

        // read 127 bytes from a non-chained source
        let output_x = {
            let input_x = Cursor::new(random_bytes.clone());

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
                    Cursor::new(random_bytes.iter().take(n).cloned().collect::<Vec<u8>>()).chain(
                        Cursor::new(random_bytes.iter().skip(n).cloned().collect::<Vec<u8>>()),
                    );

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
        let mut reader = Fr32Reader::new(Cursor::new(&data));
        reader.read_to_end(&mut buf).expect("in-memory read failed");

        assert_eq!(buf.clone().into_boxed_slice(), bit_vec_padding(data));
        validate_fr32(&buf);
    }

    #[test]
    #[ignore]
    fn test_long() {
        use rand::{thread_rng, RngCore};

        let mut rng = thread_rng();
        for i in 1..100 {
            for j in 1..50 {
                let mut data = vec![0u8; i * j];
                rng.fill_bytes(&mut data);

                let mut buf = Vec::new();
                let mut reader = Fr32Reader::new(Cursor::new(&data));
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
            let _ = bytes_into_fr(chunk).unwrap_or_else(|_| {
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
        let mut reader = Fr32Reader::new(Cursor::new(&source));
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
}
