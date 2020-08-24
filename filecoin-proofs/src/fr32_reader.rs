use std::io;

const DATA_BITS: u64 = 254;
const TARGET_BITS: u64 = 256;

#[derive(Debug)]
pub struct Fr32Reader<R> {
    /// The source being padded.
    source: R,
    /// How much of the target already was `read` from, in bits.
    target_offset: u64,
    /// Currently read byte.
    buffer: Buffer,
    /// Are we done reading?
    done: bool,
}

impl<R: io::Read> Fr32Reader<R> {
    pub fn new(source: R) -> Self {
        Fr32Reader {
            source,
            target_offset: 0,
            buffer: Default::default(),
            done: false,
        }
    }

    fn read_u8_no_pad(&mut self, target: &mut [u8]) -> io::Result<usize> {
        target[0] = self.buffer.read_u8();
        self.target_offset += 8;

        Ok(1)
    }

    fn read_u16_no_pad(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.buffer.read_u16_into(&mut target[..2]);
        self.target_offset += 16;

        Ok(2)
    }

    fn read_u32_no_pad(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.buffer.read_u32_into(&mut target[..4]);
        self.target_offset += 32;

        Ok(4)
    }

    fn read_u64_no_pad(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.buffer.read_u64_into(&mut target[..8]);
        self.target_offset += 64;

        Ok(8)
    }

    /// Read up to 8 bytes into the targets first element.
    /// Assumes that target is not empty.
    fn read_bytes(&mut self, target: &mut [u8]) -> io::Result<usize> {
        let bit_pos = self.target_offset % TARGET_BITS;
        let bits_to_padding = if bit_pos < DATA_BITS {
            DATA_BITS as usize - bit_pos as usize
        } else {
            0
        };

        if bits_to_padding >= 8 {
            self.fill_buffer()?;
        }

        let available = self.buffer.available();
        if available > 0 {
            let target_len = target.len();
            // Try to avoid padding, and copy as much as possible over at once.

            if bits_to_padding >= 64 && available >= 64 && target_len >= 8 {
                return self.read_u64_no_pad(target);
            }

            if bits_to_padding >= 32 && available >= 32 && target_len >= 4 {
                return self.read_u32_no_pad(target);
            }

            if bits_to_padding >= 16 && available >= 16 && target_len >= 2 {
                return self.read_u16_no_pad(target);
            }

            if bits_to_padding >= 8 && available >= 8 && target_len >= 1 {
                return self.read_u8_no_pad(target);
            }
        }

        self.read_u8_padded(target, bits_to_padding, available)
    }

    fn read_u8_padded(
        &mut self,
        target: &mut [u8],
        bits_to_padding: usize,
        available: u64,
    ) -> io::Result<usize> {
        target[0] = 0;

        if available >= 6 {
            match bits_to_padding {
                6 => {
                    target[0] = self.buffer.read_u8_range(6);
                    self.target_offset += 8;
                    return Ok(1);
                }
                5 => {
                    target[0] = self.buffer.read_u8_range(5);
                    if self.buffer.read_bit() {
                        set_bit(&mut target[0], 7);
                    }
                    self.target_offset += 8;
                    return Ok(1);
                }
                _ => {}
            }
        }

        for i in 0..8 {
            if self.target_offset % TARGET_BITS < DATA_BITS {
                if !self.fill_buffer()? {
                    if i > 0 {
                        return Ok(1);
                    } else {
                        return Ok(0);
                    }
                }

                if self.buffer.read_bit() {
                    set_bit(&mut target[0], i);
                }
            };

            self.target_offset += 1;
        }

        Ok(1)
    }

    /// Fill the inner buffer, only if necessary. Returns `true` if more data is available.
    fn fill_buffer(&mut self) -> io::Result<bool> {
        if self.buffer.available() > 0 {
            // Nothing to do, already some data available.
            return Ok(true);
        }

        let read = self.source.read(&mut self.buffer[..])?;
        self.buffer.reset_available(read as u64 * 8);

        Ok(read > 0)
    }
}

impl<R: io::Read> io::Read for Fr32Reader<R> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if self.done || target.is_empty() {
            return Ok(0);
        }

        let mut read = 0;
        while read < target.len() {
            let current_read = self.read_bytes(&mut target[read..])?;
            read += current_read;

            if current_read == 0 {
                self.done = true;
                break;
            }
        }

        Ok(read)
    }
}

fn set_bit(x: &mut u8, bit: usize) {
    *x |= 1 << bit
}

use std::ops::{Deref, DerefMut};

#[derive(Debug, Default, Clone, Copy)]
struct Buffer {
    data: u64,
    /// Bits already consumed.
    pos: u64,
    /// Bits available.
    avail: u64,
}

impl Deref for Buffer {
    type Target = [u8; 8];

    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.data as *const u64 as *const [u8; 8]) }
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(&mut self.data as *mut u64 as *mut [u8; 8]) }
    }
}

impl Buffer {
    /// How many bits are available to read.
    #[inline]
    pub fn available(&self) -> u64 {
        self.avail - self.pos
    }

    pub fn reset_available(&mut self, bits: u64) {
        self.pos = 0;
        self.avail = bits;
    }

    /// Read a single bit at the current position.
    pub fn read_bit(&mut self) -> bool {
        let res = self.data & (1 << self.pos) != 0;
        debug_assert!(self.available() >= 1);
        self.pos += 1;
        res
    }

    #[cfg(target_endian = "little")]
    pub fn read_u8_range(&mut self, len: u64) -> u8 {
        use bitintr::Bextr;
        debug_assert!(self.available() >= len);
        let res = self.data.bextr(self.pos, len) as u8;
        self.pos += len;
        res
    }

    #[cfg(target_endian = "little")]
    pub fn read_u8(&mut self) -> u8 {
        use bitintr::Bextr;
        debug_assert!(self.available() >= 8);
        let res = self.data.bextr(self.pos, 8) as u8;
        self.pos += 8;
        res
    }

    #[cfg(target_endian = "little")]
    pub fn read_u16(&mut self) -> u16 {
        debug_assert!(self.available() >= 16);

        use bitintr::Bextr;
        let res = self.data.bextr(self.pos, 16) as u16;
        self.pos += 16;
        res
    }

    #[cfg(target_endian = "little")]
    pub fn read_u16_into(&mut self, target: &mut [u8]) {
        assert!(target.len() >= 2);

        let value = self.read_u16().to_le_bytes();
        target[0] = value[0];
        target[1] = value[1];
    }

    #[cfg(target_endian = "little")]
    pub fn read_u32(&mut self) -> u32 {
        debug_assert!(self.available() >= 32);

        use bitintr::Bextr;
        let res = self.data.bextr(self.pos, 32) as u32;
        self.pos += 32;
        res
    }

    #[cfg(target_endian = "little")]
    pub fn read_u32_into(&mut self, target: &mut [u8]) {
        assert!(target.len() >= 4);
        let value = self.read_u32().to_le_bytes();
        target[0] = value[0];
        target[1] = value[1];
        target[2] = value[2];
        target[3] = value[3];
    }

    pub fn read_u64(&mut self) -> u64 {
        debug_assert!(self.available() >= 64);

        self.pos += 64;
        self.data
    }

    #[cfg(target_endian = "little")]
    pub fn read_u64_into(&mut self, target: &mut [u8]) {
        assert!(target.len() >= 8);
        let value = self.read_u64().to_le_bytes();
        target[0] = value[0];
        target[1] = value[1];
        target[2] = value[2];
        target[3] = value[3];
        target[4] = value[4];
        target[5] = value[5];
        target[6] = value[6];
        target[7] = value[7];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::io::Read;

    #[test]
    fn test_buffer_read_bit() {
        let mut buffer = Buffer::default();
        let val = 12345u64.to_le_bytes();
        buffer.copy_from_slice(&val[..]);
        buffer.reset_available(64);

        for i in 0..8 {
            assert_eq!(buffer.read_bit(), 0 != val[0] & (1 << i));
        }
    }

    #[test]
    fn test_buffer_read_u8() {
        let mut buffer = Buffer::default();
        let val = 12345u64.to_le_bytes();
        buffer.copy_from_slice(&val[..]);
        buffer.reset_available(64);

        for (i, &byte) in val.iter().enumerate().take(8) {
            let read = buffer.read_u8();
            assert_eq!(read, byte, "failed to read byte {}", i);
        }
    }

    #[test]
    fn test_buffer_read_u16() {
        let mut buffer = Buffer::default();
        let val = 12345u64.to_le_bytes();
        buffer.copy_from_slice(&val[..]);
        buffer.reset_available(64);

        for val in val.chunks(2) {
            let read = buffer.read_u16();
            assert_eq!(read, u16::from_le_bytes([val[0], val[1]]));
        }
    }

    #[test]
    fn test_buffer_read_u32() {
        let mut buffer = Buffer::default();
        let val = 12345u64.to_le_bytes();
        buffer.copy_from_slice(&val[..]);
        buffer.reset_available(64);

        for val in val.chunks(4) {
            let read = buffer.read_u32();
            assert_eq!(read, u32::from_le_bytes([val[0], val[1], val[2], val[3]]));
        }
    }

    #[test]
    fn test_buffer_read_u64() {
        let mut buffer = Buffer::default();
        let val = 12345u64;
        buffer.copy_from_slice(&val.to_le_bytes()[..]);
        buffer.reset_available(64);

        let read = buffer.read_u64();
        assert_eq!(read, val);
    }

    #[test]
    fn test_simple_short() {
        // Source is shorter than 1 padding cycle.
        let data = vec![3u8; 30];
        let mut reader = Fr32Reader::new(io::Cursor::new(&data));
        let mut padded = Vec::new();
        reader
            .read_to_end(&mut padded)
            .expect("in-memory read failed");
        assert_eq!(&data[..], &padded[..]);

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
        assert_eq!(padded.len(), 33);

        assert_eq!(padded.into_boxed_slice(), bit_vec_padding(data));
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
            for j in 0..50 {
                let mut data = vec![0u8; i * j];
                rng.fill_bytes(&mut data);

                let mut buf = Vec::new();
                let mut reader = Fr32Reader::new(io::Cursor::new(&data));
                reader.read_to_end(&mut buf).expect("in-memory read failed");

                assert_eq!(buf.clone().into_boxed_slice(), bit_vec_padding(data));
            }
        }
    }

    // Simple (and slow) padder implementation using `BitVec`.
    // It is technically not quite right to use `BitVec` to test this, since at
    // the moment that function still uses
    // it for some corner cases, but since largely this implementation
    // has been replaced it seems reasonable.
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
}
