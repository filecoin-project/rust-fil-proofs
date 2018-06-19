use fr32::Fr32Ary;
use std::cmp;
use std::fmt::Debug;
use std::io::{Read, Result, Write};

pub struct Fr32Writer<W> {
    inner: W,
    prefix: u8,
    prefix_size: usize,
    bits_needed: usize,
}

pub struct Fr32Reader<R> {
    _inner: R,
}

pub const FR_INPUT_BYTE_LIMIT: usize = 254;

impl<W: Write> Write for Fr32Writer<W> {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        let bytes_remaining = buf.len();
        let mut bytes_written = 0;

        while bytes_written < bytes_remaining {
            let (remainder, remainder_size, bytes_consumed, bytes_to_write) =
                self.process_bytes(&buf);

            bytes_written += self.ensure_write(&bytes_to_write)?;

            self.prefix = remainder;
            self.prefix_size = remainder_size;

            let residual_bytes_size = buf.len() - bytes_consumed;
            let residual_bytes = &buf[(buf.len() - residual_bytes_size)..buf.len()];
            buf = residual_bytes;
        }
        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Fr32Writer<W> {
    pub fn new(inner: W) -> Fr32Writer<W> {
        Fr32Writer {
            inner: inner,
            prefix: 0,
            prefix_size: 0,
            bits_needed: FR_INPUT_BYTE_LIMIT,
        }
    }
    // Tries to process bytes.
    // Returns result of (remainder, remainder size, bytes_consumed, byte output). Remainder size is in bits.
    // NOTE: if bytes are too short, this will panic. Should we return result/error instead?
    pub fn process_bytes(&mut self, bytes: &[u8]) -> (u8, usize, usize, Fr32Ary) {
        let bits_needed = self.bits_needed;
        let full_bytes_needed = bits_needed / 8;

        // The non-byte-aligned tail bits are the suffix and will become the final byte of output.
        let suffix_size = bits_needed % 8;

        // Anything left in the byte containing the suffix will become the remainder.
        let remainder_size = 8 - suffix_size;

        // Consume as many bytes as needed, unless there aren't enough.
        let bytes_to_consume = cmp::min(full_bytes_needed, bytes.len());

        // Grab all the full bytes (excluding suffix) we intend to consume.
        let full_bytes = &bytes[0..bytes_to_consume];

        let mut final_byte = 0;
        let mut bytes_consumed = bytes_to_consume;

        if bytes_to_consume <= bytes.len() {
            if remainder_size != 0 {
                if (bytes_to_consume + 1) > bytes.len() {
                    // Too few bytes were sent.
                    unimplemented!();
                }
                // This iteration's remainder will be included in next iteration's output.
                self.bits_needed = FR_INPUT_BYTE_LIMIT - remainder_size;

                // The last byte we consume is special.
                final_byte = bytes[bytes_to_consume];

                // Increment the count of consumed bytes, since we just consumed another.
                bytes_consumed += 1;
            }
        } else {
            // Too few bytes were sent. We should arrange for this to be unreachable.
            unimplemented!();
        }
        // The suffix is the last part of this iteration's output.
        // The remainder will be the first part of next iteration's output.
        let (suffix, remainder) = split_byte(final_byte, suffix_size);
        let out_bytes = assemble_bytes(self.prefix, self.prefix_size, full_bytes, suffix);

        (remainder, remainder_size, bytes_consumed, out_bytes)
    }

    fn finish(&mut self) -> Result<usize> {
        if self.prefix_size > 0 {
            assert!(self.prefix_size <= 8);
            let b = self.prefix.clone();
            self.ensure_write(&[b])?;
            self.flush()?;
            self.prefix_size = 0;
            self.prefix = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn ensure_write(&mut self, mut buffer: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;

        while buffer.len() > 0 {
            let n = self.inner.write(buffer)?;

            buffer = &buffer[n..buffer.len()];
            bytes_written += n;
        }
        Ok(bytes_written)
    }
}

// Splits byte into two parts at position, pos.
// The more significant part is right-shifted by pos bits, and both parts are returned,
// least-significant first.
fn split_byte(byte: u8, pos: usize) -> (u8, u8) {
    let b = byte >> pos;
    let mask_size = 8 - pos;
    let mask = (0xff >> mask_size) << mask_size;
    let a = (byte & mask) >> mask_size;
    (a, b)
}

// Prepend prefix to bytes, shifting all bytes left by prefix_size.
fn assemble_bytes(mut prefix: u8, prefix_size: usize, bytes: &[u8], suffix: u8) -> Fr32Ary {
    assert!(bytes.len() <= 31);
    let mut out = [0u8; 32];
    out[0] = prefix;

    let left_shift = prefix_size;
    let right_shift = 8 - prefix_size;
    for (i, b) in bytes.iter().enumerate() {
        if prefix_size == 0 {
            out[i] |= b;
        } else {
            let shifted = b << left_shift; // This may overflow 8 bits, truncating the most significant bits.
            out[i] = prefix | shifted;
            prefix = b >> right_shift;
        }
    }
    out[31] = prefix | suffix << left_shift;
    out
}

impl<R: Read> Fr32Reader<R> {
    pub fn new(inner: R) -> Fr32Reader<R> {
        Fr32Reader { _inner: inner }
    }
}

impl<R: Read + Debug> Read for Fr32Reader<R> {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write_test(bytes: &[u8]) -> (usize, Vec<u8>) {
        use std::io::{Seek, SeekFrom};
        use tempfile;

        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let mut tmp2 = tmpfile.reopen().unwrap();

        let mut writer = Fr32Writer::new(tmpfile);
        let mut write_count = writer.write(&bytes).unwrap();
        write_count += writer.finish().unwrap();

        // Seek to start
        tmp2.seek(SeekFrom::Start(0)).unwrap();
        // Read
        let mut buffer = Vec::new();
        tmp2.read_to_end(&mut buffer).unwrap();

        (write_count, buffer)
    }

    #[test]
    fn test_write() {
        let source = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff,
        ];

        let (write_count, buf) = write_test(&source);
        assert_eq!(write_count, 65);
        assert_eq!(buf.len(), 65);

        for i in 0..31 {
            assert_eq!(buf[i], i as u8 + 1);
        }
        assert_eq!(buf[31], 63); // Six least significant bits of 0xff
        assert_eq!(buf[32], (1 << 2) | 0b11); // 7
        for i in 33..63 {
            assert_eq!(buf[i], (i as u8 - 31) << 2);
        }
        assert_eq!(buf[63], (0x0f << 2)); // 4-bits of ones, half of 0xff, shifted by two, followed by two bits of 0-padding.
        assert_eq!(buf[64], 0x0f); // The last half of 0xff, unshifted, followed by four extra 0 bits.
    }
}
