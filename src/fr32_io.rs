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
            let (remainder, remainder_size, bytes_consumed, bytes_to_write, more) =
                self.process_bytes(&buf);
            if more {
                // We read a complete chunk and should continue.
                bytes_written += self.ensure_write(&bytes_to_write)?;
            } else {
                // We read an incomplete chunk, so this is the last iteration.
                // We must have consumed all the bytes in buf.
                assert!(buf.len() == bytes_consumed);
                assert!(bytes_consumed < 32);

                // Write those bytes but no more (not a whole 32-byte chunk).
                let real_length = buf.len();
                assert!(real_length <= bytes_to_write.len());

                let truncated = &bytes_to_write[0..real_length];
                bytes_written += self.ensure_write(truncated)?;

                if self.prefix_size > 0 {
                    // Since this chunk was incomplete, what would have been the remainder was included as the last byte to write.
                    // We shouldn't write it now, though, because we may need to write more bytes later.
                    // However, we do need to save the prefix.
                    self.prefix = bytes_to_write[real_length];
                }

                break;
            }

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
    // Returns result of (remainder, remainder size, bytes_consumed, byte output, complete). Remainder size is in bits.
    // Complete is true iff we read a complete chunk of data.
    pub fn process_bytes(&mut self, bytes: &[u8]) -> (u8, usize, usize, Fr32Ary, bool) {
        let bits_needed = self.bits_needed;
        let full_bytes_needed = bits_needed / 8;

        // The non-byte-aligned tail bits are the suffix and will become the final byte of output.
        let suffix_size = bits_needed % 8;

        // Anything left in the byte containing the suffix will become the remainder.
        let mut remainder_size = 8 - suffix_size;

        // Consume as many bytes as needed, unless there aren't enough.
        let bytes_to_consume = cmp::min(full_bytes_needed, bytes.len());
        let mut final_byte = 0;
        let mut bytes_consumed = bytes_to_consume;
        let mut incomplete = false;

        if bytes_to_consume <= bytes.len() {
            if remainder_size != 0 {
                if (bytes_to_consume + 1) > bytes.len() {
                    // Too few bytes were sent.
                    incomplete = true;
                } else {
                    // This iteration's remainder will be included in next iteration's output.
                    self.bits_needed = FR_INPUT_BYTE_LIMIT - remainder_size;

                    // The last byte we consume is special.
                    final_byte = bytes[bytes_to_consume];

                    // Increment the count of consumed bytes, since we just consumed another.
                    bytes_consumed += 1;
                }
            }
        } else {
            // Too few bytes were sent.
            incomplete = true;
        }

        if incomplete {
            // Too few bytes were sent.

            // We will need the unsent bits next iteration.
            self.bits_needed = bits_needed - bytes.len();

            // We only consumed the bytes that were sent.
            bytes_consumed = bytes.len();

            // The current prefix and remainder have the same size; no padding is added in this iteration.
            remainder_size = self.prefix_size;
        }

        // Grab all the full bytes (excluding suffix) we intend to consume.
        let full_bytes = &bytes[0..bytes_to_consume];

        // The suffix is the last part of this iteration's output.
        // The remainder will be the first part of next iteration's output.
        let (suffix, remainder) = split_byte(final_byte, suffix_size);
        let out_bytes = assemble_bytes(self.prefix, self.prefix_size, full_bytes, suffix);
        (
            remainder,
            remainder_size,
            bytes_consumed,
            out_bytes,
            !incomplete,
        )
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
    if pos == 0 {
        return (0, byte);
    };
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
    out[bytes.len()] = prefix | suffix << left_shift;
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

    fn write_test(bytes: &[u8], extra_bytes: &[u8]) -> (usize, Vec<u8>) {
        let mut data = Vec::new();

        let write_count = {
            let mut writer = Fr32Writer::new(&mut data);
            let mut count = writer.write(&bytes).unwrap();
            // This tests to make sure state is correctly maintained so we can restart writing mid-32-byte chunk.
            count += writer.write(extra_bytes).unwrap();
            count += writer.finish().unwrap();
            count
        };

        (write_count, data)
    }

    #[test]
    fn test_write() {
        let source = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff, 9, 9,
        ];
        let extra = vec![9, 0xff];

        let (write_count, buf) = write_test(&source, &extra);
        assert_eq!(write_count, 69);
        assert_eq!(buf.len(), 69);

        for i in 0..31 {
            assert_eq!(buf[i], i as u8 + 1);
        }
        assert_eq!(buf[31], 63); // Six least significant bits of 0xff
        assert_eq!(buf[32], (1 << 2) | 0b11); // 7
        for i in 33..63 {
            assert_eq!(buf[i], (i as u8 - 31) << 2);
        }
        assert_eq!(buf[63], (0x0f << 2)); // 4-bits of ones, half of 0xff, shifted by two, followed by two bits of 0-padding.
        assert_eq!(buf[64], 0x0f | 9 << 4); // The last half of 0xff, 'followed' by 9.
        assert_eq!(buf[65], 9 << 4); // A shifted 9.
        assert_eq!(buf[66], 9 << 4); // Another.
        assert_eq!(buf[67], 0xf0); // The final 0xff is split into two bytes. Here is the first half.
        assert_eq!(buf[68], 0x0f); // And here is the second.
    }
}
