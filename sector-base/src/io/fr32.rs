use std::cmp::min;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;

use bitvec::{self, BitVec};
use itertools::Itertools;

pub type Fr32BitVec = BitVec<bitvec::LittleEndian, u8>;

#[derive(Debug)]
// PaddingMap represents a mapping between data and its padded equivalent.
// Padding is at the bit-level.
pub struct PaddingMap {
    // The number of bits in the unpadded data.
    data_chunk_bits: usize,
    // The number of bits in the padded data. This must be greater than data_chunk_bits.
    // The difference between padded_chunk_bits and data_chunk_bits is the number of zero/false bits
    // that should be inserted as padding.
    padded_chunk_bits: usize,
}

pub const FR_UNPADDED_BITS: usize = 254;
pub const FR_PADDED_BITS: usize = 256;

// This is the padding map corresponding to Fr32.
// Most of the code in this module is general-purpose and could move elsewhere.
// The application-specific wrappers which implicitly use Fr32 embed the FR32_PADDING_MAP.
pub const FR32_PADDING_MAP: PaddingMap = PaddingMap {
    data_chunk_bits: FR_UNPADDED_BITS,
    padded_chunk_bits: FR_PADDED_BITS,
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// Convenience interface for API functions – all bundling FR32_PADDING_MAP
// parameter/return types are tuned for current caller convenience.

pub fn target_unpadded_bytes<W: ?Sized>(target: &mut W) -> io::Result<u64>
where
    W: Seek,
{
    let (_, unpadded, _) = FR32_PADDING_MAP.target_offsets(target)?;

    Ok(unpadded)
}

// Leave the actual truncation to caller, since we can't do it generically.
// Return the length to which target should be truncated.
// We might should also handle zero-padding what will become the final byte of target.
// Technically, this should be okay though because that byte will always be overwritten later.
// If we decide this is unnecessary, then we don't need to pass target at all.
pub fn almost_truncate_to_unpadded_bytes<W: ?Sized>(
    _target: &mut W,
    length: u64,
) -> io::Result<usize>
where
    W: Read + Write + Seek,
{
    let padded = FR32_PADDING_MAP.padded_bit_bytes_from_bytes(length as usize);
    let real_length = padded.bytes_needed();
    let _final_bit_count = padded.bits;
    // TODO (maybe): Rewind stream and use final_bit_count to zero-pad last byte of data (post-truncation).
    Ok(real_length)
}

pub fn unpadded_bytes(padded_bytes: u64) -> u64 {
    FR32_PADDING_MAP.contract_bytes(padded_bytes as usize) as u64
}

pub fn padded_bytes(unpadded_bytes: usize) -> usize {
    FR32_PADDING_MAP.expand_bytes(unpadded_bytes)
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Invariant: it is an error for bit_part to be > 7.
#[derive(Debug)]
pub struct BitByte {
    bytes: usize,
    bits: usize,
}

impl BitByte {
    // Create a BitByte from number of bits. Guaranteed to return a well-formed value (bits < 8)
    pub fn from_bits(bits: usize) -> BitByte {
        BitByte {
            bytes: bits / 8,
            bits: bits % 8,
        }
    }

    pub fn from_bytes(bytes: usize) -> BitByte {
        Self::from_bits(bytes * 8)
    }

    // How many bits in the BitByte (inverse of from_bits).
    pub fn total_bits(&self) -> usize {
        self.bytes * 8 + self.bits
    }

    // True if the BitByte has no bits component.
    pub fn is_byte_aligned(&self) -> bool {
        self.bits == 0
    }

    // How many distinct bytes are needed to represent data of this size?
    pub fn bytes_needed(&self) -> usize {
        self.bytes
            + if self.bits == 0 {
                0
            } else {
                (self.bits + 8) / 8
            }
    }
}

impl PaddingMap {
    pub fn new(data_bits: usize, representation_bits: usize) -> PaddingMap {
        assert!(data_bits <= representation_bits);
        PaddingMap {
            data_chunk_bits: data_bits,
            padded_chunk_bits: representation_bits,
        }
    }

    pub fn pad(&self, bits_out: &mut Fr32BitVec) {
        for _ in 0..self.padding_bits() {
            bits_out.push(false)
        }
    }

    pub fn padding_bits(&self) -> usize {
        self.padded_chunk_bits - self.data_chunk_bits
    }

    pub fn expand_bits(&self, size: usize) -> usize {
        transform_bit_pos(size, self.data_chunk_bits, self.padded_chunk_bits)
    }

    pub fn contract_bits(&self, size: usize) -> usize {
        transform_bit_pos(size, self.padded_chunk_bits, self.data_chunk_bits)
    }

    // Calculate padded byte size from unpadded byte size, rounding up.
    pub fn expand_bytes(&self, bytes: usize) -> usize {
        transform_byte_pos(bytes, self.data_chunk_bits, self.padded_chunk_bits)
    }

    // Calculate unpadded byte size from padded byte size, rounding down.
    pub fn contract_bytes(&self, bytes: usize) -> usize {
        transform_byte_pos(bytes, self.padded_chunk_bits, self.data_chunk_bits)
    }

    pub fn padded_bit_bytes_from_bits(&self, bits: usize) -> BitByte {
        let expanded = self.expand_bits(bits);
        BitByte::from_bits(expanded)
    }

    // Calculate and return bits and bytes to which a given number of bytes expands.
    pub fn padded_bit_bytes_from_bytes(&self, bytes: usize) -> BitByte {
        self.padded_bit_bytes_from_bits(bytes * 8)
    }

    pub fn unpadded_bit_bytes_from_bits(&self, bits: usize) -> BitByte {
        let contracted = self.contract_bits(bits);
        BitByte::from_bits(contracted)
    }

    pub fn unpadded_bit_bytes_from_bytes(&self, bytes: usize) -> BitByte {
        self.unpadded_bit_bytes_from_bits(bytes * 8)
    }

    // Returns a BitByte representing the distance between current position and next Fr boundary.
    // Padding is directly before the boundary.
    pub fn next_fr_end(&self, current: &BitByte) -> BitByte {
        let current_bits = current.total_bits();

        let (previous, remainder) = div_rem(current_bits, self.padded_chunk_bits);

        let next_bit_boundary = if remainder == 0 {
            current_bits + self.padded_chunk_bits
        } else {
            (previous * self.padded_chunk_bits) + self.padded_chunk_bits
        };

        BitByte::from_bits(next_bit_boundary)
    }

    // For a seekable target, return
    // - the actual padded size in bytes
    // - the unpadded size in bytes which generated the padded size
    // - a BitByte representing the number of bits and bytes of actual data contained
    pub fn target_offsets<W: ?Sized>(&self, target: &mut W) -> io::Result<(u64, u64, BitByte)>
    where
        W: Seek,
    {
        // The current position in target is the number of PADDED bytes already written.
        let padded_bytes = target.seek(SeekFrom::End(0))?;

        let (unpadded_bytes, padded_bit_bytes) = self.calculate_offsets(padded_bytes)?;

        Ok((padded_bytes, unpadded_bytes, padded_bit_bytes))
    }

    // For a given number of padded_bytes, calculate and return
    // - the unpadded size in bytes which generates the padded size
    // - a BitByte representing the number of bits and bytes of actual data contained when so generated
    pub fn calculate_offsets(&self, padded_bytes: u64) -> io::Result<(u64, BitByte)> {
        // Convert to unpadded equivalent, rounding down.
        let unpadded_bytes = self.contract_bytes(padded_bytes as usize);

        // Convert back to padded BUT NOW WITH BIT-LEVEL PRECISION.
        // The result contains information about how many partial bits (if any) were in the last padded byte.
        let padded_bit_bytes = self.padded_bit_bytes_from_bits(unpadded_bytes * 8);

        Ok((unpadded_bytes as u64, padded_bit_bytes))
    }
}

#[inline]
fn div_rem(a: usize, b: usize) -> (usize, usize) {
    let div = a / b;
    let rem = a % b;
    (div, rem)
}

fn transform_bit_pos(p: usize, from_size: usize, to_size: usize) -> usize {
    let (div, rem) = div_rem(p, from_size);

    (div * to_size) + rem
}

fn transform_byte_pos(p: usize, from_bit_size: usize, to_bit_size: usize) -> usize {
    let bit_pos = p * 8;
    let transformed_bit_pos = transform_bit_pos(bit_pos, from_bit_size, to_bit_size);
    let transformed_byte_pos1 = transformed_bit_pos as f64 / 8.;

    (if from_bit_size < to_bit_size {
        transformed_byte_pos1.ceil()
    } else {
        transformed_byte_pos1.floor()
    }) as usize
}

pub fn write_padded<W: ?Sized>(source: &[u8], target: &mut W) -> io::Result<usize>
where
    W: Read + Write + Seek,
{
    // In order to optimize alignment in the common case of writing from an aligned start,
    // we should make the chunk a multiple of 128.
    // n was hand-tuned to do reasonably well in the benchmarks.
    let n = 1000;
    let chunk_size = 128 * n;

    let mut written = 0;

    for chunk in source.chunks(chunk_size) {
        written += write_padded_aux(&FR32_PADDING_MAP, chunk, target)?;
    }

    Ok(written)
}

fn write_padded_aux<W: ?Sized>(
    padding_map: &PaddingMap,
    source: &[u8],
    target: &mut W,
) -> io::Result<usize>
where
    W: Read + Write + Seek,
{
    let (padded_offset_bytes, _, offset) = padding_map.target_offsets(target)?;

    // The next boundary marks the start of the following Fr.
    let next_boundary = padding_map.next_fr_end(&offset);

    // How many whole bytes lie between the current position and the new Fr?
    let bytes_to_next_boundary = next_boundary.bytes - offset.bytes;

    if offset.is_byte_aligned() {
        // If current offset is byte-aligned, then write_padded_aligned's invariant is satisfied,
        // and we can call it directly.
        write_padded_aligned(
            padding_map,
            source,
            target,
            bytes_to_next_boundary * 8,
            None,
        )
    } else {
        // Otherwise, we need to align by filling in the previous, incomplete byte.
        // Prefix will hold that single byte.
        let prefix_bytes = &mut [0u8; 1];

        // Seek backward far enough to read just the prefix.
        target.seek(SeekFrom::Start(padded_offset_bytes - 1))?;

        // And read it in.
        target.read_exact(prefix_bytes)?;

        // NOTE: seek position is now back to where we started.

        // How many significant bits did the prefix contain?
        let prefix_bit_count = offset.bits;

        // Rewind by 1 again because we need to overwrite the previous, incomplete byte.
        // Because we've now rewound to before the prefix, target is indeed byte-aligned.
        // (Only the last byte was incomplete.)
        target.seek(SeekFrom::Start(padded_offset_bytes - 1))?;

        // Package up the prefix into a BitVec.
        let mut prefix_bitvec = Fr32BitVec::from(&prefix_bytes[..]);

        // But only take the number of bits that are actually part of the prefix!
        prefix_bitvec.truncate(prefix_bit_count);

        // Now we are aligned and can write the rest. We have to pass the prefix to
        // write_padded_aligned because we don't yet know what bits should follow the prefix.
        write_padded_aligned(
            padding_map,
            source,
            target,
            (bytes_to_next_boundary * 8) - prefix_bit_count,
            Some(prefix_bitvec),
        )
    }
}

// Invariant: the input so far MUST be byte-aligned.
// Any prefix_bits passed will be inserted before the bits pulled from source.
fn write_padded_aligned<W: ?Sized>(
    padding_map: &PaddingMap,
    source: &[u8],
    target: &mut W,
    next_boundary_bits: usize,
    prefix_bits: Option<Fr32BitVec>,
) -> io::Result<usize>
where
    W: Write,
{
    // bits_out is a sink for bits, to be written at the end.
    // If we received prefix_bits, put them in the sink first.
    let mut bits_out = match prefix_bits {
        None => Fr32BitVec::new(),
        Some(bv) => bv,
    };

    // We want to read up to the next Fr boundary, but we don't want to read the padding.
    let next_boundary_bits = next_boundary_bits - padding_map.padding_bits();

    // How many new bits do we need to write?
    let source_bits = source.len() * 8;

    // How many bits should we write in the first chunk - and should that chunk be padded?
    let (first_bits, pad_first_chunk) = if next_boundary_bits < source_bits {
        // If we have enough bits (more than to the next boundary), we will write all of them first,
        // and add padding.
        (next_boundary_bits, true)
    } else {
        // Otherwise, we will write everything we have – but we won't pad it.
        (source_bits, false)
    };

    {
        // Write the first chunk, padding if necessary.
        let first_unpadded_chunk = Fr32BitVec::from(source).into_iter().take(first_bits);

        bits_out.extend(first_unpadded_chunk);

        // pad
        if pad_first_chunk {
            padding_map.pad(&mut bits_out);
        }
    }

    {
        // Write all following chunks, padding if necessary.
        let remaining_unpadded_chunks = Fr32BitVec::from(source)
            .into_iter()
            .skip(first_bits)
            .chunks(padding_map.data_chunk_bits);

        for chunk in remaining_unpadded_chunks.into_iter() {
            let mut bits = Fr32BitVec::from_iter(chunk);

            if bits.len() >= padding_map.data_chunk_bits
                && (bits.len() < padding_map.padded_chunk_bits)
            {
                padding_map.pad(&mut bits);
            }

            bits_out.extend(bits);
        }
    }

    let out = &bits_out.into_boxed_slice();
    target.write_all(&out)?;

    // Always return the expected number of bytes, since this function will fail if write_all does.
    Ok(source.len())
}

// offset and num_bytes are based on the unpadded data, so
// if [0, 1, ..., 255] was the original unpadded data, offset 3 and len 4 would return
// [3, 4, 5, 6].
pub fn write_unpadded<W: ?Sized>(
    source: &[u8],
    target: &mut W,
    offset: usize,
    len: usize,
) -> io::Result<usize>
where
    W: Write,
{
    // In order to optimize alignment in the common case of writing from an aligned start,
    // we should make the chunk a multiple of 128.
    // n was hand-tuned to do reasonably well in the benchmarks.
    let n = 1000;
    let chunk_size = 128 * n;

    let mut written = 0;

    let mut offset = offset;
    let mut len = len;

    for chunk in source.chunks(chunk_size) {
        let this_len = min(len, chunk.len());

        written += write_unpadded_aux(&FR32_PADDING_MAP, source, target, offset, this_len)?;
        offset += this_len;
        len -= this_len;
    }

    Ok(written)
}

pub fn write_unpadded_aux<W: ?Sized>(
    padding_map: &PaddingMap,
    source: &[u8],
    target: &mut W,
    offset_bytes: usize,
    len: usize,
) -> io::Result<usize>
where
    W: Write,
{
    let mut offset = padding_map.padded_bit_bytes_from_bytes(offset_bytes);

    let bits_to_write = len * 8;

    let mut bits_out = Fr32BitVec::new();

    while bits_out.len() < bits_to_write {
        let start = offset.bytes;
        let bits_to_skip = offset.bits;
        let offset_total_bits = offset.total_bits();
        let next_boundary = padding_map.next_fr_end(&offset);
        let end = next_boundary.bytes;

        let current_fr_bits_end = next_boundary.total_bits() - padding_map.padding_bits();
        let bits_to_next_boundary = current_fr_bits_end - offset_total_bits;

        let raw_end = min(end, source.len());
        if start > source.len() {
            break;
        }
        let raw_bits = Fr32BitVec::from(&source[start..raw_end]);
        let skipped = raw_bits.into_iter().skip(bits_to_skip);
        let restricted = skipped.take(bits_to_next_boundary);

        let bits_left_to_write = bits_to_write - bits_out.len();
        let bits_needed = ((end - start) * 8) - bits_to_skip;
        let bits_to_take = min(bits_needed, bits_left_to_write);
        let taken = restricted.take(bits_to_take);

        bits_out.extend(taken);

        offset = BitByte {
            bytes: end,
            bits: 0,
        };
    }

    // TODO: Don't write the whole output into a huge BitVec.
    // Instead, write it incrementally –
    // but ONLY when the bits waiting in bits_out are byte-aligned. i.e. a multiple of 8

    let boxed_slice = bits_out.into_boxed_slice();

    target.write_all(&boxed_slice)?;

    Ok(boxed_slice.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use std::io::Cursor;
    use storage_proofs::fr32::bytes_into_fr;

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

    #[test]
    fn test_write_padded() {
        let data = vec![255u8; 151];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let written = write_padded(&data, &mut cursor).unwrap();
        let padded = cursor.into_inner();
        assert_eq!(written, 151);
        assert_eq!(padded.len(), FR32_PADDING_MAP.expand_bytes(151));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
    }

    #[test]
    fn test_write_padded_multiple_aligned() {
        let data = vec![255u8; 256];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let mut written = write_padded(&data[0..128], &mut cursor).unwrap();
        written += write_padded(&data[128..], &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(written, 256);
        assert_eq!(padded.len(), FR32_PADDING_MAP.expand_bytes(256));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
    }

    #[test]
    fn test_write_padded_multiple_first_aligned() {
        let data = vec![255u8; 265];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let mut written = write_padded(&data[0..128], &mut cursor).unwrap();
        written += write_padded(&data[128..], &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(written, 265);
        assert_eq!(padded.len(), FR32_PADDING_MAP.expand_bytes(265));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
    }

    fn validate_fr32(bytes: &[u8]) {
        for (i, chunk) in bytes.chunks(32).enumerate() {
            let _ = bytes_into_fr::<Bls12>(chunk).expect(&format!(
                "{}th chunk cannot be converted to valid Fr: {:?}",
                i + 1,
                chunk
            ));
        }
    }
    #[test]
    fn test_write_padded_multiple_unaligned() {
        // Use 127 for this test because it unpads to 128 – a multiple of 32.
        // Otherwise the last chunk will be too short and cannot be converted to Fr.
        for i in 0..127 {
            let data = vec![255u8; 127];
            let buf = Vec::new();
            let mut cursor = Cursor::new(buf);
            let mut written = write_padded(&data[0..i], &mut cursor).unwrap();
            written += write_padded(&data[i..], &mut cursor).unwrap();
            let padded = cursor.into_inner();
            validate_fr32(&padded);
            assert_eq!(written, 127);
            assert_eq!(padded.len(), FR32_PADDING_MAP.expand_bytes(127));
            assert_eq!(&padded[0..31], &data[0..31]);
            assert_eq!(padded[31], 0b0011_1111);
            assert_eq!(padded[32], 0b1111_1111);
            assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
            assert_eq!(padded[63], 0b0011_1111);
        }
    }

    #[test]
    fn test_write_padded_alt() {
        let mut source = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0xff, 9, 9,
        ];
        // FIXME: This doesn't exercise the ability to write a second time, which is the point of the extra_bytes in write_test.
        source.extend(vec![9, 0xff]);

        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        write_padded(&source, &mut cursor).unwrap();
        let buf = cursor.into_inner();

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

    #[test]
    fn test_read_write_padded() {
        let len = 1016; // Use a multiple of 254.
        let data = vec![255u8; len];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let padded_written = write_padded(&data, &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(padded_written, len);
        assert_eq!(padded.len(), FR32_PADDING_MAP.expand_bytes(len));

        let mut unpadded = Vec::new();
        let unpadded_written = write_unpadded(&padded, &mut unpadded, 0, len).unwrap();
        assert_eq!(unpadded_written, len);
        assert_eq!(data, unpadded);
    }

    #[test]
    fn test_read_write_padded_offset() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let len = 1016;
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        write_padded(&data, &mut cursor).unwrap();
        let padded = cursor.into_inner();

        {
            let mut unpadded = Vec::new();
            write_unpadded(&padded, &mut unpadded, 0, 1016).unwrap();
            let expected = &data[0..1016];

            assert_eq!(expected.len(), unpadded.len());
            assert_eq!(expected, &unpadded[..]);
        }

        {
            let mut unpadded = Vec::new();
            write_unpadded(&padded, &mut unpadded, 0, 44).unwrap();
            let expected = &data[0..44];

            assert_eq!(expected.len(), unpadded.len());
            assert_eq!(expected, &unpadded[..]);
        }
        for start in 0..1016 {
            let mut unpadded = Vec::new();

            let len = 35;
            let unpadded_bytes = write_unpadded(&padded, &mut unpadded, start, len).unwrap();
            let actual_len = min(data.len() - start, len);
            assert_eq!(unpadded_bytes, actual_len);

            let expected = &data[start..start + actual_len];
            assert_eq!(expected, &unpadded[..]);
        }
    }
}
