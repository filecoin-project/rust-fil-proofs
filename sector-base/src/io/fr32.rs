use std::cmp::min;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;

use bitvec::{self, BitVec};
use itertools::Itertools;

pub type Fr32BitVec = BitVec<bitvec::LittleEndian, u8>;

#[derive(Debug)]
//
// TODO: Use headings? e.g., "padding operation", "element configuration",
// "bit-alignment", etc. (the Rust core seems to do so)
// TODO: Maybe we should be using `///` or `/**` here,
// (https://doc.rust-lang.org/reference/comments.html).
//
// PaddingMap represents a mapping between data and its padded equivalent.
// The padding process takes a *byte-aligned stream* of unpadded *raw* data
// as input, applies padding at the bit-level according to `padded_chunk_bits`
// and returns an (also) byte-aligned stream of *padded* data as output. The
// (inverse) *unpadding* process maps that output back to the raw input
// that generated it.
//
// At the *byte-level*, the padded layout is:
//
//           (full)                   (full)                 (incomplete)
// ||  data_bits  pad_bits  ||  data_bits  pad_bits  ||  some_data  (no_padding)
//                          ^^                               ^^
//                   element boundary                (some_data < data_bits)
//
// TODO: Check that the names on the diagram match the ones on the structure.
// TODO: Maybe use the `FR32_PADDING_MAP` example.
//
// Each *element* is a byte-aligned stream comprised of a *full unit* of `data_bits`
// with `pad_bits` at the end, where `pad_bits` is less than a byte (we add the number
// of `pad_bits` necessary to reach the next byte-boundary from `data_bits`, this is
// a *sub-byte padding* scheme). After the last element boundary there may be an
// incomplete unit of data (`some_data`) with a length smaller than `data_bits`
// that hasn't been padded (yet), that is the only configuration possible:
//   1. Padding can only be applied to a full unit of `data_bits`.
//   2. A full data unit cannot exist without its corresponding padding.
//   3. A unit of padding is complete by definition: padding can only be
//      applied fully to each element.
//   4. If there is padding present then there has to be an already formed element there.
//
// When returning the byte-aligned output generated from the padded *bitstream*
// (since the padding is done at the bit-level) the conversion results in the
// last byte having (potentially) more bits than desired. At the *bit-level*
// the layout of the last byte can either be a complete element (bits of raw
// data followed by the corresponding padding bits) or an incomplete unit of
// data: some number of *valid* data (D) bits followed by any number of *extra*
// bits (X) necessary to complete the byte-aligned stream:
//
//  |   D   D   D   D   X   X   X   X   |
//          (data)         (extra)      ^ byte boundary (end of output)
//
// (This diagram is just for illustrative purposes, we actually return the output
//  in little-endian order, see `Fr32BitVec`).
//
// It's important to distinguish these extra bits (generated as a side
// effect of the conversion to a byte-aligned stream) from the padding bits
// themselves introduced in the padding process: even though both will be
// left with a zero value, these extra bits are a place-holder for the actual
// raw data bits needed to complete the current unit of data (and hence also
// the element, with the corresponding padding bits added after it). Since
// extra bits are only a product of an incomplete unit of data there can't
// be extra bits after padding bits.
//
// There's no metadata signaling the number of extra bits present in the
// last byte in any given padded layout, but it can be deduced knowing that
// only a *single* D/R configuration in the last byte maps to a byte-aligned
// raw data stream and a specified `padded_chunk_bits` of padding.
//
// Key terms and definitions:
// * Raw data: unpadded user-supplied data (we don't use the *unpadded* term
//   to avoid excessive *padding* suffixes in the code). Padding (data) bits.
// * Element: generated in the padding process to adjust the raw data to a size
//   of `padded_chunk_bits`: byte-aligned stream consisting of a full data unit
//   and padding bits.
// * Full unit of `data_chunk_bits` raw data bits, always followed by padding.
//   Incomplete unit, not followed by padding, doesn't form an element.
// * Byte-aligned stream: always input and output, either as raw data or padded
//   (using the term "byte-aligned" and not "byte stream" to stress the boundaries).
//   Bit streams: used internally when padding data.
// * Valid (data and padding) bits, only in the context of the last byte of
//   a byte-aligned stream generated from the padding process. extra bits:
//   what's left unused of the last byte (in a way the extra bits are the
//   padding at the byte-level, but don't use that term here to avoid confusions).
// * Sub-byte padding.
//
// TODO: Add "boundary limit"?
//
// TODO: We should keep a simple state while padding, maybe not here but in
// a new `Padder` structure which would know if we are in the data or pad
// areas (bit position), and how much bits until we reach a boundary.
pub struct PaddingMap {
    // The number of bits of raw data in an element.
    data_bits: usize,
    // Number of bits in an element: `data_bits` + `padding_bits()`. Its value
    // is fixed to the next byte-aligned size after `data_bits` (sub-byte padding).
    element_bits: usize,
}

pub const FR_UNPADDED_BITS: usize = 254;
pub const FR_PADDED_BITS: usize = 256;

// This is the padding map corresponding to Fr32.
// Most of the code in this module is general-purpose and could move elsewhere.
// The application-specific wrappers which implicitly use Fr32 embed the FR32_PADDING_MAP.
pub const FR32_PADDING_MAP: PaddingMap = PaddingMap {
    data_bits: FR_UNPADDED_BITS,
    element_bits: FR_PADDED_BITS,
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
    let padded = BitByte::from_bits(FR32_PADDING_MAP.transform_bit_pos((length * 8) as usize, true));
    let real_length = padded.bytes_needed();
    let _final_bit_count = padded.bits;
    // TODO (maybe): Rewind stream and use final_bit_count to zero-pad last byte of data (post-truncation).
    Ok(real_length)
}

pub fn unpadded_bytes(padded_bytes: u64) -> u64 {
    FR32_PADDING_MAP.transform_byte_pos(padded_bytes as usize, false) as u64
}

pub fn padded_bytes(unpadded_bytes: usize) -> usize {
    FR32_PADDING_MAP.transform_byte_pos(unpadded_bytes, true)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// BitByte represents a size expressed in bytes extended
// with bit precision, that is, not rounded.
// Invariant: it is an error for bits to be > 7.
// TODO: Evaluate dropping the entire structure altogether in favor of only
// handling bit lengths which might better represent the nature of the internal
// bit streams in the padding process. Provide the functions to covert to byte
// only when necessary.
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
    // TODO: Maybe closer to a `ceil` method?
    pub fn bytes_needed(&self) -> usize {
        self.bytes
            + if self.bits == 0 {
                0
            } else {
                (self.bits + 8) / 8
            // TODO: Since `bits` > 0 and < 7 (invariant) why not just
            // explicitly make this 1?
            }
    }
}

impl PaddingMap {
    pub fn new(data_bits: usize, element_bits: usize) -> PaddingMap {
        // Check that we add less than 1 byte of padding (sub-byte padding).
        assert!(element_bits - data_bits <= 7);
        // Check that the element is byte aligned.
        assert_eq!(element_bits % 8, 0);

        PaddingMap {
            data_bits,
            element_bits,
        }
    }

    pub fn pad(&self, bits_out: &mut Fr32BitVec) {
        for _ in 0..self.padding_bits() {
            bits_out.push(false)
        }
        // TODO: Can we push an entire stream of zero pad bits?
    }

    pub fn padding_bits(&self) -> usize {
        self.element_bits - self.data_bits
    }

    // Transform a position in a raw byte-aligned data stream (expressed
    // in bits) to its equivalent in a generated padded bit stream (if
    // `padding_direction` is `true`: padding process) or vice versa
    // (if `false`: unpadding).
    //
    // TODO: Abusing the element terminology here: explaining that we
    // are converting from one element size to another when, in the current
    // documentation one is actually *the* (complete) element and the other
    // is the data unit *inside* it.
    // TODO: This is also used for sizes, not only positions, use a more
    // general term like offset.
    // TODO: Why are we interpreting a byte-aligned stream position in bits
    // in the first place?
    pub fn transform_bit_pos(&self, pos: usize, padding_direction: bool) -> usize {

        // Set the sizes of the elements we're converting to and from.
        let (from_size, to_size) = if padding_direction {
            (self.data_bits, self.element_bits)
        } else {
            (self.element_bits, self.data_bits)
        };

        // For both the padding and unpadding cases the operation is the same.
        // The quotient is the number of full elements that can be directly converted
        // to the equivalent size in the other layout.
        // The remainder (in both cases) is the last *incomplete* data unit. Even
        // in the padded layout, if there is an incomplete element it has to consist
        // *only* of data (see `PaddingMap`). That amount of spare raw data doesn't
        // need conversion, it can just be added to the new position.
        // TODO: Good example of when a heading is needed in the main doc, we want to
        // point to the section that contains the list that explains the properties of
        // an element.
        let (full_elements, incomplete_data) = div_rem(pos, from_size);
        (full_elements * to_size) + incomplete_data
    }

    // Similar to `transform_bit_pos` this function transforms a position
    // expressed in bytes.
    // TODO: Expand on the difference between the two functions, do we actually
    // need both? Can they be merged?
    pub fn transform_byte_pos(&self, pos: usize, padding_direction: bool) -> usize {
        let transformed_bit_pos = self.transform_bit_pos(pos * 8, padding_direction);

        let transformed_byte_pos = transformed_bit_pos as f64 / 8.;

        // There's one-to-one equivalence between the bytes in a raw data
        // input that are converted to a byte-aligned padded layout (see `PaddingMap`).
        // TODO: Add heading in the doc to point to.
        // When padding, the final bits in the bit stream will grow into the
        // last (potentially incomplete) byte of the byte stream, so round the
        // number up (`ceil`). When unpadding, there's no way to know a priori
        // how many valid bits are in the last byte, we have to choose the number
        // that fits in a byte-aligned raw data stream, so round the number down
        // to that (`floor`).
        // TODO: Make sure this doesn't overlap too much with the `PaddingMap` doc,
        // this is about implementation, not the general concept.
        (if padding_direction {
            transformed_byte_pos.ceil()
        } else {
            transformed_byte_pos.floor()
        }) as usize
    }

    // From the `position` specified, it returns:
    // - the absolute position of the start of the next element,
    //   in bytes (since elements -with padding- are byte aligned).
    // - the number of bits left to read (write) from (to) the current
    //   data unit (assuming it's full).
    pub fn next_boundaries(&self, position: &BitByte) -> (usize, usize) {
        let position_bits = position.total_bits();

        let (_, bits_after_last_boundary) = div_rem(position_bits, self.element_bits);

        let remaining_data_unit_bits = self.data_bits - bits_after_last_boundary;

        let next_element_position_bits = position_bits +
            remaining_data_unit_bits + self.padding_bits();

        (next_element_position_bits / 8, remaining_data_unit_bits)
    }

    // For a `Seek`able `target` of a byte-aligned padded layout, return:
    // - the size in bytes
    // - the size in bytes of raw data which corresponds to the `target` size
    // - a BitByte representing the number of padded bits contained in the
    //   byte-aligned padded layout
    pub fn target_offsets<W: ?Sized>(&self, target: &mut W) -> io::Result<(u64, u64, BitByte)>
    where
        W: Seek,
    {
        // The current position in `target` is the number of padded bytes already written
        // to the byte-aligned stream.
        let padded_bytes = target.seek(SeekFrom::End(0))?;

        // Deduce the number of input raw bytes that generated that padded byte size.
        let raw_data_bytes = self.transform_byte_pos(padded_bytes as usize, false);

        // With the number of raw data bytes elucidated it can now be specified the
        // number of padding bits in the generated bit stream (before it was converted
        // to a byte-aligned stream), that is, `raw_data_bytes * 8` is not necessarily
        // `padded_bits`).
        let padded_bits = self.transform_bit_pos(raw_data_bytes * 8, true);

        Ok((padded_bytes, raw_data_bytes as u64, BitByte::from_bits(padded_bits)))
        // TODO: Why do we use `usize` internally and `u64` externally?
    }
}

#[inline]
fn div_rem(a: usize, b: usize) -> (usize, usize) {
    let div = a / b;
    let rem = a % b;
    (div, rem)
}

pub fn write_padded<W: ?Sized>(source: &[u8], target: &mut W) -> io::Result<usize>
where
    W: Read + Write + Seek,
// TODO: Document why we need a `Read + Write + Seek` and
// `write_unpadded` needs only `Write`.
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

// Padding process: read a `source` of raw byte-aligned data, pad it in
// a bit stream and write a byte-aligned version of it in the `target`.
//
// The reader will always be byte-aligned, the writer will operate with
// bit precision since we may have (when calling this function multiple
// times) a written `target` with extra bits (that need to be overwritten)
// and also incomplete data units.
// The ideal alignment scenario is for the writer to be positioned at the
// byte-aligned element boundary and just write whole chunks of `data_chunk_bits`
// (full data units) followed by its corresponding padding. To get there then we
// need to handle the potential bit-level misalignments:
//   1. extra bits: the last byte is only partially valid so we
//      need to get some bits from the `source` to overwrite them.
//   2. Incomplete data unit: we need to fill the rest of it and add the padding
//      to form a element that would position the writer at the desired boundary.
//
// TODO: Change name, this is the real write padded function, the previous one
// just partition data in chunks.
fn write_padded_aux<W: ?Sized>(
    padding_map: &PaddingMap,
    source: &[u8],
    target: &mut W,
) -> io::Result<usize>
where
    W: Read + Write + Seek,
{
    // TODO: Check `source` length, if it's zero we should return here and avoid all
    // the alignment calculations that will be worthless (because we wont' have any
    // data with which to align).

    // Bit stream collecting the bits that will be written to the byte-aligned `target`.
    let mut bit_stream = Fr32BitVec::new();

    let (padded_bytes, _, padded_bits) = padding_map.target_offsets(target)?;

    // (1): Overwrite the extra bits (if any): we actually don't write in-place, we
    // remove the last byte and extract its valid bits to `bit_stream` to be later rewritten
    // with new data taken from the `source`.
    if !padded_bits.is_byte_aligned() {

        // Read the last incomplete byte and left the `target` positioned to overwrite
        // it in the next `write_all`.
        let last_byte = &mut [0u8; 1];
        target.seek(SeekFrom::Start(padded_bytes - 1))?;
        target.read_exact(last_byte)?;
        target.seek(SeekFrom::Start(padded_bytes - 1))?;
        // TODO: Can we use a relative `SeekFrom::End` seek to avoid
        // setting our absolute `padded_bytes` position?

        // Extract the valid bit from the last byte (the `bits` fraction
        // of the `padded_bits` bit stream that doesn't complete a byte).
        let mut last_byte_as_bitvec = Fr32BitVec::from(&last_byte[..]);
        last_byte_as_bitvec.truncate(padded_bits.bits);
        bit_stream.extend(last_byte_as_bitvec);
    };

    // (2): Fill the current data unit adding `missing_data_bits` from the
    // `source` (if available, or as many bits as we have).
    let (_, missing_data_bits) = padding_map.next_boundaries(&padded_bits);

    // Check if we have enough `source_bits` to complete the data unit (and hence
    // add the padding and complete the element) or if we'll use all the `source_bits`
    // just to increase (but not complete) the current data unit (and hence we won't pad).
    let source_bits = source.len() * 8;
    let (data_bits_to_write, fills_data_unit) = if missing_data_bits <= source_bits {
        (missing_data_bits, true)
    } else {
        (source_bits, false)
    };
    // TODO: What happens if we were already at the element boundary?
    // Would this code write 0 (`data_bits_to_write`) bits and then
    // add an extra padding?
    // TODO: Added an equal in the comparison (`<=`), before it was just `<`, which seems
    // not to cover the corner case when we have exactly the number of available bits to
    // write (and no more), add a test case for it.
    bit_stream.extend(Fr32BitVec::from(source).into_iter().take(data_bits_to_write));
    if fills_data_unit {
        padding_map.pad(&mut bit_stream);
    }

    // Now we are at the element boundary, write entire chunks of full data
    // units with its padding.

    // If we completed the previous element (`fills_data_unit`) then we may still have
    // some data left.
    if fills_data_unit {
        let remaining_unpadded_chunks = Fr32BitVec::from(source)
            .into_iter()
            .skip(data_bits_to_write)
            // TODO: Not having a "drop first N bits" in `BitVec` makes us remember
            // the already used bits in our logic dragging them until we apply the
            // iterator.
            .chunks(padding_map.data_bits);

        for chunk in remaining_unpadded_chunks.into_iter() {
            let mut bits = Fr32BitVec::from_iter(chunk);

            // If this chunk is a full unit of data then add the padding; if not,
            // this is the last (incomplete) chunk, it will be `some_data` in the
            // next write cycle (which we'll again try to align it to the element
            // boundary).
            if bits.len() == padding_map.data_bits {
                padding_map.pad(&mut bits);
            }

            bit_stream.extend(bits);
        }
    }

    let out = &bit_stream.into_boxed_slice();
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
        // TODO: Rename, "this" seems ambiguous.
        // TODO: Why are we partitioning in chunks and not using them?
        // (just taking their len, but that can be done with the original
        // source length, without doing the actual chunking operation).

        written += write_unpadded_aux(&FR32_PADDING_MAP, source, target, offset, this_len)?;
        offset += this_len;
        len -= this_len;
    }

    Ok(written)
}

// Unpad, read a `source` of padded data and recover from it the
// byte-aligned raw data writing it in `target`, where `write_pos`
// specifies from which byte of the raw data to start recovering, up
// to `max_write_size`.
//
// There are 3 limits that tell us how much padded data to process in
// each iteration (`bits_to_extract`):
// 1. Element boundary: we can process only one element at a time (to be
//    able to skip the padding bits).
// 2. End of `source`: no more data to read.
// 3. No more space to write the recovered raw data: we shouldn't write
//    into the `target` beyond `max_write_size`.
//
// The reader will generally operate with bit precision, even if the padded
// layout is byte-aligned (no extra bits) the data inside it isn't (since
// we pad at the bit-level).
pub fn write_unpadded_aux<W: ?Sized>(
    padding_map: &PaddingMap,
    source: &[u8],
    target: &mut W,
    write_pos: usize,
    max_write_size: usize,
) -> io::Result<usize>
where
    W: Write,
{
    // Position of the reader in the padded bit stream layout, deduced from
    // the position of the writer (`write_pos`) in the raw data layout.
    let mut read_pos = BitByte::from_bits(padding_map.transform_bit_pos(write_pos * 8, true));

    // Specify the maximum data to recover (write) in bits, since the data unit
    // in the element (in contrast with the original raw data that generated it)
    // is not byte aligned.
    let max_write_size_bits = max_write_size * 8;

    // Recovered raw data unpadded from the `source` which will
    // be later packed in bytes and written to the `target`.
    let mut raw_data = Fr32BitVec::new();

    // If there is no more data to read or no more space to write stop.
    while read_pos.bytes < source.len() && raw_data.len() < max_write_size_bits {

        // (1): Find the element boundary and, assuming that there is a full
        //      unit of data (which actually may be incomplete), how many bits
        //      are left to read from `read_pos`.
        let (next_element_position, mut bits_to_extract) = padding_map.next_boundaries(&read_pos);

        // (2): As the element may be incomplete check how much data is
        //      actually available so as not to access the `source` past
        //      its limit.
        let read_element_end = min(next_element_position, source.len());

        // (3): Don't read more than `max_write_size`.
        let bits_left_to_write = max_write_size_bits - raw_data.len();
        bits_to_extract = min(bits_to_extract, bits_left_to_write);

        // Extract the specified `bits_to_extract` bits, skipping the first
        // `read_pos.bits` which have already been processed in a previous
        // iteration.
        raw_data.extend(Fr32BitVec::from(&source[read_pos.bytes..read_element_end]).into_iter()
            .skip(read_pos.bits)
            .take(bits_to_extract));

        // Position the reader in the next element boundary, this will be ignored
        // if we already hit limits (2) or (3) (in that case this was the last iteration).
        read_pos = BitByte {
            bytes: next_element_position,
            bits: 0,
        };
    }

    // TODO: Don't write the whole output into a huge BitVec.
    // Instead, write it incrementally –
    // but ONLY when the bits waiting in bits_out are byte-aligned. i.e. a multiple of 8

    let boxed_slice = raw_data.into_boxed_slice();

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

    // `write_padded` for 151 bytes of 1s, check padding bits in byte 31 and 63.
    #[test]
    fn test_write_padded() {
        let data = vec![255u8; 151];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let written = write_padded(&data, &mut cursor).unwrap();
        let padded = cursor.into_inner();
        assert_eq!(written, 151);
        assert_eq!(padded.len(), FR32_PADDING_MAP.transform_byte_pos(151, true));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
    }

    // `write_padded` for 256 bytes of 1s, splitting it in two calls of 128 bytes,
    // aligning the calls with the padded element boundaries, check padding bits
    // in byte 31 and 63.
    #[test]
    fn test_write_padded_multiple_aligned() {
        let data = vec![255u8; 256];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let mut written = write_padded(&data[0..128], &mut cursor).unwrap();
        written += write_padded(&data[128..], &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(written, 256);
        assert_eq!(padded.len(), FR32_PADDING_MAP.transform_byte_pos(256, true));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
        // TODO: This test is not checking the padding in the boundary between the
        // `write_padded` calls, it doesn't seem then to be testing anything different
        // from the previous one.
    }

    // `write_padded` for 265 bytes of 1s, splitting it in two calls of 128 bytes,
    // aligning the calls with the padded element boundaries, check padding bits
    // in byte 31 and 63.
    #[test]
    fn test_write_padded_multiple_first_aligned() {
        let data = vec![255u8; 265];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let mut written = write_padded(&data[0..128], &mut cursor).unwrap();
        written += write_padded(&data[128..], &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(written, 265);
        assert_eq!(padded.len(), FR32_PADDING_MAP.transform_byte_pos(265, true));
        assert_eq!(&padded[0..31], &data[0..31]);
        assert_eq!(padded[31], 0b0011_1111);
        assert_eq!(padded[32], 0b1111_1111);
        assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
        assert_eq!(padded[63], 0b0011_1111);
        // TODO: Same observation as before, what are we testing here?
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

    // `write_padded` for 127 bytes of 1s, splitting it in two calls of varying
    // sizes, from 0 to the full size, generating many unaligned calls, check
    // padding bits in byte 31 and 63.
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
            assert_eq!(padded.len(), FR32_PADDING_MAP.transform_byte_pos(127, true));
            assert_eq!(&padded[0..31], &data[0..31]);
            assert_eq!(padded[31], 0b0011_1111);
            assert_eq!(padded[32], 0b1111_1111);
            assert_eq!(&padded[33..63], vec![255u8; 30].as_slice());
            assert_eq!(padded[63], 0b0011_1111);
            // TODO: We seem to be repeating the same series of asserts,
            // maybe this can be abstracted away in a helper function.
        }
    }

    // `write_padded` for a raw data stream of increasing values and specific
    // outliers (0xFF, 9), check the content of the raw data encoded (with
    // different alignments) in the padded layouts.
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

    // `write_padded` and `write_unpadded` for 1016 bytes of 1s, check the
    // recovered raw data.
    #[test]
    fn test_read_write_padded() {
        let len = 1016; // Use a multiple of 254.
        let data = vec![255u8; len];
        let buf = Vec::new();
        let mut cursor = Cursor::new(buf);
        let padded_written = write_padded(&data, &mut cursor).unwrap();
        let padded = cursor.into_inner();

        assert_eq!(padded_written, len);
        assert_eq!(padded.len(), FR32_PADDING_MAP.transform_byte_pos(len, true));

        let mut unpadded = Vec::new();
        let unpadded_written = write_unpadded(&padded, &mut unpadded, 0, len).unwrap();
        assert_eq!(unpadded_written, len);
        assert_eq!(data, unpadded);
    }

    // `write_padded` and `write_unpadded` for 1016 bytes of random data, recover
    // different lengths of raw data at different offset, check integrity.
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

    // TODO: Add a test that checks integrity counting the number of set bits
    // before and after padding. This would need to assume that padding is
    // always zero and the DC bit are also zero in the underlying implementation.

    // TODO: Add a test that drops the last part of an element and tries to recover
    // the rest of the data (may already be present in some form in the above tests).
}
