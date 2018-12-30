use std::cmp::min;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;

use bitvec::{self, BitVec};
use itertools::Itertools;

pub type Fr32BitVec = BitVec<bitvec::LittleEndian, u8>;

#[derive(Debug)]
//
// TODO: Use subtitles? e.g., "padding operation", "element configuration",
// "bit-alignment", etc. (the Rust core seems to do so)
// TODO: Maybe we should be using `///` here,
// (https://doc.rust-lang.org/reference/comments.html).
//
// PaddingMap represents a mapping between data and its padded equivalent.
// Padding is at the bit-level.
// It takes an unpadded byte-aligned *raw* data as input and returns an unaligned
// *padded* data output in the (forward) *padding* process, its inverse is the
// *unpadding* process.
// At the *byte level*, the padded layout is:
//
//           (full)                   (full)                 (incomplete)
// ||  data_bits  pad_bits  ||  data_bits  pad_bits  ||  some_data  (no_padding)
//                          ^^                               ^^
//                   element boundary                (some_data < data_bits)
//
// TODO: Check that the names on the diagram match the ones on the structure.
//
// Each *element* is a byte-aligned stream comprised of *full unit* of `data_bits`
// with `pad_bits` at the end.
// TODO: Explain that the boundary is the position of the NEXT element (not
// the pos of the last byte of the previous one).
// After the last element boundary there may be an incomplete unit of data
// (`some_data`) that hasn't been padded yet with a length smaller than `data_bits`.
// That is the only configuration available after the last element boundary because:
//   1. Padding can only be applied to a full unit of `data_bits`.
//   2. A full data unit cannot exist without its corresponding padding.
//   3. If there is padding present then it would already be an element formed there.
// TODO: Check the 3rd one, might be redundant.
// TODO: Check if this byte-aligned invariant is meant to be that way (that is,
// `padded_chunk_bits % 8 == 0`).
//
// At the *bit level*, the persisted padded layout of the last byte is:
//
//  |  D  D  D  D  D  x  x  x  |
//      (valid data)    (R)
//
// The data is always *persisted* (written) in a byte-aligned layout, but as the
// padded layout is unaligned that means that its last byte may contain a number
// *redundant* bits (R) following the *valid* data bits (D) to complete it. It's
// important to distinguish these redundant bits (generated as a side effect of
// a byte-aligned persistence) from the padding bits introduced in the padding
// process: this redundant bits are a place-holder for actual data bits that may
// replace them in the future when the padding layout extended with more data.
// TODO: Review the redundant definition.
// TODO: Evaluate replacing *persisted* with just *written* to avoid too many terms.
// TODO: Clearly explain why the R bits can't be padding: 1. padding is byte-aligned
// (so we wouldn't have this problem in the first place), 2. padding is complete
// by definition.
//
// A byte-aligned padded layout is one where the last byte is comprised *only* of
// valid bits, that is, the next data bit will be placed in a new byte (since there
// are no redundant bits to replace).
// ^^ May be useful in `write_padded_aligned`.
// TODO: Also add *incomplete last byte* (it's the only byte that can be incomplete).
// TODO: Elaborate on this definition to drop the "prefix" term.
//
// List of definitions:
// * Full (or filled or complete).
// * Element.
// * Unit (to distinguish it from element) of data or pad.
// * Full unit.
// TODO: Maybe *filled data unit*.
// * Valid (bits).
// * Prefix (?)
// * Persisted.
// * Raw vs padded. Padding vs unpadding.
// TODO: Add "boundary limit".
//
// TODO: Evaluate representing this information as data bits and padding bit
// which together would form  what is now called `padded_chunk_bits` (which
// may give the wrong impression this is just the *extra* bits and not the
// total). This woulc make it easier to enforce the invariant `data_chunk_bits`
// < `padded_chunk_bits`.
// TODO: Insert the "element" term (or "Fr") to clearly indicate of what size
// are we talking about (not becasue we care about the element but to know we
// are always talking about the *same* thing).
// TODO: Document here the boundary invariant mentioned in `next_fr_end`, if
// that holds up we shouldn't need to much logic to deduce how many bits are
// data and how many are padding bits.
// TODO: We should keep a simple state while padding, maybe not here but in
// a new `Padder` structure which would know if we are in the data or pad
// areas (bit position), and how much bits until we reach a boundary.
// TOOD: Clarify that the diagrams are illustrative but we actually use a
// little endian to persist padded data (see `Fr32BitVec`).
pub struct PaddingMap {
    // The number of bits in the unpadded data.
    data_chunk_bits: usize,
    // The number of bits in the padded data. This must be greater than data_chunk_bits.
    // The difference between padded_chunk_bits and data_chunk_bits is the number of zero/false bits
    // that should be inserted as padding.
    padded_chunk_bits: usize,
    // TODO: Rename to refer to "element" and not just padding,
    // the terminology in the model should be "data" + "padding" = "element".
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
// TODO: If performance is a concern here evaluate dropping the internal
// distinction and manipulate everything a bits, converting to bytes
// when necessary (which would seems to be a minority of the time, mainly
// when interacting with the external client which normally uses bytes,
// internally thinking in bit terms seems more clear).
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
    // TODO: Rename `representation_bits` to `padded_bits` to be
    // consistent with the structure naming.
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
        // TODO: Can we push an entire stream of zero pad bits?
    }

    pub fn padding_bits(&self) -> usize {
        self.padded_chunk_bits - self.data_chunk_bits
    }

    // Transform a position/size expressed in bits from a padded
    // and to an unpadded layout (if `padding_direction` is `true`)
    // or vice versa (if `false`).
    // TODO: Abusing the element terminology here: explaining that we
    // are converting from one element size to another when in the current
    // documentation one is actually *the* (complete) element and the
    // other the data unit *inside* it.
    pub fn transform_bit_pos(&self, pos: usize, padding_direction: bool) -> usize {

        // Set the sizes of the elements we're converting to and from.
        let (from_size, to_size) = if padding_direction {
            (self.data_chunk_bits, self.padded_chunk_bits)
        } else {
            (self.padded_chunk_bits, self.data_chunk_bits)
        };

        // For both the padding and unpadding cases the operation is the same.
        // The quotient is the number of full elements that can be directly converted
        // to the equivalent size in the other layout.
        // The remainder (in both cases) is the last *incomplete* data unit,
        // even in the padded layout, if there is an incomplete element it has
        // to consist *only* of data, the presence of padding indicates a complete
        // element. That amount of spare (unpadded) raw data doesn't need conversion,
        // it can just be added to the new position.
        let (full_elements, incomplete_data) = div_rem(pos, from_size);
        (full_elements * to_size) + incomplete_data
    }

    // Similar `to transform_bit_pos` this function transforms a position/size
    // expressed in bytes.
    // TODO: Expand on the difference between the two functions, we deal with
    // bits when manipulating the data itself, we deal with bytes when we care
    // about how we persist the padded layout in byte-aligned streams. So the
    // difference is actually data vs persisted, not bit vs byte.
    pub fn transform_byte_pos(&self, pos: usize, padding_direction: bool) -> usize {
        let transformed_bit_pos = self.transform_bit_pos(pos * 8, padding_direction);

        let transformed_byte_pos = transformed_bit_pos as f64 / 8.;

        // There's one-to-one equivalence between the bytes in a raw data
        // input that are converted to a persisted padded layout.
        // When padding, the last (incomplete) byte is persisted in its
        // entirety, so round the number up (`ceil`). When unpadding a
        // persisted layout there's no way to know a priori how many valid
        // bits are in the last byte, we have to choose the number that fits
        // in a byte-aligned raw data size, so round the number down to that
        // (`floor`).
        // TODO: Some of this documentation should be higher in the call stack,
        // many functions rely on this implicit logic, maybe it should be
        // documented up in `PaddingMap`.
        (if padding_direction {
            transformed_byte_pos.ceil()
        } else {
            transformed_byte_pos.floor()
        }) as usize
    }

    // From the `position` specified, it returns:
    // - the absolute position of the start of the next element,
    //   in bytes (since elements -with padding- are byte aligned).
    // - the number of bits left to read/write from/to the data unit
    //   (assuming it's full).
    pub fn next_boundaries(&self, position: &BitByte) -> (usize, usize) {
        let position_bits = position.total_bits();

        let (_, bits_after_last_boundary) = div_rem(position_bits, self.padded_chunk_bits);

        let next_element_position_bits = position_bits +
            (self.padded_chunk_bits - bits_after_last_boundary);
        // Add the complement of `padded_chunk_bits` (element size) to reach
        // the next boundary from our current position.

        let remaining_data_unit_bits = next_element_position_bits - self.padding_bits() - position_bits;

        (next_element_position_bits / 8, remaining_data_unit_bits)
    }

    // For a `Seek`able target with a persisted padded layout, return:
    // - the persisted size in bytes
    // - the size in bytes of raw data which corresponds to the persisted size
    // - a BitByte representing the number of valid bits and bytes of actual
    //   padded data contained in the persisted layout (that is, not counting
    //   the redundant bits)
    pub fn target_offsets<W: ?Sized>(&self, target: &mut W) -> io::Result<(u64, u64, BitByte)>
    where
        W: Seek,
    {
        // The current position in target is the number of PADDED bytes already persisted.
        let persisted_padded_bytes = target.seek(SeekFrom::End(0))?;
        // TODO: Is is worth specifying the unit in the name of the variable?

        // Deduce the number of input raw bytes that generated the persisted padded size.
        // `contract_bytes` will first assume that `persisted_padded_bytes` is actually byte
        // aligned (containing no redundant bits) and will calculate the number of raw bits
        // needed to generate that size. Then it will round that down to the lower byte (since
        // raw data is byte aligned), the result is *unique*: a persisted padded layout may
        // contain different numbers of redundant bits in its last byte but there is only one
        // configuration that could have been generated by padding a byte-aligned raw data.
        let raw_data_bytes = self.transform_byte_pos(persisted_padded_bytes as usize, false);

        // With the number of raw data bytes elucidated it can now be specified the
        // size of the valid padded data contained inside the persisted layout, as
        // that size may be unaligned its represented with `BitByte`.
        // Invariant: `padded_data_bit_precision` <=  `persisted_padded_bytes`.
        let padded_data_bits = self.transform_bit_pos(raw_data_bytes * 8, true);

        Ok((persisted_padded_bytes, raw_data_bytes as u64, BitByte::from_bits(padded_data_bits)))
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

// The ideal alignment scenario is for the position to be at the element boundary
// where the persisted data is byte-aligned (no redundant bits), and just write
// chunks of `data_chunk_bits` followed by its corresponding padding, but to get
// there first there are two potential misalignments to handle:
//   1. The last persisted byte is only partially valid so we need to get some
//      bits from the `source` to overwrite the redundant bits and make it byte
//      aligned.
//   2. With a byte-aligned persisted padded layout we need to fill the rest
//      of the incomplete data unit to make it a full unit, add the padding
//      and form a element that would position as at the desired boundary.
// TODO: Change name, this is the real write padded function, the previous one
// just partition data in chunks.
// TODO: Document in a way similar to the unpadding function, focusing the names
// on which is reading and which writing (specifing that we read from a raw data
// layout and write to a padded layout).
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

    // bits_out is a sink for bits, to be written at the end.
    let mut bits_out = Fr32BitVec::new();

    let (persisted_padded_bytes, _, padded_data_bit_precision) = padding_map.target_offsets(target)?;

    // Determine the number of bits needed to fill the current unit of data in the element.
    let (_, missing_data_bits) = padding_map.next_boundaries(&padded_data_bit_precision);

    // (1): Byte align the persisted padded data.
    if !padded_data_bit_precision.is_byte_aligned() {
        // Remove the valid bits from the last byte and add it to `bits_out`
        // (simulating that it's new data to write coming from the source).

        let last_persisted_byte = &mut [0u8; 1];

        // Seek backward far enough to read just the prefix.
        target.seek(SeekFrom::Start(persisted_padded_bytes - 1))?;
        // TODO: Can we use a relative `SeekFrom::End` seek to avoid
        // setting our absolute `persisted_padded_bytes` position?

        // And read it in.
        target.read_exact(last_persisted_byte)?;
        // NOTE: seek position is now back to where we started.

        // Rewind by 1 again effectively taking the last byte out from the persisted
        // padded layout, it will be rewritten (now as a complete byte with added
        // `source` bits) later. By dropping this last incomplete byte the persisted
        // target is now byte-aligned.
        target.seek(SeekFrom::Start(persisted_padded_bytes - 1))?;

        // Package up the last byte into a `BitVec` to extract its `valid_bit_count` bits.
        let mut last_byte_as_bitvec = Fr32BitVec::from(&last_persisted_byte[..]);
        last_byte_as_bitvec.truncate(padded_data_bit_precision.bits);
        bits_out.extend(last_byte_as_bitvec);
    };

    // (2): Complete the current element to position the writer in the next element boundary.

    // TODO: What happens if we were already at the element boundary?
    // Would this code write 0 (`data_bits_to_write`) bits and then
    // add an extra padding?

    // How many new bits do we need to write?
    let source_bits = source.len() * 8;

    // Check if we have enough `source_bits` to complete the data unit (and hence
    // add the padding and complete the element) or if we'll use all the `source_bits`
    // to increase (but not complete) the current data unit (and hence we won't pad).
    let (data_bits_to_write, is_full_data_unit) = if missing_data_bits < source_bits {
        (missing_data_bits, true)
    } else {
        (source_bits, false)
    };
    // Take the first `data_bits_to_write` from `source` (which might be all
    // that's available) and flush it to `bits_out`.
    bits_out.extend(Fr32BitVec::from(source).into_iter().take(data_bits_to_write));
    // If we had enough to fill the data unit add the padding (completing the element).
    if is_full_data_unit {
        padding_map.pad(&mut bits_out);
    }

    // Now we are at the element boundary.

    // If we completed the previous element then we may still have some data left,
    // write entire chunks of filled data units with its padding.
    if is_full_data_unit {
        let remaining_unpadded_chunks = Fr32BitVec::from(source)
            .into_iter()
            .skip(data_bits_to_write)
            // TODO: Not having a "drop first N bits" in `BitVec` makes us remember
            // the already used bits in our logic dragging them until we apply the
            // iterator.
            .chunks(padding_map.data_chunk_bits);

        for chunk in remaining_unpadded_chunks.into_iter() {
            let mut bits = Fr32BitVec::from_iter(chunk);

            // If this chunk is a full unit of data then add the padding; if not,
            // this is the last (incomplete) chunk, it will be `some_data` in the
            // next write cycle (which will again try to align it to the element
            // boundary).
            if bits.len() == padding_map.data_chunk_bits {
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

// TODO: What does this function do? Is this the inverse of `write_padded`? is this *un*padding?
// or is this writing wihtouth the pad?
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

// Unpad, take a `source` of padded data and recover from it the
// (byte-aligned) raw data writing it in `target`, where `write_pos`
// specifies from which byte of the raw data to start recovering, up
// to `max_write_size`.
//
// There are 3 limits that tell us how much padded data to process in
// each iteration (`bits_to_extract`):
// 1. Element boundary: we can process one element at a time, to be
//    able to read the data unit and skip the padding bits.
// 2. End of `source`: no more data to read.
// 3. No more space to write the recovered raw data: we shouldn't write
//    into the `target` beyond `max_write_size`.
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
    // Position of the reader in the padded layout, deduced from the position
    // of the writer (`write_pos`) in the raw data unpadded layout. Since the
    // raw data is byte-aligned and the padded data isn't, this transformation
    // converts from a byte size into a `BitByte` size.
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
