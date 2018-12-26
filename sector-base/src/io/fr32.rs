use std::cmp::min;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;

use bitvec::{self, BitVec};
use itertools::Itertools;

pub type Fr32BitVec = BitVec<bitvec::LittleEndian, u8>;

#[derive(Debug)]
// PaddingMap represents a mapping between data and its padded equivalent.
// Padding is at the bit-level.
// It takes an unpadded byte-aligned *raw* data as input and returns an unaligned
// *padded* data output in the (forward) *padding* process, its inverse is the
// *unpadding* process.
// At the *byte level*, the padded layout is:
//
//           (full)                   (full)                 (incomplete)
// ||  data_bits  pad_bits  ||  data_bits  pad_bits  ||  some_data  (no_padding)
// ^^                       ^^                               ^^
// start             element boundary                (some_data < data_bits)
//
// Each *full* element is a byte-aligned stream comprised of `data_bits` with
// `pad_bits` at the end. A single *incomplete* element may be present at the end,
// comprised only of data with a length smaller than `data_bits`, that is,
// padding only exists at the end of a *full* element and an entire `data_bits`
// unit can't exist without padding.
// TODO: Evaluate renaming `full` to `filled` or `complete`.
// TODO: Find terms for a complete data unit of `data_bits` and units smaller than
// that, avoiding the same term used for the completeness at the element level.
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
// TODO: Elaborate on this definition to drop the "prefix" term.
//
// List of definitions:
// * Full (or filled or complete).
// * Element.
// * Unit (to distinguish it from element) of data or pad.
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

    // TODO: Document the whole group of converting functions.
    // TODO: Could we just store the conversion ratio instead of passing
    // data/padded bits all the time?
    // TODO: Drop the expand/contract terminology in favor of pad/unpad to be
    // more consistent.
    pub fn expand_bits(&self, size: usize) -> usize {
        transform_bit_pos(size, self.data_chunk_bits, self.padded_chunk_bits)
    }

    pub fn contract_bits(&self, size: usize) -> usize {
        transform_bit_pos(size, self.padded_chunk_bits, self.data_chunk_bits)
    }

    // Calculate padded byte size from unpadded byte size, rounding up.
    // TODO: The `expand` family of methods are not used/tested here.
    pub fn expand_bytes(&self, bytes: usize) -> usize {
        transform_byte_pos(bytes, self.data_chunk_bits, self.padded_chunk_bits)
    }

    // Calculate unpadded byte size from padded byte size, rounding down.
    pub fn contract_bytes(&self, bytes: usize) -> usize {
        transform_byte_pos(bytes, self.padded_chunk_bits, self.data_chunk_bits)
    }

    // TODO: This is the place where we figure out if we are byte-aligned or not,
    // review and document it. It receives a multiple of 8 number of bits from
    // `calculate_offsets`.
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

    // TODO: Is Fr the basic element of which we are passing the size?
    // Returns a BitByte representing the distance between current position and next Fr boundary.
    // Padding is directly before the boundary.
    pub fn next_fr_end(&self, current: &BitByte) -> BitByte {
        let current_bits = current.total_bits();

        let (previous, remainder) = div_rem(current_bits, self.padded_chunk_bits);
        // TODO: Do we need to access `div_rem` directly? Yes, because we need the remainder.

        let next_bit_boundary = if remainder == 0 {
            current_bits + self.padded_chunk_bits
        } else {
            (previous * self.padded_chunk_bits) + self.padded_chunk_bits
            // TODO: `(previous + 1) * self.padded_chunk_bits` seems more clear, we basically
            // start at the "ceil" boundary (previous * self.padded_chunk_bits) and need to
            // decide wether we add another `padded_chunk_bits` or not.
            // TODO: Document that `padded_chunk_bits` is the length of the FR element.
        };

        BitByte::from_bits(next_bit_boundary)
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
        let raw_data_bytes = self.contract_bytes(persisted_padded_bytes as usize);

        // With the number of raw data bytes elucidated it can now be specified the
        // size of the valid padded data contained inside the persisted layout, as
        // that size may be unaligned its represented with `BitByte`.
        // Invariant: `padded_data_bit_precision` <=  `persisted_padded_bytes`.
        let padded_data_bit_precision = self.padded_bit_bytes_from_bits(raw_data_bytes * 8);

        Ok((persisted_padded_bytes, raw_data_bytes as u64, padded_data_bit_precision))
        // TODO: Why do we use `usize` internally and `u64` externally?
    }
}

#[inline]
fn div_rem(a: usize, b: usize) -> (usize, usize) {
    let div = a / b;
    let rem = a % b;
    (div, rem)
}

// Transform a position between a padded and an unpadded layout.
// TODO: Move inside `PaddingMap` since it works under its semantics,
// this is not a general function. Also remove the `from_size`
// and `to_size` arguments, we always call it with the pad/unpad
// sizes, just use a bool for direction.
// TODO: Review this.
// TODO: `size` of what?
// TODO: Is `p` a position or a size itself?
// TODO: The use of `rem` seems to imply `from_size` smaller than `to_size`?
// TODO: Could we return `rem` separately?
fn transform_bit_pos(p: usize, from_size: usize, to_size: usize) -> usize {
    // For both the padding and unpadding direction the operation is the same.
    // The quotient is the conversion of full elements, the remainder is the
    // amount of unpadded data which is directly added to the result since
    // it carries no padding bits.
    let (div, rem) = div_rem(p, from_size);

    (div * to_size) + rem
    // TODO: `rem` is added because it's supposed to be bits without padding?
    // (in the case of contracting: padded -> data.)
}

// Similar `to transform_bit_pos` this function converts sizes expressed
// in bytes, al
fn transform_byte_pos(p: usize, from_bit_size: usize, to_bit_size: usize) -> usize {
    let bit_pos = p * 8;
    let transformed_bit_pos = transform_bit_pos(bit_pos, from_bit_size, to_bit_size);
    let transformed_byte_pos1 = transformed_bit_pos as f64 / 8.;
    // TODO: Drop the `1` suffix.

    // TODO: Similar to `transform_bit_pos`, remove the from/to argument and make
    // this `if` evalute the padding/unpadding direction.
    (if from_bit_size < to_bit_size {
        transformed_byte_pos1.ceil()
    } else {
        transformed_byte_pos1.floor()
        // We are using this in the case when we want to estimate how much input
        // bytes do we need to generate the padded layout.
        // TODO: But this should be documented way up in the call stack.
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
    // TODO: But the function is talking about `_fr_end` not start.
    let next_boundary = padding_map.next_fr_end(&offset);

    // How many whole bytes lie between the current position and the new Fr?
    let bytes_to_next_boundary = next_boundary.bytes - offset.bytes;

    if offset.is_byte_aligned() {
        // If current offset is byte-aligned, then write_padded_aligned's invariant is satisfied,
        // and we can call it directly.
        // TODO: Review this invariant.
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

// Invariant: the input so far MUST be byte-aligned (not pad-aligned).
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
        // TODO: If `pad_first_chunk` is false is this executed, it would seem
        // we already have writen the entire `source`.

        // Write all following chunks, padding if necessary.
        let remaining_unpadded_chunks = Fr32BitVec::from(source)
            .into_iter()
            .skip(first_bits)
            .chunks(padding_map.data_chunk_bits);

        // TODO: This seems like the core of the algorithm, we should clearly differentiate
        // it from the initial padding and alignment check.

        for chunk in remaining_unpadded_chunks.into_iter() {
            let mut bits = Fr32BitVec::from_iter(chunk);

            // TODO: What is this check enforcing? We're already chunking at `data_chunk_bits` size.
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
        // TODO: This is where it gets confusing, since we already have the next boundary,
        // isn't that where the `current_fr_bits_end`? In the boundary? Why are we substracting
        // the padding bits?
        let bits_to_next_boundary = current_fr_bits_end - offset_total_bits;

        let raw_end = min(end, source.len());
        if start > source.len() {
            break;
        }
        let raw_bits = Fr32BitVec::from(&source[start..raw_end]);
        // TODO: New `raw` terminology, can we classify this as padded/unpadded data?

        let skipped = raw_bits.into_iter().skip(bits_to_skip);
        let restricted = skipped.take(bits_to_next_boundary);
        // TODO: "restricted"? from what?

        let bits_left_to_write = bits_to_write - bits_out.len();
        let bits_needed = ((end - start) * 8) - bits_to_skip;
        let bits_to_take = min(bits_needed, bits_left_to_write);
        let taken = restricted.take(bits_to_take);

        // TODO: Why do we need 15+ statements to extract some data bits from a field?
        // Is this Rust related?

        bits_out.extend(taken);

        offset = BitByte {
            bytes: end,
            bits: 0,
        };
        // TODO: This would indicate that we always pad to a byte-align boundary.
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

    // TODO: Add a test that checks integrity counting the number of set bits
    // before and after padding. This would need to assume that padding is
    // always zero and the DC bit are also zero in the underlying implementation.
}
