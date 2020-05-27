use std::cmp::min;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};

use anyhow::{ensure, Result};
use bitvec::{order::Lsb0 as LittleEndian, vec::BitVec};

/** PaddingMap represents a mapping between data and its padded equivalent.

The padding process takes a *byte-aligned stream* of unpadded *raw* data
as input and returns another byte stream where padding is applied every
`data_bits` to align them to the byte boundary (`element_bits`). The
(inverse) *unpadding* process maps that output back to the raw input
that generated it.

# Padded layout

At the *byte-level*, the padded layout is:

```text
      (full element)              (full)                 (incomplete)
||  data_bits  pad_bits  ||  data_bits  pad_bits  ||  some_data  (no_padding)
                         ^^                               ^^
                  element boundary                (some_data < data_bits)
                   (byte-aligned)
```

Each *element* is a byte-aligned stream comprised of a *full unit* of `data_bits`
with `pad_bits` at the end to byte-align it (where `pad_bits` is less than a byte,
this is a *sub-byte padding* scheme). After the last element boundary there may be
an incomplete unit of data (`some_data`) with a length smaller than `data_bits`
that hasn't been padded. The padding rules are:
  1. Padding is always applied to a full unit of `data_bits`.
  2. A full data unit cannot exist without its corresponding padding.
  3. A unit of padding is complete by definition: padding can only be
     applied fully to each element.
  4. If there is padding present then there has to be an already formed
     element there (an element is full if and only if its data unit is full).

# Last byte

When returning the byte-aligned output generated from the padded *bitstream*
(since the padding is done at the bit-level) the conversion results in the
last byte having (potentially) more bits than desired. At the *bit-level*
the layout of the last byte can either be a complete element (bits of raw
data followed by the corresponding padding bits) or an incomplete unit of
data: some number of *valid* data (D) bits followed by any number of *extra*
bits (X) necessary to complete the byte-aligned stream:

```text
 |   D   D   D   D   X   X   X   X   |
         (data)         (extra)      ^ byte boundary (end of output)
```

(This diagram is just for illustrative purposes, we actually return the output
 in little-endian order, see `BitVecLEu8`).

It's important to distinguish these extra bits (generated as a side
effect of the conversion to a byte-aligned stream) from the padding bits
themselves introduced in the padding process: even though both will be
left with a zero value, these extra bits are a place-holder for the actual
raw data bits needed to complete the current unit of data (and hence also
the element, with the corresponding padding bits added after it). Since
extra bits are only a product of an incomplete unit of data there can't
be extra bits after padding bits.

There's no metadata signaling the number of extra bits present in the
last byte in any given padded layout, this is deduced from the fact
that there's only a single number of valid data bits in the last byte,
and hence a number of data bits in total, that maps to a byte-aligned
(multiple of 8) raw data stream that could have been used as input.

# Example: `FR32_PADDING_MAP`

In this case the `PaddingMap` is defined with a data unit of 254 bits that
are byte aligned to a 256-bit (32-byte) element. If the user writes as input,
say, 40 bytes (320 bits) of raw input data to the padding process the resulting
layout would be, at the element (byte) level:

```text
      (full element: 32 bytes)         (incomplete: 9 bytes)
||  data_bits: 254  pad_bits: 2  ||   some_data: 66 bits (+ extra bits)
                                 ^^
                          element boundary
```

That is, of the original 320 bits (40 bytes) of raw input data, 254 are
padded in the first element and the remaining 66 bits form the incomplete
data unit after it, which is aligned to 9 bytes. At the bit level, that
last incomplete byte will have 2 valid bits and 6 extra bits.

# Alignment of raw data bytes in the padded output

This section is not necessary to use this structure but it does help to
reason about it. By the previous definition, the raw data bits *embedded*
in the padded layout are not necessarily grouped in the same byte units
as in the original raw data input (due to the inclusion of the padding
bits interleaved in that bit stream, which keep shifting the data bits
after them).

This can also be stated as: the offsets of the bits (relative to the byte
they belong to, i.e., *bit-offset*) in the raw data input won't necessarily
match the bit-offsets of the raw data bits embedded in the padded layout.
The consequence is that each raw byte written to the padded layout won't
result in a byte-aligned bit stream output, i.e., it may cause the appearance
of extra bits (to convert the output to a byte-aligned stream).

There are portions of the padded layout, however, where this alignment does
happen. Particularly, when the padded layout accumulates enough padding bits
that they altogether add up to a byte, the following raw data byte written
will result in a byte-aligned output, and the same is true for all the other
raw data byte that follow it up until the element end, where new padding bits
shift away this alignment. (The other obvious case is the first element, which,
with no padded bits in front of it, has by definition all its embedded raw data
bytes aligned, independently of the `data_bits`/`pad_bits` configuration used.)

In the previous example, that happens after the fourth element, where 4 units
of `pad_bits` add up to one byte and all of the raw data bytes in the fifth
element will keep its original alignment from the byte input stream (and the
same will happen with every other element multiple of 4). When that fourth
element is completed we have then 127 bytes of raw data and 1 byte of padding
(totalling 32 * 4 = 128 bytes of padded output), so the interval of raw data
bytes `[127..159]` (indexed like this in the input raw data stream) will keep
its original alignment when embedded in the padded layout, i.e., every raw
data byte written will keep the output bit stream byte-aligned (without extra
bits). (Technically, the last byte actually won't be a full byte since its last
bits will be replaced by padding).

# Key terms

Collection of terms introduced in this documentation (with the format
`*<new-term>*`). This section doesn't provide a self-contained definition
of them (to avoid unnecessary repetition), it just provides (when appropriate)
an additional summary of what was already discussed.

 * Raw data: unpadded user-supplied data (we don't use the *unpadded* term
   to avoid excessive *padding* suffixes in the code). Padding (data) bits.
 * Element: byte-aligned stream consisting of a full unit of data plus the
   padding bits.
 * Full unit of raw `data_bits` (always followed by padding). Incomplete unit,
   not followed by padding, doesn't form an element.
 * Byte-aligned stream: always input and output of the (un)padding process,
   either as raw data or padded (using the term "byte-aligned" and not "byte
   stream" to stress the boundaries of the elements). Bit streams: used internally
   when padding data (never returned as bits).
 * Valid data bits, only in the context of the last byte of a byte-aligned stream
   generated from the padding process. Extra bits: what's left unused of the last
   byte (in a way the extra bits are the padding at the byte-level, but we don't
   use that term here to avoid confusions).
 * Sub-byte padding.
 * Bit-offset: offset of a bit within the byte it belongs to, ranging in `[0..8]`.
 * Embedded raw data: view of the input raw data when it has been decomposed in
   bit streams and padded in the resulting output.

**/
#[derive(Debug)]
pub struct PaddingMap {
    /// The number of bits of raw data in an element.
    data_bits: usize,
    /// Number of bits in an element: `data_bits` + `pad_bits()`. Its value
    /// is fixed to the next byte-aligned size after `data_bits` (sub-byte padding).
    element_bits: usize,
}
// TODO: Optimization: Evaluate saving the state of a (un)padding operation
// inside (e.g., as a cursor like in `BitVec`), maybe not in this structure but
// in a new `Padder` structure which would remember the positions (remaining
// data bits in the element, etc.) to avoid recalculating them each time across
// different (un)pad calls.

// This is the padding map corresponding to Fr32.
// Most of the code in this module is general-purpose and could move elsewhere.
// The application-specific wrappers which implicitly use Fr32 embed the FR32_PADDING_MAP.
pub const FR32_PADDING_MAP: PaddingMap = PaddingMap {
    data_bits: 254,
    element_bits: 256,
};

pub type BitVecLEu8 = BitVec<LittleEndian, u8>;

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
    let padded =
        BitByte::from_bits(FR32_PADDING_MAP.transform_bit_offset((length * 8) as usize, true));
    let real_length = padded.bytes_needed();
    let _final_bit_count = padded.bits;
    Ok(real_length)
}

pub fn to_unpadded_bytes(padded_bytes: u64) -> u64 {
    FR32_PADDING_MAP.transform_byte_offset(padded_bytes as usize, false) as u64
}

pub fn to_padded_bytes(unpadded_bytes: usize) -> usize {
    FR32_PADDING_MAP.transform_byte_offset(unpadded_bytes, true)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// BitByte represents a size expressed in bytes extended
// with bit precision, that is, not rounded.
// Invariant: it is an error for bits to be > 7.
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
        self.bytes + if self.bits == 0 { 0 } else { 1 }
    }
}

impl PaddingMap {
    pub fn new(data_bits: usize, element_bits: usize) -> Result<PaddingMap> {
        // Check that we add less than 1 byte of padding (sub-byte padding).
        ensure!(
            element_bits - data_bits <= 7,
            "Padding (num bits: {}) must be less than 1 byte.",
            element_bits - data_bits
        );
        // Check that the element is byte aligned.
        ensure!(
            element_bits % 8 == 0,
            "Element (num bits: {}) must be byte aligned.",
            element_bits
        );

        Ok(PaddingMap {
            data_bits,
            element_bits,
        })
    }

    pub fn pad(&self, bits_out: &mut BitVecLEu8) {
        for _ in 0..self.pad_bits() {
            bits_out.push(false)
        }
        // TODO: Optimization: Drop this explicit `push` padding, the padding
        // should happen implicitly when byte-aligning the data unit.
    }

    pub fn pad_bits(&self) -> usize {
        self.element_bits - self.data_bits
    }

    // Transform an offset (either a position or a size) *expressed in
    // bits* in a raw byte-aligned data stream to its equivalent in a
    // generated padded bit stream, that is, not byte aligned (so we
    // don't count the extra bits here). If `padding` is `false` calculate
    // the inverse transformation.
    pub fn transform_bit_offset(&self, pos: usize, padding: bool) -> usize {
        // Set the sizes we're converting to and from.
        let (from_size, to_size) = if padding {
            (self.data_bits, self.element_bits)
        } else {
            (self.element_bits, self.data_bits)
        };

        // For both the padding and unpadding cases the operation is the same.
        // The quotient is the number of full, either elements, in the padded layout,
        // or groups of `data_bits`, in the raw data input (that will be converted
        // to full elements).
        // The remainder (in both cases) is the last *incomplete* part of either of
        // the two. Even in the padded layout, if there is an incomplete element it
        // has to consist *only* of data (see `PaddingMap#padded-layout`). That amount
        // of spare raw data doesn't need conversion, it can just be added to the new
        // position.
        let (full_elements, incomplete_data) = div_rem(pos, from_size);
        (full_elements * to_size) + incomplete_data
    }

    // Similar to `transform_bit_pos` this function transforms an offset
    // expressed in bytes, that is, we are taking into account the extra
    // bits here.
    // TODO: Evaluate the relationship between this function and `transform_bit_offset`,
    // it seems the two could be merged, or at least restructured to better expose
    // their differences.
    pub fn transform_byte_offset(&self, pos: usize, padding: bool) -> usize {
        let transformed_bit_pos = self.transform_bit_offset(pos * 8, padding);

        let transformed_byte_pos = transformed_bit_pos as f64 / 8.;
        // TODO: Optimization: It might end up being cheaper to avoid this
        // float conversion and use / and %.

        // When padding, the final bits in the bit stream will grow into the
        // last (potentially incomplete) byte of the byte stream, so round the
        // number up (`ceil`). When unpadding, there's no way to know a priori
        // how many valid bits are in the last byte, we have to choose the number
        // that fits in a byte-aligned raw data stream, so round the number down
        // to that (`floor`).
        (if padding {
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
    pub fn next_boundary(&self, position: &BitByte) -> (usize, usize) {
        let position_bits = position.total_bits();

        let (_, bits_after_last_boundary) = div_rem(position_bits, self.element_bits);

        let remaining_data_unit_bits = self.data_bits - bits_after_last_boundary;

        let next_element_position_bits = position_bits + remaining_data_unit_bits + self.pad_bits();

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
        let raw_data_bytes = self.transform_byte_offset(padded_bytes as usize, false);

        // With the number of raw data bytes elucidated it can now be specified the
        // number of padding bits in the generated bit stream (before it was converted
        // to a byte-aligned stream), that is, `raw_data_bytes * 8` is not necessarily
        // `padded_bits`).
        let padded_bits = self.transform_bit_offset(raw_data_bytes * 8, true);

        Ok((
            padded_bytes,
            raw_data_bytes as u64,
            BitByte::from_bits(padded_bits),
        ))
        // TODO: Why do we use `usize` internally and `u64` externally?
    }
}

#[inline]
fn div_rem(a: usize, b: usize) -> (usize, usize) {
    let div = a / b;
    let rem = a % b;
    (div, rem)
}

// TODO: The following extraction functions could be moved to a different file.

/** Shift an `amount` of bits from the `input` in the direction indicated by `is_left`.

This function tries to imitate the behavior of `shl` and `shr` of a
`BitVec<LittleEndian, u8>`, where the inner vector is traversed one byte
at a time (`u8`), and inside each byte, bits are traversed (`LittleEndian`)
from LSB ("right") to MSB ("left"). For example, the bits in the this two-byte
slice will be traversed according to their numbering:

```text
ADDR     |  7  6  5  4  3  2  1  0  |

ADDR +1  |  F  E  D  C  B  A  9  8  |
```

`BitVec` uses the opposite naming convention than this function, shifting left
here is equivalent to `shr` there, and shifting right to `shl`.

If shifting in the left direction, the `input` is expanded by one extra byte to
accommodate the overflow (instead of just discarding it, which is what's done
in the right direction).

The maximum `amount` to shift is 7 (and the minimum is 1), that is, we always
shift less than a byte. This precondition is only checked during testing (with
`debug_assert!`) for performance reasons, it is up to the caller to enforce it.

# Examples

Shift the `input` (taken from the diagram above) left by an `amount` of 3 bits,
growing the output slice:

```text
ADDR     |  4  3  2  1  0  _  _  _  |  Filled with zeros.

ADDR +1  |  C  B  A  9  8  7  6  5  |

ADDR +2  |  _  _  _  _  _  F  E  D  |  The overflow of the last input byte
                                               is moved to this (new) byte.
```

Same, but shift right:

```text
ADDR     |  A  9  8  7  6  5  4  3  |  The overflow `[2,1,0]` is just discarded,
                                                         the slice doesn't grow.
ADDR +1  |  _  _  _  F  E  D  C  B  |
```

(Note: `0`, `1`, `2`, etc. are bits identified by their original position,
`_` means a bit left at zero after shifting, to avoid confusions with
the unique bit `0`, that just *started* at that position but doesn't
necessarily carry that value.)

**/
pub fn shift_bits(input: &[u8], amount: usize, is_left: bool) -> Vec<u8> {
    debug_assert!(amount >= 1);
    debug_assert!(amount <= 7);

    // Create the `output` vector from the original input values, extending
    // its size by one if shifting left.
    let mut output = Vec::with_capacity(input.len() + if is_left { 1 } else { 0 });
    output.extend_from_slice(input);
    if is_left {
        output.push(0);
    }
    // TODO: Is there a cleaner way to do this? Is the extra byte worth the initial
    // `with_capacity` call?

    // Split the shift in two parts. First, do a simple bit shift (losing the
    // overflow) for each byte, then, in a second pass, recover the lost overflow
    // from the `input`. The advantage of splitting it like this is that the place-holder
    // spaces are already being cleared with zeros to just join the overflow part with an
    // single `OR` operation (instead of assembling both parts together at the same time
    // which requires an extra clear operation with a mask of zeros).
    for output_byte in output.iter_mut().take(input.len()) {
        if is_left {
            *output_byte <<= amount;
        } else {
            *output_byte >>= amount;
        }
    }

    if is_left {
        // The `output` looks at this point like this (following the original
        // example):
        //
        // ADDR     |  4  3  2  1  0  _  _  _  |
        //
        // ADDR +1  |  C  B  A  9  8  _  _  _  |
        //
        // ADDR +2  |  _  _  _  _  _  _  _  _  |  Extra byte allocated to extend the `input`,
        //                                            hasn't been modified in the first pass.
        //
        // We need to recover the overflow of each shift (e.g., `[7,6,5]` from
        // the first byte and `[F,E,D]` from the second) and move it to the next
        // byte, shifting it to place it at the "start" (in the current ordering
        // that means aligning it to the LSB). For example, the overflow of (also)
        // `amount` bits from the first byte is:
        //
        // ADDR     |  7  6  5  4  3  2  1  0  |
        //             +-----+
        //           overflow lost
        //
        // and it's "recovered" with a shift in the opposite direction, which both
        // positions it in the correct place *and* leaves cleared the rest of the
        // bits to be able to `OR` (join) it with the next byte of `output` (shifted
        // in the first pass):
        //
        // (`output` so far)
        // ADDR +1  |  C  B  A  9  8  _  _  _  |    +
        //                                          |
        // (shifted overflow                        |  join both (`|=`)
        //      from `input`)                       |
        // ADDR     |  _  _  _  _  _  7  6  5  |    V
        //             +------------->
        //
        for i in 0..input.len() {
            let overflow = input[i] >> (8 - amount);
            output[i + 1] |= overflow;
        }
    } else {
        // The overflow handling in the right shift follows the same logic as the left
        // one with just two differences: (1) the overflow goes to the *previous* byte
        // in memory and (2) the overflow of the first byte is discarded (hence the `for`
        // loop iterates just `input.len` *minus one* positions).
        for i in 1..input.len() {
            let overflow = input[i] << (8 - amount);
            output[i - 1] |= overflow;
        }
    }

    // TODO: Optimization: Join both passes in one `for` loop for cache
    // efficiency (do everything we need to do in the same address once).
    // (This is low priority since we normally shift small arrays -32 byte
    // elements- per call.)

    output
}

/** Extract bits and relocate them.

Extract `num_bits` from the `input` starting at absolute `pos` (expressed in
bits). Format the extracted bit stream as a byte stream `output` (in a `Vec<u8>`)
where the extracted bits start at `new_offset` bits in the first byte (i.e.,
`new_offset` can't be bigger than 7) allowing them to be relocated from their
original bit-offset (encoded in `pos`). The rest of the bits (below `new_offset`
and after the extracted `num_bits`) are left at zero (to prepare them to be
joined with another extracted `output`). This function follows the ordering in
`BitVec<LittleEndian, u8>` (see `shift_bits` for more details).

The length of the input must be big enough to perform the extraction
of `num_bits`. This precondition is only checked during testing (with
`debug_assert!`) for performance reasons, it is up to the caller to enforce it.

# Example

Taking as `input` the original two-byte layout from `shift_bits`, extracting 4
`num_bits` from `pos` 12 and relocating them in `new_offset` 2 would result in
an `output` of a single byte like:

```text
ADDR     |  _  _  F  E  D  C  _  _  |
```

(The second byte in `ADDR +1` has been dropped after the extraction
as it's no longer needed.)

**/
//
// TODO: Replace the byte terminology for a generic term that can mean
// anything that implements the `bitvec::Bits` trait (`u8`, `u32`, etc.).
// `BitVec` calls it "element" but that's already used here (this function
// may need to be moved elsewhere which would allow to reuse that term).
// This also will imply removing the hardcoded `8`s (size of byte).
#[inline]
pub fn extract_bits_and_shift(
    input: &[u8],
    pos: usize,
    num_bits: usize,
    new_offset: usize,
) -> Vec<u8> {
    debug_assert!(input.len() * 8 >= pos + num_bits);
    debug_assert!(new_offset <= 7);

    // 1. Trim the whole bytes (before and after) we don't need for the
    //    extraction (we don't want to waste shift operations on them).
    // 2. Shift from the original `pos` to the `new_offset`.
    // 3. Trim the bits in the first and last byte we also don't need.
    //
    // TODO: Does (3) need to happen *after* the shift in (2)? It feels
    // more natural but can't we just trim everything in (1)?

    // Determine from `pos` the number of full bytes that can be completely skipped
    // (`skip_bytes`), and the number of bits within the first byte of interest that
    // we'll start extracting from (`extraction_offset`).
    let (skip_bytes, extraction_offset) = div_rem(pos, 8);

    // (1).
    let input = &input[skip_bytes..];
    let input = &input[..BitByte::from_bits(extraction_offset + num_bits).bytes_needed()];

    // (2).
    use std::cmp::Ordering;
    let mut output = match new_offset.cmp(&extraction_offset) {
        Ordering::Less => {
            // Shift right.
            shift_bits(input, extraction_offset - new_offset, false)
        }
        Ordering::Greater => {
            // Shift left.
            shift_bits(input, new_offset - extraction_offset, true)
        }
        Ordering::Equal => {
            // No shift needed, take the `input` as is.
            input.to_vec()
        }
    };

    // After the shift we may not need the last byte of the `output` (either
    // because the left shift extended it by one byte or because the right shift
    // move the extraction span below that threshold).
    if output.len() > BitByte::from_bits(new_offset + num_bits).bytes_needed() {
        output.pop();
    }
    // TODO: Optimization: A more specialized shift would have just dropped
    // that byte (we would need to pass it the `num_bits` we want).

    // (3).
    if new_offset != 0 {
        clear_right_bits(output.first_mut().expect("output is empty"), new_offset);
    }
    let end_offset = (new_offset + num_bits) % 8;
    if end_offset != 0 {
        clear_left_bits(output.last_mut().expect("output is empty"), end_offset);
    }

    output
}

// Set to zero all the bits to the "left" of the `offset` including
// it, that is, [MSB; `offset`].
#[inline]
pub fn clear_left_bits(byte: &mut u8, offset: usize) {
    *(byte) &= (1 << offset) - 1
}

// Set to zero all the bits to the "right" of the `offset` excluding
// it, that is, (`offset`; LSB].
#[inline]
pub fn clear_right_bits(byte: &mut u8, offset: usize) {
    *(byte) &= !((1 << offset) - 1)
}

/** Padding process.

Read a `source` of raw byte-aligned data, pad it in a bit stream and
write a byte-aligned version of it in the `target`. The `target` needs
to implement (besides `Write`) the `Read` and `Seek` traits since the
last byte written may be incomplete and will need to be rewritten.

The reader will always be byte-aligned, the writer will operate with
bit precision since we may have (when calling this function multiple
times) a written `target` with extra bits (that need to be overwritten)
and also incomplete data units.
The ideal alignment scenario is for the writer to be positioned at the
byte-aligned element boundary and just write whole chunks of `data_chunk_bits`
(full data units) followed by its corresponding padding. To get there then we
need to handle the potential bit-level misalignments:
  1. extra bits: the last byte is only partially valid so we
     need to get some bits from the `source` to overwrite them.
  2. Incomplete data unit: we need to fill the rest of it and add the padding
     to form a element that would position the writer at the desired boundary.
**/

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
    // Check that there's actually `len` raw data bytes encoded inside
    // `source` starting at `offset`.
    let read_pos = BitByte::from_bits(FR32_PADDING_MAP.transform_bit_offset(offset * 8, true));
    let raw_data_size = BitByte::from_bits(
        FR32_PADDING_MAP.transform_bit_offset(source.len() * 8 - read_pos.total_bits(), false),
    )
    .bytes_needed();
    if raw_data_size < len {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "requested extraction of {} raw data bytes when there's at most {} in the source",
                len, raw_data_size
            ),
        ));
    }

    // In order to optimize alignment in the common case of writing from an aligned start,
    // we should make the chunk a multiple of 128 (4 full elements in the padded layout).
    // n was hand-tuned to do reasonably well in the benchmarks.
    let n = 1000;
    let chunk_size = 128 * n;

    let mut written = 0;

    let mut offset = offset;
    let mut len = len;

    for chunk in source.chunks(chunk_size) {
        let write_len = min(len, chunk.len());

        written += write_unpadded_aux(&FR32_PADDING_MAP, source, target, offset, write_len)?;
        offset += write_len;
        len -= write_len;
    }

    Ok(written)
}

/**  Unpadding process.

Read a `source` of padded data and recover from it the byte-aligned
raw data writing it in `target`, where `write_pos` specifies from which
byte of the raw data stream to start recovering to, up to `max_write_size`
bytes.

There are 3 limits that tell us how much padded data to process in
each iteration (`bits_to_extract`):
1. Element boundary: we can process only one element at a time (to be
   able to skip the padding bits).
2. End of `source`: no more data to read.
3. No more space to write the recovered raw data: we shouldn't write
   into the `target` beyond `max_write_size`.

The reader will generally operate with bit precision, even if the padded
layout is byte-aligned (no extra bits) the data inside it isn't (since
we pad at the bit-level).
**/
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
    let mut read_pos = BitByte::from_bits(padding_map.transform_bit_offset(write_pos * 8, true));

    // Specify the maximum data to recover (write) in bits, since the data unit
    // in the element (in contrast with the original raw data that generated it)
    // is not byte aligned.
    let max_write_size_bits = max_write_size * 8;

    // Estimate how many bytes we'll need for the `raw_data` to allocate
    // them all at once. We need to take into account both how much do
    // we have left to read *and* write, and even then, since we may start
    // in the middle of an element (`write_pos`) there's some variability
    // as to how many padding bits will be encountered.
    // Allow then an *over*-estimation error of 1 byte: `transform_bit_offset`
    // has the implicit assumption that the data provided is starting at the
    // beginning of an element, i.e., the padding bits are as far as possible,
    // which maximizes the chances of not getting an extra `pad_bits` in the
    // `source` (which are unpadded away and not carried to the `target`). That
    // is, in this context `transform_bit_offset` is optimistic about the number
    // of raw data bits we'll be able to recover from a fixed number of `source`
    // bits.
    let mut raw_data_size = BitByte::from_bits(
        padding_map.transform_bit_offset(source.len() * 8 - read_pos.total_bits(), false),
    )
    .bytes_needed();
    raw_data_size = min(raw_data_size, max_write_size);

    // Recovered raw data unpadded from the `source` which will
    // be written to the `target`.
    let mut raw_data: Vec<u8> = Vec::with_capacity(raw_data_size);

    // Total number of raw data bits we have written (unpadded from the `source`).
    let mut written_bits = 0;
    // Bit offset within the last byte at which the next write needs to happen
    // (derived from `written_bits`), we keep track of this since we write in chunks
    // that may not be byte-aligned.
    let mut write_bit_offset = 0;

    // If there is no more data to read or no more space to write stop.
    while read_pos.bytes < source.len() && written_bits < max_write_size_bits {
        // (1): Find the element boundary and, assuming that there is a full
        //      unit of data (which actually may be incomplete), how many bits
        //      are left to read from `read_pos`.
        let (next_element_position, mut bits_to_extract) = padding_map.next_boundary(&read_pos);

        // (2): As the element may be incomplete check how much data is
        //      actually available so as not to access the `source` past
        //      its limit.
        bits_to_extract = min(bits_to_extract, source.len() * 8 - read_pos.total_bits());

        // (3): Don't read more than `max_write_size`.
        let bits_left_to_write = max_write_size_bits - written_bits;
        bits_to_extract = min(bits_to_extract, bits_left_to_write);

        // Extract the next data unit from the element (or whatever space we
        // have left to write) and reposition it in the `write_bit_offset`.
        // N.B., the bit offset of the data in the original raw data byte
        // stream and the same data in the padded layout are not necessarily
        // the same (since the added padding bits shift it).
        let mut recovered = extract_bits_and_shift(
            &source,
            read_pos.total_bits(),
            bits_to_extract,
            write_bit_offset,
        );

        if write_bit_offset != 0 {
            // Since the two data units we are joining are not byte-aligned we can't
            // just append the whole bytes to `raw_data`, we need to join the last
            // byte of the already written `raw_data` with the first one of data unit
            // `recovered` in this iteration. Since `extract_bits_and_shift` already
            // takes care of setting to zero the bits beyond the extraction limit we
            // can just `OR` the two.
            *(raw_data.last_mut().expect("raw_data is empty")) |=
                *(recovered.first().expect("recovered is empty"));
            raw_data.append(&mut recovered[1..].to_vec());
        } else {
            raw_data.append(&mut recovered);
        }

        written_bits += bits_to_extract;
        write_bit_offset = written_bits % 8;

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

    // Check that our estimated size was correct, allow it to be overestimated
    // (not *under*) by 1 byte.
    debug_assert!(raw_data_size - raw_data.len() <= 1);
    debug_assert!(raw_data_size >= raw_data.len());

    target.write_all(&raw_data)?;

    Ok(raw_data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    use itertools::Itertools;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

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

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
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
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

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
        let mut reader = crate::fr32_reader::Fr32Reader::new(io::Cursor::new(&data));
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
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let len = 1016;
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();

        let mut padded = Vec::new();
        let mut reader = crate::fr32_reader::Fr32Reader::new(io::Cursor::new(&data));
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
