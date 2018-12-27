## Refactoring plan for the `fr32` module

* [ ]: `next_fr_end`, along with `target_offsets` it completes the methods that process the padded/unpadded position, which are always the first methods that call the write functions.

* [ ]: Refactor `write_padded_aux`. Move the call to `write_padded_aligned` at the end, unifying both cases, and setting the correct last two arguments (the first 3 are the same), that will prepare it to be merged with `write_padded_aligned`. Everything before the `write_padded_aligned` call should be the logic to align the persisted data.

* [ ]: Should we always call the `write_padded_aligned` function? Is there a case where we don't have enough to byte align the persisted padded data to prepare for it? It wouldn't seem so, the input raw data (byte-aligned) is always bigger than zero (check that), hence it's always bigger than 8 bits, with 7 being the maximum needed to byte align.

* [ ]: The whole concept of byte aligning may be unnecessary altogether, what we care about is reaching the element boundary, then we can write whole chunks of `data_chunk_bits` and pad directly (as its done at the end of `write_padded_aligned`), that should take the center of the write logic (the bye aligning, even if needed, could/should be handled separately).

* [ ]: Leave this for last: go to the lower levels of the of bit/byte positions transformation logic (only after resolving the higher level logic of the write functions), review and document `transform_bit_pos` and `transform_byte_pos` functions. It should be clear why the work the way they do, based on the `PaddingMap` invariants. They seem to be correct, but in a implicit and subtle way: they handle the padding case, and its inverse, unpadding, with the same logic; there's a symmetry that draws my attention that I'm not sure I can explain clearly.
