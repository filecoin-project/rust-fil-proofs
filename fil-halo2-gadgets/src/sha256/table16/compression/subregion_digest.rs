use super::super::{super::DIGEST_SIZE, RoundWordDense};
use super::{compression_util::*, CompressionConfig, State};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, Error},
};

use crate::boolean::AssignedBits;

impl<F: FieldExt> CompressionConfig<F> {
    #[allow(clippy::many_single_char_names)]
    pub fn assign_digest(
        &self,
        region: &mut Region<'_, F>,
        state: State<F>,
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        let [a_3, a_4, a_5, a_6, a_7, a_8, _a_9] = self.advice;

        let (a, b, c, d, e, f, g, h) = match_state(state);

        let abcd_row = 0;
        self.s_digest.enable(region, abcd_row)?;
        let efgh_row = abcd_row + 2;
        self.s_digest.enable(region, efgh_row)?;

        // Assign digest for A, B, C, D
        let a = self.assign_digest_word(region, abcd_row, a_3, a_4, a_5, a.dense_halves)?;
        let b = self.assign_digest_word(region, abcd_row, a_6, a_7, a_8, b.dense_halves)?;
        let c = self.assign_digest_word(region, abcd_row + 1, a_3, a_4, a_5, c.dense_halves)?;
        let d = self.assign_digest_word(region, abcd_row + 1, a_6, a_7, a_8, d)?;

        // Assign digest for E, F, G, H
        let e = self.assign_digest_word(region, efgh_row, a_3, a_4, a_5, e.dense_halves)?;
        let f = self.assign_digest_word(region, efgh_row, a_6, a_7, a_8, f.dense_halves)?;
        let g = self.assign_digest_word(region, efgh_row + 1, a_3, a_4, a_5, g.dense_halves)?;
        let h = self.assign_digest_word(region, efgh_row + 1, a_6, a_7, a_8, h)?;

        Ok([a, b, c, d, e, f, g, h])
    }

    fn assign_digest_word(
        &self,
        region: &mut Region<'_, F>,
        row: usize,
        lo_col: Column<Advice>,
        hi_col: Column<Advice>,
        word_col: Column<Advice>,
        dense_halves: RoundWordDense<F>,
    ) -> Result<AssignedBits<F, 32>, Error> {
        dense_halves.0.copy_advice(|| "lo", region, lo_col, row)?;
        dense_halves.1.copy_advice(|| "hi", region, hi_col, row)?;
        AssignedBits::<F, 32>::assign(region, || "word", word_col, row, dense_halves.value())
    }
}
