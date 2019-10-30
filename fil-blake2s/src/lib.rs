#![feature(stdarch, stdsimd)]
#![allow(
    clippy::cast_ptr_alignment,
    clippy::missing_safety_doc,
    clippy::many_single_char_names
)]

#[cfg(target_feature = "sse4.1")]
mod hasher {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::_MM_SHUFFLE;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    const IV_0_3: [u32; 4] = [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A];
    const IV_4_7: [u32; 4] = [0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19];

    // Default Parameters
    // Digest Length = 32 (0x20)
    // Fanout = 1
    // Depth  = 1
    // Initial h is IV ^ P
    // 0x01010020 ^ IV_0_3[0] = 0x6B08E647

    pub const INITIAL_H: [u8; 32] = [
        0x47, 0xE6, 0x08, 0x6B, 0x85, 0xAE, 0x67, 0xBB, 0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xF5, 0x4F,
        0xA5, 0x7F, 0x52, 0x0E, 0x51, 0x8C, 0x68, 0x05, 0x9B, 0xAB, 0xD9, 0x83, 0x1F, 0x19, 0xCD,
        0xE0, 0x5B,
    ];

    mod blake2s_first_msg {
        use core::arch::x86_64::_MM_SHUFFLE;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        #[inline(always)]
        pub unsafe fn rnd_0(m0: &__m128i, m1: &__m128i, _m2: &__m128i, _m3: &__m128i) -> __m128i {
            _mm_castps_si128(_mm_shuffle_ps(
                _mm_castsi128_ps(*m0),
                _mm_castsi128_ps(*m1),
                _MM_SHUFFLE(2, 0, 2, 0),
            ))
        }

        #[inline(always)]
        pub unsafe fn rnd_1(_m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m1, *m2, 0x0C);
            let tmp_1 = _mm_slli_si128(*m3, 4);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0xF0);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 1, 0, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_2(_m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m2, *m3);
            let tmp_1 = _mm_blend_epi16(*m3, *m1, 0x0C);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x0F);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(3, 1, 0, 2))
        }

        #[inline(always)]
        pub unsafe fn rnd_3(m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m1);
            let tmp_1 = _mm_unpackhi_epi32(tmp_0, *m2);
            let tmp_2 = _mm_blend_epi16(tmp_1, *m3, 0x0C);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(3, 1, 0, 2))
        }

        #[inline(always)]
        pub unsafe fn rnd_4(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi64(*m1, *m2);
            let tmp_1 = _mm_unpackhi_epi64(*m0, *m2);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x33);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 0, 1, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_5(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m1);
            let tmp_1 = _mm_unpacklo_epi32(*m0, *m2);

            _mm_unpacklo_epi64(tmp_0, tmp_1)
        }

        #[inline(always)]
        pub unsafe fn rnd_6(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_slli_si128(*m1, 12);
            let tmp_1 = _mm_blend_epi16(*m0, *m3, 0x33);

            _mm_blend_epi16(tmp_1, tmp_0, 0xC0)
        }

        #[inline(always)]
        pub unsafe fn rnd_7(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m1);
            let tmp_1 = _mm_blend_epi16(tmp_0, *m3, 0x0F);

            _mm_shuffle_epi32(tmp_1, _MM_SHUFFLE(2, 0, 3, 1))
        }

        #[inline(always)]
        pub unsafe fn rnd_8(m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m1, *m3);
            let tmp_1 = _mm_unpacklo_epi64(tmp_0, *m0);
            let tmp_2 = _mm_blend_epi16(tmp_1, *m2, 0xC0);

            _mm_shufflehi_epi16(tmp_2, _MM_SHUFFLE(1, 0, 3, 2))
        }

        #[inline(always)]
        pub unsafe fn rnd_9(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m0, *m2, 0x03);
            let tmp_1 = _mm_blend_epi16(*m1, *m2, 0x30);
            let tmp_2 = _mm_blend_epi16(tmp_1, tmp_0, 0x0F);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(1, 3, 0, 2))
        }
    }

    mod blake2s_second_msg {
        use core::arch::x86_64::_MM_SHUFFLE;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        #[inline(always)]
        pub unsafe fn rnd_0(m0: &__m128i, m1: &__m128i, _m2: &__m128i, _m3: &__m128i) -> __m128i {
            _mm_castps_si128(_mm_shuffle_ps(
                _mm_castsi128_ps(*m0),
                _mm_castsi128_ps(*m1),
                _MM_SHUFFLE(3, 1, 3, 1),
            ))
        }

        #[inline(always)]
        pub unsafe fn rnd_1(_m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_shuffle_epi32(*m2, _MM_SHUFFLE(0, 0, 2, 0));
            let tmp_1 = _mm_blend_epi16(*m1, *m3, 0xC0);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0xF0);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 3, 0, 1))
        }

        #[inline(always)]
        pub unsafe fn rnd_2(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi32(*m2, *m0);
            let tmp_1 = _mm_blend_epi16(tmp_0, *m0, 0xF0);
            let tmp_2 = _mm_slli_si128(*m3, 8);

            _mm_blend_epi16(tmp_1, tmp_2, 0xC0)
        }

        #[inline(always)]
        pub unsafe fn rnd_3(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_slli_si128(*m2, 8);
            let tmp_1 = _mm_blend_epi16(*m3, *m0, 0x0C);
            let tmp_2 = _mm_blend_epi16(tmp_1, tmp_0, 0xC0);
            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 0, 1, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_4(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi64(*m1, *m3);
            let tmp_1 = _mm_unpacklo_epi64(*m0, *m1);

            _mm_blend_epi16(tmp_0, tmp_1, 0x33)
        }

        #[inline(always)]
        pub unsafe fn rnd_5(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_srli_si128(*m2, 4);
            let tmp_1 = _mm_blend_epi16(*m0, *m3, 0x03);

            _mm_blend_epi16(tmp_1, tmp_0, 0x3C)
        }

        #[inline(always)]
        pub unsafe fn rnd_6(_m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m3, *m2, 0x30);
            let tmp_1 = _mm_srli_si128(*m1, 4);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x03);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 1, 3, 0))
        }

        #[inline(always)]
        pub unsafe fn rnd_7(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m2, *m3, 0x30);
            let tmp_1 = _mm_srli_si128(*m0, 4);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x03);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(1, 0, 2, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_8(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m3);
            let tmp_1 = _mm_blend_epi16(*m2, tmp_0, 0xF0);

            _mm_shuffle_epi32(tmp_1, _MM_SHUFFLE(0, 2, 1, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_9(m0: &__m128i, m1: &__m128i, _m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_slli_si128(*m0, 4);
            let tmp_1 = _mm_blend_epi16(*m1, tmp_0, 0xC0);

            _mm_shuffle_epi32(tmp_1, _MM_SHUFFLE(1, 2, 0, 3))
        }
    }

    mod blake2s_third_msg {
        use core::arch::x86_64::_MM_SHUFFLE;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        #[inline(always)]
        pub unsafe fn rnd_0(_m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_shuffle_epi32(*m2, _MM_SHUFFLE(3, 2, 0, 1));
            let tmp_1 = _mm_shuffle_epi32(*m3, _MM_SHUFFLE(0, 1, 3, 2));

            _mm_blend_epi16(tmp_0, tmp_1, 0xC3)
        }

        #[inline(always)]
        pub unsafe fn rnd_1(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_slli_si128(*m1, 4);
            let tmp_1 = _mm_blend_epi16(*m2, tmp_0, 0x30);
            let tmp_2 = _mm_blend_epi16(*m0, tmp_1, 0xF0);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(3, 0, 1, 2))
        }

        #[inline(always)]
        pub unsafe fn rnd_2(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m0, *m2, 0x3C);
            let tmp_1 = _mm_srli_si128(*m1, 12);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x03);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(0, 3, 2, 1))
        }

        #[inline(always)]
        pub unsafe fn rnd_3(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m0, *m1, 0x0F);
            let tmp_1 = _mm_blend_epi16(tmp_0, *m3, 0xC0);

            _mm_shuffle_epi32(tmp_1, _MM_SHUFFLE(0, 1, 2, 3))
        }

        #[inline(always)]
        pub unsafe fn rnd_4(m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi64(*m3, *m1); //  7  6 15 14
            let tmp_1 = _mm_unpackhi_epi64(*m2, *m0); //  3  2 11 10
            let tmp_2 = _mm_blend_epi16(tmp_1, tmp_0, 0x33); //  3  6 11 14

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 1, 0, 3)) //  6 11 14  3
        }

        #[inline(always)]
        pub unsafe fn rnd_5(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m1, *m0, 0x0C); //  7  6  1  4
            let tmp_1 = _mm_srli_si128(*m3, 4); //  x 15 14 13
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x30); //  7 15  1  4

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 3, 0, 1)) // 15  7  4  1
        }

        #[inline(always)]
        pub unsafe fn rnd_6(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi64(*m0, *m2); //  9  8  1  0
            let tmp_1 = _mm_srli_si128(*m1, 4); //  x  7  6  5
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x0C); //  9  8  6  0
            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(3, 1, 0, 2)) //  9  6  0  8
        }

        #[inline(always)]
        pub unsafe fn rnd_7(m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi64(*m0, *m3); // 15 14  3  2
            let tmp_1 = _mm_unpacklo_epi64(*m1, *m2); //  9  8  5  4
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x3C); // 15  8  5  2

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 3, 1, 0)) //  8 15  5  2
        }

        #[inline(always)]
        pub unsafe fn rnd_8(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi64(*m0, *m3); // 13 12  1  0
            let tmp_1 = _mm_srli_si128(*m2, 8); //  x  x 11 10
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x03); // 13 12  1 10

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(1, 3, 2, 0)) //  1 13 12 10
        }

        #[inline(always)]
        pub unsafe fn rnd_9(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m3); // 15  3 14  2
            let tmp_1 = _mm_unpacklo_epi32(*m2, *m3); // 13  9 12  8
            let tmp_2 = _mm_unpackhi_epi64(tmp_0, tmp_1); // 13  9 15  3

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(0, 2, 1, 3)) //  3  9 15 13
        }
    }

    mod blake2s_fourth_msg {
        use core::arch::x86_64::_MM_SHUFFLE;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        #[inline(always)]
        pub unsafe fn rnd_0(_m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            // Could optimize by combining with third msg
            let tmp_0 = _mm_shuffle_epi32(*m2, _MM_SHUFFLE(2, 3, 1, 0)); // 10 11  9  8
            let tmp_1 = _mm_shuffle_epi32(*m3, _MM_SHUFFLE(1, 2, 0, 3)); // 13 14 12 15

            _mm_blend_epi16(tmp_0, tmp_1, 0xC3)
        }

        #[inline(always)]
        pub unsafe fn rnd_1(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m0, *m1);
            let tmp_1 = _mm_slli_si128(*m3, 4);
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x0C);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(3, 0, 1, 2))
        }

        #[inline(always)]
        pub unsafe fn rnd_2(m0: &__m128i, m1: &__m128i, _m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_slli_si128(*m3, 4);
            let tmp_1 = _mm_blend_epi16(*m0, *m1, 0x33);
            let tmp_2 = _mm_blend_epi16(tmp_1, tmp_0, 0xC0);

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(1, 2, 3, 0))
        }

        #[inline(always)]
        pub unsafe fn rnd_3(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_alignr_epi8(*m0, *m1, 4); //  0  7  6  5

            _mm_blend_epi16(tmp_0, *m2, 0x33) //  0 10  6  8
        }

        #[inline(always)]
        pub unsafe fn rnd_4(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m0, *m2, 0x03);
            let tmp_1 = _mm_slli_si128(tmp_0, 8);
            let tmp_2 = _mm_blend_epi16(tmp_1, *m3, 0x0F); //  1  8 13 12

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 0, 3, 1)) //  8 12  1 13
        }

        #[inline(always)]
        pub unsafe fn rnd_5(_m0: &__m128i, m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi64(*m2, *m1); //  5  4  9  8
            let tmp_1 = _mm_shuffle_epi32(*m3, _MM_SHUFFLE(2, 0, 1, 0)); // 14 12 13 12
            let tmp_2 = _mm_srli_si128(tmp_0, 4); //  x  5  4  9

            _mm_blend_epi16(tmp_1, tmp_2, 0x33) // 14  5 13  9
        }

        #[inline(always)]
        pub unsafe fn rnd_6(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpackhi_epi32(*m1, *m2); // 11  7 10  6
            let tmp_1 = _mm_unpackhi_epi64(*m0, tmp_0); // 11  7  3  2

            _mm_shuffle_epi32(tmp_1, _MM_SHUFFLE(0, 1, 2, 3)) //  2  3  7 11
        }

        #[inline(always)]
        pub unsafe fn rnd_7(m0: &__m128i, m1: &__m128i, m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_unpacklo_epi32(*m0, *m1); //  5  1  4  0
            let tmp_1 = _mm_unpackhi_epi32(*m1, *m2); // 11  7 10  6
            let tmp_2 = _mm_unpacklo_epi64(tmp_0, tmp_1); // 10  6  4  0

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(2, 1, 0, 3)) //  6  4  0 10
        }

        #[inline(always)]
        pub unsafe fn rnd_8(m0: &__m128i, m1: &__m128i, _m2: &__m128i, _m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m1, *m0, 0x30); //  7  2  5  4

            _mm_shuffle_epi32(tmp_0, _MM_SHUFFLE(0, 3, 2, 1)) //  4  7  2  5
        }

        #[inline(always)]
        pub unsafe fn rnd_9(m0: &__m128i, _m1: &__m128i, m2: &__m128i, m3: &__m128i) -> __m128i {
            let tmp_0 = _mm_blend_epi16(*m3, *m2, 0xC0); // 11 14 13 12
            let tmp_1 = _mm_unpacklo_epi32(*m0, *m3); // 13  1 12  0
            let tmp_2 = _mm_blend_epi16(tmp_0, tmp_1, 0x0F); // 11 14 12  0

            _mm_shuffle_epi32(tmp_2, _MM_SHUFFLE(1, 2, 3, 0)) // 12 14 11  0
        }
    }

    macro_rules! blake2s_g1 {
        ($a:expr, $b:expr, $c:expr, $d:expr, $m:expr) => {
            $a = _mm_add_epi32($a, $m);
            $a = _mm_add_epi32($a, $b);
            $d = _mm_xor_si128($d, $a);
            $d = _mm_shuffle_epi8(
                $d,
                _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2),
            );
            $c = _mm_add_epi32($c, $d);
            $b = _mm_xor_si128($b, $c);
            $b = _mm_xor_si128(_mm_srli_epi32($b, 12), _mm_slli_epi32($b, 20));
        };
    }

    macro_rules! blake2s_g2 {
        ($a:expr, $b:expr, $c:expr, $d:expr, $m:expr) => {
            $a = _mm_add_epi32($a, $m);
            $a = _mm_add_epi32($a, $b);
            $d = _mm_xor_si128($d, $a);
            $d = _mm_shuffle_epi8(
                $d,
                _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1),
            );
            $c = _mm_add_epi32($c, $d);
            $b = _mm_xor_si128($b, $c);
            $b = _mm_xor_si128(_mm_srli_epi32($b, 7), _mm_slli_epi32($b, 25));
        };
    }

    macro_rules! blake2s_g {
        ($a:expr, $b:expr, $c:expr, $d:expr, $m_even:expr, $m_odd:expr) => {
            $a = _mm_add_epi32($a, $m_even);
            $a = _mm_add_epi32($a, $b);
            $d = _mm_xor_si128($d, $a);
            $d = _mm_shuffle_epi8(
                $d,
                _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2),
            );
            $c = _mm_add_epi32($c, $d);
            $b = _mm_xor_si128($b, $c);
            $b = _mm_xor_si128(_mm_srli_epi32($b, 12), _mm_slli_epi32($b, 20));
            $a = _mm_add_epi32($a, $m_odd);
            $a = _mm_add_epi32($a, $b);
            $d = _mm_xor_si128($d, $a);
            $d = _mm_shuffle_epi8(
                $d,
                _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1),
            );
            $c = _mm_add_epi32($c, $d);
            $b = _mm_xor_si128($b, $c);
            $b = _mm_xor_si128(_mm_srli_epi32($b, 7), _mm_slli_epi32($b, 25));
        };
    }

    macro_rules! diagonalize {
        ($a:expr, $c:expr, $d:expr) => {
            $a = _mm_shuffle_epi32($a, _MM_SHUFFLE(2, 1, 0, 3));
            $d = _mm_shuffle_epi32($d, _MM_SHUFFLE(1, 0, 3, 2));
            $c = _mm_shuffle_epi32($c, _MM_SHUFFLE(0, 3, 2, 1));
        };
    }

    macro_rules! undiagonalize {
        ($a:expr, $c:expr, $d:expr) => {
            $a = _mm_shuffle_epi32($a, _MM_SHUFFLE(0, 3, 2, 1));
            $d = _mm_shuffle_epi32($d, _MM_SHUFFLE(1, 0, 3, 2));
            $c = _mm_shuffle_epi32($c, _MM_SHUFFLE(2, 1, 0, 3));
        };
    }

    macro_rules! round {
        ($a:expr, $b:expr, $c:expr, $d:expr,
     $m0:expr, $m1:expr, $m2:expr, $m3:expr, $rnd:ident) => {
            let m_i = blake2s_first_msg::$rnd(&$m0, &$m1, &$m2, &$m3);
            blake2s_g1!($a, $b, $c, $d, m_i);
            let m_i = blake2s_second_msg::$rnd(&$m0, &$m1, &$m2, &$m3);
            blake2s_g2!($a, $b, $c, $d, m_i);
            diagonalize!($a, $c, $d);
            let m_i = blake2s_third_msg::$rnd(&$m0, &$m1, &$m2, &$m3);
            blake2s_g1!($a, $b, $c, $d, m_i);
            let m_i = blake2s_fourth_msg::$rnd(&$m0, &$m1, &$m2, &$m3);
            blake2s_g2!($a, $b, $c, $d, m_i);
            undiagonalize!($a, $c, $d);
        };
    }

    #[inline(always)]
    unsafe fn blake2s_16(parents: &[&[u8]], digest: &mut [u8; 32]) {
        let mut count: i32 = 64; // Byte counter, increments by 64B
        let mut last_block: u32 = 0; // Finalization flag, !0 for last block

        // Prefetch each node value
        assert_eq!(parents.len(), 16);
        for parent in parents {
            _mm_prefetch(parent.as_ptr() as *const i8, _MM_HINT_T0);
        }

        let mut curr_digest_0_3 = _mm_loadu_si128(digest.as_ptr() as *const __m128i);
        let mut curr_digest_4_7 = _mm_loadu_si128(digest.as_ptr().add(16) as *const __m128i);

        // id + node + 14 parents, each value is 32B.  Uses 8 blocks
        for i in 0..8 {
            // set internal state
            let mut a = curr_digest_0_3;
            let mut b = curr_digest_4_7;
            let mut c = _mm_loadu_si128(IV_0_3.as_ptr() as *const __m128i);
            let mut d = _mm_xor_si128(
                _mm_loadu_si128(IV_4_7.as_ptr() as *const __m128i),
                _mm_setr_epi32(count, 0, last_block as i32, 0),
            );

            // Set for next iteration
            count += 64;
            if i == 6 {
                last_block = 0xFFFF_FFFF;
            }

            // set message
            let m0 = _mm_loadu_si128(parents[i * 2].as_ptr() as *const __m128i);
            let m1 = _mm_loadu_si128(parents[i * 2].as_ptr().add(16) as *const __m128i);
            let m2 = _mm_loadu_si128(parents[(i * 2) + 1].as_ptr() as *const __m128i);
            let m3 = _mm_loadu_si128(parents[(i * 2) + 1].as_ptr().add(16) as *const __m128i);

            // round 0
            let m_i_0 = blake2s_first_msg::rnd_0(&m0, &m1, &m2, &m3);
            let m_i_1 = blake2s_second_msg::rnd_0(&m0, &m1, &m2, &m3);
            blake2s_g!(a, b, c, d, m_i_0, m_i_1);
            diagonalize!(a, c, d);

            // TODO - difference between these is 3ns/iter
            //let m_i_0  = blake2s_third_msg::rnd_0(&m0, &m1, &m2, &m3);
            //let m_i_1  = blake2s_fourth_msg::rnd_0(&m0, &m1, &m2, &m3);
            let tmp_0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(3, 2, 0, 1));
            let tmp_1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0, 1, 3, 2));
            let m_i_0 = _mm_blend_epi16(tmp_0, tmp_1, 0xC3);
            let tmp_0 = _mm_blend_epi16(tmp_0, tmp_1, 0x3C);
            let m_i_1 = _mm_shuffle_epi32(tmp_0, _MM_SHUFFLE(2, 3, 0, 1));

            blake2s_g!(a, b, c, d, m_i_0, m_i_1);
            undiagonalize!(a, c, d);

            round!(a, b, c, d, m0, m1, m2, m3, rnd_1);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_2);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_3);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_4);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_5);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_6);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_7);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_8);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_9);

            curr_digest_0_3 = {
                let xor_vars = _mm_xor_si128(a, c);
                let h = _mm_loadu_si128(digest.as_ptr() as *const __m128i);
                _mm_xor_si128(h, xor_vars)
            };

            curr_digest_4_7 = {
                let xor_vars = _mm_xor_si128(b, d);
                let h = _mm_loadu_si128(digest.as_ptr().add(16) as *const __m128i);
                _mm_xor_si128(h, xor_vars)
            };

            _mm_storeu_si128(digest.as_ptr() as *mut __m128i, curr_digest_0_3);
            _mm_storeu_si128(digest.as_ptr().add(16) as *mut __m128i, curr_digest_4_7);
        }
        //println!("0_3 {:x?}", curr_digest_0_3);
        //println!("4_7 {:x?}", curr_digest_4_7);
    }

    pub unsafe fn hash_nodes_16(parents: &[&[u8]], digest: &mut [u8; 32]) {
        blake2s_16(parents, digest);
    }

    #[inline(always)]
    unsafe fn blake2s_8(parents: &[&[u8]], digest: &mut [u8; 32]) {
        let mut count: i32 = 64; // Byte counter, increments by 64B
        let mut last_block: u32 = 0; // Finalization flag, !0 for last block

        // Prefetch each node value
        assert_eq!(parents.len(), 8);
        for parent in parents {
            _mm_prefetch(parent.as_ptr() as *const i8, _MM_HINT_T0);
        }

        let mut curr_digest_0_3 = _mm_loadu_si128(digest.as_ptr() as *const __m128i);
        let mut curr_digest_4_7 = _mm_loadu_si128(digest.as_ptr().add(16) as *const __m128i);

        // id + node + 6 parents, each value is 32B.  Uses 4 blocks
        for i in 0..4 {
            // set internal state
            let mut a = curr_digest_0_3;
            let mut b = curr_digest_4_7;
            let mut c = _mm_loadu_si128(IV_0_3.as_ptr() as *const __m128i);
            let mut d = _mm_xor_si128(
                _mm_loadu_si128(IV_4_7.as_ptr() as *const __m128i),
                _mm_setr_epi32(count, 0, last_block as i32, 0),
            );

            // Set for next iteration
            count += 64;
            if i == 2 {
                last_block = 0xFFFF_FFFF;
            }

            // set message
            let m0 = _mm_loadu_si128(parents[i * 2].as_ptr() as *const __m128i);
            let m1 = _mm_loadu_si128(parents[i * 2].as_ptr().add(16) as *const __m128i);
            let m2 = _mm_loadu_si128(parents[(i * 2) + 1].as_ptr() as *const __m128i);
            let m3 = _mm_loadu_si128(parents[(i * 2) + 1].as_ptr().add(16) as *const __m128i);

            // round 0
            let m_i_0 = blake2s_first_msg::rnd_0(&m0, &m1, &m2, &m3);
            let m_i_1 = blake2s_second_msg::rnd_0(&m0, &m1, &m2, &m3);
            blake2s_g!(a, b, c, d, m_i_0, m_i_1);
            diagonalize!(a, c, d);

            // TODO - difference between these is 3ns/iter
            //let m_i_0  = blake2s_third_msg::rnd_0(&m0, &m1, &m2, &m3);
            //let m_i_1  = blake2s_fourth_msg::rnd_0(&m0, &m1, &m2, &m3);
            let tmp_0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(3, 2, 0, 1));
            let tmp_1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0, 1, 3, 2));
            let m_i_0 = _mm_blend_epi16(tmp_0, tmp_1, 0xC3);
            let tmp_0 = _mm_blend_epi16(tmp_0, tmp_1, 0x3C);
            let m_i_1 = _mm_shuffle_epi32(tmp_0, _MM_SHUFFLE(2, 3, 0, 1));

            blake2s_g!(a, b, c, d, m_i_0, m_i_1);
            undiagonalize!(a, c, d);

            round!(a, b, c, d, m0, m1, m2, m3, rnd_1);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_2);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_3);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_4);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_5);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_6);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_7);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_8);
            round!(a, b, c, d, m0, m1, m2, m3, rnd_9);

            curr_digest_0_3 = {
                let xor_vars = _mm_xor_si128(a, c);
                let h = _mm_loadu_si128(digest.as_ptr() as *const __m128i);
                _mm_xor_si128(h, xor_vars)
            };

            curr_digest_4_7 = {
                let xor_vars = _mm_xor_si128(b, d);
                let h = _mm_loadu_si128(digest.as_ptr().add(16) as *const __m128i);
                _mm_xor_si128(h, xor_vars)
            };

            _mm_storeu_si128(digest.as_ptr() as *mut __m128i, curr_digest_0_3);
            _mm_storeu_si128(digest.as_ptr().add(16) as *mut __m128i, curr_digest_4_7);
        }
        //println!("0_3 {:x?}", curr_digest_0_3);
        //println!("4_7 {:x?}", curr_digest_4_7);
    }

    pub unsafe fn hash_nodes_8(parents: &[&[u8]], digest: &mut [u8; 32]) {
        blake2s_8(parents, digest);
    }
}

#[cfg(target_feature = "sse4.1")]
pub fn hash_nodes_16(parents: &[&[u8]]) -> [u8; 32] {
    let digest = &mut hasher::INITIAL_H.clone();
    unsafe {
        hasher::hash_nodes_16(parents, digest);
    }

    *digest
}

#[cfg(not(target_feature = "sse4.1"))]
pub fn hash_nodes_16(parents: &[&[u8]]) -> [u8; 32] {
    let mut s = blake2s_simd::Params::new().to_state();
    for parent in parents {
        s.update(parent);
    }
    *s.finalize().as_array()
}

#[cfg(target_feature = "sse4.1")]
pub fn hash_nodes_8(parents: &[&[u8]]) -> [u8; 32] {
    let digest = &mut hasher::INITIAL_H.clone();
    unsafe {
        hasher::hash_nodes_8(parents, digest);
    }

    *digest
}

#[cfg(not(target_feature = "sse4.1"))]
pub fn hash_nodes_8(parents: &[&[u8]]) -> [u8; 32] {
    let mut s = blake2s_simd::Params::new().to_state();
    for parent in parents {
        s.update(parent);
    }
    *s.finalize().as_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_consistency_hash_16() {
        for _ in 0..1000 {
            let mut rng: SmallRng = SeedableRng::seed_from_u64(1);

            let rep: [u8; 32] = rng.gen();
            let node: [u8; 32] = rng.gen();
            let p0: [u8; 32] = rng.gen();
            let p1: [u8; 32] = rng.gen();
            let p2: [u8; 32] = rng.gen();
            let p3: [u8; 32] = rng.gen();
            let p4: [u8; 32] = rng.gen();
            let p5: [u8; 32] = rng.gen();
            let p6: [u8; 32] = rng.gen();
            let p7: [u8; 32] = rng.gen();
            let p8: [u8; 32] = rng.gen();
            let p9: [u8; 32] = rng.gen();
            let p10: [u8; 32] = rng.gen();
            let p11: [u8; 32] = rng.gen();
            let p12: [u8; 32] = rng.gen();
            let p13: [u8; 32] = rng.gen();

            let parents: [&[u8]; 16] = [
                &rep, &node, &p0, &p1, &p2, &p3, &p4, &p5, &p6, &p7, &p8, &p9, &p10, &p11, &p12,
                &p13,
            ];

            let h1 = hash_nodes_16(&parents);

            let mut s = blake2s_simd::Params::new().to_state();
            for parent in &parents {
                s.update(parent);
            }
            let h2 = *s.finalize().as_array();

            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn test_consistency_hash_8() {
        for _ in 0..1000 {
            let mut rng: SmallRng = SeedableRng::seed_from_u64(1);

            let rep: [u8; 32] = rng.gen();
            let node: [u8; 32] = rng.gen();
            let p0: [u8; 32] = rng.gen();
            let p1: [u8; 32] = rng.gen();
            let p2: [u8; 32] = rng.gen();
            let p3: [u8; 32] = rng.gen();
            let p4: [u8; 32] = rng.gen();
            let p5: [u8; 32] = rng.gen();

            let parents: [&[u8]; 8] = [&rep, &node, &p0, &p1, &p2, &p3, &p4, &p5];

            let h1 = hash_nodes_8(&parents);

            let mut s = blake2s_simd::Params::new().to_state();
            for parent in &parents {
                s.update(parent);
            }
            let h2 = *s.finalize().as_array();

            assert_eq!(h1, h2);
        }
    }
}
