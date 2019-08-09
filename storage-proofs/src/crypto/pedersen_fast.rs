use crate::fr32::bytes_into_frs;
use algebra::biginteger::BigInteger;
use algebra::curves::{
    bls12_381::Bls12_381 as Bls12,
    jubjub::JubJubParameters,
    jubjub::{JubJubAffine, JubJubProjective as JubJub},
    models::twisted_edwards_extended::GroupAffine,
    models::twisted_edwards_extended::GroupProjective,
    models::ModelParameters,
    AffineCurve, ProjectiveCurve,
};
use algebra::{
    bytes::FromBytes,
    fields::{bls12_381::Fr, Field, FpParameters, PrimeField},
    groups::Group,
};
use bitvec::{self, BitVec};
use blake2s_simd::Params;
use dpc::crypto_primitives::crh::pedersen::PedersenWindow;
use dpc::crypto_primitives::crh::FixedLengthCRH;
use dpc::Error;
use rand::Rng;
use rand::SeedableRng;
use rand::XorShiftRng;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};

lazy_static! {
    pub static ref PEDERSEN_PARAMS: PedersenParameters = {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        PedersenCRH::<BigWindow>::setup(rng).unwrap()
    };
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigWindow;

impl PedersenWindow for BigWindow {
    const WINDOW_SIZE: usize = 16;
    const NUM_WINDOWS: usize = 1;
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

#[derive(Copy, Clone)]
pub enum Personalization {
    NoteCommitment,
    MerkleTree(usize),
    None,
}

impl Personalization {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalization::NoteCommitment => {
                vec![true, true, true, true, true, true, false, false]
            }
            Personalization::MerkleTree(num) => {
                assert!(num < 63);

                (0..6).map(|i| (num >> i) & 1 == 1).collect()
            }
            Personalization::None => vec![],
        }
    }
}

pub fn pedersen_hash<I>(personalization: Personalization, bits: I) -> JubJubAffine
where
    I: IntoIterator<Item = bool>,
{
    let mut bits: Vec<bool> = personalization
        .get_bits()
        .into_iter()
        .chain(bits.into_iter())
        .collect();

    while bits.len() % 8 != 0 {
        bits.push(false);
    }

    let bytes = BitVec::<bitvec::LittleEndian, _>::from(&bits[..]);

    PedersenCRH::<BigWindow>::evaluate(&PEDERSEN_PARAMS, bytes.as_ref()).unwrap()
}

pub fn pedersen(data: &[u8]) -> JubJubAffine {
    let bits = BitVec::<bitvec::LittleEndian, u8>::from(data);
    pedersen_hash(Personalization::None, bits)
}

/// Pedersen hashing for inputs that have length multiple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Fr {
    assert!(
        data.len() >= 2 * PEDERSEN_BLOCK_BYTES,
        "must be at least 2 block sizes long, got {}bits",
        data.len()
    );
    assert_eq!(
        data.len() % PEDERSEN_BLOCK_BYTES,
        0,
        "input must be a multiple of the blocksize"
    );
    let mut chunks = data.chunks(PEDERSEN_BLOCK_BYTES);
    let mut cur = Vec::with_capacity(2 * PEDERSEN_BLOCK_BYTES);
    cur.resize(PEDERSEN_BLOCK_BYTES, 0);
    cur[0..PEDERSEN_BLOCK_BYTES].copy_from_slice(chunks.nth(0).unwrap());

    for block in chunks {
        cur.resize(2 * PEDERSEN_BLOCK_BYTES, 0);
        cur[PEDERSEN_BLOCK_BYTES..].copy_from_slice(block);
        pedersen_compression(&mut cur);
    }

    let frs = bytes_into_frs::<Bls12>(&cur[0..PEDERSEN_BLOCK_BYTES])
        .expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

pub fn pedersen_compression(bytes: &mut Vec<u8>) {
    let point = pedersen(&bytes[..]);
    bytes.truncate(0);
    point
        .x
        .into_repr()
        .write_le(bytes)
        .expect("failed to write result hash")
}

/// First 64 bytes of the BLAKE2s input during group hash.
/// This is chosen to be some random string that we couldn't have anticipated
/// when we designed the algorithm, for rigidity purposes.
/// We deliberately use an ASCII hex string of 32 bytes here.
pub const GH_FIRST_BLOCK: &'static [u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

/// BLAKE2s Personalization for Pedersen hash generators.
pub const PEDERSEN_HASH_GENERATORS_PERSONALIZATION: &'static [u8; 8] = b"Zcash_PH";

#[derive(Clone, Default)]
pub struct PedersenParameters {
    pub generators: Vec<GroupAffine<JubJubParameters>>,
    pub exp_table: Vec<Vec<Vec<GroupAffine<JubJubParameters>>>>,
}

impl PedersenParameters {
    pub fn chunks_per_generator(&self) -> usize {
        63
    }
}

pub struct PedersenCRH<W: PedersenWindow> {
    window: PhantomData<W>,
}

fn find_group_hash(m: &[u8], personalization: &[u8; 8]) -> GroupAffine<JubJubParameters> {
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    loop {
        let gh = group_hash(&tag, personalization);
        println!("group hash: {:?}", &gh);
        // We don't want to overflow and start reusing generators
        assert!(tag[i] != u8::max_value());
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}

fn group_hash(tag: &[u8], personalization: &[u8]) -> Option<GroupAffine<JubJubParameters>> {
    assert_eq!(personalization.len(), 8);

    // TODO: do we need to adjust for the different modulus bits in here? This check
    // fails for the different curves.
    // Check to see that scalar field is 255 bits
    // assert!(<G::ScalarField as PrimeField>::Params::MODULUS_BITS == 255);

    let h1 = {
        let mut p = Params::new();
        p.hash_length(32);
        p.personal(personalization);
        p.key(&[]);
        p.salt(&[]);
        let mut h = p.to_state();
        h.update(GH_FIRST_BLOCK);
        h.update(tag);
        let h = h.finalize();
        assert!(h.as_ref().len() == 32);
        h
    };
    let h2 = {
        let mut p = Params::new();
        p.hash_length(32);
        p.personal(personalization);
        p.key(&[]);
        p.salt(&[]);
        let mut h = p.to_state();
        h.update(GH_FIRST_BLOCK);
        h.update(tag);
        let h = h.finalize();
        assert!(h.as_ref().len() == 32);
        h
    };

    let mut r = h1.as_ref().to_vec();
    r.extend_from_slice(h2.as_ref());

    match JubJubAffine::read(&r[..]) {
        Ok(p) => {
            let p = p.mul_by_cofactor();

            if !AffineCurve::is_zero(&p) {
                Some(p)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

impl<W: PedersenWindow> PedersenCRH<W> {
    // Create the bases for the Pedersen hashes
    pub fn create_generators<R: Rng>(rng: &mut R) -> Vec<GroupAffine<JubJubParameters>> {
        let mut generators: Vec<GroupAffine<JubJubParameters>> = vec![];

        for m in 0..5 {
            use byteorder::{LittleEndian, WriteBytesExt};

            let mut segment_number = [0u8; 4];
            (&mut segment_number[0..4])
                .write_u32::<LittleEndian>(m)
                .unwrap();

            generators.push(find_group_hash(
                &segment_number,
                PEDERSEN_HASH_GENERATORS_PERSONALIZATION,
            ));
        }

        // Check for duplicates, far worse than spec inconsistencies!
        for (i, p1) in generators.iter().enumerate() {
            if AffineCurve::is_zero(p1) {
                panic!("Neutral element!");
            }

            for p2 in generators.iter().skip(i + 1) {
                if p1 == p2 {
                    panic!("Duplicate generator!");
                }
            }
        }

        generators
    }

    // Create the exp table for the Pedersen hash generators
    pub fn create_exp_table(
        generators: &[GroupAffine<JubJubParameters>],
    ) -> Vec<Vec<Vec<GroupAffine<JubJubParameters>>>> {
        let mut exp = vec![];
        let window = W::WINDOW_SIZE;

        for g in generators {
            let mut g = g.clone();
            let mut tables = vec![];

            let mut num_bits = 0;
            while num_bits <= <<JubJubParameters as ModelParameters>::ScalarField as PrimeField>::Params::MODULUS_BITS {
                let mut table = Vec::with_capacity(1 << window);

                let mut base = <JubJubAffine as AffineCurve>::zero();

                for _ in 0..(1 << window) {
                    table.push(base.clone());
                    base += &g;
                }

                tables.push(table);
                num_bits += window as u32;

                for _ in 0..window {
                    g.double_in_place();
                }
            }

            exp.push(tables);
        }

        exp
    }
}

impl<W: PedersenWindow> FixedLengthCRH for PedersenCRH<W> {
    const INPUT_SIZE_BITS: usize = W::WINDOW_SIZE * W::NUM_WINDOWS;
    type Output = JubJubAffine;
    type Parameters = PedersenParameters;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let generators = Self::create_generators(rng);
        let exp_table = Self::create_exp_table(&generators);

        Ok(Self::Parameters {
            generators,
            exp_table,
        })
    }

    fn evaluate(params: &Self::Parameters, bits: &[u8]) -> Result<Self::Output, Error> {
        let mut bits = BitVec::<bitvec::LittleEndian, u8>::from(bits).into_iter();
        let mut result = <JubJubAffine as AffineCurve>::zero();
        let mut generators = params.exp_table.iter();

        loop {
            let mut acc = <JubJubParameters as ModelParameters>::ScalarField::zero();
            let mut cur = <JubJubParameters as ModelParameters>::ScalarField::one();
            let mut chunks_remaining = params.chunks_per_generator();
            let mut encountered_bits = false;

            // Grab three bits from the input
            while let Some(a) = bits.next() {
                encountered_bits = true;

                let b = bits.next().unwrap_or(false);
                let c = bits.next().unwrap_or(false);

                // Start computing this portion of the scalar
                let mut tmp = cur;
                if a {
                    tmp += &cur;
                }
                cur.double_in_place(); // 2^1 * cur
                if b {
                    tmp += &cur;
                }

                // conditionally negate
                if c {
                    tmp = -tmp;
                }

                acc += &tmp;

                chunks_remaining -= 1;

                if chunks_remaining == 0 {
                    break;
                } else {
                    cur.double_in_place(); // 2^2 * cur
                    cur.double_in_place(); // 2^3 * cur
                    cur.double_in_place(); // 2^4 * cur
                }
            }

            if !encountered_bits {
                break;
            }

            let mut table: &[Vec<_>] = &generators.next().expect("we don't have enough generators");
            let window = W::WINDOW_SIZE;
            let window_mask = (1 << window) - 1;

            let mut acc = acc.into_repr();

            let mut tmp = <JubJubAffine as AffineCurve>::zero();

            while !acc.is_zero() {
                let i = (acc.as_ref()[0] & window_mask) as usize;

                tmp += &table[0][i];

                acc.divn(window as u32);
                table = &table[1..];
            }

            result += &tmp;
        }

        Ok(result)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1)
        }
    }
    bits
}

impl Debug for PedersenParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Pedersen Hash Parameters {{\n")?;
        for (i, g) in self.generators.iter().enumerate() {
            write!(f, "\t  Generator {}: {:?}\n", i, g)?;
        }
        // TODO: exp_table
        write!(f, "}}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::bytes_into_bits;
    use algebra::fields::Field;
    use rand::Rng;
    use rand::SeedableRng;
    use rand::XorShiftRng;

    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let mut bits2 = core::iter::repeat(false)
            .take(bits.len())
            .collect::<BitVec<bitvec::LittleEndian, u8>>();
        bits2.as_mut()[0..bytes.len()].copy_from_slice(&bytes[..]);

        assert_eq!(bits, bits2.iter().collect::<Vec<bool>>());
    }

    #[test]
    fn test_pedersen_compression() {
        let bytes = b"some bytes";
        let mut data = vec![0; bytes.len()];
        data.copy_from_slice(&bytes[..]);
        pedersen_compression(&mut data);
        let expected = vec![
            237, 70, 41, 231, 39, 180, 131, 120, 36, 36, 119, 199, 200, 225, 153, 242, 106, 116,
            70, 9, 12, 249, 169, 84, 105, 38, 225, 115, 165, 188, 98, 25,
        ];
        // Note: this test fails as we use different generator points and zexe used a slightly different approach
        // for Pedersen hashing (no windowing). Hence the expected output should be updated.
        assert_eq!(expected, data);
    }

    #[test]
    fn test_pedersen_md_no_padding() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..5 {
            let x: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let hashed = pedersen_md_no_padding(x.as_slice());
            assert_ne!(hashed, Fr::zero());
        }
    }
}
