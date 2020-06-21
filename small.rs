use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::size_of;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ff::{Field, PrimeField};
use groupy::{CurveAffine, CurveProjective, EncodedPoint, Wnaf};
use log::{error, info};
use paired::bls12_381::{
    Fr, G1Affine, G1Uncompressed, G2Affine, G2Uncompressed, G1 as G1Projective,
};
use rand::Rng;

use crate::{hash_to_g2, merge_pairs, same_ratio, HashWriter, PrivateKey, PublicKey};

#[derive(Clone)]
pub struct MPCSmall {
    // The Groth16 verification-key's deltas G1 and G2. For all non-initial parameters
    // `delta_g1 == contributions.last().delta_after`.
    pub(crate) delta_g1: G1Affine,
    pub(crate) delta_g2: G2Affine,

    // The Groth16 parameter's h and l vectors.
    pub(crate) h: Vec<G1Affine>,
    pub(crate) l: Vec<G1Affine>,

    // The MPC parameter's constraint system digest and participant public-key set.
    pub(crate) cs_hash: [u8; 64],
    pub(crate) contributions: Vec<PublicKey>,
}

pub struct Streamer<'a> {
    delta_g1: G1Affine,
    delta_g2: G2Affine,
    h_len_offset: u64,
    cs_hash: [u8; 64],
    contributions: Vec<PublicKey>,
    path: &'a str,
    read_raw: bool,
    write_raw: bool,
}

impl<'a> Streamer<'a> {
    // Create a new `Streamer` from small params file.
    pub fn new(path: &'a str, read_raw: bool, write_raw: bool) -> io::Result<Streamer> {
        let mut file = File::open(path)?;

        let delta_g1: G1Affine = read_g1(&mut file)?;
        let delta_g2: G2Affine = read_g2(&mut file)?;
        let g1_size = size_of::<G1Uncompressed>();
        let g2_size = size_of::<G2Uncompressed>();

        let chunk_element_read_size = if read_raw {
            G1Affine::raw_fmt_size()
        } else {
            size_of::<G1Uncompressed>()
        };
        let h_len_offset = g1_size + g2_size;
        let h_len = file.read_u32::<BigEndian>()? as usize;
        file.seek(SeekFrom::Current((h_len * chunk_element_read_size) as i64))?;

        let l_len = file.read_u32::<BigEndian>()? as usize;
        file.seek(SeekFrom::Current((l_len * chunk_element_read_size) as i64))?;
        let mut cs_hash = [0u8; 64];
        file.read_exact(&mut cs_hash)?;

        let contributions_len = file.read_u32::<BigEndian>()? as usize;
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut file)?);
        }

        let streamer = Streamer {
            delta_g1,
            delta_g2,
            h_len_offset: h_len_offset as u64,
            cs_hash,
            contributions,
            path,
            read_raw,
            write_raw,
        };

        Ok(streamer)
    }

    // Create a new `Streamer` from large params file.
    pub fn new_from_large_file(
        path: &'a str,
        read_raw: bool,
        write_raw: bool,
    ) -> io::Result<Streamer> {
        let mut file = File::open(path)?;

        /*
           `MPCParameters` are serialized in the order:
              vk.alpha_g1
              vk.beta_g1
              vk.beta_g2
              vk.gamma_g2
              vk.delta_g1
              vk.delta_g2
              vk.ic length (4 bytes)
              vk.ic (G1)
              h length (4 bytes)
              h (G1)
              l length (4 bytes)
              l (G1)
              a length (4 bytes)
              a (G1)
              b_g1 length (4 bytes)
              b_g1 (G1)
              b_g2 length (4 bytes)
              b_g2 (G2)
              cs_hash (64 bytes)
              contributions length (4 bytes)
              contributions (544 bytes per PublicKey)
        */

        let g1_size = size_of::<G1Uncompressed>() as u64; // 96 bytes
        let g2_size = size_of::<G2Uncompressed>() as u64; // 192 bytes

        let chunk_element_read_size = if read_raw {
            G1Affine::raw_fmt_size() as u64
        } else {
            size_of::<G1Uncompressed>() as u64
        };

        // Read delta_g1, delta_g2, and ic's length.
        let delta_g1_offset = g1_size + g1_size + g2_size + g2_size; // + vk.alpha_g1 + vk.beta_g1 + vk.beta_g2 + vk.gamma_g2
        file.seek(SeekFrom::Start(delta_g1_offset)).unwrap();
        let delta_g1 = read_g1(&mut file)?;
        let delta_g2 = read_g2(&mut file)?;
        let ic_len = file.read_u32::<BigEndian>()? as u64;

        // Read h's length.
        let h_len_offset = delta_g1_offset + g1_size + g2_size + 4 + ic_len * g1_size; // + vk.delta_g1 + vk.delta_g2 + ic length + ic
        file.seek(SeekFrom::Start(h_len_offset)).unwrap();
        let h_len = file.read_u32::<BigEndian>()? as u64;

        // Read l's length.
        let l_len_offset = h_len_offset + 4 + h_len * chunk_element_read_size; // + h length + h
        file.seek(SeekFrom::Start(l_len_offset)).unwrap();
        let l_len = file.read_u32::<BigEndian>()? as u64;

        // Read a's length.
        let a_len_offset = l_len_offset + 4 + l_len * chunk_element_read_size; // + l length + l
        file.seek(SeekFrom::Start(a_len_offset)).unwrap();
        let a_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g1's length.
        let b_g1_len_offset = a_len_offset + 4 + a_len * g1_size; // + a length + a
        file.seek(SeekFrom::Start(b_g1_len_offset)).unwrap();
        let b_g1_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g2's length.
        let b_g2_len_offset = b_g1_len_offset + 4 + b_g1_len * g1_size; // + b_g1 length + b_g1
        file.seek(SeekFrom::Start(b_g2_len_offset)).unwrap();
        let b_g2_len = file.read_u32::<BigEndian>()? as u64;

        // Read cs_hash.
        let cs_hash_offset = b_g2_len_offset + 4 + b_g2_len * g2_size; // + b_g2 length + b_g2
        file.seek(SeekFrom::Start(cs_hash_offset)).unwrap();
        let mut cs_hash = [0u8; 64];
        file.read_exact(&mut cs_hash)?;

        // Read contribution's length.
        let contributions_len = file.read_u32::<BigEndian>()? as u64;

        // Read the contributions.
        let contributions_offset = cs_hash_offset + 64 + 4; // + 64-byte cs_hash + contributions length
        file.seek(SeekFrom::Start(contributions_offset)).unwrap();
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len as usize);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut file)?);
        }

        let streamer = Streamer {
            delta_g1,
            delta_g2,
            h_len_offset,
            cs_hash,
            contributions,
            path,
            read_raw,
            write_raw,
        };

        Ok(streamer)
    }

    pub fn contribute<RR: Rng>(
        &mut self,
        rng: &mut RR,
        out_file: File,
        chunk_size: usize,
    ) -> io::Result<[u8; 64]> {
        let chunk_element_read_size = if self.read_raw {
            G1Affine::raw_fmt_size()
        } else {
            size_of::<G1Uncompressed>()
        };
        let chunk_element_write_size = if self.write_raw {
            G1Affine::raw_fmt_size()
        } else {
            size_of::<G1Uncompressed>()
        };

        let read_buf_size = chunk_element_read_size * chunk_size;
        let write_buf_size = chunk_element_write_size * chunk_size;

        let file = File::open(self.path)?;
        let mut reader = BufReader::with_capacity(read_buf_size, file);
        let mut writer = BufWriter::with_capacity(write_buf_size, out_file);

        let (pubkey, privkey) = keypair(rng, &self.cs_hash, &self.contributions, &self.delta_g1);

        self.delta_g1 = self.delta_g1.mul(privkey.delta).into_affine();
        self.delta_g2 = self.delta_g2.mul(privkey.delta).into_affine();

        let delta_inv = privkey.delta.inverse().expect("nonzero");

        writer.write(self.delta_g1.into_uncompressed().as_ref())?;
        writer.write(self.delta_g2.into_uncompressed().as_ref())?;

        {
            reader.seek(SeekFrom::Start(self.h_len_offset))?;
            let h_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(h_len)?;

            let chunks_to_read = h_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);

            let mut h_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);

            info!("phase2::MPCParameters::contribute() beginning streaming h");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    h_chunk.push(load_g1(&mut reader, self.read_raw)?);
                }
                chunks_read += this_chunk_size;

                batch_exp(&mut h_chunk, delta_inv);

                for h in &h_chunk {
                    dump_g1(&mut writer, h, self.write_raw)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                h_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::contribute() finished streaming h");
        }
        {
            let l_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(l_len)?;

            let chunks_to_read = l_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);

            let mut l_chunk = Vec::<G1Affine>::new();
            info!("phase2::MPCParameters::contribute() beginning streaming l");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    l_chunk.push(load_g1(&mut reader, self.read_raw)?);
                }
                chunks_read += this_chunk_size;

                batch_exp(&mut l_chunk, delta_inv);

                for l in &l_chunk {
                    dump_g1(&mut writer, l, self.write_raw)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                l_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::contribute() finished streaming l");
        }

        self.contributions.push(pubkey.clone());

        writer.write(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;

        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            Ok(sink.into_hash())
        }
    }

    /// Read from self and write out to `writer`, respecting own `read_raw` and `write_raw` flags but without otherwise changing data.
    /// Useful for converting to and from raw format.
    pub fn process(&mut self, out_file: File, chunk_size: usize) -> io::Result<()> {
        let chunk_element_read_size = if self.read_raw {
            G1Affine::raw_fmt_size()
        } else {
            size_of::<G1Uncompressed>()
        };
        let chunk_element_write_size = if self.write_raw {
            G1Affine::raw_fmt_size()
        } else {
            size_of::<G1Uncompressed>()
        };

        let read_buf_size = chunk_element_read_size * chunk_size;
        let write_buf_size = chunk_element_write_size * chunk_size;

        let file = File::open(self.path)?;
        let mut reader = BufReader::with_capacity(read_buf_size, file);
        let mut writer = BufWriter::with_capacity(write_buf_size, out_file);

        writer.write(self.delta_g1.into_uncompressed().as_ref())?;
        writer.write(self.delta_g2.into_uncompressed().as_ref())?;

        reader.seek(SeekFrom::Start(self.h_len_offset))?;
        {
            let h_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(h_len)?;

            let chunks_to_read = h_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);

            let mut h_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);

            info!("phase2::MPCParameters::convert() beginning streaming h");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    h_chunk.push(load_g1(&mut reader, self.read_raw)?);
                }
                chunks_read += this_chunk_size;

                for h in &h_chunk {
                    dump_g1(&mut writer, h, self.write_raw)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                h_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::convert() finished streaming h");
        }

        {
            let l_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(l_len)?;

            let chunks_to_read = l_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);

            let mut l_chunk = Vec::<G1Affine>::new();
            info!("phase2::MPCParameters::convert() beginning streaming l");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    l_chunk.push(load_g1(&mut reader, self.read_raw)?);
                }
                chunks_read += this_chunk_size;

                for l in &l_chunk {
                    dump_g1(&mut writer, l, self.write_raw)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                l_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::convert() finished streaming l");
        }

        writer.write(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;

        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }
        Ok(())
    }
}

// Required by `assert_eq!()`.
impl Debug for MPCSmall {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("MPCSmall")
            .field("delta_g1", &self.delta_g1)
            .field("delta_g2", &self.delta_g2)
            .field("h", &format!("<G1Uncompressed len={}>", self.h.len()))
            .field("l", &format!("<G1Uncompressed len={}>", self.l.len()))
            .field("cs_hash", &self.cs_hash.to_vec())
            .field(
                "contributions",
                &format!("<phase2::PublicKey len={}>", self.contributions.len()),
            )
            .finish()
    }
}

impl PartialEq for MPCSmall {
    fn eq(&self, other: &Self) -> bool {
        self.h == other.h
            && self.l == other.l
            && self.delta_g1 == other.delta_g1
            && self.delta_g2 == other.delta_g2
            && self.cs_hash[..] == other.cs_hash[..]
            && self.contributions == other.contributions
    }
}

impl MPCSmall {
    pub fn contribute<R: Rng>(&mut self, rng: &mut R) -> [u8; 64] {
        let (pubkey, privkey) = keypair(rng, &self.cs_hash, &self.contributions, &self.delta_g1);

        self.delta_g1 = self.delta_g1.mul(privkey.delta).into_affine();
        self.delta_g2 = self.delta_g2.mul(privkey.delta).into_affine();

        let delta_inv = privkey.delta.inverse().expect("nonzero");

        info!("phase2::MPCParameters::contribute() batch_exp of h");
        batch_exp(&mut self.h, delta_inv);
        info!("phase2::MPCParameters::contribute() finished batch_exp of h");

        info!("phase2::MPCParameters::contribute() batch_exp of l");
        batch_exp(&mut self.l, delta_inv);
        info!("phase2::MPCParameters::contribute() finished batch_exp of l");

        self.contributions.push(pubkey.clone());

        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            sink.into_hash()
        }
    }

    /// Deserialize these parameters.
    pub fn read<R: Read>(mut reader: R, raw: bool) -> io::Result<Self> {
        let delta_g1: G1Affine = read_g1(&mut reader)?;
        let delta_g2: G2Affine = read_g2(&mut reader)?;

        let h_len = reader.read_u32::<BigEndian>()? as usize;
        let mut h = Vec::<G1Affine>::with_capacity(h_len);
        for _ in 0..h_len {
            h.push(load_g1(&mut reader, raw)?);
        }

        let l_len = reader.read_u32::<BigEndian>()? as usize;
        let mut l = Vec::<G1Affine>::with_capacity(l_len);
        for _ in 0..l_len {
            l.push(load_g1(&mut reader, raw)?);
        }

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions_len = reader.read_u32::<BigEndian>()? as usize;
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader)?);
        }

        info!(
            "phase2::MPCSmall::read() read vector lengths: h={}, l={}, contributions={}",
            h.len(),
            l.len(),
            contributions.len(),
        );

        Ok(MPCSmall {
            delta_g1,
            delta_g2,
            h,
            l,
            cs_hash,
            contributions,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.delta_g1.into_uncompressed().as_ref())?;
        writer.write_all(self.delta_g2.into_uncompressed().as_ref())?;

        writer.write_u32::<BigEndian>(self.h.len() as u32)?;
        for h in &*self.h {
            writer.write_all(h.into_uncompressed().as_ref())?;
        }

        writer.write_u32::<BigEndian>(self.l.len() as u32)?;
        for l in &*self.l {
            writer.write_all(l.into_uncompressed().as_ref())?;
        }

        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }
}

fn keypair<R: Rng>(
    rng: &mut R,
    prev_cs_hash: &[u8; 64],
    prev_contributions: &[PublicKey],
    prev_delta_g1: &G1Affine,
) -> (PublicKey, PrivateKey) {
    // Sample random delta
    let delta: Fr = Fr::random(rng);

    // Compute delta s-pair in G1
    let s = G1Projective::random(rng).into_affine();
    let s_delta: G1Affine = s.mul(delta).into_affine();

    // H(cs_hash | <previous pubkeys> | s | s_delta)
    let h = {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);

        sink.write_all(&prev_cs_hash[..]).unwrap();
        for pubkey in prev_contributions {
            pubkey.write(&mut sink).unwrap();
        }
        sink.write_all(s.into_uncompressed().as_ref()).unwrap();
        sink.write_all(s_delta.into_uncompressed().as_ref())
            .unwrap();

        sink.into_hash()
    };

    // This avoids making a weird assumption about the hash into the
    // group.
    let transcript = h;

    // Compute delta s-pair in G2
    let r: G2Affine = hash_to_g2(&h).into_affine();
    let r_delta: G2Affine = r.mul(delta).into_affine();

    (
        PublicKey {
            delta_after: prev_delta_g1.mul(delta).into_affine(),
            s,
            s_delta,
            r_delta,
            transcript,
        },
        PrivateKey { delta },
    )
}

// Multiplies each element of `bases` by `coeff` (`coeff` is the number of times each base is added
// to itself when the curve group is written additively).
fn batch_exp(bases: &mut [G1Affine], coeff: Fr) {
    let coeff = coeff.into_repr();

    let cpus = num_cpus::get();
    let chunk_size = if bases.len() < cpus {
        1
    } else {
        bases.len() / cpus
    };

    let mut products = vec![G1Projective::zero(); bases.len()];

    // Multiply each base by `coeff`.
    crossbeam::thread::scope(|scope| {
        for (bases, products) in bases
            .chunks_mut(chunk_size)
            .zip(products.chunks_mut(chunk_size))
        {
            scope.spawn(move |_| {
                let mut wnaf = Wnaf::new();

                for (base, products) in bases.iter_mut().zip(products.iter_mut()) {
                    *products = wnaf.base(base.into_projective(), 1).scalar(coeff);
                }
                // Normalize the projective products.
                G1Projective::batch_normalization(products);

                bases
                    .iter_mut()
                    .zip(products.iter())
                    .for_each(|(affine, projective)| {
                        *affine = projective.into_affine();
                    });
            });
        }
    })
    .unwrap();
}

pub fn verify_contribution_small(before: &MPCSmall, after: &MPCSmall) -> Result<[u8; 64], ()> {
    // The after params must contain exactly one additonal contribution.
    if before.contributions.len() + 1 != after.contributions.len() {
        error!(
            "phase2::verify_contribution_small() non-sequential contributions:
            before.contributions.len()={}, \
            after.contributions.len()={}",
            before.contributions.len(),
            after.contributions.len()
        );
        return Err(());
    }

    // Previous participant public keys should not change.
    if before.contributions[..] != after.contributions[..after.contributions.len() - 1] {
        error!("phase2::verify_contribution_small() previous public keys have changed");
        return Err(());
    }

    let before_is_initial = before.contributions.len() == 0;
    let after_pubkey = after.contributions.last().unwrap();

    // Check that the before params' `delta_g1` and `delta_after` are the same value.
    if before_is_initial {
        if before.delta_g1 != G1Affine::one() || before.delta_g2 != G2Affine::one() {
            error!(
                "phase2::verify_contribution_small() initial params do not have identity deltas"
            );
        }
    } else {
        let before_pubkey = before.contributions.last().unwrap();
        if before.delta_g1 != before_pubkey.delta_after {
            error!("phase2::verify_contribution_small() before params' delta_g1 and delta_after are not equal");
            return Err(());
        }
    };
    // Check that the after params' `delta_g1` and `delta_after` are the same value.
    if after.delta_g1 != after_pubkey.delta_after {
        error!("phase2::verify_contribution_small() after params' delta_g1 and delta_after are not equal");
        return Err(());
    }

    // h and l will change from the contribution, but should have same length.
    if before.h.len() != after.h.len() {
        error!("phase2::verify_contribution_small() length of h has changed");
        return Err(());
    }
    if before.l.len() != after.l.len() {
        error!("phase2::verify_contribution_small() length of l has changed");
        return Err(());
    }

    // cs_hash should be the same.
    if before.cs_hash[..] != after.cs_hash[..] {
        error!("phase2::verify_contribution_small() cs_hash has changed");
        return Err(());
    }

    // Calculate the expected after params transcript.
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    sink.write_all(&before.cs_hash[..]).unwrap();
    for pubkey in &before.contributions {
        pubkey.write(&mut sink).unwrap();
    }
    sink.write_all(after_pubkey.s.into_uncompressed().as_ref())
        .unwrap();
    sink.write_all(after_pubkey.s_delta.into_uncompressed().as_ref())
        .unwrap();
    let calculated_after_transcript = sink.into_hash();

    // Check the after params transcript against its calculated transcript.
    if &after_pubkey.transcript[..] != calculated_after_transcript.as_ref() {
        error!("phase2::verify_contribution_small() inconsistent transcript");
        return Err(());
    }

    let after_r = hash_to_g2(&after_pubkey.transcript[..]).into_affine();

    // Check the signature of knowledge. Check that the participant's r and s were shifted by the
    // same factor.
    if !same_ratio(
        (after_r, after_pubkey.r_delta),
        (after_pubkey.s, after_pubkey.s_delta),
    ) {
        error!("phase2::verify_contribution_small() participant's r and s were shifted by different deltas");
        return Err(());
    }

    // Check that delta_g1 and r were shifted by the same factor.
    if !same_ratio(
        (before.delta_g1, after.delta_g1),
        (after_r, after_pubkey.r_delta),
    ) {
        error!("phase2::verify_contribution_small() participant's delta_g1 and r where shifted by different deltas");
        return Err(());
    }

    // Check that delta_g1 and delta_g2 were shifted by the same factor.
    if !same_ratio(
        (G1Affine::one(), after.delta_g1),
        (G2Affine::one(), after.delta_g2),
    ) {
        error!("phase2::verify_contribution_small() delta_g1 and delta_g2 were shifted by different deltas");
        return Err(());
    }

    // h and l queries should be updated with `delta^-1`.
    if !same_ratio(
        merge_pairs(&before.h, &after.h),
        (after.delta_g2, before.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution_small() h was not updated by delta^-1");
        return Err(());
    }
    if !same_ratio(
        merge_pairs(&before.l, &after.l),
        (after.delta_g2, before.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution_small() l was not updated by delta^-1");
        return Err(());
    }

    // Calculate the "after" participant's contribution hash.
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    after_pubkey.write(&mut sink).unwrap();
    Ok(sink.into_hash())
}

#[inline]
pub fn read_g1<R: Read>(mut reader: R) -> io::Result<G1Affine> {
    let mut affine_bytes = G1Uncompressed::empty();
    reader.read_exact(affine_bytes.as_mut())?;
    let affine = affine_bytes
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if affine.is_zero() {
        let e = io::Error::new(
            io::ErrorKind::InvalidData,
            "deserialized G1Affine is point at infinity",
        );
        Err(e)
    } else {
        Ok(affine)
    }
}

#[inline]
fn load_g1<R: Read>(mut reader: R, raw: bool) -> io::Result<G1Affine> {
    if raw {
        G1Affine::read_raw(&mut reader)
    } else {
        read_g1(reader)
    }
}

#[inline]
fn dump_g1<W: Write>(mut writer: W, g1: &G1Affine, raw: bool) -> io::Result<usize> {
    if raw {
        g1.write_raw(&mut writer)
    } else {
        writer.write(g1.into_uncompressed().as_ref())
    }
}

#[inline]
pub fn read_g2<R: Read>(mut reader: R) -> io::Result<G2Affine> {
    let mut affine_bytes = G2Uncompressed::empty();
    reader.read_exact(affine_bytes.as_mut())?;
    let affine = affine_bytes
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if affine.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deserialized G2Affine is point at infinity",
        ))
    } else {
        Ok(affine)
    }
}

pub fn read_small_params_from_large_file(large_path: &str) -> io::Result<MPCSmall> {
    /*
       `MPCParameters` are serialized in the order:
          vk.alpha_g1
          vk.beta_g1
          vk.beta_g2
          vk.gamma_g2
          vk.delta_g1
          vk.delta_g2
          vk.ic length (4 bytes)
          vk.ic (G1)
          h length (4 bytes)
          h (G1)
          l length (4 bytes)
          l (G1)
          a length (4 bytes)
          a (G1)
          b_g1 length (4 bytes)
          b_g1 (G1)
          b_g2 length (4 bytes)
          b_g2 (G2)
          cs_hash (64 bytes)
          contributions length (4 bytes)
          contributions (544 bytes per PublicKey)
    */

    let g1_size = size_of::<G1Uncompressed>() as u64; // 96 bytes
    let g2_size = size_of::<G2Uncompressed>() as u64; // 192 bytes

    let mut file = File::open(large_path)?;

    // Read delta_g1, delta_g2, and ic's length.
    let delta_g1_offset = g1_size + g1_size + g2_size + g2_size; // + vk.alpha_g1 + vk.beta_g1 + vk.beta_g2 + vk.gamma_g2
    file.seek(SeekFrom::Start(delta_g1_offset)).unwrap();
    let delta_g1 = read_g1(&mut file)?;
    let delta_g2 = read_g2(&mut file)?;
    let ic_len = file.read_u32::<BigEndian>()? as u64;

    // Read h's length.
    let h_len_offset = delta_g1_offset + g1_size + g2_size + 4 + ic_len * g1_size; // + vk.delta_g1 + vk.delta_g2 + ic length + ic
    file.seek(SeekFrom::Start(h_len_offset)).unwrap();
    let h_len = file.read_u32::<BigEndian>()? as u64;

    // Read l's length.
    let l_len_offset = h_len_offset + 4 + h_len * g1_size; // + h length + h
    file.seek(SeekFrom::Start(l_len_offset)).unwrap();
    let l_len = file.read_u32::<BigEndian>()? as u64;

    // Read a's length.
    let a_len_offset = l_len_offset + 4 + l_len * g1_size; // + l length + l
    file.seek(SeekFrom::Start(a_len_offset)).unwrap();
    let a_len = file.read_u32::<BigEndian>()? as u64;

    // Read b_g1's length.
    let b_g1_len_offset = a_len_offset + 4 + a_len * g1_size; // + a length + a
    file.seek(SeekFrom::Start(b_g1_len_offset)).unwrap();
    let b_g1_len = file.read_u32::<BigEndian>()? as u64;

    // Read b_g2's length.
    let b_g2_len_offset = b_g1_len_offset + 4 + b_g1_len * g1_size; // + b_g1 length + b_g1
    file.seek(SeekFrom::Start(b_g2_len_offset)).unwrap();
    let b_g2_len = file.read_u32::<BigEndian>()? as u64;

    // Read cs_hash.
    let cs_hash_offset = b_g2_len_offset + 4 + b_g2_len * g2_size; // + b_g2 length + b_g2
    file.seek(SeekFrom::Start(cs_hash_offset)).unwrap();
    let mut cs_hash = [0u8; 64];
    file.read_exact(&mut cs_hash)?;

    // Read contribution's length.
    let contributions_len = file.read_u32::<BigEndian>()? as u64;

    drop(file);

    // Read the (potentially large) h, l, and contributions arrays using buffered io.
    let file = File::open(large_path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);

    // Read h.
    let h_offset = h_len_offset + 4; // + h length
    reader.seek(SeekFrom::Start(h_offset)).unwrap();
    let mut h = Vec::<G1Affine>::with_capacity(h_len as usize);
    for _ in 0..h_len {
        h.push(read_g1(&mut reader)?);
    }

    // Read l. Skip l's length because it was already read.
    let _ = reader.read_u32::<BigEndian>()? as u64;
    let mut l = Vec::<G1Affine>::with_capacity(l_len as usize);
    for _ in 0..l_len {
        l.push(read_g1(&mut reader)?);
    }

    // Read the contributions.
    let contributions_offset = cs_hash_offset + 64 + 4; // + 64-byte cs_hash + contributions length
    reader.seek(SeekFrom::Start(contributions_offset)).unwrap();
    let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len as usize);
    for _ in 0..contributions_len {
        contributions.push(PublicKey::read(&mut reader)?);
    }

    Ok(MPCSmall {
        delta_g1,
        delta_g2,
        h,
        l,
        cs_hash,
        contributions,
    })
}
