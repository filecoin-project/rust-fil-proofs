use byteorder::{ByteOrder, LittleEndian};
use rocksdb;
use serde_cbor;
use std::path::Path;

use super::errors::Result;
const SECTORS_KEY: &'static [u8; 7] = b"sectors";
const SECTOR_KEY_PREFIX_SIZE: usize = 7;
const SECTORS_KEY_PREFIX: &'static [u8; SECTOR_KEY_PREFIX_SIZE] = b"sector-";
// A key is the prefix + a u32 in little endian format.
const SECTOR_KEY_SIZE: usize = SECTOR_KEY_PREFIX_SIZE + 4;

fn concat_merge(
    _new_key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &mut rocksdb::MergeOperands,
) -> Option<Vec<u8>> {
    // TODO: check new_key for sector prefix
    let mut result: Vec<u8> = Vec::with_capacity(operands.size_hint().0);
    existing_val.map(|v| {
        for e in v {
            result.push(*e)
        }
    });
    for op in operands {
        for e in op {
            result.push(*e)
        }
    }
    Some(result)
}

// SSS is a horrible name, so gonna called it just Storage for now.
#[derive(Debug)]
pub struct Storage {
    /// Internal cache of all known sectors.
    // TODO: better data structure
    sectors: Vec<Option<Sector>>,

    db: rocksdb::DB,
}

impl Storage {
    pub fn new<T: AsRef<Path>>(path: T) -> Result<Storage> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_merge_operator("concat_merge", concat_merge, None);
        let db = rocksdb::DB::open(&opts, path)?;

        // load sectors from disk

        let sectors = match db.get(SECTORS_KEY)? {
            Some(keys) => {
                let mut res = Vec::new();
                for key in keys.chunks(SECTOR_KEY_SIZE) {
                    match db.get(key)? {
                        Some(val) => {
                            let key = from_db_key(key);
                            if key as usize > res.len() {
                                for _ in res.len()..key as usize {
                                    res.push(None);
                                }
                            }
                            res.push(Some(serde_cbor::from_slice(&val)?));
                        }
                        None => {
                            // TODO: update sectors list
                            println!("WARNING: invalid entry in sectors list detected")
                        }
                    }
                }
                res
            }
            None => Vec::new(),
        };

        Ok(Storage { sectors, db })
    }

    /// Adds a new sector, and returns the index of the sector.
    pub fn add_sector(&mut self, sector: Sector) -> Result<usize> {
        let index = self.sectors.len();
        let key = to_db_key(index as u32);

        // TODO: we could push this into the background, but that would change the
        // gurantees.
        {
            let mut batch = rocksdb::WriteBatch::default();
            batch.put(&key, &serde_cbor::to_vec(&sector)?)?;
            batch.merge(SECTORS_KEY, &key)?;
            self.db.write(batch)?;
        }

        // udpate cache
        self.sectors.push(Some(sector));

        Ok(index)
    }

    /// Retrieves a sector by its index.
    pub fn get_sector(&self, index: usize) -> Result<&Sector> {
        if index >= self.sectors.len() {
            return Err(format_err!(
                "out of bounds: no sector found with index: {}",
                index
            ));
        }
        match self.sectors[index] {
            Some(ref sector) => Ok(sector),
            None => Err(format_err!("no sector found with index: {}", index)),
        }
    }

    /// Removes a sector from use.
    pub fn remove_sector(&mut self, index: usize) -> Result<Sector> {
        self.get_sector(index)?;
        // we know the sector should exist, so proceeding with that assumption.

        let old_keys = self.db.get(SECTORS_KEY)?.expect("corrupted db");
        let mut new_keys = vec![0u8; old_keys.len() - SECTOR_KEY_SIZE];
        new_keys[0..index * SECTOR_KEY_SIZE].copy_from_slice(&old_keys[0..index * SECTOR_KEY_SIZE]);
        new_keys[index * SECTOR_KEY_SIZE..]
            .copy_from_slice(&old_keys[(index + 1) * SECTOR_KEY_SIZE..]);

        let key = to_db_key(index as u32);
        {
            let mut batch = rocksdb::WriteBatch::default();
            batch.delete(&key)?;
            batch.put(SECTORS_KEY, &new_keys)?;
            self.db.write(batch)?;
        }

        Ok(self.sectors[index].take().unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sector {
    id: u64,
}

impl Sector {
    pub fn new(id: u64) -> Sector {
        Sector { id }
    }
}

fn to_db_key(val: u32) -> Vec<u8> {
    let l = SECTOR_KEY_PREFIX_SIZE;
    let mut key = vec![0u8; SECTOR_KEY_SIZE];
    key[0..l].copy_from_slice(&SECTORS_KEY_PREFIX[..]);
    LittleEndian::write_u32(&mut key[l..], val);
    key
}

fn from_db_key(val: &[u8]) -> u32 {
    let l = SECTOR_KEY_PREFIX_SIZE;
    LittleEndian::read_u32(&val[l..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use tempfile::Builder;

    #[test]
    fn test_storage_basics() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let db_path = Builder::new().prefix("fil-storage-db").tempdir().unwrap();
        {
            let mut storage = Storage::new(&db_path).unwrap();

            let indicies: Vec<_> = (0..10)
                .map(|_| {
                    let sector = Sector::new(rng.gen());
                    storage.add_sector(sector).expect("failed to add sector")
                }).collect();

            for i in indicies {
                storage.get_sector(i).expect("failed to retrieve sector");
            }

            // remove one index
            storage.remove_sector(7).expect("failed to remove sector 7");
        }

        {
            // second time around, should read the sectors back out
            let storage = Storage::new(&db_path).unwrap();

            for i in 0..10 {
                if i == 7 {
                    // 7 was removed above
                    assert!(storage.get_sector(i).is_err());
                } else {
                    storage
                        .get_sector(i)
                        .expect("failed to retrieve sector, after load");
                }
            }
        }
    }
}
