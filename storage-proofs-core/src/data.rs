use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use log::info;

/// A wrapper around data either on disk or a slice in memory, that can be dropped and read back into memory,
/// to allow for better control of memory consumption.
#[derive(Debug)]
pub struct Data<'a> {
    raw: Option<RawData<'a>>,
    path: Option<PathBuf>,
    len: usize,
}

#[derive(Debug)]
enum RawData<'a> {
    Slice(&'a mut [u8]),
    Mmap(memmap::MmapMut),
}

use std::ops::{Deref, DerefMut};

impl<'a> Deref for RawData<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            RawData::Slice(ref raw) => raw,
            RawData::Mmap(ref raw) => raw,
        }
    }
}

impl<'a> DerefMut for RawData<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            RawData::Slice(ref mut raw) => raw,
            RawData::Mmap(ref mut raw) => raw,
        }
    }
}

impl<'a> From<&'a mut [u8]> for Data<'a> {
    fn from(raw: &'a mut [u8]) -> Self {
        let len = raw.len();
        Data {
            raw: Some(RawData::Slice(raw)),
            path: None,
            len,
        }
    }
}

impl<'a> From<(memmap::MmapMut, PathBuf)> for Data<'a> {
    fn from(raw: (memmap::MmapMut, PathBuf)) -> Self {
        let len = raw.0.len();
        Data {
            raw: Some(RawData::Mmap(raw.0)),
            path: Some(raw.1),
            len,
        }
    }
}

impl<'a> AsRef<[u8]> for Data<'a> {
    fn as_ref(&self) -> &[u8] {
        match self.raw {
            Some(ref raw) => raw,
            None => panic!("figure it out"),
        }
    }
}

impl<'a> AsMut<[u8]> for Data<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        match self.raw {
            Some(ref mut raw) => raw,
            None => panic!("figure it out"),
        }
    }
}

impl<'a> Data<'a> {
    pub fn from_path(path: PathBuf) -> Self {
        Data {
            raw: None,
            path: Some(path),
            len: 0,
        }
    }

    pub fn new(raw: &'a mut [u8], path: PathBuf) -> Self {
        let len = raw.len();

        Data {
            raw: Some(RawData::Slice(raw)),
            path: Some(path),
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Recover the data.
    pub fn ensure_data(&mut self) -> Result<()> {
        match self.raw {
            Some(..) => {}
            None => {
                ensure!(self.path.is_some(), "Missing path");
                let path = self.path.as_ref().expect("path as_ref failure");

                info!("restoring {}", path.display());

                let f_data = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .with_context(|| format!("could not open path={:?}", path))?;
                let data = unsafe {
                    memmap::MmapOptions::new()
                        .map_mut(&f_data)
                        .with_context(|| format!("could not mmap path={:?}", path))?
                };

                self.len = data.len();
                self.raw = Some(RawData::Mmap(data));
            }
        }

        Ok(())
    }

    /// Drops the actual data, if we can recover it.
    pub fn drop_data(&mut self) {
        if let Some(ref p) = self.path {
            info!("dropping data {}", p.display());
            self.raw.take();
        }
    }
}
