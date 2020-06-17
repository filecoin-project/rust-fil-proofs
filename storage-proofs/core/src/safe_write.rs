//! Module provides safe write functionality by first checking if
//! there is enough space on the file system before writing.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub trait SafeFileExt {
    fn safe_write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn safe_set_len(&self, size: u64) -> io::Result<()>;
}

impl SafeFileExt for File {
    fn safe_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let size = buf.len();
        self.safe_set_len(size as u64)?;
        self.write_all(buf)
    }

    fn safe_set_len(&self, size: u64) -> io::Result<()> {
        let metadata = self.metadata()?;
        let orig = metadata.len();

        if self.set_len(size).is_err() {
            if self.set_len(orig).is_err() {
                panic!("truncating to original length failed");
            }
        }
        Ok(())
    }
}

pub fn safe_copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    let from_path = from.as_ref();
    let mut from_file = OpenOptions::new().read(true).open(from_path)?;
    let metadata = from_file.metadata()?;
    let size = metadata.len();

    let to_path = to.as_ref();
    let mut to_file = OpenOptions::new().read(true).open(to_path)?;

    to_file.safe_set_len(size)?;

    io::copy(&mut from_file, &mut to_file)
}
