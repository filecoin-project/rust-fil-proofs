use std::fs::remove_file;
use std::path::Path;

impl<'a, T: AsRef<Path>> FileCleanup<T> {
    pub fn new(path: T) -> FileCleanup<T> {
        FileCleanup {
            path,
            success: false,
        }
    }
}

impl<T: AsRef<Path>> Drop for FileCleanup<T> {
    fn drop(&mut self) {
        if !self.success {
            let _ = remove_file(&self.path);
        }
    }
}

/// Minimal support for cleaning (deleting) a file unless it was successfully populated.
pub struct FileCleanup<T: AsRef<Path>> {
    path: T,
    pub success: bool,
}
