use memmap::MmapMut;
use memmap::MmapOptions;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn setup_replica(data: &[u8], replica_path: &Path) -> MmapMut {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(replica_path)
        .expect("Failed to create replica");
    f.write_all(data).expect("Failed to write data to replica");

    unsafe {
        MmapOptions::new()
            .map_mut(&f)
            .expect("Failed to back memory map with tempfile")
    }
}

#[macro_export]
macro_rules! table_tests {
    ($property_test_func:ident {
        $( $(#[$attr:meta])* $test_name:ident( $( $param:expr ),* ); )+
    }) => {
        $(
            $(#[$attr])*
                #[test]
            fn $test_name() {
                $property_test_func($( $param ),* )
            }
        )+
    }
}
