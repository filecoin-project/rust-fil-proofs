#[macro_use]
extern crate criterion;
extern crate rand;
extern crate sector_base;
extern crate storage_proofs;
extern crate tempfile;

use criterion::{Criterion, ParameterizedBenchmark, Throughput};
use rand::{thread_rng, Rng};
use sector_base::io::fr32::{write_padded, write_unpadded};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

fn random_data(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut data = vec![0u8; size as usize];
    for i in 0..data.len() {
        data[i] = rng.gen();
    }
    data
}

fn preprocessing_benchmark(c: &mut Criterion) {
    c.bench(
        "preprocessing",
        ParameterizedBenchmark::new(
            "write_padded",
            |b, size| {
                let data = &random_data(*size);

                b.iter(|| {
                    let mut tmpfile: File = tempfile::tempfile().unwrap();

                    write_padded_bench(&mut tmpfile, data);
                })
            },
            vec![128, 256, 512, 256_000, 512_000, 1024_000, 2048_000],
        )
        .with_function("write_padded + unpadded", |b, size| {
            let data = &random_data(*size);
            b.iter(|| {
                let mut tmpfile: File = tempfile::tempfile().unwrap();

                write_padded_unpadded_bench(&mut tmpfile, &data);
            })
        })
        .sample_size(2)
        .throughput(|s| Throughput::Bytes(*s as u32))
        .warm_up_time(Duration::from_secs(1)),
    );
}

fn write_padded_bench(file: &mut File, data: &[u8]) {
    write_padded(&data, file).unwrap();

    let padded_written = file.seek(SeekFrom::End(0)).unwrap() as usize;

    assert!(padded_written > data.len());
}

fn write_padded_unpadded_bench(file: &mut File, data: &[u8]) {
    write_padded(&data, file).unwrap();

    let padded_written = file.seek(SeekFrom::End(0)).unwrap() as usize;

    assert!(padded_written > data.len());

    let mut buf = Vec::with_capacity(padded_written);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_end(&mut buf).unwrap();

    let mut unpadded_file: File = tempfile::tempfile().unwrap();

    write_unpadded(&buf, &mut unpadded_file, 0, data.len()).unwrap();

    let unpadded_written = unpadded_file.seek(SeekFrom::End(0)).unwrap() as usize;

    assert!(unpadded_written == data.len());
}

criterion_group!(benches, preprocessing_benchmark);
criterion_main!(benches);
