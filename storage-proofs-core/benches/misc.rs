use std::io::{Read, Seek, SeekFrom, Write};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use tempfile::tempfile;

fn read_bytes_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 512, 1024, 64 * 1024];

    let mut group = c.benchmark_group("read");
    for bytes in params {
        group.bench_function(format!("from_disk-{}", bytes), |b| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();

            let mut f = tempfile().unwrap();
            f.write_all(&data).unwrap();
            f.sync_all().unwrap();

            b.iter(|| {
                let mut res = vec![0u8; bytes];
                f.seek(SeekFrom::Start(0)).unwrap();
                f.read_exact(&mut res).unwrap();

                black_box(res)
            })
        });
    }

    group.finish();
}

criterion_group!(benches, read_bytes_benchmark);
criterion_main!(benches);
