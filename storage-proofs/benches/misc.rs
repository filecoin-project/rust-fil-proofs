use std::io::{Read, Seek, Write};

use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};
use tempfile::tempfile;

fn read_bytes_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 512, 1024, 64 * 1024];

    c.bench(
        "read",
        ParameterizedBenchmark::new(
            "from_disk",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                let mut f = tempfile().unwrap();
                f.write_all(&data).unwrap();
                f.sync_all().unwrap();

                b.iter(|| {
                    let mut res = vec![0u8; *bytes];
                    f.seek(std::io::SeekFrom::Start(0)).unwrap();
                    f.read_exact(&mut res).unwrap();

                    black_box(res)
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, read_bytes_benchmark);
criterion_main!(benches);
