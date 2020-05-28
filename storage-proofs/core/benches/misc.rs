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

                let mut f = tempfile().expect("tempfile failed");
                f.write_all(&data).expect("write_all failed");
                f.sync_all().expect("sync_all failed");

                b.iter(|| {
                    let mut res = vec![0u8; *bytes];
                    f.seek(std::io::SeekFrom::Start(0)).expect("seek failed");
                    f.read_exact(&mut res).expect("read_exact failed");

                    black_box(res)
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, read_bytes_benchmark);
criterion_main!(benches);
