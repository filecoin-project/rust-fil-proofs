#[cfg(all(feature = "nova", feature = "halo2"))]
compile_error!("Cannot enable 'nova' and 'halo2' features simultaneously");

fn main() {}
