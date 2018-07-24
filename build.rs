extern crate cbindgen;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    let cfg = cbindgen::Config::from_root_or_default(std::path::Path::new(&crate_dir));

    cbindgen::Builder::new()
        .with_config(cfg)
        .with_crate(crate_dir)
        .with_header(format!("/* libproofs Header Version {} */", VERSION))
        .with_language(cbindgen::Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("libproofs.h");
}
