fn main() {
    println!("cargo::rustc-check-cfg=cfg(nightly)");
    cfg_if_nightly()
}

#[rustversion::nightly]
fn cfg_if_nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn cfg_if_nightly() {}
