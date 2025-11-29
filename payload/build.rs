fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        cc::Build::new().file("src/seh.c").compile("seh_wrapper");

        println!("cargo:rerun-if-changed=src/seh.c");
    }
}
