use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = Path::new(&manifest_dir);

    // --- 1. Base64-encode the SVG logo and write a const to OUT_DIR ---
    let svg_path = manifest_path.join("../../assets/logo.svg");
    println!("cargo:rerun-if-changed={}", svg_path.display());

    let svg_bytes = fs::read(&svg_path).expect("failed to read assets/logo.svg");
    let encoded = data_encoding::BASE64.encode(&svg_bytes);

    let out_dir = env::var("OUT_DIR").unwrap();
    let logo_rs = Path::new(&out_dir).join("logo.rs");
    fs::write(
        &logo_rs,
        format!("const LOGO_SVG_BASE64: &str = \"{encoded}\";\n"),
    )
    .expect("failed to write logo.rs");

    // --- 2. Compile the .rc resource file to embed the ICO in the exe ---
    let ico_path = manifest_path.join("../../assets/logo.ico");
    println!("cargo:rerun-if-changed={}", ico_path.display());

    let rc_path = manifest_path.join("passkms.rc");
    println!("cargo:rerun-if-changed={}", rc_path.display());

    let _ = embed_resource::compile(&rc_path, embed_resource::NONE);
}
