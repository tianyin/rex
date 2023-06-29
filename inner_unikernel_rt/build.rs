use std::env;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let linux_dir = env::var("LINUX").unwrap();

    let output = Command::new("python3")
        .arg("build.py")
        .arg(&linux_dir)
        .arg(&out_dir)
        .output()
        .unwrap();

    // add more debug log
    println!("cargo:warning={}", String::from_utf8_lossy(&output.stdout));
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=./src/*");
}
