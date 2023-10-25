#![feature(exit_status_error)]

use std::env;
use std::fs;
use std::process::Command;
use std::string::String;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let linux_dir = env::var("LINUX").unwrap();

    let output = Command::new("python3")
        .arg("build.py")
        .arg(&linux_dir)
        .arg(&out_dir)
        .output()
        .expect("failed to run build.py");

    output
        .status
        .exit_ok()
        .map(|_| print!("{}", String::from_utf8_lossy(&output.stdout)))
        .map_err(|_| panic!("\n{}", String::from_utf8_lossy(&output.stderr)))
        .unwrap();

    let iustub_pathbuf = fs::canonicalize("./libiustub").unwrap();
    let iustub_path = iustub_pathbuf.to_str().unwrap();
    Command::new("make")
        .arg("-C")
        .arg(iustub_path)
        .output()
        .expect("failed to build libiustub");

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=./src/*");
    println!("cargo:rerun-if-changed=./libiustub/*");
    println!("cargo:rustc-link-lib=dylib=iustub");
    println!("cargo:rustc-link-search=native={}", iustub_path);
}
