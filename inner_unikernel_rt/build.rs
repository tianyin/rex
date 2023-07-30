#![feature(exit_status_error)]

use std::env;
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
        .expect("failed to execute process");

    output.status.exit_ok().unwrap_or_else(|_| {
        panic!("{}", String::from_utf8_lossy(&output.stderr))
    });

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=./src/*");
}
