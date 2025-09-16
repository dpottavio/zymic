use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["describe", "--always", "--dirty"])
        .output()
        .expect("git describe");

    let git_describe = String::from_utf8(output.stdout).unwrap();
    let git_describe = git_describe.trim();
    println!("cargo:rustc-env=GIT_DESCRIBE={}", git_describe);
}
