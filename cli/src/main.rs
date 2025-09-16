// SPDX-License-Identifier: MIT
use std::process::ExitCode;
use zymic_cli::cli;

fn main() -> ExitCode {
    match cli::handle_input() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
