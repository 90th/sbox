use std::os::unix::process::ExitStatusExt;
use std::process::ExitCode;

use clap::Parser;
use sbox::cli::Cli;
use sbox::run_omp;

fn main() -> ExitCode {
    match execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sbox: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> anyhow::Result<u8> {
    let cli = Cli::parse();
    let spec = cli.launch_spec()?;
    let status = run_omp(&spec, &cli.omp_args)?;
    let code = match status.code() {
        Some(code) => code,
        None => 128 + status.signal().unwrap_or(1),
    };
    Ok(u8::try_from(code).unwrap_or(1))
}
