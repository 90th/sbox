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
    if let Some("wl-paste") = std::env::args_os()
        .next()
        .as_deref()
        .and_then(|arg| std::path::Path::new(arg).file_name())
        .and_then(|name| name.to_str())
    {
        return sbox::bridge::client(std::env::args().skip(1));
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--payload")
    {
        return payload();
    }
    let cli = Cli::parse();
    if cli.reset {
        let project = std::fs::canonicalize(&cli.project)?;
        let home = std::fs::canonicalize(
            std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?,
        )?;
        sbox::lifecycle::reset(&home, &project)?;
        return Ok(0);
    }
    if !cli.no_limits && !cli.scoped && !cli.trust && !cli.permissions {
        return Ok(status_code(sbox::lifecycle::scoped(
            cli.memory_mib,
            cli.tasks_limit,
            cli.cpu_percent,
        )?));
    }
    let mut spec = cli.launch_spec()?;
    for warning in &spec.warnings {
        eprintln!("sbox: warning: {warning}");
    }
    if cli.permissions || cli.trust {
        sbox::lifecycle::report(&spec);
        if cli.trust {
            sbox::authority::approve(&spec)?;
            println!("Approved external dependencies and native omp configuration.");
        }
        return Ok(0);
    }
    spec.approval = Some(sbox::authority::directory(&spec.home, &spec.project));
    Ok(status_code(run_omp(&spec, &cli.omp_args)?))
}

fn status_code(status: std::process::ExitStatus) -> u8 {
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    u8::try_from(code).unwrap_or(1)
}

fn payload() -> anyhow::Result<u8> {
    use std::os::unix::process::CommandExt;
    unsafe extern "C" {
        fn close_range(first: u32, last: u32, flags: i32) -> i32;
    }
    // Overlay source paths referring to /proc/self/fd can leave handles behind.
    // Drop every construction capability before the untrusted program starts.
    if unsafe { close_range(3, u32::MAX, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut args = std::env::args_os().skip(2);
    let executable = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing payload executable"))?;
    Err(std::process::Command::new(executable)
        .args(args)
        .exec()
        .into())
}
