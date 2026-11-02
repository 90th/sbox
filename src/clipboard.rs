//! Wayland clipboard reads without exposing the compositor socket to the sandbox.
use anyhow::{Context, Result, bail};
use std::process::Command;

pub(crate) fn arguments(args: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut args = args.into_iter();
    let mut accepted = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-l" | "--list-types" | "-n" | "--no-newline" | "-p" | "--primary" | "-v"
            | "--version" => accepted.push(arg),
            "-t" | "--type" => {
                let value = args
                    .next()
                    .context("clipboard --type requires a MIME type")?;
                mime_type(&value)?;
                accepted.extend(["--type".to_owned(), value]);
            }
            _ if arg.starts_with("--type=") => {
                let value = arg.strip_prefix("--type=").unwrap();
                mime_type(value)?;
                accepted.extend(["--type".to_owned(), value.to_owned()]);
            }
            _ => bail!(
                "clipboard option {arg:?} is not permitted; only format listing and one-shot text/image reads are supported"
            ),
        }
    }
    Ok(accepted)
}

fn mime_type(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with('-')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid clipboard MIME type");
    }
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<Command> {
    let args = arguments(args.iter().cloned())?;
    let mut command = Command::new("/usr/bin/wl-paste");
    command.env_clear().env("PATH", "/usr/bin:/bin");
    for name in ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"] {
        let value = std::env::var_os(name)
            .with_context(|| format!("host {name} is unavailable for clipboard access"))?;
        command.env(name, value);
    }
    command.args(args);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_requests_cannot_run_watch_commands_or_open_display_options() {
        for args in [
            vec!["--watch", "sh"],
            vec!["-w", "sh"],
            vec!["--seat", "seat0"],
            vec!["sh"],
            vec!["--type", "--watch"],
            vec!["--type="],
        ] {
            assert!(arguments(args.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn mime_values_cannot_cross_the_host_option_boundary() {
        for value in [
            "",
            "-w",
            "text/plain\n--watch",
            "text/plain\0",
            " image/png",
        ] {
            assert!(arguments(["--type".into(), value.into()]).is_err());
        }
    }
}
