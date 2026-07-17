use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::mcp::{dedupe_roots, resolve_executable, resolve_runtime};
use crate::{LaunchSpec, McpDiscoveryPolicy, discover_mcp_mounts_with_policy};

const FORWARDED_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "COPILOT_GITHUB_TOKEN",
    "OMP_AUTH_BROKER_URL",
    "OMP_AUTH_BROKER_TOKEN",
    "OMP_AUTH_BROKER_SNAPSHOT_TTL_MS",
    "OMP_MCP_TIMEOUT_MS",
    "PI_SMOL_MODEL",
    "PI_SLOW_MODEL",
    "PI_PLAN_MODEL",
    "CONTEXT7_API_KEY",
    "CONTEXT7_API_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

#[derive(Debug, Parser)]
#[command(
    name = "sbox",
    about = "Run OMP inside a project-scoped Bubblewrap sandbox"
)]
pub struct Cli {
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub project: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub allow_read: Vec<PathBuf>,

    #[arg(long, value_name = "NAME")]
    pub pass_env: Vec<OsString>,

    #[arg(long)]
    pub strict_mcp: bool,

    #[arg(
        value_name = "OMP_ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub omp_args: Vec<OsString>,
}

impl Cli {
    pub fn launch_spec(&self) -> Result<LaunchSpec> {
        let host_path = env::var_os("PATH").context("PATH is not set")?;
        let home_value = env::var_os("HOME").context("HOME is not set")?;
        let home_path = PathBuf::from(home_value);
        if !home_path.is_absolute() {
            bail!("HOME must be an absolute path");
        }
        let home = fs::canonicalize(&home_path)
            .with_context(|| format!("cannot resolve HOME {}", home_path.display()))?;
        let project = resolve_directory(&self.project, "project")?;
        let bwrap = resolve_executable(OsStr::new("bwrap"), &host_path, None)
            .context("cannot resolve required Bubblewrap executable")?;
        let omp = resolve_runtime(OsStr::new("omp"), &host_path, &home)
            .context("cannot resolve required OMP runtime")?;
        let discovery = discover_mcp_mounts_with_policy(
            &home,
            &project,
            &host_path,
            McpDiscoveryPolicy {
                strict: self.strict_mcp,
            },
        )?;

        let mut read_only = omp.mount_roots.clone();
        read_only.extend(discovery.mount_roots);
        for path in &self.allow_read {
            read_only.push(resolve_existing(path, "--allow-read path")?);
        }
        read_only.retain(|path| !path.starts_with(&project));
        let read_only = dedupe_roots(read_only);

        let mut path_dirs = omp.path_dirs.clone();
        path_dirs.extend(discovery.path_dirs);
        let uid = home.metadata()?.uid();
        let environment = build_environment(&home, &project, uid, &path_dirs, &self.pass_env)?;

        Ok(LaunchSpec {
            bwrap,
            project: project.clone(),
            home,
            state_dir: project.join(".sbox/state"),
            uid,
            omp,
            read_only,
            environment,
            warnings: discovery.warnings,
        })
    }
}

pub fn valid_env_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    (first.is_ascii_alphabetic() || *first == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn build_environment(
    home: &Path,
    project: &Path,
    uid: u32,
    path_dirs: &[PathBuf],
    pass_env: &[OsString],
) -> Result<BTreeMap<OsString, OsString>> {
    let mut result = BTreeMap::new();
    result.insert("HOME".into(), home.as_os_str().to_owned());
    copy_or_default(&mut result, "USER", "user");
    let user = result.get(OsStr::new("USER")).cloned().unwrap();
    result.insert("LOGNAME".into(), env::var_os("LOGNAME").unwrap_or(user));
    copy_or_default(&mut result, "SHELL", "/bin/sh");
    result.insert("PWD".into(), project.as_os_str().to_owned());
    copy_or_default(&mut result, "TERM", "xterm-256color");
    copy_or_default(&mut result, "COLORTERM", "truecolor");
    copy_or_default(&mut result, "LANG", "C.UTF-8");
    result.insert(
        "XDG_RUNTIME_DIR".into(),
        OsString::from(format!("/run/user/{uid}")),
    );
    result.insert("PI_CONFIG_DIR".into(), ".omp".into());

    let mut dirs = BTreeSet::new();
    for directory in path_dirs {
        dirs.insert(directory.clone());
    }
    dirs.insert(PathBuf::from("/usr/bin"));
    dirs.insert(PathBuf::from("/bin"));
    result.insert(
        "PATH".into(),
        env::join_paths(dirs).context("sandbox PATH contains an invalid directory")?,
    );

    for (name, value) in env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"LC_") {
            result.insert(name, value);
        }
    }
    for name in FORWARDED_ENV {
        if let Some(value) = env::var_os(name) {
            result.insert((*name).into(), value);
        }
    }
    for name in pass_env {
        if !valid_env_name(name) {
            bail!("invalid environment variable name {:?}", name);
        }
        let value = env::var_os(name)
            .with_context(|| format!("requested environment variable {:?} is not set", name))?;
        result.insert(name.clone(), value);
    }
    Ok(result)
}

fn copy_or_default(map: &mut BTreeMap<OsString, OsString>, name: &str, default: &str) {
    map.insert(
        name.into(),
        env::var_os(name).unwrap_or_else(|| default.into()),
    );
}

fn resolve_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = resolve_existing(path, label)?;
    if !canonical.is_dir() {
        bail!("{label} {} is not a directory", canonical.display());
    }
    Ok(canonical)
}

fn resolve_existing(path: &Path, label: &str) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("cannot resolve {label} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn parses_fixed_cli_and_preserves_trailing_bytes() {
        let opaque = OsString::from_vec(vec![b'a', 0xff, b'z']);
        let cli = Cli::try_parse_from([
            OsString::from("sbox"),
            OsString::from("--project"),
            OsString::from("/work"),
            OsString::from("--allow-read"),
            OsString::from("/context"),
            OsString::from("--strict-mcp"),
            OsString::from("--"),
            OsString::from("--model"),
            opaque.clone(),
        ])
        .unwrap();
        assert_eq!(cli.project, Path::new("/work"));
        assert_eq!(cli.allow_read, [PathBuf::from("/context")]);
        assert!(cli.strict_mcp);
        assert_eq!(cli.omp_args, [OsString::from("--model"), opaque]);
    }

    #[test]
    fn validates_shell_environment_names() {
        for valid in ["A", "_A", "CONTEXT7_TOKEN_2"] {
            assert!(valid_env_name(OsStr::new(valid)));
        }
        for invalid in ["", "2BAD", "BAD-NAME", "BAD=VALUE"] {
            assert!(!valid_env_name(OsStr::new(invalid)));
        }
    }

    #[test]
    fn missing_pass_env_error_names_only_the_variable() {
        let name = OsString::from("SBOX_TEST_VARIABLE_THAT_MUST_NOT_EXIST_6E2A");
        let error = build_environment(
            Path::new("/home/test"),
            Path::new("/project"),
            1000,
            &[],
            &[name.clone()],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(name.to_str().unwrap()));
        assert!(!error.contains('='));
    }
}
