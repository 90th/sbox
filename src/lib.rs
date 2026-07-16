use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::Result;

pub mod cli;
pub mod mcp;
pub mod sandbox;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Runtime {
    pub lexical_executable: PathBuf,
    pub canonical_executable: PathBuf,
    pub mount_roots: Vec<PathBuf>,
    pub path_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Discovery {
    pub mount_roots: Vec<PathBuf>,
    pub path_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSpec {
    pub bwrap: PathBuf,
    pub project: PathBuf,
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub uid: u32,
    pub omp: Runtime,
    pub read_only: Vec<PathBuf>,
    pub environment: BTreeMap<OsString, OsString>,
}

pub fn discover_mcp_mounts(home: &Path, project: &Path, host_path: &OsStr) -> Result<Discovery> {
    mcp::discover_mcp_mounts(home, project, host_path)
}

pub fn build_bwrap_command(
    spec: &LaunchSpec,
    overlay_work_dir: &Path,
    omp_args: &[OsString],
) -> Command {
    sandbox::build_bwrap_command(spec, overlay_work_dir, omp_args)
}

pub fn run_omp(spec: &LaunchSpec, omp_args: &[OsString]) -> Result<ExitStatus> {
    sandbox::run_omp(spec, omp_args)
}
