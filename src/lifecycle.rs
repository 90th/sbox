use crate::LaunchSpec;
use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

pub fn git_metadata(project: &Path) -> Result<Vec<PathBuf>> {
    let marker = project.join(".git");
    if !marker.is_file() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(&marker)?;
    let target = contents
        .trim()
        .strip_prefix("gitdir:")
        .context("invalid linked-worktree .git file")?
        .trim();
    let target = fs::canonicalize(project.join(target))?;
    if !target.join("HEAD").is_file() {
        bail!("linked git directory has no HEAD");
    }
    let common = target.join("commondir");
    let common = if common.is_file() {
        fs::canonicalize(target.join(fs::read_to_string(common)?.trim()))?
    } else {
        target.clone()
    };
    if !common.join("objects").is_dir() || !common.join("HEAD").is_file() {
        bail!("invalid shared git metadata directory");
    }
    Ok(crate::mcp::dedupe_roots(vec![target, common]))
}

pub fn report(spec: &LaunchSpec) {
    println!("Project read/write: {}", spec.project.display());
    println!(
        "Native omp state read/write: {}",
        spec.home.join(".omp/agent").display()
    );
    println!("Global omp config/extensions: read-only approved snapshot");
    println!("Private caches/overlays: {}", spec.state_dir.display());
    for path in &spec.read_only {
        println!("External read-only: {}", path.display());
    }
    for path in &spec.git_metadata {
        println!("Approved Git metadata read/write: {}", path.display());
    }
    println!(
        "SSH aliases: kali-vm, windows-vm -> windows-builder, windows-builder (keys stay on host)"
    );
    println!(
        "Clipboard: host Wayland format listing/text/image reads; compositor socket stays hidden"
    );
    println!("Networking: shared; remote services/VMs are explicit capabilities");
    println!("Linked-worktree Git configuration/hooks: read-only approved snapshot");
}

pub fn reset(project: &Path) -> Result<()> {
    let root = project.join(".sbox");
    if !root.exists() {
        return Ok(());
    }
    if fs::canonicalize(&root)? != root {
        bail!("refusing to reset symlinked state directory");
    }
    let lock = root.join("state/omp.lock");
    let guard = if lock.exists() {
        Some(crate::sandbox::acquire_state_lock(&lock)?)
    } else {
        None
    };
    // remove_dir_all does not follow symlinks. Keep the lock until deletion ends.
    fs::remove_dir_all(&root)?;
    drop(guard);
    println!("Removed private sandbox state only: {}", root.display());
    Ok(())
}

pub fn scoped(memory_mib: u64, tasks: u64, cpu: u32) -> Result<ExitStatus> {
    if memory_mib == 0 || tasks == 0 || cpu == 0 {
        bail!("resource limits must be positive");
    }
    Command::new("/usr/bin/systemd-run").args(["--user","--scope","--quiet"])
 .arg(format!("--property=MemoryMax={}M",memory_mib))
 .arg("--property=MemorySwapMax=0")
 .arg(format!("--property=TasksMax={tasks}"))
 .arg(format!("--property=CPUQuota={cpu}%"))
 .arg("--").arg(std::env::current_exe()?).arg("--scoped").args(std::env::args_os().skip(1)).status()
 .context("cannot enter resource-limited user scope; check your systemd user manager or explicitly select --no-limits")
}
