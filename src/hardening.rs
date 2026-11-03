use crate::LaunchSpec;
use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub(crate) fn validate(spec: &LaunchSpec) -> Result<()> {
    if spec.home.starts_with(&spec.project) || spec.project == Path::new("/") {
        bail!("project must not contain the home directory or filesystem root");
    }
    let policy = spec.home.join(".config/sbox");
    if policy.starts_with(&spec.project) || spec.home.join(".omp").starts_with(&spec.project) {
        bail!("project must not contain sandbox policy or native omp state");
    }
    for path in [&spec.home.join(".omp"), &spec.home.join(".omp/agent")] {
        if path.exists() && fs::canonicalize(path)? != *path {
            bail!("OMP state must not traverse symlinks: {}", path.display());
        }
    }
    for path in spec
        .read_only
        .iter()
        .chain(&spec.omp.mount_roots)
        .chain(&spec.git_metadata)
    {
        let canonical = fs::canonicalize(path)?;
        if !fs::metadata(&canonical)?.is_file() && !fs::metadata(&canonical)?.is_dir() {
            bail!(
                "mount grant is not a regular file or directory: {}",
                path.display()
            );
        }
        if canonical.starts_with(spec.home.join(".ssh"))
            || canonical.starts_with(spec.home.join(".gnupg"))
            || canonical.starts_with(&policy)
            || policy.starts_with(&canonical)
        {
            bail!(
                "private keys and sandbox permission authority cannot be mounted: {}",
                path.display()
            );
        }
        if spec.home.starts_with(&canonical)
            || canonical.starts_with("/run")
            || canonical.starts_with("/proc")
            || canonical.starts_with("/sys")
            || canonical.starts_with("/dev")
            || canonical == Path::new("/tmp")
        {
            bail!("refusing broad or host-runtime mount: {}", path.display());
        }
        if fs::metadata(path)?.is_dir() && canonical != *path {
            bail!(
                "directory mount must use its canonical path: {}",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn prepare(spec: &LaunchSpec, instance_dir: &Path, work: &Path) -> Result<()> {
    for name in ["cargo-home", "rustup-home", "npm-cache", "cache"] {
        fs::create_dir_all(instance_dir.join(name))?;
        if fs::canonicalize(instance_dir.join(name))? != instance_dir.join(name) {
            bail!("sandbox cache directory must not traverse symlinks");
        }
    }
    for name in ["registry", "git"] {
        let source = spec.home.join(".cargo").join(name);
        if source.exists() {
            if fs::canonicalize(&source)? != source {
                bail!(
                    "Cargo dependency directory must not traverse symlinks: {}",
                    source.display()
                );
            }
            fs::create_dir_all(instance_dir.join(format!("cargo-{name}-upper")))?;
            if fs::canonicalize(instance_dir.join(format!("cargo-{name}-upper")))?
                != instance_dir.join(format!("cargo-{name}-upper"))
            {
                bail!("Cargo overlay upper must not traverse symlinks");
            }
            fs::create_dir(work.join(name))?;
        }
    }
    Ok(())
}

pub(crate) fn mounts(command: &mut Command, spec: &LaunchSpec, instance_dir: &Path, work: &Path) {
    for (source, destination) in [("npm-cache", ".npm"), ("cache", ".cache")] {
        command
            .arg("--bind")
            .arg(instance_dir.join(source))
            .arg(spec.home.join(destination));
    }
    let cargo = spec.home.join(".cargo");
    command
        .arg("--bind")
        .arg(instance_dir.join("cargo-home"))
        .arg(&cargo);
    for name in ["registry", "git"] {
        let source = cargo.join(name);
        if source.is_dir() {
            command
                .arg("--overlay-src")
                .arg(source)
                .arg("--overlay")
                .arg(instance_dir.join(format!("cargo-{name}-upper")))
                .arg(work.join(name))
                .arg(cargo.join(name));
        }
    }
    let rustup = spec.home.join(".rustup");
    command
        .arg("--bind")
        .arg(instance_dir.join("rustup-home"))
        .arg(&rustup);
    for name in ["toolchains", "settings.toml"] {
        let source = rustup.join(name);
        command.arg("--ro-bind-try").arg(&source).arg(&source);
    }
    for name in [
        "cargo",
        "rustc",
        "rustdoc",
        "rustup",
        "rustfmt",
        "cargo-fmt",
        "cargo-clippy",
        "clippy-driver",
        "rust-analyzer",
    ] {
        let source = cargo.join("bin").join(name);
        command.arg("--ro-bind-try").arg(&source).arg(&source);
    }
}

pub(crate) fn secure_descriptors(command: &mut Command, lease: &File) -> Result<()> {
    use std::ffi::{CString, OsString};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    unsafe extern "C" {
        fn close_range(first: u32, last: u32, flags: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn syscall(number: i64, ...) -> i64;
    }
    let mut replacement = Command::new(command.get_program());
    let lease = lease.try_clone()?;
    replacement
        .arg("--sync-fd")
        .arg(lease.as_raw_fd().to_string());
    let mut args = command.get_args();
    let mut sources = vec![lease];
    while let Some(arg) = args.next() {
        if arg == "--" {
            replacement.arg(arg).args(args);
            break;
        }
        if ["--bind", "--ro-bind", "--ro-bind-try", "--overlay-src"]
            .iter()
            .any(|flag| arg == *flag)
        {
            let path = args.next().context("missing mount source")?;
            if arg == "--ro-bind-try" && !Path::new(path).exists() {
                args.next();
                continue;
            }
            let canonical = fs::canonicalize(path)?;
            if canonical != Path::new(path)
                && fs::metadata(&canonical)?.is_dir()
                && !Path::new(path).starts_with("/etc")
            {
                bail!("directory mount changed through a symlink: {:?}", path);
            }
            let name = CString::new(canonical.as_os_str().as_bytes())?;
            let how = OpenHow {
                flags: 0x200000 | 0x80000,
                mode: 0,
                resolve: 4,
            };
            // Linux openat2: reject symlinks in every component, including races
            // after canonicalization. The pinned O_PATH handle authorizes the mount.
            let raw = unsafe {
                syscall(
                    437,
                    -100i32,
                    name.as_ptr(),
                    &how as *const OpenHow,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let file = unsafe { fs::File::from_raw_fd(raw as i32) };
            let metadata = file.metadata()?;
            if !metadata.is_file() && !metadata.is_dir() {
                bail!("refusing special mount source: {:?}", path);
            }
            let fd = file.as_raw_fd();
            if arg == "--overlay-src" {
                replacement.arg(arg).arg(format!("/proc/self/fd/{fd}"));
            } else {
                replacement
                    .arg(if arg == "--bind" {
                        "--bind-fd"
                    } else {
                        "--ro-bind-fd"
                    })
                    .arg(OsString::from(fd.to_string()))
                    .arg(args.next().context("missing mount destination")?);
            }
            sources.push(file);
        } else {
            replacement.arg(arg);
        }
    }
    // Retain the slot lease in bwrap's supervisor until the sandbox exits.
    // The trusted payload drops construction descriptors before starting omp.
    unsafe {
        replacement.pre_exec(move || {
            if close_range(3, u32::MAX, 4) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for file in &sources {
                if fcntl(file.as_raw_fd(), 2, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    *command = replacement;
    Ok(())
}

pub(crate) fn validate_toolchains(home: &Path) -> Result<()> {
    for path in [
        home.join(".rustup/toolchains"),
        home.join(".rustup/settings.toml"),
    ] {
        if path.exists()
            && fs::canonicalize(&path)
                .with_context(|| format!("cannot inspect {}", path.display()))?
                != path
        {
            bail!(
                "Rust toolchain grant must not traverse symlinks: {}",
                path.display()
            );
        }
    }
    Ok(())
}
