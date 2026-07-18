use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use tempfile::Builder;

use crate::LaunchSpec;
use crate::mcp::dedupe_roots;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

const LOCK_EX: i32 = 2;

const ETC_PATHS: &[&str] = &[
    "passwd",
    "group",
    "nsswitch.conf",
    "resolv.conf",
    "hosts",
    "gai.conf",
    "localtime",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "pki",
    "ssl",
    "alternatives",
    "crypto-policies",
];

pub fn build_bwrap_command(
    spec: &LaunchSpec,
    overlay_work_dir: &Path,
    omp_args: &[OsString],
) -> Command {
    let mut command = Command::new(&spec.bwrap);
    command.args([
        "--unshare-user",
        "--unshare-all",
        "--share-net",
        "--disable-userns",
        "--die-with-parent",
    ]);

    command
        .arg("--bind")
        .arg(spec.state_dir.join("omp.lock"))
        .arg("/.sbox-omp.lock")
        .arg("--lock-file")
        .arg("/.sbox-omp.lock")
        .arg("--remount-ro")
        .arg("/.sbox-omp.lock");

    command.args(["--proc", "/proc", "--dev", "/dev"]);
    command.args(["--perms", "1777", "--tmpfs", "/tmp"]);
    command.args(["--perms", "1777", "--tmpfs", "/var/tmp"]);
    command.args([
        "--perms",
        "0555",
        "--dir",
        "/run",
        "--perms",
        "0555",
        "--dir",
        "/run/user",
    ]);
    command
        .args(["--perms", "0700", "--tmpfs"])
        .arg(format!("/run/user/{}", spec.uid));

    command.args(["--ro-bind", "/usr", "/usr"]);
    command.args(["--symlink", "usr/bin", "/bin"]);
    command.args(["--symlink", "usr/sbin", "/sbin"]);
    command.args(["--symlink", "usr/lib", "/lib"]);
    command.args(["--symlink", "usr/lib64", "/lib64"]);
    command.args(["--perms", "0555", "--dir", "/etc"]);
    for name in ETC_PATHS {
        let path = Path::new("/etc").join(name);
        command.arg("--ro-bind-try").arg(&path).arg(&path);
    }

    let mut created_parents = BTreeSet::new();
    add_parent_dirs(&mut command, &spec.home, &mut created_parents);
    command.args(["--perms", "0555", "--dir"]).arg(&spec.home);

    command
        .arg("--overlay-src")
        .arg(spec.home.join(".omp"))
        .arg("--overlay")
        .arg(spec.state_dir.join("omp-upper"))
        .arg(overlay_work_dir)
        .arg(spec.home.join(".omp"));

    let mut read_only = spec.read_only.clone();
    read_only.extend(spec.omp.mount_roots.iter().cloned());
    for path in dedupe_roots(read_only) {
        if path == Path::new("/usr") || path.starts_with(&spec.project) {
            continue;
        }
        add_parent_dirs(&mut command, &path, &mut created_parents);
        command.arg("--ro-bind").arg(&path).arg(&path);
    }
    // OMP stores OAuth credentials in a WAL-mode SQLite database. Share the
    // whole agent directory so agent.db, its WAL/SHM sidecars, refresh leases,
    // and session state remain one host-backed store.

    let agent_dir = spec.home.join(".omp/agent");
    add_parent_dirs(&mut command, &agent_dir, &mut created_parents);
    command.arg("--bind").arg(&agent_dir).arg(&agent_dir);

    add_parent_dirs(&mut command, &spec.project, &mut created_parents);
    command.arg("--bind").arg(&spec.project).arg(&spec.project);
    let hidden_state = spec.project.join(".sbox");
    command
        .args(["--perms", "0700", "--tmpfs"])
        .arg(&hidden_state)
        .arg("--remount-ro")
        .arg(&hidden_state);
    command.arg("--remount-ro").arg("/");

    command.arg("--clearenv");
    for (name, value) in &spec.environment {
        command.arg("--setenv").arg(name).arg(value);
    }
    command.arg("--chdir").arg(&spec.project);
    command.arg("--").arg(&spec.omp.lexical_executable);
    command.args(omp_args);
    command
}

pub fn run_omp(spec: &LaunchSpec, omp_args: &[OsString]) -> Result<ExitStatus> {
    preflight(spec)?;
    prepare_state(spec)?;
    let _state_lock = acquire_state_lock(&spec.state_dir.join("omp.lock"))?;
    let work = Builder::new()
        .prefix("omp-work-")
        .tempdir_in(&spec.state_dir)
        .with_context(|| {
            format!(
                "cannot create OverlayFS work directory in {}",
                spec.state_dir.display()
            )
        })?;
    fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700))?;

    let mut command = build_bwrap_command(spec, work.path(), omp_args);
    let launch = command.status().with_context(|| {
        format!(
            "failed to launch Bubblewrap {}; required overlay isolation was not weakened",
            spec.bwrap.display()
        )
    });
    let cleanup = make_tree_removable(work.path()).and_then(|()| {
        work.close()
            .context("cannot remove temporary OverlayFS work directory")
    });
    match launch {
        Ok(status) => {
            cleanup?;
            Ok(status)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

fn make_tree_removable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(path)? {
            make_tree_removable(&entry?.path())?;
        }
    } else if !metadata.file_type().is_symlink() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn acquire_state_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open state lock {}", path.display()))?;
    // SAFETY: `file` owns a valid descriptor for the duration of the call.
    if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot exclusively lock {}", path.display()));
    }
    Ok(file)
}

fn preflight(spec: &LaunchSpec) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("sbox requires Linux Bubblewrap");

    let namespaces = fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .context("cannot read /proc/sys/user/max_user_namespaces")?;
    let count: u64 = namespaces
        .trim()
        .parse()
        .context("invalid /proc/sys/user/max_user_namespaces")?;
    if count == 0 {
        bail!("unprivileged user namespaces are disabled (max_user_namespaces=0)");
    }
    let tiocsti = Path::new("/proc/sys/dev/tty/legacy_tiocsti");
    if tiocsti.exists() {
        let value =
            fs::read_to_string(tiocsti).context("cannot read /proc/sys/dev/tty/legacy_tiocsti")?;
        if value.trim() != "0" {
            bail!("legacy TIOCSTI is enabled; refusing to retain the controlling terminal");
        }
    }
    let bwrap_mode = fs::metadata(&spec.bwrap)
        .with_context(|| format!("cannot inspect Bubblewrap {}", spec.bwrap.display()))?
        .permissions()
        .mode();
    if bwrap_mode & 0o4000 != 0 {
        bail!("setuid Bubblewrap does not support the required --overlay isolation");
    }
    let lower = spec.home.join(".omp");
    if !lower.is_dir() {
        bail!("host OMP state lower layer {} is missing", lower.display());
    }
    Ok(())
}

fn prepare_state(spec: &LaunchSpec) -> Result<()> {
    let expected = spec.project.join(".sbox/state");
    if spec.state_dir != expected {
        bail!(
            "state directory {} must be exactly {}",
            spec.state_dir.display(),
            expected.display()
        );
    }
    ensure_private_directory(&spec.project.join(".sbox"))?;
    prepare_shared_agent_dir(spec)?;

    ensure_private_directory(&spec.state_dir)?;
    ensure_private_directory(&spec.state_dir.join("omp-upper"))?;

    let canonical_state = fs::canonicalize(&spec.state_dir)?;
    if !canonical_state.starts_with(&spec.project) {
        bail!(
            "sandbox state {} escapes project {}",
            canonical_state.display(),
            spec.project.display()
        );
    }

    let lock = spec.state_dir.join("omp.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("state lock {} must be a regular file", lock.display());
        }
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .open(&lock)
        .with_context(|| format!("cannot create state lock {}", lock.display()))?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn prepare_shared_agent_dir(spec: &LaunchSpec) -> Result<()> {
    ensure_private_directory(&spec.home.join(".omp/agent"))?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!(
                    "sandbox state component {} must not be a symlink",
                    path.display()
                );
            }
            if !metadata.is_dir() {
                bail!(
                    "sandbox state component {} is not a directory",
                    path.display()
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).with_context(|| {
                format!("cannot create private state directory {}", path.display())
            })?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()));
        }
    }
    Ok(())
}

fn add_parent_dirs(command: &mut Command, destination: &Path, seen: &mut BTreeSet<PathBuf>) {
    let mut parents = destination
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .filter(|path| path != &Path::new("/"))
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    parents.reverse();
    for parent in parents {
        if parent.starts_with("/usr") || parent == Path::new("/etc") {
            continue;
        }
        if seen.insert(parent.clone()) {
            command.args(["--perms", "0555", "--dir"]).arg(parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::Runtime;

    fn fixture() -> LaunchSpec {
        LaunchSpec {
            bwrap: "/usr/bin/bwrap".into(),
            project: "/home/u/project".into(),
            home: "/home/u".into(),
            state_dir: "/home/u/project/.sbox/state".into(),
            uid: 1000,
            omp: Runtime {
                lexical_executable: "/home/u/.bin/omp".into(),
                canonical_executable: "/home/u/pkg/omp.js".into(),
                mount_roots: vec!["/home/u/pkg".into(), "/home/u/.bin".into()],
                path_dirs: vec!["/home/u/.bin".into()],
            },
            read_only: vec!["/home/u/pkg/subdir".into(), "/opt/context".into()],
            environment: BTreeMap::from([("HOME".into(), "/home/u".into())]),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn command_preserves_security_order_and_deduplicates_mounts() {
        let spec = fixture();
        let command = build_bwrap_command(&spec, Path::new("/work"), &["config".into()]);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let index = |needle: &str| args.iter().position(|arg| arg == needle).unwrap();
        let project_bind = args
            .windows(3)
            .position(|window| window == ["--bind", "/home/u/project", "/home/u/project"])
            .unwrap();
        let agent_bind = args
            .windows(3)
            .position(|window| window == ["--bind", "/home/u/.omp/agent", "/home/u/.omp/agent"])
            .unwrap();
        assert!(index("--lock-file") < index("--proc"));
        assert!(index("--overlay") < agent_bind);
        assert!(agent_bind < project_bind);

        assert!(project_bind < index("--clearenv"));
        assert!(index("--clearenv") < index("--chdir"));
        assert_eq!(args.iter().filter(|arg| *arg == "/home/u/pkg").count(), 2);
        assert!(!args.iter().any(|arg| arg == "/home/u/pkg/subdir"));
        assert!(!args.iter().any(|arg| arg == "--new-session"));
    }
    #[test]
    fn host_agent_state_is_shared_after_overlay() {
        let spec = fixture();
        let command = build_bwrap_command(&spec, Path::new("/work"), &[]);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let agent_bind = args
            .windows(3)
            .position(|window| window == ["--bind", "/home/u/.omp/agent", "/home/u/.omp/agent"])
            .unwrap();
        let project_bind = args
            .windows(3)
            .position(|window| window == ["--bind", "/home/u/project", "/home/u/project"])
            .unwrap();
        assert!(agent_bind < project_bind);
    }
}
