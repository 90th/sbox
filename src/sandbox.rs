use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use tempfile::Builder;

use crate::LaunchSpec;
use crate::mcp::dedupe_roots;
use crate::state::private_directory;

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
    instance_dir: &Path,
    overlay_work_dir: &Path,
    omp_args: &[OsString],
    ssh_bridge: Option<&Path>,
) -> Result<Command> {
    let mut command = Command::new(&spec.bwrap);
    command.args([
        "--unshare-user",
        "--unshare-all",
        "--share-net",
        "--disable-userns",
        "--die-with-parent",
    ]);

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
        .arg(instance_dir.join("omp-upper"))
        .arg(overlay_work_dir)
        .arg(spec.home.join(".omp"));
    crate::hardening::mounts(&mut command, spec, instance_dir, overlay_work_dir);
    for name in ["run", "ssh-control"] {
        command
            .args(["--perms", "0700", "--tmpfs"])
            .arg(spec.home.join(".omp").join(name));
    }

    let mut read_only = spec.read_only.clone();
    read_only.extend(spec.omp.mount_roots.iter().cloned());
    for path in dedupe_roots(read_only) {
        if path == Path::new("/usr") || path.starts_with(&spec.project) {
            continue;
        }
        add_parent_dirs(&mut command, &path, &mut created_parents);
        command.arg("--ro-bind").arg(&path).arg(&path);
    }
    for path in &spec.git_metadata {
        add_parent_dirs(&mut command, path, &mut created_parents);
        command.arg("--bind").arg(path).arg(path);
    }
    // OMP stores OAuth credentials in a WAL-mode SQLite database. Share the
    // whole agent directory so agent.db, its WAL/SHM sidecars, refresh leases,
    // and session state remain one host-backed store.

    let agent_dir = spec.home.join(".omp/agent");
    add_parent_dirs(&mut command, &agent_dir, &mut created_parents);
    command.arg("--bind").arg(&agent_dir).arg(&agent_dir);
    command.args(["--dir", "/sbox", "--dir", "/sbox/bin"]);
    command
        .arg("--ro-bind")
        .arg(&spec.launcher)
        .arg("/sbox/bin/sbox");
    crate::authority::protect(&mut command, spec)?;
    if let Some(directory) = ssh_bridge {
        command
            .arg("--ro-bind")
            .arg(directory)
            .arg("/run/sbox-host");
        command
            .arg("--ro-bind")
            .arg(&spec.launcher)
            .arg("/sbox/bin/wl-paste");
        if directory.join("ssh").is_dir() {
            command
                .arg("--ro-bind")
                .arg(directory.join("ssh"))
                .arg(spec.home.join(".ssh"));
        }
    }

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
    if let Some(directory) = ssh_bridge
        && directory.join("ssh-agent").exists()
    {
        command
            .arg("--setenv")
            .arg("SSH_AUTH_SOCK")
            .arg("/run/sbox-host/ssh-agent");
    }
    command.arg("--chdir").arg(&spec.project);
    command
        .arg("--")
        .arg("/sbox/bin/sbox")
        .arg("--payload")
        .arg(&spec.omp.lexical_executable);
    command.args(omp_args);
    Ok(command)
}

pub fn run_omp(spec: &LaunchSpec, omp_args: &[OsString]) -> Result<ExitStatus> {
    preflight(spec)?;
    let _project_lock = crate::state::shared(&spec.home, &spec.project)?;
    if let Some(directory) = &spec.approval
        && crate::authority::authorize(spec)? != *directory
    {
        bail!("sandbox approval directory does not match the project");
    }
    prepare_state(spec)?;
    let instance = crate::state::Instance::acquire(spec)?;
    let _bridge = if spec.approval.is_some() {
        Some(crate::bridge::Bridge::start()?)
    } else {
        None
    };
    let _agent = if let Some(bridge) = &_bridge {
        crate::native_ssh::Agent::start(&spec.home, &bridge.directory, &spec.ssh_hosts)?
    } else {
        None
    };
    let work = Builder::new()
        .prefix("omp-work-")
        .tempdir_in(&instance.directory)
        .with_context(|| {
            format!(
                "cannot create OverlayFS work directory in {}",
                spec.state_dir.display()
            )
        })?;
    fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700))?;
    crate::hardening::prepare(spec, &instance.directory, work.path())?;

    let mut command = build_bwrap_command(
        spec,
        &instance.directory,
        work.path(),
        omp_args,
        _bridge.as_ref().map(|bridge| bridge.directory.as_path()),
    )?;
    crate::hardening::secure_descriptors(&mut command, &instance.lease)?;
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

pub(crate) fn make_tree_removable(path: &Path) -> Result<()> {
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

fn preflight(spec: &LaunchSpec) -> Result<()> {
    crate::hardening::validate(spec)?;
    crate::hardening::validate_toolchains(&spec.home)?;
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
    private_directory(&spec.project.join(".sbox"))?;
    prepare_shared_agent_dir(spec)?;
    private_directory(&spec.state_dir)?;

    let canonical_state = fs::canonicalize(&spec.state_dir)?;
    if !canonical_state.starts_with(&spec.project) {
        bail!(
            "sandbox state {} escapes project {}",
            canonical_state.display(),
            spec.project.display()
        );
    }

    Ok(())
}

fn prepare_shared_agent_dir(spec: &LaunchSpec) -> Result<()> {
    private_directory(&spec.home.join(".omp/agent"))?;
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
