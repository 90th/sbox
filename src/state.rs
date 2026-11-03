use crate::LaunchSpec;
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const SHARED: i32 = 1;
const EXCLUSIVE: i32 = 2;
const NONBLOCK: i32 = 4;

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Err(error) = DirBuilder::new().mode(0o700).create(path)
                && error.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(error.into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || fs::canonicalize(path)? != path {
        bail!(
            "sandbox state directory must be canonical and not symlinked: {}",
            path.display()
        );
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn open_lock(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .custom_flags(0x20000 | 0x800)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot open sandbox lock {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!(
            "sandbox lock must be a single-link regular file: {}",
            path.display()
        );
    }
    Ok(file)
}
fn try_lock(file: &File, mode: i32) -> Result<bool> {
    // flock follows the open file description. A duplicated lease can also be
    // retained by bwrap after the launcher releases its copy.
    if unsafe { flock(file.as_raw_fd(), mode | NONBLOCK) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}
fn project_lock(home: &Path, project: &Path, mode: i32) -> Result<File> {
    // Keep this inode outside .sbox so reset cannot unlink the synchronization
    // point while a new launcher is waiting to acquire it.
    let directory = crate::authority::directory(home, project);
    fs::create_dir_all(&directory)?;
    private_directory(&directory)?;
    let lock = open_lock(&directory.join("lifecycle.lock"), true)?;
    if !try_lock(&lock, mode)? {
        bail!(
            "project state is in use; wait for active sbox instances or a reset/trust update to finish"
        );
    }
    Ok(lock)
}
pub(crate) fn shared(home: &Path, project: &Path) -> Result<File> {
    project_lock(home, project, SHARED)
}

pub(crate) struct Exclusive {
    _project: File,
    _legacy: Option<File>,
}
pub(crate) fn exclusive(home: &Path, project: &Path) -> Result<Exclusive> {
    let mut guard = Exclusive {
        _project: project_lock(home, project, EXCLUSIVE)?,
        _legacy: None,
    };
    let state = project.join(".sbox/state");
    if !state.exists() {
        return Ok(guard);
    }
    if fs::canonicalize(&state)? != state {
        bail!("refusing symlinked sandbox state");
    }
    // Old launchers use this exclusive lock and the old upper directories. Do
    // not stop them or touch those directories while they are still running.
    let legacy = state.join("omp.lock");
    if legacy.exists() {
        let lock = open_lock(&legacy, false)?;
        if !try_lock(&lock, EXCLUSIVE)? {
            bail!("an older sbox instance is active; exit it before reset or trust updates");
        }
        guard._legacy = Some(lock);
    }
    let instances = state.join("instances");
    if instances.exists() {
        if fs::canonicalize(&instances)? != instances {
            bail!("refusing symlinked instance storage");
        }
        for entry in fs::read_dir(instances)? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                bail!("refusing symlinked instance state");
            }
            let lock = path.join("instance.lock");
            if lock.exists() && !try_lock(&open_lock(&lock, false)?, EXCLUSIVE)? {
                bail!(
                    "a sandbox still holds its instance lease; wait before reset or trust updates"
                );
            }
        }
    }
    Ok(guard)
}

pub(crate) struct Instance {
    pub directory: PathBuf,
    pub lease: File,
}
impl Instance {
    pub fn acquire(spec: &LaunchSpec) -> Result<Self> {
        let instances = spec.state_dir.join("instances");
        private_directory(&instances)?;
        for index in 0u64.. {
            let directory = instances.join(index.to_string());
            private_directory(&directory)?;
            let lease = open_lock(&directory.join("instance.lock"), true)?;
            if !try_lock(&lease, EXCLUSIVE)? {
                continue;
            }
            private_directory(&directory.join("omp-upper"))?;
            // A killed launcher may leave temporary OverlayFS work directories.
            // The lease proves that no live sandbox can still use this slot.
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                if entry.file_name().to_string_lossy().starts_with("omp-work-") {
                    crate::sandbox::make_tree_removable(&entry.path())?;
                    if fs::symlink_metadata(entry.path())?.is_dir() {
                        fs::remove_dir_all(entry.path())?;
                    } else {
                        fs::remove_file(entry.path())?;
                    }
                }
            }
            return Ok(Self { directory, lease });
        }
        unreachable!("instance numbering exhausted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LaunchSpec, Runtime};
    use std::{
        collections::BTreeMap,
        process::{Child, Command},
        thread,
        time::{Duration, Instant},
    };

    struct SandboxChild(Child);
    impl Drop for SandboxChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires bwrap and unprivileged user namespaces"]
    fn supervisor_retains_instance_lease_after_launcher_handles_close() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(home.join(".omp/agent")).unwrap();
        fs::create_dir_all(project.join(".sbox/state")).unwrap();
        let spec = LaunchSpec {
            bwrap: "/usr/bin/bwrap".into(),
            project: project.clone(),
            home: home.clone(),
            state_dir: project.join(".sbox/state"),
            uid: home.metadata().unwrap().uid(),
            omp: Runtime {
                lexical_executable: "/usr/bin/sh".into(),
                canonical_executable: "/usr/bin/sh".into(),
                mount_roots: vec![],
                path_dirs: vec![],
            },
            read_only: vec![],
            environment: BTreeMap::from([
                ("HOME".into(), home.as_os_str().to_owned()),
                ("PATH".into(), "/usr/bin:/bin".into()),
            ]),
            warnings: vec![],
            approval: None,
            git_metadata: vec![],
            launcher: "/usr/bin/sh".into(),
            ssh_hosts: vec![],
        };
        let project_guard = shared(&home, &project).unwrap();
        let instance = Instance::acquire(&spec).unwrap();
        let mut command = Command::new("/usr/bin/bwrap");
        command.args(["--unshare-user","--unshare-all","--share-net","--disable-userns","--die-with-parent",
            "--ro-bind","/usr","/usr","--symlink","usr/bin","/bin","--symlink","usr/lib","/lib","--symlink","usr/lib64","/lib64",
            "--proc","/proc","--dev","/dev","--bind"]).arg(&project).arg("/work")
            .args(["--chdir","/work","--clearenv","--setenv","PATH","/usr/bin:/bin","--","/usr/bin/sh","-c",
                "for fd in /proc/self/fd/*; do n=${fd##*/}; case \"$n\" in 0|1|2) ;; *) eval \"exec $n>&-\" ;; esac; done; touch ready; while test ! -e release; do sleep 0.02; done"]);
        crate::hardening::secure_descriptors(&mut command, &instance.lease).unwrap();
        let mut child = SandboxChild(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !project.join("ready").exists() {
            assert!(
                Instant::now() < deadline,
                "sandbox did not signal readiness"
            );
            thread::sleep(Duration::from_millis(20));
        }
        drop(command);
        drop(instance);
        drop(project_guard);
        // No launcher lock remains. The only live lease is retained by bwrap.
        drop(project_lock(&home, &project, EXCLUSIVE).unwrap());
        assert!(crate::lifecycle::reset(&home, &project).is_err());
        assert!(crate::authority::approve(&spec).is_err());
        assert!(spec.state_dir.is_dir());
        fs::write(project.join("release"), b"release").unwrap();
        assert!(child.0.wait().unwrap().success());
        crate::lifecycle::reset(&home, &project).unwrap();
        assert!(!project.join(".sbox").exists());
        assert!(project.join("ready").exists());
    }

    #[test]
    fn reset_guard_survives_removal_of_the_entire_state_directory() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir(&home).unwrap();
        fs::create_dir_all(project.join(".sbox/state")).unwrap();
        let guard = exclusive(&home, &project).unwrap();
        fs::remove_dir_all(project.join(".sbox")).unwrap();
        assert!(shared(&home, &project).is_err());
        drop(guard);
        let running = shared(&home, &project).unwrap();
        fs::create_dir_all(project.join(".sbox/state")).unwrap();
        assert!(exclusive(&home, &project).is_err());
        drop(running);
        assert!(exclusive(&home, &project).is_ok());
    }
}
