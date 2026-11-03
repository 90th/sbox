#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sbox::{LaunchSpec, Runtime, discover_mcp_mounts, run_omp};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        let project = root.join("project");
        let home = root.join("home");
        fs::create_dir_all(home.join(".omp")).unwrap();
        fs::create_dir(&project).unwrap();
        Self {
            _temp: temp,
            root,
            project: fs::canonicalize(project).unwrap(),
            home: fs::canonicalize(home).unwrap(),
        }
    }

    fn spec(&self, command: &Path) -> LaunchSpec {
        let lexical = command.to_path_buf();
        let canonical = fs::canonicalize(command).unwrap();
        let uid = self.home.metadata().unwrap().uid();
        LaunchSpec {
            bwrap: "/usr/bin/bwrap".into(),
            project: self.project.clone(),
            home: self.home.clone(),
            state_dir: self.project.join(".sbox/state"),
            uid,
            omp: Runtime {
                lexical_executable: lexical,
                canonical_executable: canonical,
                mount_roots: Vec::new(),
                path_dirs: Vec::new(),
            },
            read_only: Vec::new(),
            environment: BTreeMap::from([
                ("HOME".into(), self.home.as_os_str().to_owned()),
                ("USER".into(), "sbox-test".into()),
                ("LOGNAME".into(), "sbox-test".into()),
                ("SHELL".into(), "/bin/sh".into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("PWD".into(), self.project.as_os_str().to_owned()),
                ("TERM".into(), "dumb".into()),
                ("LANG".into(), "C.UTF-8".into()),
                ("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid}").into()),
                ("PI_CONFIG_DIR".into(), ".omp".into()),
            ]),
            warnings: Vec::new(),
            approval: None,
            git_metadata: Vec::new(),
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_sbox")),
            ssh_hosts: Vec::new(),
        }
    }
}

fn shell_args(script: String) -> Vec<OsString> {
    vec!["-c".into(), script.into()]
}

fn run_shell(spec: &LaunchSpec, script: String) {
    let status = run_omp(spec, &shell_args(script)).unwrap();
    assert!(status.success(), "sandbox payload failed with {status}");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn project_writes_work_and_outside_writes_fail() {
    let fixture = Fixture::new();
    let canary = fixture.root.join("outside-canary");
    fs::write(&canary, b"original").unwrap();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    run_shell(
        &spec,
        format!(
            "printf project > project-write; if printf changed > '{}'; then exit 41; fi",
            canary.display()
        ),
    );
    assert_eq!(
        fs::read(fixture.project.join("project-write")).unwrap(),
        b"project"
    );
    assert_eq!(fs::read(canary).unwrap(), b"original");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn allow_read_is_readable_and_read_only() {
    let fixture = Fixture::new();
    let context = fixture.root.join("context.txt");
    fs::write(&context, b"trusted context").unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/sh"));
    spec.read_only.push(context.clone());
    run_shell(
        &spec,
        format!(
            "cat '{}' > copied; if printf altered > '{}'; then exit 42; fi",
            context.display(),
            context.display()
        ),
    );
    assert_eq!(
        fs::read(fixture.project.join("copied")).unwrap(),
        b"trusted context"
    );
    assert_eq!(fs::read(context).unwrap(), b"trusted context");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn discovered_opencode_assets_are_readable_and_read_only() {
    let fixture = Fixture::new();
    let opencode = fixture.home.join(".config/opencode");
    let skill = opencode.join("skills/review.md");
    fs::create_dir_all(skill.parent().unwrap()).unwrap();
    fs::write(&skill, b"review instructions").unwrap();
    let discovery =
        discover_mcp_mounts(&fixture.home, &fixture.project, OsStr::new("/usr/bin:/bin")).unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/sh"));
    spec.read_only = discovery.mount_roots;

    run_shell(
        &spec,
        format!(
            "cat '{}' > copied; if printf altered > '{}'; then exit 43; fi",
            skill.display(),
            skill.display()
        ),
    );

    assert_eq!(
        fs::read(fixture.project.join("copied")).unwrap(),
        b"review instructions"
    );
    assert_eq!(fs::read(skill).unwrap(), b"review instructions");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn omp_overlay_persists_without_changing_lower_or_exposing_state() {
    let fixture = Fixture::new();
    let lower = fixture.home.join(".omp/value");
    fs::write(&lower, b"host lower").unwrap();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));

    run_shell(
        &spec,
        "printf sandbox > \"$HOME/.omp/value\"; test ! -e \"$PWD/.sbox/state\"; ! mkdir \"$PWD/.sbox/state\"".into(),
    );
    assert_eq!(fs::read(&lower).unwrap(), b"host lower");

    run_shell(&spec, "cat \"$HOME/.omp/value\" > observed".into());
    assert_eq!(
        fs::read(fixture.project.join("observed")).unwrap(),
        b"sandbox"
    );
    assert_eq!(fs::read(lower).unwrap(), b"host lower");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn omp_session_survives_sbox_state_deletion() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    let sessions_root = fixture.home.join(".omp/agent/sessions");

    run_shell(
        &spec,
        "mkdir -p \"$HOME/.omp/agent/sessions/project\"; printf session > \"$HOME/.omp/agent/sessions/project/persisted-session.jsonl\""
            .into(),
    );

    let session_dir = fs::read_dir(&sessions_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("sandbox did not prepare a project session directory");
    let session_file = session_dir.join("persisted-session.jsonl");

    fs::remove_dir_all(fixture.project.join(".sbox")).unwrap();
    assert_eq!(fs::read(session_file).unwrap(), b"session");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn omp_auth_state_survives_sbox_state_deletion() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    let marker = fixture.home.join(".omp/agent/oauth-state-marker");

    run_shell(
        &spec,
        "printf shared > \"$HOME/.omp/agent/oauth-state-marker\"".into(),
    );

    fs::remove_dir_all(fixture.project.join(".sbox")).unwrap();
    assert_eq!(fs::read(marker).unwrap(), b"shared");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn shared_loopback_reaches_host_tcp_listener() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"loopback").unwrap();
    });
    let spec = fixture.spec(Path::new("/usr/bin/python3"));
    let code = "import socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); s.sendall(b'ping'); open('network-result','wb').write(s.recv(32))";
    let status = run_omp(&spec, &["-c".into(), code.into(), port.to_string().into()]).unwrap();
    assert!(status.success());
    server.join().unwrap();
    assert_eq!(
        fs::read(fixture.project.join("network-result")).unwrap(),
        b"loopback"
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn exact_namespace_sequence_succeeds() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Path::new("/usr/bin/true"));
    let status = run_omp(&spec, &[]).unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn project_symlink_cannot_reach_private_home() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fs::create_dir(fixture.home.join(".ssh")).unwrap();
    fs::write(fixture.home.join(".ssh/canary"), b"private").unwrap();
    symlink(fixture.home.join(".ssh"), fixture.project.join("escape")).unwrap();
    run_shell(
        &fixture.spec(Path::new("/usr/bin/sh")),
        "test ! -e escape/canary; test ! -e \"$HOME/.ssh/canary\"".into(),
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn symlinked_directory_and_socket_grants_are_rejected() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let fixture = Fixture::new();
    let private = fixture.home.join("private");
    fs::create_dir(&private).unwrap();
    let alias = fixture.home.join("alias");
    symlink(&private, &alias).unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/true"));
    spec.read_only.push(alias);
    assert!(run_omp(&spec, &[]).is_err());
    let socket = fixture.home.join("host.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    spec.read_only = vec![socket];
    assert!(run_omp(&spec, &[]).is_err());
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn inherited_host_descriptor_is_not_visible() {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    let fixture = Fixture::new();
    let secret = fixture.home.join("private");
    fs::write(&secret, b"host-descriptor-canary").unwrap();
    let file = fs::File::open(&secret).unwrap();
    let fd = file.as_raw_fd();
    assert_eq!(unsafe { fcntl(fd, 2, 0) }, 0);
    run_shell(
        &fixture.spec(Path::new("/usr/bin/sh")),
        format!("test ! -e /proc/self/fd/{fd}"),
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn cargo_cache_is_writable_without_host_credentials_or_host_mutation() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home.join(".cargo/registry")).unwrap();
    fs::write(fixture.home.join(".cargo/registry/canary"), b"dependency").unwrap();
    fs::write(fixture.home.join(".cargo/credentials.toml"), b"private").unwrap();
    run_shell(&fixture.spec(Path::new("/usr/bin/sh")), "test ! -e \"$HOME/.cargo/credentials.toml\" && test \"$(cat \"$HOME/.cargo/registry/canary\")\" = dependency && printf sandbox > \"$HOME/.cargo/registry/canary\"".into());
    assert_eq!(
        fs::read(fixture.home.join(".cargo/registry/canary")).unwrap(),
        b"dependency"
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn sandbox_cannot_change_future_mount_authority_or_native_extensions() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home.join(".omp/agent")).unwrap();
    fs::write(fixture.home.join(".omp/agent/mcp.json"), b"{}").unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/sh"));
    sbox::authority::approve(&spec).unwrap();
    spec.approval = Some(sbox::authority::authorize(&spec).unwrap());
    run_shell(&spec, "if printf evil > \"$HOME/.omp/agent/mcp.json\"; then exit 81; fi; if printf evil > \"$HOME/.omp/agent/extensions/evil.js\"; then exit 82; fi; if mkdir -p \"$HOME/.config/sbox/forged\"; then exit 83; fi".into());
    assert_eq!(
        fs::read(fixture.home.join(".omp/agent/mcp.json")).unwrap(),
        b"{}"
    );
    assert!(!fixture.home.join(".omp/agent/extensions/evil.js").exists());
    // Even a configuration changed externally cannot grant a new path merely
    // by appearing as an MCP argument on the next launch.
    let private = fixture.home.join("private");
    fs::create_dir(&private).unwrap();
    fs::write(private.join("canary"), b"private").unwrap();
    fs::write(
        fixture.home.join(".omp/agent/mcp.json"),
        serde_json::to_vec(
            &serde_json::json!({"mcpServers":{"bad":{"command":"/usr/bin/true","args":[private]}}}),
        )
        .unwrap(),
    )
    .unwrap();
    spec.read_only = discover_mcp_mounts(&fixture.home, &fixture.project, OsStr::new("/usr/bin"))
        .unwrap()
        .mount_roots;
    assert!(
        sbox::authority::authorize(&spec)
            .unwrap_err()
            .to_string()
            .contains("requires host approval")
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn reset_preserves_project_and_native_sessions() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    run_shell(&spec, "printf project > source; mkdir -p \"$HOME/.omp/agent/sessions\"; printf session > \"$HOME/.omp/agent/sessions/canary\"".into());
    sbox::lifecycle::reset(&fixture.home, &fixture.project).unwrap();
    assert!(!fixture.project.join(".sbox").exists());
    assert_eq!(
        fs::read(fixture.project.join("source")).unwrap(),
        b"project"
    );
    assert_eq!(
        fs::read(fixture.home.join(".omp/agent/sessions/canary")).unwrap(),
        b"session"
    );
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn mount_source_descriptors_do_not_reopen_host_paths() {
    let fixture = Fixture::new();
    run_shell(&fixture.spec(Path::new("/usr/bin/sh")), "for fd in /proc/self/fd/*; do target=$(readlink \"$fd\" || :); case \"$target\" in *\"$HOME\"*) echo \"host descriptor leak: $target\"; exit 85;; esac; done".into());
}

#[test]
#[ignore = "requires bwrap, git and unprivileged user namespaces"]
fn linked_worktree_can_commit_without_exposing_its_parent_working_tree() {
    use std::process::Command;
    let fixture = Fixture::new();
    let main = fixture.root.join("main");
    let git = |args: &[&str]| {
        let result = Command::new("/usr/bin/git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=QA",
                "-c",
                "user.email=qa@example.invalid",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    };
    git(&["init", "-q", main.to_str().unwrap()]);
    git(&[
        "-C",
        main.to_str().unwrap(),
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "base",
    ]);
    git(&[
        "-C",
        main.to_str().unwrap(),
        "worktree",
        "add",
        "-q",
        "-b",
        "sandbox",
        fixture.project.to_str().unwrap(),
    ]);
    fs::write(main.join("personal-canary"), b"private").unwrap();
    fs::create_dir_all(fixture.home.join(".omp/agent")).unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/sh"));
    spec.git_metadata = sbox::lifecycle::git_metadata(&fixture.project).unwrap();
    sbox::authority::approve(&spec).unwrap();
    spec.approval = Some(sbox::authority::authorize(&spec).unwrap());
    run_shell(
        &spec,
        format!(
            "git -c user.name=QA -c user.email=qa@example.invalid -c commit.gpgsign=false commit -q --allow-empty -m sandbox; test ! -e '{}/personal-canary'; if printf evil > '{}/.git/config'; then exit 86; fi",
            main.display(),
            main.display()
        ),
    );
    let output = git(&[
        "-C",
        fixture.project.to_str().unwrap(),
        "log",
        "-1",
        "--format=%s",
    ]);
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "sandbox");
}

#[test]
fn newly_discovered_ssh_host_requires_explicit_host_approval() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.home.join(".omp/agent")).unwrap();
    fs::create_dir(fixture.home.join(".ssh")).unwrap();
    fs::write(
        fixture.home.join(".ssh/config"),
        "Host existing-build-host\n HostName example.invalid\n",
    )
    .unwrap();
    let mut spec = fixture.spec(Path::new("/usr/bin/true"));
    spec.ssh_hosts = sbox::ssh_hosts::configured_hosts(&fixture.home).unwrap();
    sbox::authority::approve(&spec).unwrap();
    fs::write(
        fixture.home.join(".ssh/config"),
        "Host existing-build-host new-credential-host\n HostName example.invalid\n",
    )
    .unwrap();
    spec.ssh_hosts = sbox::ssh_hosts::configured_hosts(&fixture.home).unwrap();
    let error = sbox::authority::authorize(&spec).unwrap_err().to_string();
    assert!(
        error.contains("new SSH credential destination new-credential-host requires host approval")
    );
}

struct RunningSandbox {
    release: PathBuf,
    handle: Option<thread::JoinHandle<()>>,
}

impl RunningSandbox {
    fn finish(mut self) {
        fs::write(&self.release, b"release").unwrap();
        self.handle.take().unwrap().join().unwrap();
    }
}

impl Drop for RunningSandbox {
    fn drop(&mut self) {
        let _ = fs::write(&self.release, b"release");
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "sandbox did not signal readiness"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn concurrent_instances_have_independent_persistent_overlays_and_shared_project_files() {
    let fixture = Fixture::new();
    fs::write(fixture.home.join(".omp/value"), b"lower").unwrap();
    fs::create_dir_all(fixture.home.join(".cargo/registry")).unwrap();
    fs::write(fixture.home.join(".cargo/registry/value"), b"lower").unwrap();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    let first_spec = spec.clone();
    let first = RunningSandbox {
        release: fixture.project.join("release-first"),
        handle: Some(thread::spawn(move || {
            run_shell(&first_spec, "set -eu; printf first > \"$HOME/.omp/value\"; printf first > \"$HOME/.cargo/registry/value\"; touch first-ready; while test ! -e release-first; do sleep 0.02; done; test \"$(cat \"$HOME/.omp/value\")\" = first; test \"$(cat \"$HOME/.cargo/registry/value\")\" = first".into());
        })),
    };
    wait_for(&fixture.project.join("first-ready"));
    run_shell(&spec, "set -eu; test -e first-ready; test \"$(cat \"$HOME/.omp/value\")\" = lower; test \"$(cat \"$HOME/.cargo/registry/value\")\" = lower; printf second > \"$HOME/.omp/value\"; printf second > \"$HOME/.cargo/registry/value\"; touch second-completed".into());
    assert!(fixture.project.join("second-completed").exists());
    // While the first instance is still live, the freed second slot is reusable.
    run_shell(&spec, "set -eu; test \"$(cat \"$HOME/.omp/value\")\" = second; test \"$(cat \"$HOME/.cargo/registry/value\")\" = second".into());
    assert!(sbox::lifecycle::reset(&fixture.home, &fixture.project).is_err());
    assert!(sbox::authority::approve(&spec).is_err());
    assert!(fixture.project.join(".sbox").is_dir());
    first.finish();
    run_shell(&spec, "set -eu; test \"$(cat \"$HOME/.omp/value\")\" = first; test \"$(cat \"$HOME/.cargo/registry/value\")\" = first".into());
    assert_eq!(fs::read(fixture.home.join(".omp/value")).unwrap(), b"lower");
    assert_eq!(
        fs::read(fixture.home.join(".cargo/registry/value")).unwrap(),
        b"lower"
    );
    sbox::authority::approve(&spec).unwrap();
    sbox::lifecycle::reset(&fixture.home, &fixture.project).unwrap();
    assert!(fixture.project.join("second-completed").exists());
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn new_instances_can_coexist_with_an_old_launcher_lock_without_touching_old_state() {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    let fixture = Fixture::new();
    let state = fixture.project.join(".sbox/state");
    fs::create_dir_all(state.join("omp-upper")).unwrap();
    fs::write(
        state.join("omp-upper/legacy-value"),
        b"running-old-instance",
    )
    .unwrap();
    let legacy = fs::File::create(state.join("omp.lock")).unwrap();
    assert_eq!(unsafe { flock(legacy.as_raw_fd(), 2 | 4) }, 0);
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    run_shell(&spec, "set -eu; test ! -e \"$HOME/.omp/legacy-value\"; printf new > \"$HOME/.omp/value\"; touch new-completed".into());
    assert!(fixture.project.join("new-completed").exists());
    assert!(sbox::lifecycle::reset(&fixture.home, &fixture.project).is_err());
    assert!(sbox::authority::approve(&spec).is_err());
    assert_eq!(
        fs::read(state.join("omp-upper/legacy-value")).unwrap(),
        b"running-old-instance"
    );
    drop(legacy);
    sbox::lifecycle::reset(&fixture.home, &fixture.project).unwrap();
    assert!(fixture.project.join("new-completed").exists());
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn simultaneous_first_launches_allocate_distinct_state_without_initialization_races() {
    use std::sync::{Arc, Barrier};
    let fixture = Fixture::new();
    let barrier = Arc::new(Barrier::new(3));
    let mut children = Vec::new();
    for name in ["alpha", "beta"] {
        let spec = fixture.spec(Path::new("/usr/bin/sh"));
        let start = barrier.clone();
        children.push(RunningSandbox {
            release:fixture.project.join("release"),
            handle:Some(thread::spawn(move|| {
                start.wait();
                run_shell(&spec,format!("set -eu; test ! -e \"$HOME/.omp/own\"; printf {name} > \"$HOME/.omp/own\"; touch {name}-ready; while test ! -e release; do sleep 0.02; done; cat \"$HOME/.omp/own\" > {name}-observed"));
            })),
        });
    }
    barrier.wait();
    wait_for(&fixture.project.join("alpha-ready"));
    wait_for(&fixture.project.join("beta-ready"));
    for child in children {
        child.finish();
    }
    assert_eq!(
        fs::read(fixture.project.join("alpha-observed")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        fs::read(fixture.project.join("beta-observed")).unwrap(),
        b"beta"
    );
    assert!(!fixture.home.join(".omp/own").exists());
}
