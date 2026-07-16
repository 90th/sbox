#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sbox::{LaunchSpec, Runtime, run_omp};
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
    assert!(fixture.project.join(".sbox/state/omp-upper").is_dir());

    run_shell(&spec, "cat \"$HOME/.omp/value\" > observed".into());
    assert_eq!(
        fs::read(fixture.project.join("observed")).unwrap(),
        b"sandbox"
    );
    assert_eq!(fs::read(lower).unwrap(), b"host lower");
}

#[test]
#[ignore = "requires bwrap and unprivileged user namespaces"]
fn lock_serializes_launches_sharing_an_upper() {
    let fixture = Fixture::new();
    let spec = fixture.spec(Path::new("/usr/bin/sh"));
    let first_spec = spec.clone();
    let first = thread::spawn(move || {
        run_shell(
            &first_spec,
            "touch first-started; sleep 2; touch first-finished".into(),
        );
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.project.join("first-started").exists() {
        assert!(Instant::now() < deadline, "first payload did not start");
        thread::sleep(Duration::from_millis(20));
    }

    let second_spec = spec.clone();
    let second = thread::spawn(move || {
        run_shell(&second_spec, "touch second-started".into());
    });
    thread::sleep(Duration::from_millis(300));
    assert!(!fixture.project.join("second-started").exists());
    first.join().unwrap();
    second.join().unwrap();
    assert!(fixture.project.join("first-finished").exists());
    assert!(fixture.project.join("second-started").exists());
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
