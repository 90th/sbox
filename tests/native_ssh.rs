#![cfg(target_os = "linux")]
use sbox::{LaunchSpec, Runtime};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

struct Server {
    child: Child,
    port: u16,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn key(path: &Path) {
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}
fn server(root: &Path, identity: &Path, name: &str) -> Server {
    let host = root.join(format!("{name}-host"));
    key(&host);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let config = root.join(format!("{name}-config"));
    let user = std::env::var("USER").unwrap();
    fs::write(&config,format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowUsers {user}\nSubsystem sftp internal-sftp\n",host.display(),root.join(format!("{name}-pid")).display(),identity.with_extension("pub").display())).unwrap();
    let log = root.join(format!("{name}-log"));
    let child = Command::new("/usr/bin/sshd")
        .args(["-D", "-e", "-f"])
        .arg(config)
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let mut server = Server { child, port };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!(
                "sshd exited {status}: {}",
                fs::read_to_string(&log).unwrap()
            );
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    server
}

struct Fixture {
    _temp: TempDir,
    home: PathBuf,
    project: PathBuf,
    remote: PathBuf,
    _server: Server,
    other: Server,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let home = root.join("home");
        let project = root.join("project");
        let remote = root.join("remote space");
        for path in [
            home.join(".ssh"),
            home.join(".omp/agent"),
            project.clone(),
            remote.clone(),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        let identity = home.join(".ssh/vm-private");
        key(&identity);
        let vm_server = server(root, &identity, "vm");
        let other = server(root, &identity, "unrelated");
        let public = fs::read_to_string(root.join("vm-host.pub")).unwrap();
        fs::write(
            home.join(".ssh/known_hosts"),
            format!("[127.0.0.1]:{} {public}", vm_server.port),
        )
        .unwrap();
        fs::create_dir(home.join(".ssh/conf.d")).unwrap();
        fs::write(
            home.join(".ssh/config"),
            format!(
                "Include {}\nHost *\n ServerAliveInterval 15\n",
                home.join(".ssh/conf.d/*.conf").display()
            ),
        )
        .unwrap();
        fs::write(home.join(".ssh/conf.d/hosts.conf"),format!("Host build-node file-node\n HostName 127.0.0.1\n Port {}\n User {}\n IdentityFile {}\n IdentitiesOnly yes\n UserKnownHostsFile {}\n",vm_server.port,std::env::var("USER").unwrap(),identity.display(),home.join(".ssh/known_hosts").display())).unwrap();
        fs::create_dir(home.join("personal")).unwrap();
        fs::write(home.join("personal/canary"), b"private").unwrap();
        Self {
            _temp: temp,
            home,
            project,
            remote,
            _server: vm_server,
            other,
        }
    }
    fn run(&self, script: String) {
        let mut spec = LaunchSpec {
            bwrap: "/usr/bin/bwrap".into(),
            project: self.project.clone(),
            home: self.home.clone(),
            state_dir: self.project.join(".sbox/state"),
            uid: self.home.metadata().unwrap().uid(),
            omp: Runtime {
                lexical_executable: "/usr/bin/sh".into(),
                canonical_executable: "/usr/bin/sh".into(),
                mount_roots: vec![],
                path_dirs: vec![],
            },
            read_only: vec![],
            environment: BTreeMap::from([
                ("HOME".into(), self.home.as_os_str().to_owned()),
                ("PATH".into(), "/sbox/bin:/usr/bin:/bin".into()),
            ]),
            warnings: vec![],
            approval: None,
            git_metadata: vec![],
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_sbox")),
            ssh_hosts: sbox::ssh_hosts::configured_hosts(&self.home).unwrap(),
        };
        sbox::authority::approve(&spec).unwrap();
        spec.approval = Some(sbox::authority::authorize(&spec).unwrap());
        let status = sbox::run_omp(&spec, &["-c".into(), script.into()]).unwrap();
        assert!(status.success(), "native client failed: {status}");
    }
}

#[test]
#[ignore = "requires bwrap, local sshd and OpenSSH 8.9+ destination constraints"]
fn native_clients_transfer_both_directions_without_private_key_access() {
    let fixture = Fixture::new();
    let bytes: Vec<u8> = (0..=255).cycle().take(131072).collect();
    fs::write(fixture.project.join("upload.bin"), &bytes).unwrap();
    fs::create_dir(fixture.project.join("tree space")).unwrap();
    fs::write(fixture.project.join("tree space/nested.bin"), &bytes).unwrap();
    fs::write(
        fixture.project.join("batch"),
        format!(
            "put upload.bin \"{}/sftp.bin\"\nget \"{}/sftp.bin\" sftp-download.bin\n",
            fixture.remote.display(),
            fixture.remote.display()
        ),
    )
    .unwrap();
    fixture.run(format!(
        r#"set -eu
 test "$(command -v ssh)" = /usr/bin/ssh
 test "$(command -v scp)" = /usr/bin/scp
 test "$(command -v sftp)" = /usr/bin/sftp
 test ! -e "$HOME/.ssh/vm-private"
 test ! -e "$HOME/personal/canary"
 ssh -V
 config="$HOME/.ssh/config"
 test "$(ssh -F "$config" -o BatchMode=yes -o ConnectTimeout=5 build-node 'printf CI_OK')" = CI_OK
 scp -F "$config" -o BatchMode=yes upload.bin 'file-node:{remote}/scp.bin'
 scp -F "$config" -o ConnectTimeout=5 'file-node:{remote}/scp.bin' download.bin
 scp -F "$config" -r 'tree space' 'build-node:{remote}/'
 scp -F "$config" -O upload.bin 'build-node:{legacy}/legacy.bin'
 scp -F "$config" -O 'build-node:{legacy}/legacy.bin' legacy-download.bin
 sftp -F "$config" -o BatchMode=yes -b batch file-node
 "#,
        remote = fixture.remote.display(),
        legacy = fixture.remote.parent().unwrap().display()
    ));
    for path in ["download.bin", "sftp-download.bin", "legacy-download.bin"] {
        assert_eq!(fs::read(fixture.project.join(path)).unwrap(), bytes);
    }
    assert_eq!(
        fs::read(fixture.remote.join("tree space/nested.bin")).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read(fixture.home.join("personal/canary")).unwrap(),
        b"private"
    );
}

#[test]
#[ignore = "requires bwrap, local sshd and OpenSSH 8.9+ destination constraints"]
fn vm_identity_cannot_authenticate_to_an_unrelated_host_key() {
    let fixture = Fixture::new();
    fixture.run(format!(r#"set -eu
 ssh -F "$HOME/.ssh/config" -o BatchMode=yes build-node true
 if ssh -F "$HOME/.ssh/config" -p {} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 build-node 'printf WRONG_DESTINATION'; then exit 91; fi
 test ! -e "$HOME/.ssh/vm-private"
 "#,fixture.other.port));
}
