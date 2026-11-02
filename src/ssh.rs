//! Narrow host SSH and clipboard capabilities without sharing host keys or desktop sockets.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

const SOCKET: &str = "/run/sbox-host/connect";
const MAX_FRAME: usize = 65536;
#[derive(Debug, Serialize, Deserialize)]
struct Request {
    host: String,
    command: Vec<String>,
    tty: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum Operation {
    Ssh(Request),
    Clipboard { args: Vec<String> },
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Request> {
    let mut args = args.into_iter();
    let mut tty = false;
    let mut host = None;
    for arg in args.by_ref() {
        match arg.as_str() {
            "-T" => tty = false,
            "-t" | "-tt" => tty = true,
            "--" => {
                host = args.next();
                break;
            }
            _ if arg.starts_with('-') => bail!(
                "SSH option {arg} is not permitted; forwarding, custom configs and arbitrary destinations are disabled"
            ),
            _ => {
                host = Some(arg);
                break;
            }
        }
    }
    let host = host.context("usage: ssh [-T|-t] HOST [COMMAND ...]")?;
    if host.starts_with('-') || host.contains('@') {
        bail!("use an approved host alias without user/options");
    }
    Ok(Request {
        host,
        command: args.collect(),
        tty,
    })
}

fn frame(stream: &mut impl Write, kind: u8, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)
}
fn receive(stream: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0];
    match stream.read_exact(&mut kind) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized SSH frame",
        ));
    }
    let mut data = vec![0; size];
    stream.read_exact(&mut data)?;
    Ok(Some((kind[0], data)))
}

pub fn client(args: impl IntoIterator<Item = String>) -> Result<u8> {
    exchange(Operation::Ssh(parse(args)?))
}

pub fn clipboard_client(args: impl IntoIterator<Item = String>) -> Result<u8> {
    exchange(Operation::Clipboard {
        args: crate::clipboard::arguments(args)?,
    })
}

fn exchange(request: Operation) -> Result<u8> {
    let mut stream = UnixStream::connect(SOCKET)
        .context("host connector is available only inside an approved sbox session")?;
    let mut request = serde_json::to_vec(&request)?;
    request.push(b'\n');
    stream.write_all(&request)?;
    let mut input = stream.try_clone()?;
    thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = frame(&mut input, 4, &[]);
                    break;
                }
                Ok(n) => {
                    if frame(&mut input, 0, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    while let Some((kind, data)) = receive(&mut stream)? {
        match kind {
            1 => {
                let mut out = std::io::stdout().lock();
                out.write_all(&data)?;
                out.flush()?;
            }
            2 => std::io::stderr().write_all(&data)?,
            3 => return Ok(*data.first().context("missing SSH exit code")?),
            _ => bail!("invalid SSH response"),
        }
    }
    bail!("SSH connector disconnected without exit status")
}

pub(crate) struct Bridge {
    pub directory: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    _temp: tempfile::TempDir,
}
impl Bridge {
    pub fn start(hosts: BTreeMap<String, String>) -> Result<Self> {
        let temp = tempfile::Builder::new().prefix("sbox-host-").tempdir()?;
        let directory = temp.path().to_path_buf();
        let listener = UnixListener::bind(directory.join("connect"))?;
        fs_mode(&directory.join("connect"), 0o600)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let thread = thread::spawn(move || {
            let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                workers.retain(|worker| !worker.is_finished());
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.fetch_add(1, Ordering::AcqRel) >= 32 {
                            active.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                        let hosts = hosts.clone();
                        let active = active.clone();
                        let stop = stopping.clone();
                        workers.push(thread::spawn(move || {
                            if let Err(error) = serve(stream, &hosts, stop) {
                                eprintln!("sbox host connector: {error:#}");
                            }
                            active.fetch_sub(1, Ordering::AcqRel);
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(25))
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            directory,
            stop,
            thread: Some(thread),
            _temp: temp,
        })
    }
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn fs_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn ssh_command(request: &Request, hosts: &BTreeMap<String, String>) -> Result<Command> {
    let host = hosts
        .get(&request.host)
        .context("SSH host is not approved")?;
    let mut command = Command::new("/usr/bin/ssh");
    command.env_clear();
    for name in ["HOME", "USER", "LOGNAME", "SSH_AUTH_SOCK", "TERM"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("PATH", "/usr/bin:/bin");
    command.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ForwardX11Trusted=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=yes",
    ]);
    command
        .arg(if request.tty { "-tt" } else { "-T" })
        .arg("--")
        .arg(host)
        .args(&request.command);
    Ok(command)
}

fn serve(
    mut stream: UnixStream,
    hosts: &BTreeMap<String, String>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    std::io::Read::by_ref(&mut reader)
        .take((MAX_FRAME + 1) as u64)
        .read_line(&mut line)?;
    if line.len() > MAX_FRAME || !line.ends_with('\n') {
        bail!("invalid host capability request");
    }
    let request: Operation = serde_json::from_str(&line)?;
    let command = match match request {
        Operation::Ssh(request) => ssh_command(&request, hosts),
        Operation::Clipboard { args } => crate::clipboard::command(&args),
    } {
        Ok(command) => command,
        Err(error) => {
            frame(&mut stream, 2, error.to_string().as_bytes())?;
            frame(&mut stream, 3, &[126])?;
            return Ok(());
        }
    };
    run_stream(stream, reader, command, stop)
}

fn run_stream(
    stream: UnixStream,
    mut reader: BufReader<UnixStream>,
    mut command: Command,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    stream.set_read_timeout(None)?;
    let output = Arc::new(Mutex::new(stream.try_clone()?));
    let mut stdin = child.stdin.take();
    let disconnected = Arc::new(AtomicBool::new(false));
    let input_disconnected = disconnected.clone();
    let input = thread::spawn(move || {
        while let Ok(Some((kind, data))) = receive(&mut reader) {
            if kind == 4 {
                stdin.take();
                continue;
            }
            if kind != 0
                || stdin
                    .as_mut()
                    .is_none_or(|pipe| pipe.write_all(&data).is_err())
            {
                break;
            }
        }
        input_disconnected.store(true, Ordering::Relaxed);
    });
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let drain = |mut pipe: Box<dyn Read + Send>, kind, output: Arc<Mutex<UnixStream>>| {
        thread::spawn(move || {
            let mut buf = [0; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if frame(&mut *output.lock().unwrap(), kind, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    };
    let out = drain(Box::new(stdout), 1, output.clone());
    let err = drain(Box::new(stderr), 2, output.clone());
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if stop.load(Ordering::Relaxed) || disconnected.load(Ordering::Relaxed) {
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            unsafe {
                kill(-(child.id() as i32), 9);
            }
            break child.wait()?;
        }
        thread::sleep(std::time::Duration::from_millis(25));
    };
    let _ = stream.shutdown(Shutdown::Read);
    let _ = input.join();
    let _ = out.join();
    let _ = err.join();
    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    frame(
        &mut *output.lock().unwrap(),
        3,
        &[u8::try_from(code).unwrap_or(1)],
    )?;
    Ok(())
}

pub(crate) fn hosts() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("kali-vm".into(), "kali-vm".into()),
        ("windows-vm".into(), "windows-builder".into()),
        ("windows-builder".into(), "windows-builder".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_cannot_authorize_host_execution_or_forwarding() {
        for args in [
            vec!["-oProxyCommand=touch /tmp/no"],
            vec!["-F", "/tmp/config"],
            vec!["-L", "1234:host:22"],
            vec!["user@kali-vm"],
        ] {
            assert!(parse(args.into_iter().map(str::to_owned)).is_err());
        }
    }
    #[test]
    fn unapproved_destinations_are_rejected() {
        let request = parse(["other-host".into(), "true".into()]).unwrap();
        assert!(ssh_command(&request, &hosts()).is_err());
    }
    #[test]
    fn remote_command_cannot_become_a_local_ssh_option() {
        let request = parse([
            "-T".into(),
            "kali-vm".into(),
            "-oProxyCommand=PROXY_INJECTION_CANARY".into(),
        ])
        .unwrap();
        let command = ssh_command(&request, &hosts()).unwrap();
        let output = Command::new("/usr/bin/ssh")
            .args(["-F", "/dev/null", "-G"])
            .args(command.get_args())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PROXY_INJECTION_CANARY"));
    }
    #[test]
    fn unauthorized_host_is_rejected_over_the_actual_broker_socket() {
        let bridge = Bridge::start(hosts()).unwrap();
        let mut stream = UnixStream::connect(bridge.directory.join("connect")).unwrap();
        stream
            .write_all(b"{\"operation\":\"ssh\",\"host\":\"unapproved\",\"command\":[\"true\"],\"tty\":false}\n")
            .unwrap();
        let (kind, message) = receive(&mut stream).unwrap().unwrap();
        assert_eq!(kind, 2);
        assert!(String::from_utf8(message).unwrap().contains("not approved"));
        assert_eq!(receive(&mut stream).unwrap(), Some((3, vec![126])));
    }

    #[test]
    fn clipboard_watch_is_rejected_even_without_client_validation() {
        let bridge = Bridge::start(hosts()).unwrap();
        let mut stream = UnixStream::connect(bridge.directory.join("connect")).unwrap();
        stream
            .write_all(b"{\"operation\":\"clipboard\",\"args\":[\"--watch\",\"sh\"]}\n")
            .unwrap();
        let (kind, message) = receive(&mut stream).unwrap().unwrap();
        assert_eq!(kind, 2);
        assert!(
            String::from_utf8(message)
                .unwrap()
                .contains("not permitted")
        );
        assert_eq!(receive(&mut stream).unwrap(), Some((3, vec![126])));
    }

    #[test]
    #[ignore = "requires local sshd, ssh-keygen and unprivileged SSH server support"]
    fn real_ssh_stream_keeps_stdout_stderr_and_exit_status_separate() {
        use std::fs;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for name in ["host", "identity"] {
            assert!(
                Command::new("/usr/bin/ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", ""])
                    .arg("-f")
                    .arg(root.join(name))
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let user = std::env::var("USER").unwrap();
        fs::write(root.join("sshd_config"),format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowUsers {user}\n",root.join("host").display(),root.join("pid").display(),root.join("identity.pub").display())).unwrap();
        let log = fs::File::create(root.join("sshd.log")).unwrap();
        let server = Command::new("/usr/bin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(root.join("sshd_config"))
            .stderr(log)
            .spawn()
            .unwrap();
        struct Guard(std::process::Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut server = Guard(server);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = server.0.try_wait().unwrap() {
                panic!(
                    "local sshd exited {status}: {}",
                    fs::read_to_string(root.join("sshd.log")).unwrap()
                );
            }
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "local sshd did not listen"
            );
            thread::sleep(std::time::Duration::from_millis(20));
        }
        fs::write(
            root.join("known_hosts"),
            format!(
                "[127.0.0.1]:{port} {}",
                fs::read_to_string(root.join("host.pub")).unwrap()
            ),
        )
        .unwrap();
        fs::write(root.join("ssh_config"),format!("Host fixture\n HostName 127.0.0.1\n Port {port}\n User {user}\n IdentityFile {}\n IdentitiesOnly yes\n UserKnownHostsFile {}\n",root.join("identity").display(),root.join("known_hosts").display())).unwrap();
        let request = Request {
            host: "fixture".into(),
            command: vec!["printf stdout-marker; printf stderr-marker >&2; exit 7".into()],
            tty: false,
        };
        let original = ssh_command(
            &request,
            &BTreeMap::from([("fixture".into(), "fixture".into())]),
        )
        .unwrap();
        let mut command = Command::new(original.get_program());
        command
            .arg("-F")
            .arg(root.join("ssh_config"))
            .args(original.get_args())
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        let reader = BufReader::new(server.try_clone().unwrap());
        let worker = thread::spawn(move || {
            run_stream(server, reader, command, Arc::new(AtomicBool::new(false)))
        });
        frame(&mut client, 4, &[]).unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let (kind, data) = receive(&mut client).unwrap().unwrap();
            match kind {
                1 => stdout.extend(data),
                2 => stderr.extend(data),
                3 => {
                    assert_eq!(
                        data,
                        vec![7],
                        "SSH error: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                    break;
                }
                _ => panic!("invalid channel"),
            }
        }
        worker.join().unwrap().unwrap();
        assert_eq!(stdout, b"stdout-marker");
        assert_eq!(stderr, b"stderr-marker");
    }
    #[test]
    fn disconnect_after_stdin_eof_terminates_the_host_process() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let reader = BufReader::new(server.try_clone().unwrap());
        let mut command = Command::new("/usr/bin/sleep");
        command.arg("60");
        let (done, completion) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let result = run_stream(server, reader, command, Arc::new(AtomicBool::new(false)));
            done.send(result.is_err()).unwrap();
        });
        frame(&mut client, 4, &[]).unwrap();
        drop(client);
        assert!(
            completion
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap()
        );
        worker.join().unwrap();
    }
}
