//! Native OpenSSH clients with host-approved signing authority, not private files.
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Destination {
    alias: String,
    hostname: String,
    user: String,
    port: String,
    lookup: String,
    keys: Vec<PathBuf>,
    hostkeys: Vec<(String, String)>,
    options: Vec<(String, String)>,
}
pub(crate) struct Agent {
    child: Child,
}
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn checked(command: &mut Command, description: &str) -> Result<Vec<u8>> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| description.to_owned())?;
    if !output.status.success() {
        bail!(
            "{description}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}
fn home_path(home: &Path, value: &str) -> PathBuf {
    value
        .strip_prefix("~/")
        .map_or_else(|| PathBuf::from(value), |tail| home.join(tail))
}
fn quoted(value: &str) -> Result<String> {
    if value.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
        bail!("invalid line break in SSH configuration value");
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn discover(home: &Path, directory: &Path, hosts: &[String]) -> Result<Vec<Destination>> {
    let config = directory.join("resolve-config");
    let mut include = String::new();
    for path in [
        home.join(".ssh/config"),
        PathBuf::from("/etc/ssh/ssh_config"),
    ] {
        if path.is_file() {
            include.push_str(&format!(
                "Host *\nInclude {}\n",
                quoted(path.to_str().context("SSH config path is not UTF-8")?)?
            ));
        }
    }
    fs::write(&config, include)?;
    let mut result = Vec::new();
    for source in hosts {
        crate::ssh_hosts::validate_alias(source)?;
        let output = checked(
            Command::new("/usr/bin/ssh")
                .arg("-G")
                .arg("-F")
                .arg(&config)
                .arg("--")
                .arg(source),
            "cannot resolve SSH configuration",
        )?;
        let text = String::from_utf8(output)?;
        let mut values: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once(' ') {
                values.entry(key).or_default().push(value.trim());
            }
        }
        let get = |key: &str| values.get(key).and_then(|values| values.first()).copied();
        let hostname = get("hostname").context("SSH hostname is missing")?;
        let user = get("user").context("SSH username is missing")?;
        let port = get("port").unwrap_or("22");
        quoted(hostname)?;
        quoted(user)?;
        quoted(port)?;
        let mut keys: Vec<_> = values
            .get("identityfile")
            .into_iter()
            .flatten()
            .filter(|path| **path != "none")
            .map(|path| home_path(home, path))
            .filter(|path| path.is_file())
            .map(fs::canonicalize)
            .collect::<std::io::Result<Vec<_>>>()?;
        let alias = get("hostkeyalias").filter(|value| *value != "none");
        let lookup = alias.map(str::to_owned).unwrap_or_else(|| {
            if port == "22" {
                hostname.into()
            } else {
                format!("[{hostname}]:{port}")
            }
        });
        quoted(&lookup)?;
        let mut hostkeys = BTreeSet::new();
        for name in ["userknownhostsfile", "globalknownhostsfile"] {
            for path in values
                .get(name)
                .into_iter()
                .flatten()
                .flat_map(|paths| paths.split_whitespace())
            {
                let path = home_path(home, path);
                if !path.is_file() {
                    continue;
                }
                let output = Command::new("/usr/bin/ssh-keygen")
                    .args(["-F", &lookup, "-f"])
                    .arg(path)
                    .output()?;
                if !output.status.success() {
                    continue;
                }
                for line in String::from_utf8(output.stdout)?
                    .lines()
                    .filter(|line| !line.starts_with('#'))
                {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let (marker, index) =
                        if fields.first().is_some_and(|field| field.starts_with('@')) {
                            (fields[0], 1)
                        } else {
                            ("", 0)
                        };
                    if fields.len() >= index + 3 {
                        hostkeys.insert((
                            marker.to_owned(),
                            format!("{} {}", fields[index + 1], fields[index + 2]),
                        ));
                    }
                }
            }
        }
        if !hostkeys.iter().any(|(marker, _)| marker != "@revoked") {
            if !keys.is_empty() {
                eprintln!(
                    "sbox SSH: {source}: no trusted host key; no private-key authentication delegated. Verify this host with native SSH first."
                );
            }
            keys.clear();
        }
        let excluded = [
            "host",
            "hostname",
            "user",
            "port",
            "identityfile",
            "certificatefile",
            "identityagent",
            "userknownhostsfile",
            "globalknownhostsfile",
            "controlpath",
            "pkcs11provider",
            "securitykeyprovider",
        ];
        let options = text
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(key, value)| {
                !(excluded.contains(key) || *key == "hostkeyalias" && *value == "none")
            })
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        result.push(Destination {
            alias: source.clone(),
            hostname: hostname.into(),
            user: user.into(),
            port: port.into(),
            lookup,
            keys,
            hostkeys: hostkeys.into_iter().collect(),
            options,
        });
    }
    Ok(result)
}

struct Credential {
    key: PathBuf,
    public: Vec<u8>,
    indices: BTreeSet<usize>,
    paths: Vec<PathBuf>,
}
impl Agent {
    pub(crate) fn start(home: &Path, directory: &Path, hosts: &[String]) -> Result<Option<Self>> {
        if hosts.is_empty() {
            return Ok(None);
        }
        let destinations = discover(home, directory, hosts)?;
        Self::from_destinations(directory, &destinations).map(Some)
    }
    fn from_destinations(directory: &Path, destinations: &[Destination]) -> Result<Self> {
        let ssh = directory.join("ssh");
        fs::create_dir(&ssh)?;
        let known = ssh.join("known_hosts");
        let constraints = directory.join("agent_hosts");
        let mut known_hosts = String::new();
        let mut constraint_hosts = String::new();
        for (index, destination) in destinations.iter().enumerate() {
            for (marker, key) in &destination.hostkeys {
                let prefix = if marker.is_empty() {
                    String::new()
                } else {
                    format!("{marker} ")
                };
                known_hosts.push_str(&format!("{prefix}{} {key}\n", destination.lookup));
                if marker != "@revoked" {
                    constraint_hosts.push_str(&format!("{prefix}sbox-host-{index} {key}\n"));
                }
            }
        }
        fs::write(&known, known_hosts)?;
        fs::write(&constraints, constraint_hosts)?;
        let socket = directory.join("ssh-agent");
        let log = fs::File::create(directory.join("agent.log"))?;
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/usr/bin/ssh-agent");
        command
            .args(["-D", "-P", ""])
            .arg("-a")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        let parent = std::process::id() as i32;
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn prctl(option: i32, ...) -> i32;
                    fn getppid() -> i32;
                }
                if prctl(1, 15, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if getppid() != parent {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "sandbox launcher exited",
                    ));
                }
                Ok(())
            });
        }
        let child = command.spawn().context("cannot start private ssh-agent")?;
        let mut agent = Self { child };
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = agent.child.try_wait()? {
                bail!(
                    "private ssh-agent exited {status}: {}",
                    fs::read_to_string(directory.join("agent.log"))?
                );
            }
            if UnixStream::connect(&socket).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                bail!("private ssh-agent did not create its socket");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut paths: BTreeMap<PathBuf, BTreeSet<usize>> = BTreeMap::new();
        for (index, destination) in destinations.iter().enumerate() {
            for key in &destination.keys {
                paths
                    .entry(fs::canonicalize(key)?)
                    .or_default()
                    .insert(index);
            }
        }
        let mut credentials: BTreeMap<String, Credential> = BTreeMap::new();
        for (key, indices) in paths {
            let public = match checked(
                Command::new("/usr/bin/ssh-keygen")
                    .args(["-y", "-P", "", "-f"])
                    .arg(&key),
                "SSH identity is not usable without a passphrase prompt",
            ) {
                Ok(public) => public,
                Err(error) => {
                    eprintln!("sbox SSH: {} was not delegated: {error:#}", key.display());
                    continue;
                }
            };
            let mut fields = std::str::from_utf8(&public)?.split_whitespace();
            let identity = format!(
                "{} {}",
                fields.next().context("missing public key type")?,
                fields.next().context("missing public key data")?
            );
            match credentials.entry(identity) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Credential {
                        key: key.clone(),
                        public,
                        indices,
                        paths: vec![key],
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    existing.indices.extend(indices);
                    existing.paths.push(key);
                }
            }
        }
        let mut public_paths = BTreeMap::new();
        for (number, credential) in credentials.values().enumerate() {
            let name = format!("identity-{number}.pub");
            fs::write(ssh.join(&name), &credential.public)?;
            for path in &credential.paths {
                public_paths.insert(path.clone(), name.clone());
            }
            let mut add = Command::new("/usr/bin/ssh-add");
            add.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("SSH_AUTH_SOCK", &socket)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("SSH_ASKPASS", "/usr/bin/false")
                .arg("-q")
                .arg("-H")
                .arg(&constraints);
            for destination in &credential.indices {
                add.arg("-h").arg(format!("sbox-host-{destination}"));
                for (source, endpoint) in destinations.iter().enumerate() {
                    if endpoint
                        .hostkeys
                        .iter()
                        .any(|(marker, _)| marker != "@revoked")
                    {
                        add.arg("-h")
                            .arg(format!("sbox-host-{source}>sbox-host-{destination}"));
                    }
                }
            }
            checked(
                add.arg("--").arg(&credential.key),
                "cannot load destination-constrained SSH identity",
            )?;
        }
        let mut config = fs::File::create(ssh.join("config"))?;
        for destination in destinations {
            writeln!(
                config,
                "Host {}\n HostName {}\n User {}\n Port {}",
                destination.alias,
                quoted(&destination.hostname)?,
                quoted(&destination.user)?,
                quoted(&destination.port)?
            )?;
            for (key, value) in &destination.options {
                writeln!(config, " {key} {value}")?;
            }
            writeln!(
                config,
                " IdentityAgent /run/sbox-host/ssh-agent\n UserKnownHostsFile /run/sbox-host/ssh/known_hosts\n GlobalKnownHostsFile /dev/null\n ControlPath /tmp/sbox-ssh-%C"
            )?;
            let identities: Vec<_> = destination
                .keys
                .iter()
                .filter_map(|key| public_paths.get(key))
                .collect();
            if identities.is_empty() {
                writeln!(config, " IdentityFile none")?;
            }
            for name in identities {
                writeln!(config, " IdentityFile /run/sbox-host/ssh/{name}")?;
            }
        }
        Ok(agent)
    }
}
