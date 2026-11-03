use crate::LaunchSpec;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const FILES: &[(&str, &[&str], &str)] = &[
    ("config.yml", &["config.yml", "config.yaml"], "{}\n"),
    (
        "models.yml",
        &["models.yml", "models.yaml", "models.json"],
        "{}\n",
    ),
    ("mcp.json", &["mcp.json"], "{}\n"),
    (".env", &[".env"], ""),
    ("AGENTS.md", &["AGENTS.md"], ""),
    ("CLAUDE.md", &["CLAUDE.md"], ""),
];
const DIRS: &[&str] = &["extensions", "agents", "skills", "rules"];
#[derive(Serialize, Deserialize)]
struct Approval {
    project: PathBuf,
    grants: Vec<PathBuf>,
    git_metadata: Vec<PathBuf>,
    #[serde(default)]
    ssh_hosts: Vec<String>,
}

pub fn directory(home: &Path, project: &Path) -> PathBuf {
    let mut hash = DefaultHasher::new();
    project.hash(&mut hash);
    home.join(".config/sbox/approvals")
        .join(format!("{:016x}", hash.finish()))
}

pub fn authorize(spec: &LaunchSpec) -> Result<PathBuf> {
    let dir = directory(&spec.home, &spec.project);
    let approval: Approval = serde_json::from_slice(&fs::read(dir.join("approval.json")).context("external dependencies are not approved; run sbox --trust --project PATH from your host terminal first")?)?;
    if approval.project != spec.project {
        bail!("approval belongs to a different project");
    }
    for host in &spec.ssh_hosts {
        if !approval.ssh_hosts.contains(host) {
            bail!(
                "new SSH credential destination {host} requires host approval; inspect --permissions then run --trust"
            );
        }
    }
    for path in &spec.git_metadata {
        if !approval.git_metadata.contains(path) {
            bail!(
                "new writable Git metadata {} requires host approval",
                path.display()
            );
        }
    }
    for path in &spec.read_only {
        if !approval
            .grants
            .iter()
            .any(|allowed| path == allowed || (allowed.is_dir() && path.starts_with(allowed)))
        {
            bail!(
                "new external mount {} requires host approval; inspect --permissions then run --trust",
                path.display()
            );
        }
    }
    Ok(dir)
}

pub fn approve(spec: &LaunchSpec) -> Result<()> {
    crate::hardening::validate(spec)?;
    let _guard = crate::state::exclusive(&spec.home, &spec.project)?;
    let dir = directory(&spec.home, &spec.project);
    fs::create_dir_all(&dir)?;
    if fs::canonicalize(&dir)? != dir {
        bail!("approval storage must not traverse symlinks");
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let staged = tempfile::Builder::new()
        .prefix("approval-")
        .tempdir_in(&dir)?;
    let agent = spec.home.join(".omp/agent");
    for (name, alternatives, default) in FILES {
        let source = alternatives
            .iter()
            .map(|name| agent.join(name))
            .find(|path| path.is_file());
        let data = match source {
            Some(path) => {
                if fs::canonicalize(&path)? != path {
                    bail!(
                        "trusted configuration must not be symlinked: {}",
                        path.display()
                    );
                }
                fs::read(path)?
            }
            None => default.as_bytes().to_vec(),
        };
        fs::write(staged.path().join(name), &data)?;
        // Reserve the effective primary name so an absent file cannot be planted by
        // the sandbox and later picked up by native omp. Existing files are untouched.
        let target = agent.join(name);
        if !target.exists() {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            file.write_all(&data)?;
        }
    }
    for name in DIRS {
        let source = agent.join(name);
        if !source.exists() {
            fs::create_dir(&source)?;
        }
        copy_tree(&source, &staged.path().join(name))?;
    }
    for (index, root) in spec.git_metadata.iter().enumerate() {
        let target = staged.path().join(format!("git-{index}"));
        fs::create_dir(&target)?;
        for name in ["config", "config.worktree"] {
            let source = root.join(name);
            if !source.exists() {
                fs::write(&source, b"")?;
            }
            copy_tree(&source, &target.join(name))?;
        }
        let hooks = root.join("hooks");
        if !hooks.exists() {
            fs::create_dir(&hooks)?;
        }
        copy_tree(&hooks, &target.join("hooks"))?;
    }
    let snapshot = staged.keep();
    let approval = Approval {
        project: spec.project.clone(),
        grants: spec.read_only.clone(),
        git_metadata: spec.git_metadata.clone(),
        ssh_hosts: spec.ssh_hosts.clone(),
    };
    let mut data = serde_json::to_value(approval)?;
    data["snapshot"] =
        serde_json::Value::String(snapshot.file_name().unwrap().to_string_lossy().into());
    let temporary = dir.join("approval.new");
    fs::write(&temporary, serde_json::to_vec_pretty(&data)?)?;
    fs::rename(temporary, dir.join("approval.json"))?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        bail!(
            "trusted extension/rule tree contains a symlink: {}",
            source.display()
        );
    }
    if metadata.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        fs::copy(source, destination)?;
    } else {
        bail!(
            "special file in trusted configuration: {}",
            source.display()
        );
    }
    Ok(())
}

pub(crate) fn protect(command: &mut Command, spec: &LaunchSpec) -> Result<()> {
    let Some(dir) = &spec.approval else {
        return Ok(());
    };
    let value: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("approval.json"))?)?;
    let name = value["snapshot"]
        .as_str()
        .context("missing trusted snapshot")?;
    if !matches!(
        Path::new(name).components().next(),
        Some(std::path::Component::Normal(_))
    ) || Path::new(name).components().count() != 1
    {
        bail!("invalid trusted snapshot path");
    }
    let snapshot = dir.join(name);
    for (name, _, _) in FILES {
        command
            .arg("--ro-bind")
            .arg(snapshot.join(name))
            .arg(spec.home.join(".omp/agent").join(name));
    }
    for name in DIRS {
        command
            .arg("--ro-bind")
            .arg(snapshot.join(name))
            .arg(spec.home.join(".omp/agent").join(name));
    }
    for (index, root) in spec.git_metadata.iter().enumerate() {
        for name in ["config", "config.worktree", "hooks"] {
            command
                .arg("--ro-bind")
                .arg(snapshot.join(format!("git-{index}")).join(name))
                .arg(root.join(name));
        }
    }
    Ok(())
}
