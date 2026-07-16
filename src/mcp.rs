use std::collections::{BTreeSet, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};

use crate::{Discovery, Runtime};

#[derive(Debug)]
struct LocalServer {
    name: String,
    source: PathBuf,
    command: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
}

pub fn discover_mcp_mounts(home: &Path, project: &Path, host_path: &OsStr) -> Result<Discovery> {
    let mut servers = Vec::new();
    let omp_config = home.join(".omp/agent/mcp.json");
    let opencode_root = home.join(".config/opencode");
    let opencode_config = opencode_root.join("opencode.json");

    if omp_config.is_file() {
        servers.extend(parse_omp_config(&omp_config)?);
    }
    if opencode_config.is_file() {
        servers.extend(parse_opencode_config(&opencode_config)?);
    }

    let mut mount_roots = Vec::new();
    let mut path_dirs = Vec::new();
    if opencode_root.is_dir() {
        let canonical = fs::canonicalize(&opencode_root).with_context(|| {
            format!(
                "cannot resolve trusted OpenCode configuration root {}",
                opencode_root.display()
            )
        })?;
        reject_broad_root(&canonical, home)?;
        mount_roots.push(canonical);
    }

    for server in servers {
        discover_server(
            &server,
            home,
            project,
            host_path,
            &mut mount_roots,
            &mut path_dirs,
        )?;
    }

    Ok(Discovery {
        mount_roots: dedupe_roots(mount_roots),
        path_dirs: dedupe_paths(path_dirs),
    })
}

pub fn resolve_runtime(command: &OsStr, host_path: &OsStr, home: &Path) -> Result<Runtime> {
    let lexical = resolve_executable(command, host_path, None)
        .with_context(|| format!("cannot resolve executable {:?}", command))?;
    let canonical = fs::canonicalize(&lexical)
        .with_context(|| format!("cannot canonicalize executable {}", lexical.display()))?;
    let mut roots = Vec::new();
    let mut path_dirs = Vec::new();

    add_executable_layout(&lexical, &canonical, home, &mut roots, &mut path_dirs)?;
    add_shebang_runtime(&lexical, host_path, home, &mut roots, &mut path_dirs, "OMP")?;

    Ok(Runtime {
        lexical_executable: lexical,
        canonical_executable: canonical,
        mount_roots: dedupe_roots(roots),
        path_dirs: dedupe_paths(path_dirs),
    })
}

pub fn resolve_executable(
    command: &OsStr,
    host_path: &OsStr,
    cwd: Option<&Path>,
) -> Result<PathBuf> {
    let command_path = Path::new(command);
    if command_path.components().count() > 1 || command_path.is_absolute() {
        let path = if command_path.is_absolute() {
            command_path.to_path_buf()
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(command_path)
        };
        ensure_executable(&path)?;
        return Ok(absolutize_lexical(&path)?);
    }

    for dir in env::split_paths(host_path) {
        let candidate = dir.join(command_path);
        if ensure_executable(&candidate).is_ok() {
            return absolutize_lexical(&candidate);
        }
    }
    bail!("executable {:?} was not found on PATH", command)
}

fn parse_json_object(path: &Path) -> Result<Map<String, Value>> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("malformed trusted MCP config {}", path.display()))?;
    value.as_object().cloned().ok_or_else(|| {
        anyhow!(
            "trusted MCP config {} must be a JSON object",
            path.display()
        )
    })
}

fn parse_omp_config(path: &Path) -> Result<Vec<LocalServer>> {
    let root = parse_json_object(path)?;
    let disabled = match root.get("disabledServers") {
        None => HashSet::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    anyhow!("disabledServers in {} must contain strings", path.display())
                })
            })
            .collect::<Result<HashSet<_>>>()?,
        Some(_) => bail!("disabledServers in {} must be an array", path.display()),
    };
    let entries = match root.get("mcpServers") {
        None => return Ok(Vec::new()),
        Some(Value::Object(entries)) => entries,
        Some(_) => bail!("mcpServers in {} must be an object", path.display()),
    };

    let mut servers = Vec::new();
    for (name, value) in entries {
        if disabled.contains(name) {
            continue;
        }
        let entry = value
            .as_object()
            .ok_or_else(|| anyhow!("MCP server {name} in {} must be an object", path.display()))?;
        if matches!(entry.get("enabled"), Some(Value::Bool(false))) {
            continue;
        }
        if let Some(enabled) = entry.get("enabled") {
            if !enabled.is_boolean() {
                bail!(
                    "enabled for MCP server {name} in {} must be boolean",
                    path.display()
                );
            }
        }
        let Some(command_value) = entry.get("command") else {
            if entry.contains_key("url") {
                continue;
            }
            bail!("MCP server {name} in {} has no command", path.display());
        };
        let command = command_value.as_str().ok_or_else(|| {
            anyhow!(
                "command for MCP server {name} in {} must be a string",
                path.display()
            )
        })?;
        let args = string_array(entry.get("args"), "args", name, path)?;
        validate_object(entry.get("env"), "env", name, path)?;
        let cwd = optional_absolute_path(entry.get("cwd"), "cwd", name, path)?;
        servers.push(LocalServer {
            name: name.clone(),
            source: path.to_path_buf(),
            command: command.into(),
            args,
            cwd,
        });
    }
    Ok(servers)
}

fn parse_opencode_config(path: &Path) -> Result<Vec<LocalServer>> {
    let root = parse_json_object(path)?;
    let entries = match root.get("mcp") {
        None => return Ok(Vec::new()),
        Some(Value::Object(entries)) => entries,
        Some(_) => bail!("mcp in {} must be an object", path.display()),
    };
    let mut servers = Vec::new();
    for (name, value) in entries {
        let entry = value
            .as_object()
            .ok_or_else(|| anyhow!("MCP server {name} in {} must be an object", path.display()))?;
        if matches!(entry.get("enabled"), Some(Value::Bool(false))) {
            continue;
        }
        if let Some(enabled) = entry.get("enabled") {
            if !enabled.is_boolean() {
                bail!(
                    "enabled for MCP server {name} in {} must be boolean",
                    path.display()
                );
            }
        }
        match entry.get("type").and_then(Value::as_str) {
            Some("local") => {}
            Some(_) => continue,
            None => bail!("MCP server {name} in {} has no string type", path.display()),
        }
        validate_object(entry.get("environment"), "environment", name, path)?;
        let words = match entry.get("command") {
            Some(Value::Array(words)) if !words.is_empty() => words
                .iter()
                .map(|word| {
                    word.as_str().map(OsString::from).ok_or_else(|| {
                        anyhow!(
                            "command for MCP server {name} in {} must contain only strings",
                            path.display()
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => bail!(
                "command for MCP server {name} in {} must be a non-empty string array",
                path.display()
            ),
        };
        servers.push(LocalServer {
            name: name.clone(),
            source: path.to_path_buf(),
            command: words[0].clone(),
            args: words[1..].to_vec(),
            cwd: None,
        });
    }
    Ok(servers)
}

fn string_array(
    value: Option<&Value>,
    field: &str,
    server: &str,
    source: &Path,
) -> Result<Vec<OsString>> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(OsString::from).ok_or_else(|| {
                    anyhow!(
                        "{field} for MCP server {server} in {} must contain strings",
                        source.display()
                    )
                })
            })
            .collect(),
        Some(_) => bail!(
            "{field} for MCP server {server} in {} must be an array",
            source.display()
        ),
    }
}

fn validate_object(value: Option<&Value>, field: &str, server: &str, source: &Path) -> Result<()> {
    if let Some(value) = value {
        if !value.is_object() {
            bail!(
                "{field} for MCP server {server} in {} must be an object",
                source.display()
            );
        }
    }
    Ok(())
}

fn optional_absolute_path(
    value: Option<&Value>,
    field: &str,
    server: &str,
    source: &Path,
) -> Result<Option<PathBuf>> {
    let Some(value) = value else { return Ok(None) };
    let text = value.as_str().ok_or_else(|| {
        anyhow!(
            "{field} for MCP server {server} in {} must be a string",
            source.display()
        )
    })?;
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        bail!(
            "{field} for MCP server {server} in {} must be absolute",
            source.display()
        );
    }
    Ok(Some(path))
}

fn discover_server(
    server: &LocalServer,
    home: &Path,
    project: &Path,
    host_path: &OsStr,
    roots: &mut Vec<PathBuf>,
    path_dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    let lexical = resolve_executable(&server.command, host_path, server.cwd.as_deref())
        .with_context(|| {
            format!(
                "MCP server {} in {} cannot resolve its command",
                server.name,
                server.source.display()
            )
        })?;
    let canonical = fs::canonicalize(&lexical).with_context(|| {
        format!(
            "MCP server {} in {} cannot canonicalize command {}",
            server.name,
            server.source.display(),
            lexical.display()
        )
    })?;
    add_executable_layout(&lexical, &canonical, home, roots, path_dirs).with_context(|| {
        format!(
            "unsafe runtime inferred for MCP server {} in {}",
            server.name,
            server.source.display()
        )
    })?;
    add_shebang_runtime(
        &lexical,
        host_path,
        home,
        roots,
        path_dirs,
        &format!("MCP server {} in {}", server.name, server.source.display()),
    )?;

    if let Some(cwd) = &server.cwd {
        add_declared_path(cwd, home, project, roots).with_context(|| {
            format!(
                "invalid cwd for MCP server {} in {}",
                server.name,
                server.source.display()
            )
        })?;
    }
    for argument in &server.args {
        let path = Path::new(argument);
        if path.is_absolute() {
            add_declared_path(path, home, project, roots).with_context(|| {
                format!(
                    "invalid path argument {} for MCP server {} in {}",
                    path.display(),
                    server.name,
                    server.source.display()
                )
            })?;
            add_shebang_runtime(
                path,
                host_path,
                home,
                roots,
                path_dirs,
                &format!("MCP server {} in {}", server.name, server.source.display()),
            )?;
        }
    }
    if is_python_interpreter(&lexical, &canonical)
        && server.args.iter().map(Path::new).any(|argument| {
            argument
                .extension()
                .is_some_and(|extension| extension == "py")
        })
    {
        add_python_user_sites(home, roots)?;
    }

    Ok(())
}

fn is_python_interpreter(lexical: &Path, canonical: &Path) -> bool {
    [lexical, canonical].into_iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "python" || name.starts_with("python3"))
    })
}

fn add_python_user_sites(home: &Path, roots: &mut Vec<PathBuf>) -> Result<()> {
    let lib = home.join(".local/lib");
    let Ok(entries) = fs::read_dir(&lib) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry?.path().join("site-packages");
        if path.is_dir() {
            roots.push(fs::canonicalize(path)?);
        }
    }
    Ok(())
}

fn add_declared_path(
    path: &Path,
    home: &Path,
    project: &Path,
    roots: &mut Vec<PathBuf>,
) -> Result<()> {
    if !path.exists() {
        bail!("configured path {} does not exist", path.display());
    }
    let canonical = fs::canonicalize(path)?;
    if canonical.starts_with(project) {
        return Ok(());
    }
    let inferred = infer_runtime_root(&canonical).unwrap_or_else(|| {
        if canonical.is_dir() {
            canonical.clone()
        } else {
            canonical.parent().unwrap_or(Path::new("/")).to_path_buf()
        }
    });
    reject_broad_root(&inferred, home)?;
    roots.push(inferred);
    Ok(())
}

fn add_executable_layout(
    lexical: &Path,
    canonical: &Path,
    home: &Path,
    roots: &mut Vec<PathBuf>,
    path_dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    let transient = is_fnm_transient(lexical);
    if !transient && !is_system_path(lexical) {
        if let Some(parent) = lexical.parent() {
            reject_broad_root(parent, home)?;
            roots.push(parent.to_path_buf());
            path_dirs.push(parent.to_path_buf());
        }
    }

    if let Some(node_root) = find_node_install(canonical).or_else(|| find_node_install(lexical)) {
        reject_broad_root(&node_root, home)?;
        path_dirs.push(node_root.join("bin"));
        roots.push(node_root);
    } else {
        for path in [lexical, canonical] {
            if is_system_path(path) {
                continue;
            }
            if let Some(root) = infer_runtime_root(path) {
                reject_broad_root(&root, home)?;
                roots.push(root);
            }
        }
    }

    if let Some(node_modules) = top_level_node_modules(canonical) {
        reject_broad_root(&node_modules, home)?;
        roots.push(node_modules);
    }
    Ok(())
}

fn add_shebang_runtime(
    script: &Path,
    host_path: &OsStr,
    home: &Path,
    roots: &mut Vec<PathBuf>,
    path_dirs: &mut Vec<PathBuf>,
    label: &str,
) -> Result<()> {
    let Some(interpreter) = read_shebang(script)
        .with_context(|| format!("cannot inspect shebang for {label}: {}", script.display()))?
    else {
        return Ok(());
    };
    let lexical = if interpreter.0 == Path::new("/usr/bin/env") {
        let name = interpreter
            .1
            .first()
            .ok_or_else(|| anyhow!("{label} has an env shebang without an interpreter"))?;
        resolve_executable(name, host_path, None)
            .with_context(|| format!("{label} has unresolved shebang interpreter {:?}", name))?
    } else {
        ensure_executable(&interpreter.0).with_context(|| {
            format!(
                "{label} has unresolved shebang interpreter {}",
                interpreter.0.display()
            )
        })?;
        interpreter.0
    };
    let canonical = fs::canonicalize(&lexical)?;
    add_executable_layout(&lexical, &canonical, home, roots, path_dirs)
}

fn read_shebang(path: &Path) -> Result<Option<(PathBuf, Vec<OsString>)>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let line = bytes[2..]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let words = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|word| !word.is_empty())
        .map(|word| OsString::from(OsStr::from_bytes(word)))
        .collect::<Vec<_>>();
    let Some(first) = words.first() else {
        bail!("empty shebang in {}", path.display());
    };
    let interpreter = PathBuf::from(first);
    if !interpreter.is_absolute() {
        bail!("relative shebang interpreter in {}", path.display());
    }
    let mut args = words[1..].to_vec();
    if interpreter == Path::new("/usr/bin/env") && args.first().is_some_and(|arg| arg == "-S") {
        args.remove(0);
    }
    while interpreter == Path::new("/usr/bin/env")
        && args
            .first()
            .is_some_and(|arg| arg.as_bytes().starts_with(b"-"))
    {
        args.remove(0);
    }
    Ok(Some((interpreter, args)))
}

fn infer_runtime_root(path: &Path) -> Option<PathBuf> {
    if let Some(node) = find_node_install(path) {
        return Some(node);
    }
    for ancestor in path.ancestors() {
        if ancestor.join("pyvenv.cfg").is_file() {
            return Some(ancestor.to_path_buf());
        }
    }
    for ancestor in path.ancestors() {
        if ancestor.join("pyproject.toml").is_file() || ancestor.join("package.json").is_file() {
            return Some(ancestor.to_path_buf());
        }
    }
    path.parent().map(Path::to_path_buf)
}

fn find_node_install(path: &Path) -> Option<PathBuf> {
    path.ancestors().find_map(|ancestor| {
        let node = ancestor.join("bin/node");
        let modules = ancestor.join("lib/node_modules");
        (node.is_file()
            && modules.is_dir()
            && (path.starts_with(ancestor.join("bin")) || path.starts_with(&modules)))
        .then(|| ancestor.to_path_buf())
    })
}

fn top_level_node_modules(path: &Path) -> Option<PathBuf> {
    let mut result = None;
    for ancestor in path.ancestors() {
        if ancestor
            .file_name()
            .is_some_and(|name| name == "node_modules")
        {
            result = Some(ancestor.to_path_buf());
        }
    }
    result
}

fn reject_broad_root(root: &Path, home: &Path) -> Result<()> {
    if root == Path::new("/") || root == Path::new("/home") || root == home {
        bail!(
            "refusing inferred broad mount {}; use --allow-read with a narrower path",
            root.display()
        );
    }
    Ok(())
}

fn ensure_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)
        .with_context(|| format!("executable {} does not exist", path.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!("{} is not an executable file", path.display());
    }
    Ok(())
}

fn absolutize_lexical(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(env::current_dir()?.join(path))
}

fn is_fnm_transient(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(value) => value == "fnm_multishells",
        _ => false,
    })
}

fn is_system_path(path: &Path) -> bool {
    path.starts_with("/usr")
        || path.starts_with("/bin")
        || path.starts_with("/lib")
        || path.starts_with("/lib64")
}

pub(crate) fn dedupe_roots(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_by_key(|path| path.components().count());
    let mut result = Vec::new();
    for path in paths {
        if !result.iter().any(|root: &PathBuf| path.starts_with(root)) {
            result.push(path);
        }
    }
    result.sort();
    result
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut set = BTreeSet::new();
    set.extend(paths);
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use serde_json::json;
    use tempfile::TempDir;

    fn mkdir(path: &Path) {
        fs::create_dir_all(path).unwrap();
    }

    fn executable(path: &Path, contents: &str) {
        mkdir(path.parent().unwrap());
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn write_json(path: &Path, value: &Value) {
        mkdir(path.parent().unwrap());
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    struct Layout {
        _temp: TempDir,
        home: PathBuf,
        project: PathBuf,
        mdb: PathBuf,
        node: PathBuf,
        ghidra: PathBuf,
        transient: PathBuf,
    }

    fn fixture_layout() -> Layout {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let home = root.join("home/user");
        let project = root.join("project");
        let mdb = home.join("temp/MDB-MCP");
        let node = home.join(".local/share/fnm/node-versions/v24.13.0/installation");
        let ghidra = home.join(".local/share/opencode/ghidra");
        let transient = root.join("run/user/1000/fnm_multishells/session/bin");
        let python_site = home.join(".local/lib/python3.14/site-packages");
        mkdir(&project);

        fs::write(mdb.join("pyproject.toml"), b"[project]\nname='mdb'\n").unwrap_or_else(|_| {
            mkdir(&mdb);
            fs::write(mdb.join("pyproject.toml"), b"[project]\nname='mdb'\n").unwrap()
        });
        mkdir(&mdb.join("venv/bin"));
        fs::write(mdb.join("venv/pyvenv.cfg"), b"home = fixture\n").unwrap();
        executable(&mdb.join("venv/bin/python"), "fixture binary\n");
        fs::write(mdb.join("server.py"), b"print('fixture')\n").unwrap();

        executable(&node.join("bin/node"), "fixture node\n");
        mkdir(&node.join("lib/node_modules/@upstash/context7-mcp/dist"));
        fs::write(
            node.join("lib/node_modules/@upstash/context7-mcp/package.json"),
            b"{}",
        )
        .unwrap();
        executable(
            &node.join("lib/node_modules/@upstash/context7-mcp/dist/index.js"),
            "#!/usr/bin/env node-tool\n",
        );
        mkdir(&transient);
        symlink(node.join("bin/node"), transient.join("node-tool")).unwrap();

        mkdir(&ghidra);
        fs::write(ghidra.join("bridge.py"), b"print('fixture')\n").unwrap();
        mkdir(&python_site.join("mcp"));

        Layout {
            _temp: temp,
            home,
            project,
            mdb,
            node,
            ghidra,
            transient,
        }
    }

    #[test]
    fn discovers_both_schemas_and_stable_runtime_roots() {
        let layout = fixture_layout();
        write_json(
            &layout.home.join(".omp/agent/mcp.json"),
            &json!({
                "disabledServers": ["disabled"],
                "mcpServers": {
                    "debugger-mcp": {
                        "command": layout.mdb.join("venv/bin/python"),
                        "args": [layout.mdb.join("server.py")]
                    },
                    "disabled": {"command": "/definitely/missing"},
                    "off": {"command": "/also/missing", "enabled": false}
                }
            }),
        );
        write_json(
            &layout.home.join(".config/opencode/opencode.json"),
            &json!({
                "mcp": {
                    "context7": {
                        "type": "local",
                        "command": [layout.node.join("lib/node_modules/@upstash/context7-mcp/dist/index.js")],
                        "enabled": true
                    },
                    "ghidra": {
                        "type": "local",
                        "command": ["/usr/bin/python3", layout.ghidra.join("bridge.py")],
                        "environment": {"GHIDRA_MCP_URL": "http://127.0.0.1:8080"}
                    },
                    "remote": {"type": "remote", "url": "https://example.invalid"},
                    "off": {"type": "local", "command": ["/missing"], "enabled": false}
                }
            }),
        );
        let path = env::join_paths([&layout.transient]).unwrap();
        let discovery = discover_mcp_mounts(&layout.home, &layout.project, &path).unwrap();

        assert!(discovery.mount_roots.contains(&layout.mdb));
        assert!(discovery.mount_roots.contains(&layout.node));
        assert!(discovery.mount_roots.contains(&layout.ghidra));
        assert!(
            discovery
                .mount_roots
                .contains(&layout.home.join(".local/lib/python3.14/site-packages"))
        );
        assert!(
            !discovery
                .mount_roots
                .iter()
                .any(|root| root.starts_with(&layout.transient))
        );
        assert!(discovery.path_dirs.contains(&layout.node.join("bin")));
        assert!(
            discovery
                .mount_roots
                .contains(&layout.home.join(".config/opencode"))
        );
    }

    #[test]
    fn mounts_opencode_assets_without_an_mcp_configuration() {
        let layout = fixture_layout();
        let opencode = layout.home.join(".config/opencode");
        mkdir(&opencode.join("skills"));
        fs::write(opencode.join("skills/review.md"), b"review instructions").unwrap();

        let discovery =
            discover_mcp_mounts(&layout.home, &layout.project, OsStr::new("/usr/bin:/bin"))
                .unwrap();

        assert_eq!(discovery.mount_roots, [opencode]);
        assert!(discovery.path_dirs.is_empty());
    }

    #[test]
    fn reports_missing_local_runtime_with_server_and_source() {
        let layout = fixture_layout();
        let source = layout.home.join(".omp/agent/mcp.json");
        write_json(
            &source,
            &json!({"mcpServers": {"broken": {"command": "not-present"}}}),
        );
        let error = discover_mcp_mounts(&layout.home, &layout.project, OsStr::new("/usr/bin:/bin"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("broken"));
        assert!(error.contains(source.to_str().unwrap()));
    }

    #[test]
    fn reports_unresolved_shebang_with_server_and_source() {
        let layout = fixture_layout();
        let script = layout.home.join("server/run");
        executable(&script, "#!/usr/bin/env absent-interpreter\n");
        let source = layout.home.join(".omp/agent/mcp.json");
        write_json(
            &source,
            &json!({"mcpServers": {"broken-shebang": {"command": script}}}),
        );
        let error = discover_mcp_mounts(&layout.home, &layout.project, OsStr::new("/usr/bin:/bin"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("broken-shebang"));
        assert!(error.contains(source.to_str().unwrap()));
    }

    #[test]
    fn rejects_root_home_and_entire_user_home_inference() {
        let layout = fixture_layout();
        fs::write(layout.home.join("package.json"), b"{}").unwrap();
        let source = layout.home.join(".omp/agent/mcp.json");
        for path in [Path::new("/"), Path::new("/home"), layout.home.as_path()] {
            write_json(
                &source,
                &json!({
                    "mcpServers": {
                        "broad": {
                            "command": "/usr/bin/true",
                            "args": [path]
                        }
                    }
                }),
            );
            let error = format!(
                "{:#}",
                discover_mcp_mounts(&layout.home, &layout.project, OsStr::new("/usr/bin:/bin"),)
                    .unwrap_err()
            );
            assert!(error.contains("broad"));
            assert!(
                error.contains("refusing inferred broad mount"),
                "{path:?}: {error}"
            );
        }
    }

    #[test]
    fn preserves_lexical_symlink_while_mounting_canonical_install() {
        let layout = fixture_layout();
        let runtime = resolve_runtime(
            OsStr::new("node-tool"),
            layout.transient.as_os_str(),
            &layout.home,
        )
        .unwrap();
        assert_eq!(
            runtime.lexical_executable,
            layout.transient.join("node-tool")
        );
        assert_eq!(runtime.canonical_executable, layout.node.join("bin/node"));
        assert_eq!(runtime.mount_roots, [layout.node]);
        assert_eq!(runtime.path_dirs, [runtime.mount_roots[0].join("bin")]);
    }
}
