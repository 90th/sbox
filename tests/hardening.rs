use sbox::{discover_mcp_mounts, mcp::resolve_runtime};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

#[test]
fn standalone_executable_does_not_grant_sibling_secrets() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("omp"), b"binary").unwrap();
    fs::set_permissions(bin.join("omp"), fs::Permissions::from_mode(0o755)).unwrap();
    let secret = bin.join("secret");
    fs::write(&secret, b"private").unwrap();
    let runtime = resolve_runtime(OsStr::new("omp"), bin.as_os_str(), &home).unwrap();
    assert!(
        !runtime
            .mount_roots
            .iter()
            .any(|root| secret.starts_with(root))
    );
}

#[test]
fn mcp_file_argument_does_not_grant_siblings() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(home.join(".omp/agent")).unwrap();
    fs::create_dir_all(home.join("scripts")).unwrap();
    let script = home.join("scripts/server.py");
    fs::write(&script, b"pass").unwrap();
    let secret = home.join("scripts/secret");
    fs::write(&secret, b"private").unwrap();
    fs::write(home.join(".omp/agent/mcp.json"), serde_json::to_vec(&serde_json::json!({"mcpServers":{"test":{"command":"/usr/bin/python3","args":[script]}}})).unwrap()).unwrap();
    let result = discover_mcp_mounts(&home, &home.join("project"), OsStr::new("/usr/bin")).unwrap();
    assert!(
        !result
            .mount_roots
            .iter()
            .any(|root| secret.starts_with(root))
    );
}

#[test]
fn symlinked_executable_does_not_grant_its_target_directory() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(home.join("bin")).unwrap();
    fs::create_dir_all(home.join("install")).unwrap();
    let executable = home.join("install/omp");
    fs::write(&executable, b"binary").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&executable, home.join("bin/omp")).unwrap();
    let secret = home.join("install/private");
    fs::write(&secret, b"private").unwrap();
    let runtime = resolve_runtime(OsStr::new("omp"), home.join("bin").as_os_str(), &home).unwrap();
    assert!(
        !runtime
            .mount_roots
            .iter()
            .any(|root| secret.starts_with(root))
    );
}
