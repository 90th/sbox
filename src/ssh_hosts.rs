use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

/// Enumerate concrete Host aliases. OpenSSH itself resolves their settings.
/// Wildcard Host/Match rules still apply through ssh -G, but cannot enumerate names.
pub fn configured_hosts(home: &Path) -> Result<Vec<String>> {
    discover_files(home, Some(Path::new("/etc/ssh/ssh_config")))
}
fn discover_files(home: &Path, system: Option<&Path>) -> Result<Vec<String>> {
    let mut aliases = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let config = home.join(".ssh/config");
    if config.is_file() {
        read_config(&config, home, 0, &mut visited, &mut aliases)?;
    }
    if let Some(system) = system
        && system.is_file()
    {
        read_config(system, home, 0, &mut visited, &mut aliases)?;
    }
    Ok(aliases.into_iter().collect())
}
pub(crate) fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty()
        || alias.starts_with('-')
        || alias.contains(['@', '*', '?', '[', ']'])
        || alias
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\')
    {
        bail!("invalid concrete SSH Host alias");
    }
    Ok(())
}
fn read_config(
    path: &Path,
    home: &Path,
    depth: usize,
    visited: &mut BTreeSet<PathBuf>,
    aliases: &mut BTreeSet<String>,
) -> Result<()> {
    if depth > 16 {
        bail!("SSH Include nesting exceeds 16 levels");
    }
    let path = fs::canonicalize(path)?;
    if !visited.insert(path.clone()) {
        return Ok(());
    }
    for line in fs::read_to_string(&path)?.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // OpenSSH accepts both `Host name` and `Host=name` forms.
        let Some(split) = trimmed.find(|c: char| c.is_whitespace() || c == '=') else {
            continue;
        };
        let keyword = &trimmed[..split];
        let rest = trimmed[split..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
        if !keyword.eq_ignore_ascii_case("host") && !keyword.eq_ignore_ascii_case("include") {
            continue;
        }
        let fields = shlex::split(rest)
            .with_context(|| format!("invalid quoting in SSH config {}", path.display()))?;
        if keyword.eq_ignore_ascii_case("host") {
            for alias in fields {
                if alias.starts_with('!') || alias.contains(['*', '?', '[', ']']) {
                    continue;
                }
                validate_alias(&alias)?;
                aliases.insert(alias);
            }
        } else if keyword.eq_ignore_ascii_case("include") {
            for pattern in fields {
                let pattern = if let Some(tail) = pattern.strip_prefix("~/") {
                    home.join(tail)
                } else {
                    let value = PathBuf::from(&pattern);
                    if value.is_absolute() {
                        value
                    } else if path.starts_with("/etc/ssh") {
                        Path::new("/etc/ssh").join(value)
                    } else {
                        home.join(".ssh").join(value)
                    }
                };
                for included in
                    glob::glob(pattern.to_str().context("SSH Include path is not UTF-8")?)?
                {
                    let included = included?;
                    if included.is_file() {
                        read_config(&included, home, depth + 1, visited, aliases)?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_are_discovered_through_includes_quotes_and_wildcard_defaults() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path();
        fs::create_dir_all(home.join(".ssh/conf.d")).unwrap();
        fs::write(home.join(".ssh/config"),"Host *\n ServerAliveInterval 20\nInclude conf.d/*.conf\nHost \"custom-build-host\" second-host !excluded\n HostName example.invalid\n").unwrap();
        fs::write(
            home.join(".ssh/conf.d/hosts.conf"),
            "Host=storage-node\n User builder\nInclude config\n",
        )
        .unwrap();
        assert_eq!(
            discover_files(home, None).unwrap(),
            vec!["custom-build-host", "second-host", "storage-node"]
        );
    }
    #[test]
    fn host_patterns_are_not_mistaken_for_concrete_credential_grants() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".ssh")).unwrap();
        fs::write(
            root.path().join(".ssh/config"),
            "Host *.internal !private-host\n HostName %h\nMatch host hidden-host\n User builder\n",
        )
        .unwrap();
        assert!(discover_files(root.path(), None).unwrap().is_empty());
    }
}
