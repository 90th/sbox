use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use globset::Glob;
use serde::Deserialize;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UserPolicy {
    pub allow_read: Vec<PathBuf>,
    pub pass_env: Vec<OsString>,
    pub strict_mcp: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserConfig {
    #[serde(default)]
    project: Vec<ProjectRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRule {
    path: String,
    #[serde(default)]
    allow_read: Vec<PathBuf>,
    #[serde(default)]
    pass_env: Vec<String>,
    #[serde(default)]
    strict_mcp: bool,
}

pub(crate) fn load_user_policy(home: &Path, project: &Path) -> Result<UserPolicy> {
    load_user_policy_at(&user_config_path(home)?, project)
}

fn user_config_path(home: &Path) -> Result<PathBuf> {
    match env::var_os("XDG_CONFIG_HOME") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                bail!("XDG_CONFIG_HOME must be an absolute path");
            }
            Ok(path.join("sbox/config.toml"))
        }
        None => Ok(home.join(".config/sbox/config.toml")),
    }
}

fn load_user_policy_at(path: &Path, project: &Path) -> Result<UserPolicy> {
    if !path.exists() {
        return Ok(UserPolicy::default());
    }
    if !path.is_file() {
        bail!(
            "user configuration {} must be a regular file",
            path.display()
        );
    }

    let source = fs::read_to_string(path)
        .with_context(|| format!("cannot read user configuration {}", path.display()))?;
    let config: UserConfig = toml::from_str(&source)
        .with_context(|| format!("malformed user configuration {}", path.display()))?;
    let mut policy = UserPolicy::default();

    for rule in config.project {
        let pattern_path = Path::new(&rule.path);
        if !pattern_path.is_absolute() {
            bail!(
                "project path pattern {:?} in {} must be absolute",
                rule.path,
                path.display()
            );
        }
        let matcher = Glob::new(&rule.path)
            .with_context(|| {
                format!(
                    "invalid project path pattern {:?} in {}",
                    rule.path,
                    path.display()
                )
            })?
            .compile_matcher();
        if !matcher.is_match(project) {
            continue;
        }

        for allowed_path in rule.allow_read {
            if !allowed_path.is_absolute() {
                bail!(
                    "allow_read path {} in {} must be absolute",
                    allowed_path.display(),
                    path.display()
                );
            }
            policy.allow_read.push(allowed_path);
        }
        policy
            .pass_env
            .extend(rule.pass_env.into_iter().map(OsString::from));
        policy.strict_mcp |= rule.strict_mcp;
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn merges_rules_matching_the_canonical_project_path() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let project = root.join("work/app");
        let context = root.join("context");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir(&context).unwrap();
        let config = root.join("config.toml");
        fs::write(
            &config,
            format!(
                r#"
[[project]]
path = "{}"
allow_read = ["{}"]
pass_env = ["SERVICE_TOKEN"]

[[project]]
path = "{}"
strict_mcp = true
"#,
                root.join("work/**").display(),
                context.display(),
                project.display(),
            ),
        )
        .unwrap();

        let policy = load_user_policy_at(&config, &project).unwrap();

        assert_eq!(policy.allow_read, [context]);
        assert_eq!(policy.pass_env, [OsString::from("SERVICE_TOKEN")]);
        assert!(policy.strict_mcp);
    }

    #[test]
    fn ignores_non_matching_rules() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let project = root.join("work/app");
        fs::create_dir_all(&project).unwrap();
        let config = root.join("config.toml");
        fs::write(
            &config,
            format!(
                r#"
[[project]]
path = "{}"
pass_env = ["SERVICE_TOKEN"]
strict_mcp = true
"#,
                root.join("other/**").display(),
            ),
        )
        .unwrap();

        assert_eq!(
            load_user_policy_at(&config, &project).unwrap(),
            UserPolicy::default()
        );
    }

    #[test]
    fn rejects_relative_project_patterns() {
        let temp = TempDir::new().unwrap();
        let config = temp.path().join("config.toml");
        fs::write(&config, "[[project]]\npath = \"projects/**\"\n").unwrap();

        let error = load_user_policy_at(&config, temp.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("must be absolute"));
    }
}
