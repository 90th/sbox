# sbox

Run omp in a project-scoped Linux sandbox. Keep your existing accounts, sessions, rules, and MCP setup without exposing unrelated personal directories.

The project stays writable. Native omp account and session data remain shared. Native tools run inside the sandbox with limited host filesystem access.

## Install

Requires Linux, omp, OpenSSH 8.9 or newer, non-setuid Bubblewrap with overlay support, and a systemd user manager. Wayland clipboard access requires `wl-clipboard`.

```sh
cargo build --release
install -m 755 target/release/sbox "$HOME/.local/bin/sbox"
```

Use the installed binary. Keep it outside projects that the agent can modify.

## Start a project

From your normal host terminal:

```sh
cd /path/to/project
sbox --permissions
sbox --trust
sbox
```

`--permissions` shows proposed access. Review the paths before `--trust` approves them. Each project needs its own approval.

For later launches, run `sbox` from the project directory. You can also select a project from anywhere:

```sh
sbox --project /path/to/project
```

Open another terminal and run `sbox` in the same project to start another instance. No extra flags are needed.

Each instance has separate private overlays and caches. Later launches reuse idle state slots. All instances share project files and native omp storage. Use separate conversations and coordinate simultaneous edits.

After changing global omp settings, rules, extensions, or dependency paths, close every instance for that project. Review `--permissions` and repeat `--trust` from the host terminal.

## Pass options to omp

Put omp options after `--`:

```sh
sbox -- --continue
sbox -- --resume
sbox -- --model opus
sbox -- "Investigate the failing build."
```

## Allow extra reference files

Use `--allow-read` for directories outside the project:

```sh
sbox --allow-read /path/to/docs --permissions
sbox --allow-read /path/to/docs --trust
sbox --allow-read /path/to/docs
```

Repeat the flag for multiple paths. Read-only access still exposes file contents. Do not approve directories with unrelated personal data.

## Use SSH and clipboard

sbox discovers named hosts from your SSH configuration and its included files. Use the same host names as native SSH:

```sh
ssh -o BatchMode=yes -o ConnectTimeout=5 build-host 'echo OK'
scp ./file build-host:/work/file
scp build-host:/work/result ./result
sftp build-host
```

Review discovered hosts with `--permissions`, then approve their credentials with `--trust`. There are no built-in host names. New hosts require approval from the host terminal.

SSH options, SCP, SFTP, recursive copies, and stdio MCPs use native clients without an option wrapper. Your real `~/.ssh` and private key files stay hidden. The sandbox gets generated configuration, public keys, and a separate authentication agent.

Delegated keys work only with approved host keys. Configure and verify connections with native host SSH first. Only identity files that load without a passphrase prompt are delegated automatically.

Wildcard rules still apply, but they cannot enumerate host names. Use `--ssh-host concrete-host` when a host has no named entry. In Windows SFTP sessions, use `/C:/work` for an absolute drive path.

Wayland clipboard paste supports text and images without exposing the desktop socket. The agent can read clipboard contents, so avoid copying secrets while it runs. Restart existing sbox sessions after updates.

## Adjust resource limits

Each instance gets 8 GiB memory, four CPUs' worth of CPU time, 512 processes/threads, and no swap. Remote VMs are unaffected.

```sh
sbox --memory-mib 16384 --cpu-percent 600 --tasks-limit 1024
```

Use `--no-limits` to disable resource limits explicitly. Disk usage has no quota.

## Reset private caches

Exit every sandbox instance for that project first:

```sh
sbox --project /path/to/project --reset
```

Reset removes private caches and overlays. It keeps project files, Git commits, native omp accounts/sessions, and permission approvals.

Add `.sbox/` to your project's ignore rules. Reset and approval updates refuse to run while any instance is active.

## Other options

| Option | Use |
|---|---|
| `--pass-env NAME` | Forward an existing host environment variable. Its value becomes visible to agent tools. |
| `--strict-mcp` | Stop the launch if local MCP dependency discovery fails. |
| `--ssh-host HOST` | Add a concrete host for wildcard-only SSH configuration. Named hosts are detected automatically. |
| `--help` | Show all sbox options. |
| `-- --help` | Show omp options inside the sandbox. |
