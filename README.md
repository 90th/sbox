# sbox

Run omp in a project-scoped Linux sandbox. Keep your existing accounts, sessions, rules, and MCP setup without exposing unrelated personal directories.

The project stays writable. Native omp account and session data remain shared. SSH and clipboard access use restricted host connectors.

## Install

Requires Linux, omp, non-setuid Bubblewrap with overlay support, and a systemd user manager. Wayland clipboard access requires `wl-clipboard`.

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

After changing global omp settings, rules, extensions, or dependency paths, close sbox. Review `--permissions` and repeat `--trust` from the host terminal.

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

Inside the sandbox, the agent can run commands on the approved VMs:

```sh
ssh kali-vm 'uname -a'
ssh windows-vm 'whoami'
```

`windows-vm` maps to the host's `windows-builder` alias. Both names work. Use `-T` for SSH-backed stdio MCPs. Other destinations, custom SSH options, and forwarding are blocked. Keys stay on the host.

Wayland clipboard paste supports text and images without exposing the desktop socket. The agent can read clipboard contents, so avoid copying secrets while it runs. Restart existing sbox sessions after updates.

## Adjust resource limits

Defaults are 8 GiB memory, four CPUs' worth of execution time, 512 processes/threads, and no swap. These limits do not affect remote VMs.

```sh
sbox --memory-mib 16384 --cpu-percent 600 --tasks-limit 1024
```

Use `--no-limits` to disable resource limits explicitly. Disk usage has no quota.

## Reset private caches

Exit the project's sandbox first:

```sh
sbox --project /path/to/project --reset
```

Reset removes private caches and overlays. It keeps project files, Git commits, native omp accounts/sessions, and permission approvals.

Add `.sbox/` to your project's ignore rules. Only one sbox instance can use a project at a time.

## Other options

| Option | Use |
|---|---|
| `--pass-env NAME` | Forward an existing host environment variable. Its value becomes visible to agent tools. |
| `--strict-mcp` | Stop the launch if local MCP dependency discovery fails. |
| `--help` | Show all sbox options. |
| `-- --help` | Show omp options inside the sandbox. |
