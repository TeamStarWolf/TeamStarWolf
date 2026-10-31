# systemd and systemctl Reference

systemd is the init system and service manager on most mainstream Linux distributions. `systemctl` controls units, and `journalctl` reads the logs systemd collects. This page covers service control, unit files, timers, and the hardening directives that limit what a service can do. It targets administrators and security engineers managing Linux hosts.

## What it is and where it runs

systemd is PID 1 on Debian, Ubuntu, RHEL, Fedora, SUSE, Arch, and their derivatives. It starts and supervises services, sockets, mounts, timers, and other units. `systemctl` talks to the system manager, or to a per-user manager with `--user`. Most state-changing commands need root, usually through `sudo`.

```bash
systemctl --version
systemctl is-system-running    # overall state
```

## Core commands

### Service control

```bash
systemctl start nginx
systemctl stop nginx
systemctl restart nginx
systemctl reload nginx          # re-read config without a full restart
systemctl status nginx
```

| Command | Purpose |
|---------|---------|
| `start` / `stop` | Activate or deactivate a unit now |
| `restart` / `reload` | Restart, or reload config in place |
| `enable` / `disable` | Set or clear start at boot |
| `mask` / `unmask` | Make a unit unstartable, or reverse that |
| `status` | Show state, recent logs, and the main PID |

### Boot behavior

```bash
systemctl enable --now nginx    # enable at boot and start immediately
systemctl disable nginx
systemctl is-enabled nginx
```

### Listing and inspecting

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled
systemctl cat nginx.service      # show the effective unit file
systemctl show nginx -p ExecStart
```

`list-units` shows loaded units and their live state. `list-unit-files` shows installed units and their enablement.

### Reloading systemd itself

```bash
systemctl daemon-reload          # after editing unit files on disk
```

Run `daemon-reload` whenever you change a unit file so systemd re-reads it.

### Editing units

```bash
systemctl edit nginx             # create a drop-in override
systemctl edit --full nginx      # edit a full copy of the unit
```

`systemctl edit` writes a drop-in under `/etc/systemd/system/<unit>.d/` and leaves the packaged unit intact.

### Unit file structure

A minimal service unit:

```ini
[Unit]
Description=Example API
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/example-api --port 8080
Restart=on-failure
User=example

[Install]
WantedBy=multi-user.target
```

`[Unit]` holds metadata and ordering. `[Service]` defines how to run. `[Install]` controls what `enable` wires up.

### Timers versus cron

```bash
systemctl list-timers --all
```

A timer unit triggers a matching service unit on a schedule. Example `example.timer`:

```ini
[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Timers log through `journalctl`, run as defined units, and handle missed runs with `Persistent=true`. Cron remains simpler for one-off per-user jobs.

### journalctl basics

```bash
journalctl -u nginx -f                 # follow one unit's logs
journalctl -u nginx --since "1 hour ago"
journalctl -p err -b                   # errors from the current boot
journalctl --since "2026-10-31 00:00"
```

| Flag | Purpose |
|------|---------|
| `-u` | Filter to one unit |
| `-f` | Follow new entries live |
| `-p` | Filter by priority (`err`, `warning`, `info`) |
| `-b` | Current boot (`-b -1` for the previous one) |
| `--since` / `--until` | Bound the time range |

## Common workflows

Deploy a new service unit and bring it up:

```bash
sudo cp example-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now example-api
systemctl status example-api
```

Investigate a service that keeps restarting:

```bash
systemctl status example-api
journalctl -u example-api -p err --since "30 min ago"
systemctl show example-api -p NRestarts,Result,ExecMainStatus
```

Harden an existing service with a drop-in override:

```bash
sudo systemctl edit example-api
# add under [Service]:
#   NoNewPrivileges=true
#   ProtectSystem=strict
#   PrivateTmp=true
sudo systemctl daemon-reload
sudo systemctl restart example-api
```

Disable a risky service so it cannot start at all:

```bash
sudo systemctl disable --now avahi-daemon
sudo systemctl mask avahi-daemon
```

## Flags and options worth knowing

| Flag | Command | Purpose |
|------|---------|---------|
| `--now` | `enable` / `disable` | Also start or stop in the same step |
| `--full` | `edit` | Edit a full unit copy, not a drop-in |
| `--user` | most | Act on the per-user manager |
| `--state=` | `list-units` | Filter by load/active/sub state |
| `--failed` | `systemctl` | Show only failed units |
| `--no-pager` | most | Print directly without a pager |

## Security notes

Unit hardening directives shrink a compromised service's reach. `NoNewPrivileges=true` blocks setuid escalation. `ProtectSystem=strict` makes most of the filesystem read-only, and `ProtectHome=true` hides user home directories. `PrivateTmp=true` gives the service its own `/tmp`, which blocks symlink and predictable-temp-file attacks (CWE-377). `CapabilityBoundingSet=` drops Linux capabilities the service never needs; running a service with excess capability is unnecessary privilege (CWE-250). Review effective hardening with `systemd-analyze security <unit>`.

Give each service its own unprivileged account with `User=` and `DynamicUser=` where possible, rather than running as root. Least privilege limits the blast radius if the process is exploited.

`journald` is an audit source. Keep it persistent (`Storage=persistent` in `journald.conf`), protect the journal from tampering, and forward to a central collector so a local compromise cannot erase evidence. Attackers may stop logging or rotate the journal to cover tracks; alert on unexpected `systemctl stop systemd-journald`.

Masking is stronger than disabling. A disabled unit can still be started by a dependency or by hand; a masked unit is symlinked to `/dev/null` and cannot start until unmasked. Mask services you intend to keep off. Protect `/etc/systemd/system/` and unit-file permissions, since a writable unit file is a direct path to root execution. See /SECURE_CODING_REFERENCE.md for privilege and file-permission guidance.

## Resources

- man pages: `systemctl(1)`, `systemd.unit(5)`, `systemd.service(5)`, `systemd.exec(5)`, `systemd.timer(5)`, `journalctl(1)`
- `systemd-analyze security` built-in report
- freedesktop.org systemd documentation
- Linux distribution systemd administration guides

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/linux-commands.md
- /commands/networking-commands.md
- /commands/ssh.md
