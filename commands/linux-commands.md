# Linux Command Reference

The GNU/Linux core utilities are the programs you reach for at any shell prompt on a Linux system. They run on servers, workstations, containers, and embedded devices. This page groups the commands by task: files, text, processes, permissions, disk, archives, and packages. Every example is a real invocation you can paste at a `bash` prompt.

## What it is and where it runs

Most of these tools come from GNU coreutils, `util-linux`, `findutils`, and `grep`, installed by default on nearly every Linux distribution. They operate on files, streams, and processes through the kernel. They read from standard input, write to standard output, and signal errors through standard error and an exit status. Pipes (`|`) and redirection (`>`, `<`) compose them into larger operations.

## Core commands

Files and directories:

```bash
ls -lah /var/log            # long listing, human sizes, including dotfiles
cp -a src/ dst/             # copy recursively, preserve attributes
mv old.txt new.txt          # rename or move
rm -i file.txt              # remove, prompt before each delete
find / -name '*.conf' -type f   # locate files by name and type
ln -s /opt/app/bin app      # create a symbolic link
stat config.yaml            # show inode, size, timestamps, permissions
```

| Command | Purpose |
|---|---|
| `ls` | List directory contents |
| `cp` | Copy files and directories |
| `mv` | Move or rename |
| `rm` | Delete files |
| `find` | Search the filesystem by attribute |
| `ln` | Create hard or symbolic links |
| `stat` | Display file metadata |

Text and streams:

```bash
grep -rn 'TODO' src/        # recursive search with line numbers
sed 's/foo/bar/g' in.txt    # substitute all occurrences on each line
awk -F: '{print $1}' /etc/passwd   # print first colon-delimited field
cut -d, -f2 data.csv        # extract second comma field
sort -u names.txt           # sort and drop duplicate lines
uniq -c sorted.txt          # count adjacent duplicate lines
tr 'a-z' 'A-Z' < in.txt     # translate lowercase to uppercase
wc -l access.log            # count lines
```

| Command | Purpose |
|---|---|
| `cat` | Concatenate and print files |
| `grep` | Search text with regular expressions |
| `sed` | Stream editor for substitution |
| `awk` | Field-based text processing |
| `head` / `tail` | Show first or last lines |
| `less` | Page through output |

Processes and jobs:

```bash
ps aux                      # snapshot of all running processes
top                         # live process and resource view
kill -TERM 4821             # send SIGTERM to a process by PID
nice -n 10 ./batch.sh       # start a job with lower priority
nohup ./server &            # run detached from the terminal
jobs                        # list background jobs in this shell
```

| Command | Purpose |
|---|---|
| `ps` | Report process status |
| `top` / `htop` | Monitor processes live |
| `kill` | Send signals to processes |
| `nice` | Adjust scheduling priority |
| `nohup` | Keep a job running after logout |

Permissions and users:

```bash
chmod 640 secret.key        # owner rw, group r, others none
chown app:app /srv/app      # set owner and group
id alice                    # show uid, gid, and groups
sudo systemctl restart nginx    # run one command as root
umask 027                   # mask group write and all other bits
```

| Command | Purpose |
|---|---|
| `chmod` | Change file mode bits |
| `chown` | Change owner and group |
| `sudo` | Run a command as another user |
| `id` | Show user and group identity |
| `useradd` / `passwd` | Create users and set passwords |
| `umask` | Set default permission mask |

Disk and archives:

```bash
df -h                       # free space per mounted filesystem
du -sh /var/*               # size of each entry under /var
lsblk                       # tree of block devices
tar -czf backup.tgz data/   # create a gzip-compressed archive
tar -xzf backup.tgz         # extract a gzip archive
```

Packages:

```bash
sudo apt update && sudo apt install nmap   # Debian and Ubuntu
sudo dnf install nmap                      # Fedora and RHEL
dpkg -l | grep openssl                     # query installed deb packages
rpm -qa | grep openssl                     # query installed rpm packages
```

## Common workflows

Find and delete old logs safely, prompting with `find -ok`:

```bash
find /var/log -name '*.log' -mtime +30 -ok rm {} \;
```

Extract and count the top client IPs from an access log:

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
```

Audit files that anyone can write, a common misconfiguration:

```bash
find / -xdev -type f -perm -0002 -ls 2>/dev/null
```

Create a timestamped backup, verify its contents, then store it:

```bash
tar -czf "home-$(date +%F).tgz" /home/alice
tar -tzf home-*.tgz | head
```

## Flags and options worth knowing

| Flag | Command | Effect |
|---|---|---|
| `-i` | `rm`, `cp`, `mv` | Prompt before overwrite or delete |
| `-r` / `-R` | `rm`, `cp`, `grep`, `chmod` | Operate recursively |
| `-a` | `cp` | Archive mode, preserve links and attributes |
| `-exec` / `-ok` | `find` | Run a command per match (`-ok` prompts) |
| `-n` | `grep`, `sort` | Line numbers, or numeric sort |
| `--preserve-root` | `rm` | Refuse to act on `/` (default on GNU `rm`) |
| `-p` | `mkdir` | Create parent directories as needed |

## Security notes

Permission bits are the first access control you set. A mode of `777` or a careless `chmod -R 777` grants write to everyone and maps to CWE-732, incorrect permission assignment for a critical resource. Set `umask 027` for service accounts so new files are not group or world readable by default. Audit world-writable files with the `find -perm -0002` command above.

`sudo` and `setuid` binaries run with elevated privilege. Keep `/etc/sudoers` minimal, prefer `sudo visudo` to edit it, and avoid `NOPASSWD` on broad commands. A writable `setuid` program, or one that trusts `PATH`, is a privilege-escalation path. List setuid files with `find / -perm -4000 -type f 2>/dev/null`.

`rm -rf` has no undo and expands globs before running, so a stray space in `rm -rf / home/old` is catastrophic. Quote variables (`rm -rf "$dir"`) so an empty variable does not become `/`. Redirection truncates: `>` overwrites, `>>` appends. In scripts, set `set -euo pipefail` so errors and unset variables stop execution. See `/SECURE_CODING_REFERENCE.md` for input handling and command-injection guidance when shell commands take untrusted data.

For defenders, these tools drive triage: `find -mtime` surfaces recently changed files, `stat` reveals timestamp tampering, and `grep` over logs spots indicators. For attackers, the same binaries are living-off-the-land tools, so monitor unusual `curl`, `base64`, and `chmod +x` activity in audit logs.

## Resources

- `man` pages for each utility (`man find`, `man 1 chmod`, `man 7 signal`).
- GNU Coreutils manual (`info coreutils`).
- The Linux Programming Interface, Michael Kerrisk.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/macos-commands.md
- /commands/systemctl.md
- /commands/ssh.md
- /commands/tmux.md
