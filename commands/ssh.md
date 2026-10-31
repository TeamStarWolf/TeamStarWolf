# SSH Command Reference

SSH (Secure Shell) opens an encrypted channel to a remote host for login, command execution, and file transfer. The OpenSSH suite provides the client, server, and key tools used on most systems. This page covers connecting, moving files, managing keys, port forwarding, and the config that ties them together. Public-key authentication is the default for anything beyond a one-off login.

## What it is and where it runs

The `ssh` client ships with Linux, macOS, the BSDs, and modern Windows. It talks to an `sshd` server, usually on TCP port 22. Authentication happens with a key pair or a password, after the client verifies the server's host key. User keys live in `~/.ssh`, the per-user `config` file sets defaults per host, and `sshd_config` controls the server side.

## Core commands

Connect and run commands.

```bash
ssh user@host                # interactive login
ssh user@host 'uptime'       # run one command and exit
ssh -p 2222 user@host        # non-default port
ssh -i ~/.ssh/id_ed25519 user@host   # pick an identity file
```

Transfer files.

```bash
scp file.txt user@host:/path/        # copy a file to the host
scp user@host:/path/file.txt .       # copy a file from the host
scp -r dir/ user@host:/path/         # copy a directory
sftp user@host                       # interactive file session
```

Manage keys and agents.

| Command | Purpose |
| --- | --- |
| `ssh-keygen -t ed25519 -C "label"` | generate a modern key pair |
| `ssh-copy-id user@host` | install your public key on a host |
| `ssh-add ~/.ssh/id_ed25519` | load a key into the agent |
| `ssh-add -l` | list keys held by the agent |
| `eval "$(ssh-agent -s)"` | start an agent in the shell |

Port forwarding.

```bash
ssh -L 8080:localhost:80 user@host   # local port to a remote service
ssh -R 9000:localhost:3000 user@host # remote port back to a local service
ssh -D 1080 user@host                # dynamic SOCKS proxy
```

Jump through a bastion.

```bash
ssh -J bastion.example.com user@internal-host
```

## Common workflows

Set up key-based login so you stop typing passwords.

```bash
ssh-keygen -t ed25519 -C "laptop-2026"
ssh-copy-id user@host
ssh user@host                # now authenticates with the key
```

Define a host alias so long commands shrink to a name.

```bash
# ~/.ssh/config
Host prod
    HostName 203.0.113.10
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    ProxyJump bastion.example.com
```

```bash
ssh prod                     # uses every setting above
```

Reach a database on a private network through a tunnel.

```bash
ssh -L 5432:db.internal:5432 user@bastion
# in another shell, connect your client to localhost:5432
psql -h localhost -p 5432 -U appuser appdb
```

Copy a build artifact from a remote host.

```bash
scp -P 2222 user@prod:/var/www/release.tar.gz ./release.tar.gz
```

## Flags and options worth knowing

| Flag | Applies to | Effect |
| --- | --- | --- |
| `-i <file>` | `ssh`, `scp` | choose the private key |
| `-J <host>` | `ssh` | connect via a jump host |
| `-L` / `-R` / `-D` | `ssh` | local, remote, and dynamic forwarding |
| `-N` | `ssh` | set up forwarding with no remote command |
| `-f` | `ssh` | background after authentication |
| `-v` / `-vvv` | `ssh` | verbose output for debugging |
| `-o <opt>` | `ssh` | set any `config` option inline |

Use `-N -f` together to open a tunnel in the background without starting a shell.

## Security notes

Prefer `ed25519` keys. They are short, fast, and avoid the weak small-key risk of older RSA. If RSA is required, use at least 3072 bits. Protect every private key with a passphrase; a stolen unencrypted key is a direct login. Load passphrase-protected keys into `ssh-agent` so you unlock once per session.

Host key verification stops a man-in-the-middle attack. On first connect, SSH records the server's key in `~/.ssh/known_hosts` and warns loudly if it later changes. Do not disable `StrictHostKeyChecking` or blindly accept a changed key, because that defeats the protection against an impersonated server (CWE-295, improper certificate or host-key validation). Distribute known host keys ahead of time for automation.

Disable password authentication on servers once keys work. Set `PasswordAuthentication no` and `PermitRootLogin no` in `sshd_config` to shut down brute-force attempts. Restrict each entry in `~/.ssh/authorized_keys` with options such as `from="10.0.0.0/8"`, `command="..."`, and `no-port-forwarding` to limit what a key can do.

Agent forwarding (`-A`) lets a remote host use your local keys for the duration of the session. A compromised intermediate host can abuse that socket, so forward the agent only to hosts you fully trust, and prefer `ProxyJump` for bastions. See /SECURE_CODING_REFERENCE.md for authentication and secret-handling guidance.

## Resources

- The `ssh(1)`, `scp(1)`, `sftp(1)`, `ssh-keygen(1)`, and `ssh_config(5)` man pages.
- The OpenSSH project manual at the openssh.com documentation.
- SSH Mastery by Michael W. Lucas.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/git.md
- /commands/networking-commands.md
- /commands/linux-commands.md
