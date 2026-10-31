# Command reference

Practical cheat-sheet references for the command-line tools that developers, administrators, and security engineers use every day: operating-system and shell commands, developer and version-control tools, containers and infrastructure, the cloud provider CLIs, and the standard security testing and analysis tools. Each page lists the commands a practitioner reaches for first, shows real invocations and workflows, calls out the flags that matter, and gives the security notes that turn a convenience into a risk or a defense.

These pages are reference, not tutorials. For the languages behind the shells see [All languages](/languages/README.md); for secure usage patterns see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md). The security testing tools are documented for authorized testing, defense, and learning, and every one ends with how defenders detect and mitigate what it finds.

Related: [All languages](/languages/README.md), [Software frameworks](/frameworks/README.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Reference Index](/INDEX.md).

---

## Operating system and shell commands

| Reference | Summary |
|---|---|
| [Linux commands](/commands/linux-commands.md) | Core GNU/Linux utilities: files, text, processes, permissions, disk, archives, packages |
| [Windows Command Prompt](/commands/windows-cmd.md) | `cmd.exe` builtins and utilities for files, services, accounts, and the registry |
| [macOS commands](/commands/macos-commands.md) | macOS-specific tools: `brew`, `defaults`, `launchctl`, `codesign`, `spctl` |
| [PowerShell commands](/commands/powershell-commands.md) | The cmdlet cheat sheet: verb-noun cmdlets, the pipeline, events, and ACLs |
| [Networking commands](/commands/networking-commands.md) | `ip`, `ss`, `dig`, `ping`, `traceroute`, `nc`, and DNS and connectivity checks |
| [systemd and systemctl](/commands/systemctl.md) | Service and unit management, `journalctl`, timers, and unit hardening |

## Developer and version-control tools

| Reference | Summary |
|---|---|
| [Git](/commands/git.md) | Version control: branching, merging, rebasing, history, and secret hygiene |
| [SSH](/commands/ssh.md) | Secure shell, key management, config, tunneling, and host verification |
| [curl](/commands/curl.md) | HTTP from the command line: methods, headers, auth, TLS, and SSRF caution |
| [jq](/commands/jq.md) | Filtering and transforming JSON, with safe shell integration |
| [Vim](/commands/vim.md) | Modal editing: motions, operators, search and replace, buffers |
| [tmux](/commands/tmux.md) | Terminal multiplexing: sessions, windows, panes, and scripting |

## Containers and infrastructure

| Reference | Summary |
|---|---|
| [Docker](/commands/docker.md) | Building and running containers, with image and runtime hardening |
| [kubectl](/commands/kubectl.md) | Operating Kubernetes, RBAC checks, and secret handling |
| [Terraform](/commands/terraform.md) | Infrastructure as code: plan, apply, state, and secret safety |

## Cloud provider CLIs

| Reference | Summary |
|---|---|
| [AWS CLI](/commands/aws-cli.md) | Operating AWS, credential handling, and least-privilege IAM |
| [Azure CLI](/commands/azure-cli.md) | Operating Azure, managed identities, and Key Vault |
| [Google Cloud CLI](/commands/gcloud.md) | Operating Google Cloud, service accounts, and workload identity |

## Security testing and analysis

Documented for authorized testing, security audits, and defense. Each page includes detection and mitigation.

| Reference | Summary |
|---|---|
| [Nmap](/commands/nmap.md) | Host discovery, port and service scanning, and the scripting engine |
| [sqlmap](/commands/sqlmap.md) | Detecting and confirming SQL injection; defense is parameterized queries |
| [gobuster](/commands/gobuster.md) | Content, DNS, and virtual-host enumeration; defense is monitoring and least exposure |
| [Metasploit Framework](/commands/metasploit.md) | The `msfconsole` workflow for authorized testing, with detection guidance |
| [hashcat](/commands/hashcat.md) | Password-hash auditing; defense is slow salted hashing |
| [GDB](/commands/gdb.md) | Debugging, crash analysis, and exploit development in authorized research |
| [tshark](/commands/tshark.md) | Command-line packet capture and analysis for authorized network work |
