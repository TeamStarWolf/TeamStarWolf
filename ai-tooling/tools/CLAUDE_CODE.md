# Claude Code

> In one minute: Claude Code is Anthropic's agentic coding tool. It reads a codebase, edits files, runs shell commands, and works with git from a terminal, an IDE, a desktop app, or a browser. Because it acts with your user account's access, its permission modes and sandbox settings are security controls, not just preferences.

| | |
|---|---|
| Category | Coding agent |
| Maintainer | Anthropic |
| License / access | Commercial (proprietary, "All rights reserved"); needs a Claude subscription, a Claude Console account, or a supported cloud provider |
| Official docs | [code.claude.com](https://code.claude.com/docs/en/overview) |
| Repository | [anthropics/claude-code](https://github.com/anthropics/claude-code) (issues, changelog, plugins; not the full source) |
| Checked | 8 Oct 2026, v2.1.293 (npm `@anthropic-ai/claude-code`) |

## What it is for

- Explaining an unfamiliar codebase and tracing a bug from an error message to its root cause.
- Writing tests, fixing lint errors, resolving merge conflicts, and updating dependencies.
- Creating commits, branches, and pull requests through git.
- Running non-interactively with `claude -p` in scripts and CI, for example to review changed files for security issues.
- Connecting to outside tools and data (ticketing, docs, chat) through Model Context Protocol (MCP) servers.

## Quick start

1. Install with the native installer (it updates itself in the background).

   macOS, Linux, or WSL:

   ```bash
   curl -fsSL https://claude.ai/install.sh | bash
   ```

   Windows PowerShell:

   ```powershell
   irm https://claude.ai/install.ps1 | iex
   ```

   Package managers are also supported. These installs do not auto-update:

   ```bash
   brew install --cask claude-code      # macOS, Homebrew
   winget install Anthropic.ClaudeCode  # Windows, WinGet
   ```

   On native Windows, Git for Windows is recommended so Claude Code can use its Bash tool. Without it, Claude Code uses PowerShell.

2. Open a new terminal and confirm the install:

   ```bash
   claude --version
   ```

3. Start a session in a project folder and log in when prompted:

   ```bash
   cd /path/to/your/project
   claude
   ```

4. Ask a read-only question first, such as `what does this project do?`, then request a small change and review the diff before approving it.
5. Press `Shift+Tab` to cycle permission modes. Type `/help` for commands and `/permissions` to review rules.

## Key concepts

- **Permission modes**: `default` (labeled Manual), `acceptEdits`, `plan`, `auto`, `dontAsk`, and `bypassPermissions`. From v2.1.283, `auto` is the built-in starting mode for interactive terminal and VS Code sessions; a separate classifier model reviews actions instead of you.
- **Permission rules**: `allow`, `ask`, and `deny` rules in settings files. Rules are evaluated deny, then ask, then allow, so an allow rule cannot carve an exception out of a deny rule. Managed settings override every other level.
- **Sandbox**: an operating-system boundary around the shell commands Claude runs (Seatbelt on macOS, bubblewrap on Linux and WSL2). It is off by default and applies to shell commands only.
- **Workspace trust**: a dialog shown the first time you start an interactive session in an untrusted folder. It gates repository-supplied settings such as allow rules and MCP servers.
- **CLAUDE.md**: a Markdown file of project instructions that Claude Code reads at the start of every session.
- **Hooks**: shell commands that run before or after Claude Code actions, defined in settings files.
- **MCP servers**: external tool servers. Project-scoped servers live in `.mcp.json` and can be committed to a repository.
- **Headless mode**: `claude -p "<prompt>"` runs one task and exits, for scripts and CI.

## Security notes

- **Pick the permission mode on purpose.** `bypassPermissions`, started with `--dangerously-skip-permissions` or `--permission-mode bypassPermissions`, skips prompts, including writes to protected paths such as `.git` and `.claude`. Anthropic says to use it only in isolated containers or VMs. Never run it on a workstation that holds SSH keys, cloud credentials, or tokens. Administrators can block it by setting `permissions.disableBypassPermissionsMode` (and `permissions.disableAutoMode`) to `"disable"` in managed settings. See [Choose a permission mode](https://code.claude.com/docs/en/permission-modes).
- **Turn on the sandbox, and know its limits.** Run `/sandbox` or set `sandbox.enabled` to `true`. File tools, web tools, hooks, and local MCP servers run outside it, and on native Windows commands run unsandboxed (use WSL2). For one boundary around everything, run the whole process in a dev container, a VM, or Anthropic's sandbox runtime. See [Sandboxing](https://code.claude.com/docs/en/sandboxing).
- **Treat repository content as untrusted input.** Source files, CLAUDE.md, issues, and fetched web pages can carry prompt injection. A cloned repository can also ship hooks in `.claude/settings.json` and servers in `.mcp.json`. A `claude -p` or SDK run never shows the trust dialog: repository hooks are used and `.mcp.json` servers connect without asking. Do not run headless sessions against untrusted code.
- **Limit network reach.** Commands such as `curl` and `wget` are not auto-approved by default. Add deny rules for them, or use sandbox network isolation, which does not depend on how a command is written. Anthropic also advises not piping untrusted content directly to Claude and using VMs for scripts that touch external services. See [Security](https://code.claude.com/docs/en/security).
- **Learn from s1ngularity (August 2025).** Malicious versions of the Nx build system on npm ran a post-install script that checked for installed AI CLIs. If present, it ran `claude --dangerously-skip-permissions -p` (and `gemini --yolo -p` and `q chat --trust-all-tools --no-interactive`) with a prompt to list files such as `.env`, `id_rsa`, `*.key`, and crypto wallets. The script also took GitHub and npm tokens and pushed the stolen data to public `s1ngularity-repository` repositories. The Hacker News reported 2,349 distinct secrets leaked. An installed agent plus a bypass flag is a ready-made tool for malware. Write-ups: [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html), [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware), [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack), and the [Nx advisory](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c).
- **Keep it updated and watch advisories.** Anthropic publishes [security advisories](https://github.com/anthropics/claude-code/security/advisories) for Claude Code. 2026 entries include a sandbox escape through git worktree path confusion and a trust-dialog bypass. Native installs auto-update; Homebrew and WinGet installs must be upgraded by hand.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Claude Code overview](https://code.claude.com/docs/en/overview): install options and every surface (terminal, IDE, desktop, web).
- [Quickstart](https://code.claude.com/docs/en/quickstart): first session, first change, and git workflow.
- [Configure permissions](https://code.claude.com/docs/en/permissions): rule syntax, managed settings, and what runs before you trust a folder.
- [Security](https://code.claude.com/docs/en/security): Anthropic's safeguards and best practices.
- [Claude Code 101](https://academy.claude.com/courses/claude-code-101): free self-paced course on Claude Academy.
