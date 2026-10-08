# OpenAI Codex CLI

> In one minute: Codex CLI is OpenAI's open-source coding agent for the terminal. It reads a repository, edits files, and runs commands inside an operating-system sandbox, asking for approval when it needs to step outside that boundary. Its sandbox modes and approval policies make it a useful case study in how a coding agent can be contained.

| | |
|---|---|
| Category | Coding agent |
| Maintainer | OpenAI |
| License / access | Open source (Apache-2.0); sign in with a ChatGPT account or use an OpenAI API key |
| Official docs | [learn.chatgpt.com](https://learn.chatgpt.com/docs) |
| Repository | [openai/codex](https://github.com/openai/codex) |
| Checked | 8 Oct 2026, v0.161.0 (release `rust-v0.161.0`, npm `@openai/codex`) |

## What it is for

- Asking questions about a codebase and getting answers grounded in the files.
- Making multi-file code changes and running tests or builds to check them.
- Working inside a sandbox so routine edits and local commands need no prompt, while riskier steps still ask.
- Scripted and CI use through `codex exec`.
- Sharing project conventions with the agent through `AGENTS.md` files.

## Quick start

1. Install Codex CLI with one of the methods from the repository README.

   macOS or Linux (standalone installer):

   ```bash
   curl -fsSL https://chatgpt.com/codex/install.sh | sh
   ```

   Windows (PowerShell installer):

   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"
   ```

   Any platform with npm, or macOS with Homebrew:

   ```bash
   npm install -g @openai/codex
   brew install --cask codex
   ```

   Prebuilt binaries for macOS and Linux are also attached to each GitHub release.

2. Start it from a project directory:

   ```bash
   cd /path/to/your/project
   codex
   ```

3. On first run, choose **Sign in with ChatGPT** (recommended by OpenAI) or set up an API key.
4. Ask a question about the project, then ask for a small change. Review the diff and any command Codex wants to run outside the sandbox.

## Key concepts

- **Sandbox mode** (`sandbox_mode`, or `--sandbox`): `read-only`, `workspace-write` (the default for local work, with network access off), or `danger-full-access` (no sandbox).
- **Approval policy** (`approval_policy`, or `--ask-for-approval` / `-a`): `on-request` (work inside the sandbox and ask to go beyond it), `never`, or `granular`. The old `untrusted` value is retired.
- **Platform sandboxes**: Seatbelt through `sandbox-exec` on macOS; `bwrap` plus `seccomp` on Linux; on Windows, a native Windows sandbox or the Linux sandbox under WSL2.
- **Writable roots**: `sandbox_workspace_write.writable_roots` adds directories Codex may modify in `workspace-write` mode.
- **AGENTS.md**: Markdown instructions Codex reads before it works. It merges a global file in `~/.codex/` with files from the project root down to the working directory.
- **config.toml**: the Codex configuration file where sandbox, approval, and network settings live.
- **`codex exec`**: non-interactive runs for scripts and automation.

## Security notes

- **Keep the sandbox on.** `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`) turns off both the sandbox and approvals, and the `danger-full-access` mode is marked "not recommended" in OpenAI's docs. Never run either on a workstation that holds secrets. Even inside a dev container, OpenAI warns that a malicious project running with full access can exfiltrate anything in that container, including Codex credentials. See [Agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security).
- **Leave network access off unless a task needs it.** In `workspace-write`, network access is off by default and must be enabled with `[sandbox_workspace_write] network_access = true`. Only enable it for trusted tasks.
- **Treat fetched content as untrusted.** OpenAI notes that prompt injection can cause the agent to fetch and follow untrusted instructions. The same applies to repository files, issues, and `AGENTS.md` files from third parties, which Codex reads before it does any work.
- **`--full-auto` is deprecated.** For `codex exec`, OpenAI prefers `codex exec --sandbox workspace-write`, which keeps the sandbox boundary.
- **Patch promptly.** [CVE-2025-59532](https://github.com/openai/codex/security/advisories/GHSA-w5fx-fh39-j5rw) (High): a bug let Codex CLI treat a model-generated working directory as the sandbox's writable root, allowing writes and command execution outside the workspace. Fixed in CLI 0.39.0 and IDE extension 0.4.12.
- **Learn from s1ngularity (August 2025).** Malicious Nx packages on npm ran installed AI CLIs with permission-bypass flags (`claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`) to find wallets, keys, and `.env` files, then published the data to public GitHub repositories. Codex was not among the targeted CLIs, but its bypass flag offers the same shortcut. See [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html), [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware) and [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack).
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Codex documentation](https://learn.chatgpt.com/docs): overview, features, configuration, and security.
- [Codex CLI](https://learn.chatgpt.com/docs/cli): install, run, and sign-in for the terminal agent.
- [Sandboxing](https://learn.chatgpt.com/docs/sandboxing): sandbox modes, approval policies, and `config.toml` keys.
- [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md): how Codex discovers and merges instruction files.
- [openai/codex on GitHub](https://github.com/openai/codex): source, releases, and security advisories.
