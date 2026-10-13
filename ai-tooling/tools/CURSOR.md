# Cursor

> In one minute: Cursor is an AI code editor with a built-in agent that can explain code, plan and make multi-file changes, and run terminal commands. It also ships a command-line agent and cloud agents. Because the agent can write files and run commands in your workspace, its run modes, sandbox, and workspace trust settings decide how much a malicious repository or prompt can do.

| | |
|---|---|
| Category | Coding agent / AI editor |
| Maintainer | Cursor |
| License / access | Commercial, closed source; a free tier exists (Hobby plan) |
| Official docs | [cursor.com/docs](https://cursor.com/docs) |
| Repository | None (closed source) |
| Checked | 8 Oct 2026, desktop 3.22 on the downloads page and 3.23.23 on the stable update channel |

## What it is for

- Understanding an unfamiliar codebase: asking the agent for entry points, key modules, and files to read first.
- Planning and building features across many files, with a written plan you approve first.
- Finding and fixing bugs, then running tests, type checks, linting, or builds to confirm the fix.
- Reviewing changes in a diff view before keeping them.
- Running the same agent from a terminal (Cursor CLI) or in the cloud.

## Quick start

1. Download Cursor from [cursor.com/downloads](https://cursor.com/downloads). Installers exist for macOS (`.dmg`, macOS 12 or later), Windows (`.exe`, Windows 10 or later), and Linux (`.deb`, RPM, or AppImage; the `.deb` and RPM packages are preferred because they include updates and CLI tools).
2. Open the app, sign in, and pick a project folder.
3. Open Agent (the quickstart shortcut is `Cmd+I` on macOS) and ask it to explain the codebase.
4. Ask for one small change, then check the diff view and ask Cursor to run your tests or linter.
5. For larger work, press `Shift+Tab` in the agent input to toggle **Plan Mode**. Cursor researches the code, writes a plan, and waits for your approval before building.
6. Optional: install the Cursor CLI.

   macOS, Linux, or WSL:

   ```bash
   curl https://cursor.com/install -fsS | bash
   ```

   Windows (PowerShell):

   ```powershell
   irm 'https://cursor.com/install?win32=true' | iex
   ```

   Then run `agent` in a project folder (`agent --version` checks the install).

## Key concepts

- **Agent**: the assistant that reads code, edits files, and runs terminal commands in your workspace.
- **Plan Mode**: the agent researches, asks questions, and writes a plan before changing code.
- **Run modes**: control which tool calls run without a prompt. **Auto-review** (the default) runs allowlisted calls, sandboxes other shell commands when possible, and sends the rest to a classifier. **Allowlist** runs only listed actions without approval. **Run Everything** runs every tool call automatically, with no sandbox and no classifier.
- **Sandbox**: limits agent shell commands. It uses Seatbelt on macOS (Cursor 2.0 or later) and Landlock plus seccomp on Linux (kernel 6.2 or later).
- **Rules**: persistent instructions in `.cursor/rules` (`.mdc` files with frontmatter) or in plain `AGENTS.md` files.
- **MCP servers**: external tools configured in `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global).
- **`.cursorignore`**: a file that blocks the agent from specific files.
- **Workspace trust**: an optional setting that opens new workspaces in a restricted mode with AI features disabled.

## Security notes

- **Avoid Run Everything on machines with secrets.** It runs every tool call with no sandbox and no classifier. Cursor also says Auto-review and allowlists are best-effort guardrails, not a hard security boundary. Keep terminal commands behind approval or the sandbox, and use version control so you can revert changes, which are written to disk immediately. See [Agent security](https://cursor.com/docs/agent/security) and [Run modes](https://cursor.com/docs/agent/security/run-modes).
- **Turn on workspace trust for untrusted code.** Workspace trust is off by default. When enabled, it asks whether to open a new workspace normally or in restricted mode. For untrusted repositories, Cursor suggests restricted mode or a basic text editor. Organizations can enforce the setting through MDM.
- **Prompt injection can reach configuration.** [CVE-2025-54135](https://nvd.nist.gov/vuln/detail/CVE-2025-54135): before version 1.3.9, the agent could create a missing dotfile such as `.cursor/mcp.json` without approval, so an indirect prompt injection could register a malicious MCP server and run code. Fixed in 1.3.9; see the [vendor advisory](https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm).
- **Approve MCP servers deliberately.** Every MCP connection and each MCP tool call needs approval by default. Cursor advises installing servers only from trusted sources, giving them least-privilege API keys, keeping secrets in environment variables, and preferring local `stdio` servers for sensitive work. See [MCP](https://cursor.com/docs/mcp).
- **Keep Cursor updated.** Cursor's [security advisories](https://github.com/cursor/cursor/security/advisories) for 2026 include several sandbox escapes (through Git hooks, an agent-controlled working directory, symlinks, and tampered Python virtual environments).
- **Protect sensitive files.** Add secrets and credential files to `.cursorignore`. Report vulnerabilities to `security-reports@cursor.com`.
- **Supply-chain context.** In the August 2025 s1ngularity attack, malicious Nx packages ran installed AI CLIs with permission-bypass flags (`claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`) to find wallets, keys, and `.env` files. Cursor was not among the targets, but any agent set to run everything without approval offers the same shortcut. See [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html) and [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware).
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Cursor documentation](https://cursor.com/docs): start here for features, models, and the changelog.
- [Quickstart](https://cursor.com/docs/get-started/quickstart): install, first change, review, and Plan Mode.
- [Rules](https://cursor.com/docs/rules): project rules, user rules, and AGENTS.md.
- [Cursor CLI installation](https://cursor.com/docs/cli/installation).
- [Cursor Learn](https://cursor.com/learn): a course on programming with AI models and tools.
