# GitHub Copilot

> In one minute: GitHub Copilot is GitHub's AI coding assistant. It offers inline code suggestions and chat in editors, an agent mode that edits files and runs commands, a terminal agent (Copilot CLI), and a cloud agent that opens pull requests on GitHub. Because these agents can edit code and run commands, their approval settings and repository permissions are security controls.

| | |
|---|---|
| Category | Coding agent |
| Maintainer | GitHub |
| License / access | Commercial, free tier (Copilot Free); Copilot CLI is distributed under a proprietary GitHub license |
| Official docs | [docs.github.com](https://docs.github.com/en/copilot) |
| Repository | [github/copilot-cli](https://github.com/github/copilot-cli) (Copilot CLI releases and issues; the service itself is closed source) |
| Checked | 8 Oct 2026, hosted service; Copilot CLI v1.0.93 (released 7 Oct 2026) |

## What it is for

- Inline code suggestions while you type in a supported IDE such as VS Code.
- Chat about the open file or a selected block of code, for example to explain it or suggest a fix.
- Agent mode in the IDE: describe a task and let Copilot create and edit files across the project.
- Copilot CLI: an agent in the terminal that reads, edits, and runs commands in a trusted folder.
- Copilot cloud agent: works on GitHub and opens draft pull requests for human review.

## Quick start

1. Get access. You need a Copilot plan; a free plan (Copilot Free) exists with limited features. Organization owners can disable Copilot features, including the CLI.
2. In VS Code, install the Copilot extension and sign in to GitHub.
3. Try an inline suggestion: create a `.js` file, type a function header such as `function calculateDaysBetweenDates(begin, end) {`, and press `Tab` to accept the grey suggestion.
4. Open chat with `Ctrl+Alt+I` (Windows, Linux) or `Control+Command+I` (macOS). Select **Agent** in the chat window to give it a multi-step task, then review the changes before you accept them.
5. Optional: install Copilot CLI (npm needs Node.js 22 or later).

   ```bash
   npm install -g @github/copilot                    # all platforms
   brew install --cask copilot-cli                   # macOS, Linux
   curl -fsSL https://gh.io/copilot-install | bash   # macOS, Linux
   ```

   ```powershell
   winget install GitHub.Copilot   # Windows, needs PowerShell 6 or later
   ```

6. Start it in a project folder, answer the folder trust prompt, and log in if asked:

   ```bash
   cd /path/to/your/project
   copilot
   ```

   Inside the session, type `/login` if you are not signed in to GitHub.

## Key concepts

- **Inline suggestions**: grey-text completions in the editor that you accept with `Tab`.
- **Copilot Chat and agent mode**: chat in the IDE; in agent mode Copilot plans the task, edits files, and proposes changes for you to accept.
- **Copilot CLI**: a terminal agent. It asks before using a tool that can modify or execute files, unless you pre-approve tools.
- **Trusted directories**: folders where Copilot CLI may read, modify, and execute files. You confirm trust when a session starts.
- **Tool approval options**: `--allow-tool`, `--deny-tool`, and `--allow-all-tools`. Deny rules always take precedence over allow rules.
- **Autopilot**: a Copilot CLI mode that works through several steps without waiting for input. `--max-autopilot-continues` caps the number of continuations.
- **Copilot cloud agent**: runs on GitHub, works on its own `copilot/` branch, and opens a draft pull request.

## Security notes

- **Keep permission-bypass options for isolated machines.** `--allow-all-tools` lets Copilot CLI use any tool without asking. `--allow-all` and its alias `--yolo` combine `--allow-all-tools`, `--allow-all-paths`, and `--allow-all-urls`; `/allow-all` and `/yolo` do the same inside a session. GitHub strongly recommends using these only in an isolated environment and never putting them in a shell alias. Never use them on a machine that holds secrets. Business and Enterprise administrators may block them. See [Allowing and denying tool use](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools).
- **Scope approvals narrowly.** Approving a tool "for the rest of the running session" is broad: approving `rm` once can allow any `rm` command. Prefer explicit rules such as `--allow-tool='shell(git:*)' --deny-tool='shell(git push)'`.
- **Use the sandbox options.** GitHub suggests running Copilot CLI in a VM, container, or dedicated system with tight permissions and network access. Inside a session, `/sandbox enable` restricts the commands and tools Copilot runs; a cloud session runs in an isolated remote environment. Do not launch Copilot CLI from your home directory, because trust scoping is heuristic. See [About Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-copilot-cli).
- **Assume prompt injection.** Repository files, issues, and web pages can carry hidden instructions. [CVE-2025-53773](https://nvd.nist.gov/vuln/detail/CVE-2025-53773) is a command injection flaw in GitHub Copilot and Visual Studio that let an attacker execute code locally (CVSS 7.8). Keep the IDE and extension patched.
- **Know the cloud agent's guardrails.** Only users with write access can trigger it, and comments from users without write access are never shown to it. It pushes only to its own branch, its internet access is restricted by a firewall, hidden characters such as HTML comments are filtered out, and GitHub Actions workflows do not run on its pull requests until a person with write access approves them, unless an administrator allows automatic runs. A human must review and merge. See [Risks and mitigations](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/risks-and-mitigations).
- **Supply-chain context.** In the August 2025 s1ngularity attack, malicious Nx packages ran installed AI CLIs with permission-bypass flags (`claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`) to find wallets, keys, and `.env` files. Copilot CLI was not on that list, but any CLI agent with a bypass flag offers malware the same shortcut. See [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html) and [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware).
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [GitHub Copilot documentation](https://docs.github.com/en/copilot): concepts, how-tos, and reference.
- [Quickstart for GitHub Copilot in your IDE](https://docs.github.com/en/copilot/get-started/quickstart-for-using-github-copilot-in-your-ide).
- [Installing GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli).
- [Allowing GitHub Copilot CLI to work autonomously](https://docs.github.com/en/copilot/concepts/agents/copilot-cli/autopilot): autopilot mode and its warnings.
- [Getting Started with GitHub Copilot](https://github.com/skills/getting-started-with-github-copilot): hands-on GitHub Skills exercise.
