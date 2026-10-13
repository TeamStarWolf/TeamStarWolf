# Gemini CLI

> In one minute: Gemini CLI is Google's open-source AI agent for the terminal, built on Gemini models. It reads and edits files, runs shell commands, searches the web, and connects to MCP servers and extensions. It was one of the AI CLIs abused in the s1ngularity supply-chain attack, which makes its approval and sandbox settings worth understanding.

| | |
|---|---|
| Category | Coding agent |
| Maintainer | Google |
| License / access | Open source (Apache-2.0). Google's docs state that for unpaid-tier and Google One users, Gemini CLI was replaced by Antigravity CLI on 18 June 2026; Google's announcement says access continues through paid Gemini API keys and Gemini Code Assist Standard or Enterprise licenses |
| Official docs | [geminicli.com](https://geminicli.com/docs/) |
| Repository | [google-gemini/gemini-cli](https://github.com/google-gemini/gemini-cli) |
| Checked | 8 Oct 2026, v0.63.0 (released 6 Oct 2026, npm `@google/gemini-cli`) |

## What it is for

- Explaining a repository and answering questions about how its code works.
- Writing and editing code, including unit tests, from the terminal.
- File and data chores, such as renaming files by content or merging CSV files.
- Non-interactive automation with `gemini -p`, for scripts and GitHub Actions.
- Extending the agent with MCP servers, extensions, and agent skills.

## Quick start

1. Check requirements: Node.js 20 or later; macOS 15+, Windows 11 24H2+, or Ubuntu 20.04+; and a location where Gemini Code Assist is supported.
2. Install with one of the documented methods:

   ```bash
   npm install -g @google/gemini-cli   # any OS with Node.js
   brew install gemini-cli             # macOS or Linux, Homebrew
   sudo port install gemini-cli        # macOS, MacPorts
   ```

   To try it without a global install: `npx @google/gemini-cli`.

3. Start it from a project folder:

   ```bash
   cd /path/to/your/project
   gemini
   ```

4. Choose an authentication method when asked: **Sign in with Google**, a Gemini API key (`GEMINI_API_KEY`), or Vertex AI (`GOOGLE_API_KEY` with `GOOGLE_GENAI_USE_VERTEXAI=true`). Some account types need a Google Cloud project (`GOOGLE_CLOUD_PROJECT`).
5. Give it a first task, such as `Write unit tests for Login.js`. Gemini CLI asks for permission before acting on files. Run `/stats model` to see token usage and quota.

## Key concepts

- **Approval mode** (`--approval-mode`): `default` (ask before tools run), `auto_edit`, `yolo` (auto-approve all actions), or `plan`. The older `--yolo` / `-y` flag is deprecated in favor of `--approval-mode=yolo`.
- **Sandbox** (`-s` / `--sandbox`, the `GEMINI_SANDBOX` variable, or `tools.sandbox` in settings): off by default. Methods include macOS Seatbelt, Docker or Podman containers, a native Windows sandbox, gVisor (`runsc`) on Linux, and experimental LXC.
- **Trusted folders**: an opt-in feature. When enabled, untrusted folders ignore project settings and `.env` files, do not connect MCP servers, and disable tool auto-acceptance.
- **GEMINI.md**: context files with persistent instructions. A global file in `~/.gemini/GEMINI.md` is combined with files from the workspace and loaded with every prompt.
- **Headless mode**: `-p` / `--prompt` runs a single prompt non-interactively.
- **Extensions and MCP servers**: add tools and integrations to the agent.
- **Policy engine**: TOML rules that allow, deny, or require confirmation for each tool call, for users and administrators.

## Security notes

- **Do not use YOLO mode on machines with secrets.** `--approval-mode=yolo` (or the deprecated `--yolo`) auto-approves every action, including shell commands. Keep the `default` mode for interactive work, and if you need unattended runs, combine them with a sandbox on a disposable machine. See the [CLI reference](https://geminicli.com/docs/cli/cli-reference).
- **Learn from s1ngularity (August 2025).** Malicious versions of the Nx build system on npm ran a post-install script that checked for installed AI CLIs and ran `gemini --yolo -p` (along with `claude --dangerously-skip-permissions -p` and `q chat --trust-all-tools --no-interactive`) with a prompt to list `.env` files, private keys, and crypto wallets. The script also took GitHub and npm tokens and published the data to public `s1ngularity-repository` repositories. See [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html), [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware), [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack), and the [Nx advisory](https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c).
- **Turn on the sandbox.** Sandboxing is off until you enable it. On macOS, the default Seatbelt profile, `permissive-open`, confines writes to the project directory but allows broad file reads and network access; `strict-proxied` restricts reads and writes and sends network traffic through a proxy (set it with `SEATBELT_PROFILE`). Container sandboxes mount your working directory into the container. Google notes sandboxing reduces but does not eliminate risk. See [Sandboxing](https://geminicli.com/docs/cli/sandbox).
- **Enable trusted folders.** The feature is off by default; turn it on with `security.folderTrust.enabled` in your user `settings.json`. In headless use, an untrusted folder stops the CLI unless you pass `--skip-trust` or set `GEMINI_CLI_TRUST_WORKSPACE=true`, so avoid those in pipelines that handle third-party code. See [Trusted folders](https://geminicli.com/docs/cli/trusted-folders).
- **Expect prompt injection.** GEMINI.md files, source files, issues, and web results all reach the model. A cloned repository can carry instructions or project settings meant for the agent, so review them before running the CLI in that folder.
- **Protect credentials.** API keys and Google credentials grant model access and may carry billing. Keep them out of repositories and project `.env` files you do not control.
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Gemini CLI documentation](https://geminicli.com/docs/): features, configuration, and reference.
- [Get started](https://geminicli.com/docs/get-started/): install, authenticate, and first prompts.
- [Project context with GEMINI.md](https://geminicli.com/docs/cli/gemini-md): how context files are found and loaded.
- [Gemini CLI: Code and Create with an Open-Source Agent](https://www.deeplearning.ai/courses/gemini-cli-code-and-create-with-an-open-source-agent): short beginner course from DeepLearning.AI built with Google.
- [Transition announcement](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli): Google's notice about the move to Antigravity CLI.
