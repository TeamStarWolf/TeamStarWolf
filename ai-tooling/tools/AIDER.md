# Aider

> In one minute: Aider is an open-source AI pair programmer that runs in your terminal and edits code in a local git repository. It works with many model providers, including hosted APIs and local models, and commits each change to git so it can be reviewed or undone. Its docs do not describe an operating-system sandbox, so how you run it decides what it can reach.

| | |
|---|---|
| Category | Coding agent |
| Maintainer | Aider-AI (open-source project) |
| License / access | Open source (Apache-2.0); you supply your own model provider API keys |
| Official docs | [aider.chat](https://aider.chat/docs/) |
| Repository | [Aider-AI/aider](https://github.com/Aider-AI/aider) |
| Checked | 8 Oct 2026, v0.86.2 (PyPI `aider-chat`, released 12 Feb 2026) |

## What it is for

- Pair programming in the terminal: describe a change and let aider edit the files in your repository.
- Asking questions about a codebase without changing it (ask mode).
- Using one model to plan a change and a second model to apply the edits (architect mode).
- Running lint and test commands after edits and feeding failures back to the model.
- Working from your editor: with `--watch-files`, aider acts on special comments you add to source files.

## Quick start

1. Install aider. The documented method for any OS uses the `aider-install` helper (Python 3.8 to 3.13), which puts aider in its own environment:

   ```bash
   python -m pip install aider-install
   aider-install
   ```

   One-line installers are also documented.

   macOS and Linux:

   ```bash
   curl -LsSf https://aider.chat/install.sh | sh
   ```

   Windows:

   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://aider.chat/install.ps1 | iex"
   ```

2. Change into your project (a git repository) and start aider with a model and key. Examples from the docs:

   ```bash
   cd /to/your/project
   aider --model sonnet --api-key anthropic=<key>
   aider --model o3-mini --api-key openai=<key>
   ```

3. Add the files you want changed with `/add`, describe the change, and review the commit aider makes. Use `/undo` to discard the last aider commit.

## Key concepts

- **Chat modes**: `code` (edit files), `ask` (discuss without editing), `architect` (a main model proposes, an editor model applies), and `help` (questions about aider).
- **In-chat commands**: `/add`, `/drop`, `/read-only`, `/run` (alias `!`), `/test`, `/undo`, `/diff`, and `/web`.
- **Repository map**: a condensed map of the repository's important classes and functions that aider sends to the model for context.
- **Git integration**: aider commits each edit by default and marks commits it authored with "(aider)". It commits pre-existing uncommitted changes separately before editing a file.
- **Watch mode**: `--watch-files` monitors repository files for comments ending in `AI!` (make changes) or `AI?` (answer a question).
- **Configuration**: options can come from the command line, environment variables, a `.env` file (by default in the git root), or `.aider.conf.yml`.

## Security notes

- **Aider runs with your user access.** Its docs describe no operating-system sandbox. It can suggest shell commands and offers to run them, and `/run` executes commands you type. For untrusted code, run aider in its documented Docker image, where `/run` executes inside the container rather than on your machine. See [Aider with Docker](https://aider.chat/docs/install/docker.html).
- **Do not use `--yes-always` on a machine that holds secrets.** It answers yes to every confirmation, which removes your chance to stop a harmful command. Use it only in a disposable container or VM. To stop aider from suggesting or offering to run shell commands at all, use `--no-suggest-shell-commands`. See the [options reference](https://aider.chat/docs/config/options.html).
- **Watch mode turns file comments into instructions.** With `--watch-files`, a comment ending in `AI!` in any watched file tells aider to make changes. Do not enable it on repositories that contain third-party or untrusted code you have not reviewed.
- **Expect prompt injection.** Files you `/add`, pages fetched with `/web`, and command output added to the chat all reach the model and can carry hidden instructions. Review every diff before you push, and use `/undo` or git to revert.
- **Keep keys out of git.** The docs suggest storing provider keys in a `.env` file or `.aider.conf.yml`. Make sure those files are not committed. Keys passed on the command line can end up in shell history.
- **Know the defaults.** Auto-commits are on (`--no-auto-commits` turns them off), and aider adds `.aider*` to `.gitignore`. Analytics are opt-in; `aider --analytics-disable` opts out permanently, and aider states it never collects code, chat messages, or keys.
- **Supply-chain context.** In the August 2025 s1ngularity attack, malicious Nx packages ran installed AI CLIs with permission-bypass flags (`claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools`) to find wallets, keys, and `.env` files. Aider was not among the targets, but the lesson applies to any agent that can run commands without asking. See [The Hacker News](https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html) and [StepSecurity](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware).
- Related library pages: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Aider documentation](https://aider.chat/docs/): installation, usage, configuration, and troubleshooting.
- [Installation](https://aider.chat/docs/install.html): every install method, including uv and pipx.
- [In-chat commands](https://aider.chat/docs/usage/commands.html).
- [Git integration](https://aider.chat/docs/git.html): auto-commits, attribution, and undo.
- [Tutorial videos](https://aider.chat/docs/usage/tutorials.html): community-made walkthroughs listed in the docs.
