# Claude Agent SDK

> In one minute: The Claude Agent SDK is Anthropic's Python and TypeScript library for building agents on the same agent loop, built-in tools, and context management that power Claude Code. An agent built with it can read and edit files, run shell commands, search the web, and call MCP tools without step-by-step prompting. Because it acts directly on a filesystem and a shell, its permission settings and deployment isolation decide how much harm a prompt injection can cause.

| | |
|---|---|
| Category | Agent framework |
| Maintainer | Anthropic |
| License / access | SDK source is MIT-licensed; use is governed by Anthropic's Commercial Terms of Service. Needs a Claude API key, or Amazon Bedrock, Google Cloud, or Microsoft Foundry access. |
| Official docs | [code.claude.com](https://code.claude.com/docs/en/agent-sdk/overview) |
| Repository | [anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python) (TypeScript: [anthropics/claude-agent-sdk-typescript](https://github.com/anthropics/claude-agent-sdk-typescript)) |
| Checked | 8 Oct 2026, claude-agent-sdk 0.2.164 (Python, PyPI) |

## What it is for

- Coding agents that review a repository, find bugs, and fix them.
- Headless automation in CI/CD, such as pull request review or failure triage.
- Research and operations agents that combine built-in tools with your own tools, exposed as in-process MCP servers.
- Multi-step work split across subagents that run in isolated contexts.
- Production agents with resumable sessions, policy hooks, and OpenTelemetry observability.

## Quick start

1. Create and activate a virtual environment, then install the SDK (Python 3.10 or later). The package bundles the Claude Code binary it drives.

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install claude-agent-sdk
   ```

2. Set your API key in the shell that runs the agent. The SDK reads it from the environment and does not load `.env` files on its own.

   ```bash
   export ANTHROPIC_API_KEY=your-api-key
   ```

3. Create a small file with bugs for the agent to fix, saved as `utils.py`:

   ```python
   def calculate_average(numbers):
       total = 0
       for num in numbers:
           total += num
       return total / len(numbers)

   def get_user_name(user):
       return user["name"].upper()
   ```

4. Create `agent.py` (official quickstart code). It pre-approves only the `Read`, `Edit`, and `Glob` tools.

   ```python
   import asyncio
   from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, ResultMessage

   async def main():
       async for message in query(
           prompt="Review utils.py for bugs that would cause crashes. Fix any issues you find.",
           options=ClaudeAgentOptions(
               allowed_tools=["Read", "Edit", "Glob"],  # Auto-approve these tools
               permission_mode="acceptEdits",  # Auto-approve file edits
           ),
       ):
           if isinstance(message, AssistantMessage):
               for block in message.content:
                   if hasattr(block, "text"):
                       print(block.text)
                   elif hasattr(block, "name"):
                       print(f"Tool: {block.name}")
           elif isinstance(message, ResultMessage):
               print(f"Done: {message.subtype}")

   asyncio.run(main())
   ```

5. Run it with `python agent.py`, then inspect the changes it made to `utils.py`.

## Key concepts

- **`query()`**: async function that runs the agent loop and streams messages (`AssistantMessage`, `ResultMessage`, and others) as the agent works.
- **`ClaudeAgentOptions`**: run configuration, including `allowed_tools`, `disallowed_tools`, `permission_mode`, `cwd`, `system_prompt`, `setting_sources`, and MCP servers.
- **`ClaudeSDKClient`**: client for interactive, multi-turn sessions; supports custom tools and hooks defined as Python functions.
- **Built-in tools**: Claude Code's toolset, such as `Read`, `Write`, `Edit`, `Glob`, and `Bash`, plus web search.
- **Custom tools**: Python functions marked with `@tool` and served through `create_sdk_mcp_server` as an in-process MCP server.
- **Permissions**: each tool call passes hooks, deny rules, ask rules, the permission mode, allow rules, and finally your `can_use_tool` callback.
- **Hooks**: code that runs at lifecycle points; a `PreToolUse` hook can block or change a tool call.
- **Sessions and subagents**: sessions keep context and can be resumed or forked; subagents run focused subtasks in separate contexts.

## Security notes

- The official threat model is prompt injection: instructions hidden in files, web pages, or a README can steer the agent. Anthropic's secure-deployment guide recommends defense in depth: run the agent inside a sandbox, container, gVisor, or VM; mount only needed directories, read-only where possible; restrict network egress through a proxy; and inject credentials at a proxy so the agent never sees them.
- `allowed_tools` auto-approves tools; it does not remove others. Unlisted tools stay available and fall through to the permission mode. Use `disallowed_tools` for hard blocks (deny rules apply even in `bypassPermissions` mode), and pair `allowed_tools` with `permission_mode="dontAsk"` for a locked-down agent. Auto-approved calls skip your callback, so put checks that must always run in a `PreToolUse` hook.
- By default the SDK loads project settings, `CLAUDE.md`, and `.claude/` skills, agents, and commands from the working directory. When the agent works on code you do not control, pass `setting_sources=[]` and configure it in code. For multi-tenant hosting, give each tenant its own filesystem and set `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`.
- Repository-controlled settings are a real vector: [CVE-2026-33068](https://nvd.nist.gov/vuln/detail/CVE-2026-33068) let a committed `.claude/settings.json` silently skip Claude Code's workspace trust dialog (fixed in 2.1.53). [CVE-2026-39861](https://nvd.nist.gov/vuln/detail/CVE-2026-39861) was a symlink sandbox escape (fixed in 2.1.64). The SDK runs this binary, so keep it current and follow the [Claude Code security advisories](https://github.com/anthropics/claude-code/security/advisories).
- Validate anything you pass into SDK options. Advisory [GHSA-h4mw-j7qp-8mwm](https://github.com/anthropics/claude-agent-sdk-python/security/advisories/GHSA-h4mw-j7qp-8mwm) (critical): the Python SDK passed the `resume` session ID to the CLI unvalidated, so a value starting with `-` could inject a flag that defined an MCP server and ran commands. Fixed in claude-agent-sdk 0.2.121.
- Every MCP server you attach extends what the agent can reach. Vet each server, expose only the tools it needs, and treat tool output as untrusted.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- [Agent SDK quickstart](https://code.claude.com/docs/en/agent-sdk/quickstart)
- [Configure permissions](https://code.claude.com/docs/en/agent-sdk/permissions)
- [Securely deploying AI agents](https://code.claude.com/docs/en/agent-sdk/secure-deployment)
- [Hooks](https://code.claude.com/docs/en/agent-sdk/hooks)
- [Example agents repository](https://github.com/anthropics/claude-agent-sdk-demos)
