# OpenAI Agents SDK

> In one minute: The OpenAI Agents SDK is a lightweight, open-source Python framework for building agents from a small set of primitives: agents, tools, handoffs, guardrails, and sessions. It is OpenAI's production successor to its earlier Swarm experiment and uses the Responses API by default for OpenAI models, with integration points for other providers. Teams use it to build single agents or coordinated multi-agent workflows with built-in tracing.

| | |
|---|---|
| Category | Agent framework |
| Maintainer | OpenAI |
| License / access | Open source (MIT). Model calls need an API key for OpenAI or another configured provider. |
| Official docs | [openai.github.io/openai-agents-python](https://openai.github.io/openai-agents-python/) |
| Repository | [openai/openai-agents-python](https://github.com/openai/openai-agents-python) |
| Checked | 8 Oct 2026, openai-agents 0.23.1 (PyPI) |

## What it is for

- Tool-using assistants where plain Python functions become tools with generated, validated schemas.
- Multi-agent workflows: a triage agent hands off to specialists, or an orchestrator calls specialists as tools.
- Input, output, and per-tool guardrails that validate or stop a run.
- Human approval of sensitive tool calls, with paused runs that can be saved and resumed.
- Sandbox agents that inspect and edit files inside an isolated workspace.
- Voice and realtime agents.

## Quick start

1. Create a project and a virtual environment, then activate it.

   ```bash
   mkdir my_project
   cd my_project
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install the SDK.

   ```bash
   pip install openai-agents
   ```

3. Set your API key for the current terminal session (PowerShell: `$env:OPENAI_API_KEY = "sk-..."`). Do not put it in code.

   ```bash
   export OPENAI_API_KEY=sk-...
   ```

4. Create an agent with one tool and run it (official quickstart code). In this release, `tool` is an alias for `function_tool`.

   ```python
   import asyncio
   from agents import Agent, Runner
   from agents.decorators import tool


   @tool
   def history_fun_fact() -> str:
       """Return a short history fact."""
       return "Sharks are older than trees."


   agent = Agent(
       name="History Tutor",
       instructions="Answer history questions clearly. Use history_fun_fact when it helps.",
       tools=[history_fun_fact],
   )


   async def main():
       result = await Runner.run(
           agent,
           "Tell me something surprising about ancient life on Earth.",
       )
       print(result.final_output)


   if __name__ == "__main__":
       asyncio.run(main())
   ```

5. For a second turn, pass `result.to_input_list()` back into `Runner.run(...)`, or attach a session so the SDK stores history for you.

## Key concepts

- **Agent**: an LLM configured with a name, instructions, tools, and optional model, guardrails, and handoffs.
- **Runner**: runs the agent loop (`Runner.run`, `Runner.run_sync`) until a final output, and returns a result with `final_output`.
- **Function tool**: a Python function turned into a tool, with a schema built from its signature and docstring.
- **Handoffs and agents as tools**: two multi-agent patterns. A handoff lets a specialist take over the turn; agents as tools keep an orchestrator in control.
- **Guardrails**: input guardrails, output guardrails, and tool guardrails. A failed check raises a tripwire exception that stops the run.
- **Sessions**: a memory layer that loads and saves conversation history across runs.
- **Tracing**: built-in spans for generations, tool calls, handoffs, and guardrails, shown in the OpenAI Traces dashboard.
- **MCP support**: local MCP servers (stdio, SSE, Streamable HTTP) and hosted MCP tools appear to the agent alongside function tools.

## Security notes

- Know the guardrail boundaries. Input guardrails run only for the first agent and output guardrails only for the last. In workflows with handoffs or delegated specialists, attach tool guardrails to each function tool. Hosted tools (for example `WebSearchTool`, `CodeInterpreterTool`, `HostedMCPTool`) and execution tools (`ShellTool`, `ComputerTool`) do not use the tool-guardrail pipeline.
- Input guardrails run in parallel with the agent by default, so the agent may already have called tools when a tripwire fires. Set `run_in_parallel=False` on guardrails that must finish before any side effect.
- Require approval for risky actions: `needs_approval=True` on function tools, and `require_approval` (`"always"` or per tool name) on MCP servers. Use `tool_filter` or `create_static_tool_filter` to expose only the MCP tools an agent needs.
- Tracing is on by default and exports to OpenAI's backend, and `trace_include_sensitive_data` defaults to `True`, so spans can hold model and tool inputs and outputs. Set `RunConfig(trace_include_sensitive_data=False)` or `OPENAI_AGENTS_TRACE_INCLUDE_SENSITIVE_DATA=0`, or turn tracing off with `OPENAI_AGENTS_DISABLE_TRACING=1`. Tracing is unavailable for organizations under Zero Data Retention.
- Treat tool results, web content, handoff inputs, and MCP tool descriptions as untrusted; any of them can carry prompt injection. Give file and shell work to sandbox agents; the docs suggest the Unix-local sandbox client only for trusted local development and offer a Docker-backed option (`openai-agents[docker]`).
- No GitHub security advisories were listed for the `openai-agents` package when this page was checked. Pin versions anyway and review the release notes before upgrading.
- Background reading: [AI & MCP Security Reference](/AI_MCP_SECURITY_REFERENCE.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Agentic AI Swarm Attacks](/AGENTIC_AI_ATTACK_REFERENCE.md), [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [Quickstart](https://openai.github.io/openai-agents-python/quickstart/)
- [Guardrails](https://openai.github.io/openai-agents-python/guardrails/)
- [Human in the loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)
- [Tracing](https://openai.github.io/openai-agents-python/tracing/)
- [Model Context Protocol in the SDK](https://openai.github.io/openai-agents-python/mcp/)
- [Sandbox agents](https://openai.github.io/openai-agents-python/sandbox_agents/)
